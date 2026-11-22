import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

export type Provider = 'telegram' | 'tiktok';
type Config = { id: string; secret: string; redirect: string };

export function providerConfig(provider: Provider): Config | null {
  const prefix = provider === 'telegram' ? 'TELEGRAM' : 'TIKTOK';
  const id = process.env[`${prefix}_${provider === 'telegram' ? 'CLIENT_ID' : 'CLIENT_KEY'}`] ?? '';
  const secret = process.env[`${prefix}_CLIENT_SECRET`] ?? '';
  const redirect = process.env[`${prefix}_REDIRECT_URI`] ?? '';
  if (!id || !secret || !redirect) return null;
  try {
    const url = new URL(redirect);
    if (url.protocol !== 'https:' || url.pathname !== `/api/customer/oauth/${provider}/callback`) return null;
  } catch { return null; }
  return { id, secret, redirect };
}

export function authorizationUrl(provider: Provider, config: Config, state: string, nonce: string, verifier: string): string {
  if (provider === 'tiktok') {
    const url = new URL('https://www.tiktok.com/v2/auth/authorize/');
    url.search = new URLSearchParams({ client_key: config.id, response_type: 'code', scope: 'user.info.basic', redirect_uri: config.redirect, state }).toString();
    return url.toString();
  }
  const url = new URL('https://oauth.telegram.org/auth');
  url.search = new URLSearchParams({ client_id: config.id, response_type: 'code', redirect_uri: config.redirect, scope: 'openid profile', state, nonce, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
  return url.toString();
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid provider response');
  return value as Record<string, unknown>;
}

async function telegramIdentity(config: Config, code: string, nonce: string, verifier: string) {
  const credentials = Buffer.from(`${config.id}:${config.secret}`).toString('base64');
  const response = await fetch('https://oauth.telegram.org/token', {
    method: 'POST', headers: { Authorization: `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: config.redirect, client_id: config.id, code_verifier: verifier }), signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error('Telegram token exchange failed');
  const token = object(await response.json()).id_token;
  if (typeof token !== 'string') throw new Error('Telegram ID token missing');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid Telegram ID token');
  const header = object(JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')));
  const claims = object(JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Unsupported Telegram signature');
  const keysResponse = await fetch('https://oauth.telegram.org/.well-known/jwks.json', { signal: AbortSignal.timeout(10000) });
  if (!keysResponse.ok) throw new Error('Telegram key lookup failed');
  const keys = object(await keysResponse.json()).keys;
  const key = Array.isArray(keys) ? keys.find(item => item?.kid === header.kid && item?.kty === 'RSA') : null;
  if (!key) throw new Error('Telegram signing key missing');
  const publicKey = createPublicKey({ key: key as import('node:crypto').JsonWebKey, format: 'jwk' });
  if (!verifySignature('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url'))) throw new Error('Invalid Telegram signature');
  const audience = claims.aud;
  if (claims.iss !== 'https://oauth.telegram.org' || !(audience === config.id || (Array.isArray(audience) && audience.includes(config.id))) || claims.nonce !== nonce || typeof claims.sub !== 'string' || !claims.sub || typeof claims.exp !== 'number' || claims.exp <= Date.now() / 1000 || typeof claims.iat !== 'number' || claims.iat > Date.now() / 1000 + 60) throw new Error('Invalid Telegram token claims');
  return { id: claims.sub, name: typeof claims.name === 'string' ? claims.name.slice(0, 120) : '' };
}

async function tiktokIdentity(config: Config, code: string) {
  const response = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_key: config.id, client_secret: config.secret, code, grant_type: 'authorization_code', redirect_uri: config.redirect }), signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error('TikTok token exchange failed');
  const token = object(await response.json());
  if (typeof token.open_id !== 'string' || !token.open_id || typeof token.access_token !== 'string') throw new Error('Invalid TikTok token response');
  let name = '';
  try {
    const userResponse = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=display_name', { headers: { Authorization: `Bearer ${token.access_token}` }, signal: AbortSignal.timeout(10000) });
    if (userResponse.ok) { const user = object(object(await userResponse.json()).data).user; if (typeof object(user).display_name === 'string') name = String(object(user).display_name).slice(0, 120); }
  } catch { /* Profile name can be completed in the store. */ }
  return { id: token.open_id, name };
}

export async function exchangeIdentity(provider: Provider, config: Config, code: string, nonce: string, verifier: string) {
  return provider === 'telegram' ? telegramIdentity(config, code, nonce, verifier) : tiktokIdentity(config, code);
}
