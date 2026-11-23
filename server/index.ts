import { loadEnvFile } from 'node:process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, createHmac, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import pg from 'pg';
import { telegramIdentity } from './telegram.js';
import { products as catalog } from '../src/products.js';
import { authorizationUrl, exchangeIdentity, providerConfig, type Provider } from './social.js';

try { loadEnvFile('.env'); } catch { /* optional */ }
try { loadEnvFile('.env.local'); } catch { /* optional */ }
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL?.replace('sslmode=require', 'sslmode=verify-full'), max: 5, ssl: { rejectUnauthorized: true } });
let passcode = process.env.ADMIN_PASSCODE ?? '';
const superadminPasscode = process.env.SUPERADMIN_PASSCODE ?? '';
const sessionSecret = process.env.SESSION_SECRET ?? '';
if (!process.env.DATABASE_URL || !passcode || !sessionSecret) throw new Error('DATABASE_URL, ADMIN_PASSCODE and SESSION_SECRET are required');
const ready = pool.query("ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_fit text NOT NULL DEFAULT 'cover' CHECK (cover_fit IN ('cover', 'contain')); ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_position text NOT NULL DEFAULT 'center' CHECK (cover_position IN ('top', 'center', 'bottom')); ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_zoom integer NOT NULL DEFAULT 100 CHECK (cover_zoom BETWEEN 100 AND 200); CREATE TABLE IF NOT EXISTS customer_accounts (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text UNIQUE, password_hash text NOT NULL, name text NOT NULL, phone text NOT NULL, city text NOT NULL, delivery_address text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())").then(() => pool.query("ALTER TABLE customer_accounts ALTER COLUMN email DROP NOT NULL; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS phone_key text UNIQUE; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS telegram_id text UNIQUE; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS tiktok_id text UNIQUE")).then(() => pool.query("CREATE INDEX IF NOT EXISTS orders_user_date_idx ON orders (user_id, created_at DESC); CREATE TABLE IF NOT EXISTS system_events (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, event_type text NOT NULL, method text, path text, status integer, user_id bigint, message text, created_at timestamptz NOT NULL DEFAULT now()); CREATE INDEX IF NOT EXISTS system_events_created_idx ON system_events (created_at DESC); CREATE INDEX IF NOT EXISTS system_events_type_created_idx ON system_events (event_type, created_at DESC); CREATE TABLE IF NOT EXISTS password_resets (token_hash text PRIMARY KEY, user_id bigint NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()); CREATE INDEX IF NOT EXISTS password_resets_user_created_idx ON password_resets(user_id,created_at DESC)")).then(() => pool.query("SELECT value FROM admin_settings WHERE key = 'passcode'")).then(({ rows }) => { if (rows[0]?.value) passcode = rows[0].value; });
const staffReady = ready.then(() => pool.query("CREATE TABLE IF NOT EXISTS staff_sessions (token_hash text PRIMARY KEY, role text NOT NULL CHECK (role IN ('admin','developer')), credential_version text NOT NULL, expires_at timestamptz NOT NULL); CREATE INDEX IF NOT EXISTS staff_sessions_expires_idx ON staff_sessions(expires_at); CREATE TABLE IF NOT EXISTS staff_login_attempts (role text NOT NULL, key_hash text NOT NULL, failures integer NOT NULL DEFAULT 0, blocked_until timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (role,key_hash))"));

type Item = { tone: string; variant: number; quantity: number };
const send = (res: ServerResponse, value: unknown, status = 200, headers: Record<string, string> = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(value)); };
const safeEqual = (a: string, b: string) => { const left = createHmac('sha256', sessionSecret).update(a).digest(); const right = createHmac('sha256', sessionSecret).update(b).digest(); return timingSafeEqual(left, right); };
const sign = (value: string) => createHmac('sha256', sessionSecret).update(value).digest('hex');
const deriveStaffPasscode = promisify(scrypt);
const hashStaffPasscode = async (value: string) => { const salt = randomBytes(16).toString('hex'); const hash = await deriveStaffPasscode(value, salt, 64) as Buffer; return `scrypt$${salt}$${hash.toString('hex')}`; };
const verifyStaffPasscode = async (value: string, stored: string) => { if (!stored.startsWith('scrypt$')) return safeEqual(value, stored); const [,salt,hash] = stored.split('$'); if (!/^[a-f0-9]{32}$/.test(salt ?? '') || !/^[a-f0-9]{128}$/.test(hash ?? '')) return false; const actual = await deriveStaffPasscode(value, salt, 64) as Buffer; return timingSafeEqual(actual, Buffer.from(hash, 'hex')); };
type StaffRole = 'admin' | 'developer';
const staffName = (role: StaffRole) => role === 'admin' ? 'yc_admin' : 'yc_superadmin';
const staffPath = (role: StaffRole) => `/api/${role === 'admin' ? 'admin' : 'developer'}`;
const staffToken = (role: StaffRole, req: IncomingMessage) => req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(`${staffName(role)}=`))?.slice(staffName(role).length + 1) ?? '';
const staffHash = (token: string) => createHash('sha256').update(token).digest('hex');
const staffVersion = (role: StaffRole) => sign(`staff.${role}.${role === 'admin' ? passcode : superadminPasscode}`);
const refreshAdminPasscode = async () => { const { rows } = await pool.query("SELECT value FROM admin_settings WHERE key='passcode'"); let current = rows[0]?.value ?? process.env.ADMIN_PASSCODE ?? ''; if (rows[0]?.value && !current.startsWith('scrypt$')) { const upgraded = await hashStaffPasscode(current); const saved = await pool.query("UPDATE admin_settings SET value=$1 WHERE key='passcode' AND value=$2 RETURNING value", [upgraded, current]); current = saved.rows[0]?.value ?? (await pool.query("SELECT value FROM admin_settings WHERE key='passcode'")).rows[0]?.value ?? current; } passcode = current; };
const staffSession = async (role: StaffRole, req: IncomingMessage) => {
  if (role === 'admin') await refreshAdminPasscode();
  const token = staffToken(role, req);
  if (!/^[a-f0-9]{64}$/.test(token)) return false;
  const { rows } = await pool.query('SELECT 1 FROM staff_sessions WHERE token_hash=$1 AND role=$2 AND credential_version=$3 AND expires_at>now()', [staffHash(token), role, staffVersion(role)]);
  return rows.length > 0;
};
const admin = (req: IncomingMessage) => staffSession('admin', req);
const developer = (req: IncomingMessage) => staffSession('developer', req);
const issueStaffSession = async (role: StaffRole) => {
  const token = randomBytes(32).toString('hex');
  const age = role === 'admin' ? 4 * 60 * 60 : 2 * 60 * 60;
  await pool.query('INSERT INTO staff_sessions(token_hash,role,credential_version,expires_at) VALUES($1,$2,$3,$4)', [staffHash(token), role, staffVersion(role), new Date(Date.now() + age * 1000)]);
  return `${staffName(role)}=${token}; HttpOnly; SameSite=Strict; Path=${staffPath(role)}; Max-Age=${age}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
};
const revokeStaffSession = async (role: StaffRole, req: IncomingMessage) => { const token = staffToken(role, req); if (/^[a-f0-9]{64}$/.test(token)) await pool.query('DELETE FROM staff_sessions WHERE token_hash=$1 AND role=$2', [staffHash(token), role]); };
const clearStaffCookie = (role: StaffRole) => `${staffName(role)}=; HttpOnly; SameSite=Strict; Path=${staffPath(role)}; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
const staffIpKey = (role: StaffRole, req: IncomingMessage) => {
  const forwarded = process.env.VERCEL ? req.headers['x-vercel-forwarded-for'] : undefined;
  const address = (typeof forwarded === 'string' ? forwarded.split(',')[0] : req.socket.remoteAddress) || 'unknown';
  return createHmac('sha256', sessionSecret).update(`${role}.${address}`).digest('hex');
};
const staffLocked = async (role: StaffRole, key: string) => { const { rows } = await pool.query('SELECT 1 FROM staff_login_attempts WHERE role=$1 AND key_hash=$2 AND blocked_until>now()', [role, key]); return rows.length > 0; };
const staffFailed = async (role: StaffRole, key: string) => pool.query("INSERT INTO staff_login_attempts(role,key_hash,failures,blocked_until,updated_at) VALUES($1,$2,1,NULL,now()) ON CONFLICT(role,key_hash) DO UPDATE SET failures=CASE WHEN staff_login_attempts.updated_at<now()-interval '15 minutes' THEN 1 ELSE staff_login_attempts.failures+1 END, blocked_until=CASE WHEN staff_login_attempts.updated_at<now()-interval '15 minutes' THEN NULL WHEN staff_login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END, updated_at=now()", [role, key]);
type Customer = { id: string; email: string | null; name: string; phone: string; city: string; deliveryAddress: string };
const customerCookie = (req: IncomingMessage) => req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('yc_customer='))?.slice(12);
const customerSession = async (req: IncomingMessage): Promise<Customer | null> => {
  const [id, expiry, mac] = customerCookie(req)?.split('.') ?? [];
  if (!id || !/^\d+$/.test(id) || !expiry || !mac || Number(expiry) <= Date.now() || !safeEqual(mac, sign(`${id}.${expiry}`))) return null;
  const { rows } = await pool.query('SELECT id::text, email, name, phone, city, delivery_address AS "deliveryAddress" FROM customer_accounts WHERE id = $1', [id]);
  return rows[0] ?? null;
};
const authCookie = (id: string) => { const expiry = String(Date.now() + 30 * 24 * 60 * 60 * 1000); return `yc_customer=${id}.${expiry}.${sign(`${id}.${expiry}`)}; HttpOnly; SameSite=Lax; Path=/api; Max-Age=2592000${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`; };
const passwordHash = (password: string) => { const salt = randomBytes(16).toString('hex'); return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`; };
const verifyPassword = (password: string, stored: string) => { const [salt, hash] = stored.split(':'); if (!salt || !hash || !/^[a-f0-9]{128}$/.test(hash)) return false; return timingSafeEqual(scryptSync(password, salt, 64), Buffer.from(hash, 'hex')); };
const profileFields = (input: Record<string, unknown>) => ({ name: String(input.name ?? '').trim(), phone: String(input.phone ?? '').trim(), city: String(input.city ?? '').trim(), deliveryAddress: String(input.deliveryAddress ?? '').trim() });
const optionalEmail = (input: Record<string, unknown>) => { const value = String(input.email ?? '').trim().toLowerCase(); return value || null; };
const validEmail = (email: string | null) => email === null || (email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
const validProfile = (p: ReturnType<typeof profileFields>) => p.name.length > 0 && p.name.length <= 120 && /^\+?[0-9\s-]{7,20}$/.test(p.phone) && p.city.length > 0 && p.city.length <= 120 && p.deliveryAddress.length > 0 && p.deliveryAddress.length <= 500;
const phoneKey = (value: string) => { const digits = value.replace(/\D/g, ''); return /^09\d{7,9}$/.test(digits) ? `95${digits.slice(1)}` : /^959\d{7,9}$/.test(digits) ? digits : null; };
const customerReady = ready.then(async () => {
  const { rows } = await pool.query("SELECT id, phone FROM customer_accounts WHERE phone_key IS NULL AND phone <> ''");
  for (const row of rows) {
    const key = phoneKey(row.phone);
    if (!key) continue;
    try { await pool.query('UPDATE customer_accounts SET phone_key = $1 WHERE id = $2 AND phone_key IS NULL', [key, row.id]); }
    catch (error) { if ((error as { code?: string }).code !== '23505') throw error; }
  }
});
const customerAttempts = new Map<string, { count: number; until: number }>();
const oauthStateCookie = (provider: Provider) => `yc_oauth_${provider}`;
const clearOauthCookie = (provider: Provider) => `${oauthStateCookie(provider)}=; HttpOnly; SameSite=Lax; Path=/api/customer/oauth/${provider}/callback; Max-Age=0`;
const body = async (req: IncomingMessage) => { let text = ''; for await (const chunk of req) { text += chunk; if (text.length > 50_000_000) throw new Error('Request too large'); } return JSON.parse(text) as Record<string, unknown>; };
const recordEvent = (event: { eventType: string; req: IncomingMessage; status?: number; message?: string }) => { const cookie = event.req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('yc_customer='))?.slice(12); const userId = cookie?.split('.')[0]; void pool.query('INSERT INTO system_events(event_type,method,path,status,user_id,message) VALUES($1,$2,$3,$4,$5,$6)', [event.eventType, event.req.method ?? null, new URL(event.req.url ?? '/', 'http://localhost').pathname, event.status ?? null, userId && /^\d+$/.test(userId) ? userId : null, event.message?.slice(0, 500) ?? null]).catch(() => undefined); };
let requestLogging: 'full' | 'errors-only' = 'full';
let requestLoggingExpires = 0;
const getRequestLogging = async () => { if (Date.now() < requestLoggingExpires) return requestLogging; const { rows } = await pool.query("SELECT value FROM admin_settings WHERE key='request_logging'"); requestLogging = rows[0]?.value === 'errors-only' ? 'errors-only' : 'full'; requestLoggingExpires = Date.now() + 30_000; return requestLogging; };
const landingAsset = (key: string) => ({ 'chocobrown-1.png': 'product-stocking-chocobrown.png', 'magicblack-1.jpg': 'product-stocking-magicblack-1.jpg', 'skincolor-1.png': 'product-stocking-skincolor-1.png' }[key] ?? key);
const imageUrl = (key: string) => { if (key.startsWith('data:image/') || key.startsWith('https://')) return key; const clean = decodeURIComponent(key.replace(/^\/products\//, '').replace(/^\//, '')); return `/${landingAsset(clean).split('/').map(encodeURIComponent).join('/')}`; };

async function listProducts() {
  const { rows } = await pool.query('SELECT tone, name, description, images, price_note, cover_fit, cover_position, cover_zoom FROM products ORDER BY name');
  const { rows: variants } = await pool.query('SELECT product_tone, variant_index, size_group, label, fit, price_ks FROM product_variants ORDER BY variant_index');
  return rows.map(p => ({ name: p.name, tone: p.tone, description: p.description, images: (p.images as string[]).map(imageUrl), coverFit: p.cover_fit === 'contain' ? 'contain' : 'cover', coverPosition: ['top','center','bottom'].includes(p.cover_position) ? p.cover_position : 'center', coverZoom: p.cover_zoom, priceNote: p.price_note, prices: variants.filter(v => v.product_tone === p.tone).map(v => ({ group: v.size_group, label: v.label, fit: v.fit, price: `${Number(v.price_ks).toLocaleString()} Ks` })) }));
}

async function placeOrder(customer: string, phone: string, address: string, note: string, items: Item[], userId: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let total = 0;
    const lines: { item: Item; price: number }[] = [];
    for (const item of items) {
      if (typeof item.tone !== 'string' || !Number.isInteger(item.variant) || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 99) throw new Error('Invalid product selection');
      const { rows } = await client.query('SELECT price_ks FROM product_variants WHERE product_tone = $1 AND variant_index = $2', [item.tone, item.variant]);
      if (!rows.length) throw new Error('Invalid product selection');
      const price = Number(rows[0].price_ks); total += price * item.quantity; lines.push({ item, price });
    }
    const { rows } = await client.query('INSERT INTO orders (customer_name, customer_phone, delivery_address, customer_note, total_ks, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, customer_name, total_ks, status, created_at', [customer, phone, address, note, total, userId]);
    for (const { item, price } of lines) await client.query('INSERT INTO order_items (order_id, product_tone, variant_index, quantity, unit_price_ks) VALUES ($1, $2, $3, $4, $5)', [rows[0].id, item.tone, item.variant, item.quantity, price]);
    await client.query('COMMIT');
    return { id: rows[0].id, total, status: rows[0].status };
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}

export async function route(req: IncomingMessage, res: ServerResponse) {
  await Promise.all([customerReady, staffReady]);
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;
  if (path.startsWith('/api/admin/') || path.startsWith('/api/developer/')) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (!['GET','HEAD'].includes(req.method ?? 'GET')) {
      const origin = req.headers.origin;
      let sameOrigin = true;
      try {
        if (origin) {
          const source = new URL(origin);
          const forwardedHost = req.headers['x-forwarded-host'];
          const hosts = [req.headers.host, typeof forwardedHost === 'string' ? forwardedHost : undefined, process.env.PUBLIC_SITE_URL ? new URL(process.env.PUBLIC_SITE_URL).host : undefined];
          sameOrigin = hosts.includes(source.host);
          if (!sameOrigin && !process.env.VERCEL) {
            const loopback = new Set(['localhost', '127.0.0.1', '[::1]']);
            sameOrigin = loopback.has(source.hostname) && loopback.has(new URL(`http://${req.headers.host}`).hostname);
          }
        }
      } catch { sameOrigin = false; }
      if (!sameOrigin || req.headers['sec-fetch-site'] === 'cross-site') return send(res, { error: 'Cross-site request rejected' }, 403);
    }
  }
  if (path === '/api/store/status' && req.method === 'GET') { const { rows } = await pool.query("SELECT value FROM admin_settings WHERE key = 'maintenance_mode'"); return send(res, { maintenance: rows[0]?.value === 'on' }); }
  if (!path.startsWith('/api/developer/') && !path.startsWith('/api/admin/') && path !== '/api/store/status') {
    const { rows } = await pool.query("SELECT value FROM admin_settings WHERE key = 'maintenance_mode'");
    if (rows[0]?.value === 'on') return send(res, { error: 'Store under maintenance', maintenance: true }, 503);
  }
  if (req.method === 'GET' && path === '/api/products') return send(res, await listProducts());
  if (req.method === 'GET' && path === '/api/store/banner') { const { rows } = await pool.query('SELECT key, value FROM admin_settings WHERE key IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)', ['store_banner_desktop','store_banner_mobile','store_banner','store_banner_desktop_view','store_banner_mobile_view','store_banner_desktop_position','store_banner_mobile_position','store_banner_desktop_zoom','store_banner_mobile_zoom','store_banner_desktop_x','store_banner_desktop_y','store_banner_mobile_x','store_banner_mobile_y']); const values = Object.fromEntries(rows.map(row => [row.key, row.value])); const view=(key:string,positionKey:string,zoomKey:string,xKey:string,yKey:string)=>({ fit: values[key] === 'contain' ? 'contain' : 'cover', position: ['top','center','bottom'].includes(values[positionKey]) ? values[positionKey] : 'center', zoom: Math.min(180,Math.max(100,Number(values[zoomKey]||100))), x: Math.min(100,Math.max(0,Number(values[xKey]||50))), y: Math.min(100,Math.max(0,Number(values[yKey]||50))) }); return send(res, { desktop: values.store_banner_desktop ?? values.store_banner ?? null, mobile: values.store_banner_mobile ?? values.store_banner_desktop ?? values.store_banner ?? null, desktopView: view('store_banner_desktop_view','store_banner_desktop_position','store_banner_desktop_zoom','store_banner_desktop_x','store_banner_desktop_y'), mobileView: view('store_banner_mobile_view','store_banner_mobile_position','store_banner_mobile_zoom','store_banner_mobile_x','store_banner_mobile_y') }); }
  if (req.method === 'GET' && path === '/api/customer/providers') return send(res, { telegram: !!providerConfig('telegram'), tiktok: !!providerConfig('tiktok') });
  if (req.method === 'POST' && path === '/api/customer/telegram-miniapp') {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    if (!token) return send(res, { error: 'Telegram Mini App sign-in is not configured' }, 503);
    const input = await body(req);
    let identity;
    try { identity = telegramIdentity(String(input.initData || ''), token); }
    catch { return send(res, { error: 'Telegram sign-in expired or invalid. Reopen the Mini App.' }, 401); }
    const { rows } = await pool.query(`INSERT INTO customer_accounts (email,password_hash,name,phone,city,delivery_address,telegram_id) VALUES (NULL,$1,$2,'','','',$3) ON CONFLICT (telegram_id) DO UPDATE SET telegram_id=EXCLUDED.telegram_id RETURNING id::text,email,name,phone,city,delivery_address AS "deliveryAddress"`, ['!telegram-only:' + randomBytes(32).toString('hex'), identity.name, identity.id]);
    return send(res, { profile: rows[0] }, 200, { 'Set-Cookie': authCookie(rows[0].id) });
  }
  const oauth = path.match(/^\/api\/customer\/oauth\/(telegram|tiktok)\/(start|callback)$/);
  if (req.method === 'GET' && oauth) {
    const provider = oauth[1] as Provider; const config = providerConfig(provider);
    if (!config) return send(res, { error: `${provider} sign-in is not configured` }, 503);
    if (oauth[2] === 'start') {
      const state = randomBytes(24).toString('base64url'), nonce = randomBytes(24).toString('base64url'), verifier = randomBytes(32).toString('base64url'), expiry = String(Date.now() + 10 * 60_000);
      const value = `${state}.${nonce}.${verifier}.${expiry}`;
      res.writeHead(302, { Location: authorizationUrl(provider, config, state, nonce, verifier), 'Set-Cookie': `${oauthStateCookie(provider)}=${value}.${sign(`${provider}.${value}`)}; HttpOnly; SameSite=Lax; Path=/api/customer/oauth/${provider}/callback; Max-Age=600; Secure` });
      return res.end();
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    const raw = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(`${oauthStateCookie(provider)}=`))?.split('=')[1] ?? '';
    const [state, nonce, verifier, expiry, mac] = raw.split('.');
    const fail = () => { res.writeHead(302, { Location: '/login?error=social', 'Set-Cookie': clearOauthCookie(provider) }); res.end(); };
    if (!state || !nonce || !verifier || !expiry || !mac || Number(expiry) <= Date.now() || !safeEqual(mac, sign(`${provider}.${state}.${nonce}.${verifier}.${expiry}`)) || !safeEqual(state, url.searchParams.get('state') ?? '') || !url.searchParams.get('code') || url.searchParams.has('error')) return fail();
    try {
      const identity = await exchangeIdentity(provider, config, url.searchParams.get('code')!, nonce, verifier);
      const column = provider === 'telegram' ? 'telegram_id' : 'tiktok_id';
      let { rows } = await pool.query(`SELECT id::text, name, phone, city, delivery_address AS "deliveryAddress" FROM customer_accounts WHERE ${column} = $1`, [identity.id]);
      if (!rows.length) {
        const created = await pool.query(`INSERT INTO customer_accounts (email,password_hash,name,phone,city,delivery_address,${column}) VALUES (NULL,$1,$2,'','','',$3) ON CONFLICT DO NOTHING RETURNING id::text, name, phone, city, delivery_address AS "deliveryAddress"`, [passwordHash(randomBytes(32).toString('hex')), identity.name, identity.id]);
        rows = created.rows.length ? created.rows : (await pool.query(`SELECT id::text, name, phone, city, delivery_address AS "deliveryAddress" FROM customer_accounts WHERE ${column} = $1`, [identity.id])).rows;
      }
      if (!rows.length) return fail();
      const incomplete = !rows[0].name || !rows[0].phone || !rows[0].city || !rows[0].deliveryAddress;
      res.writeHead(302, { Location: incomplete ? '/profile?complete=1' : '/orders', 'Set-Cookie': [authCookie(rows[0].id), clearOauthCookie(provider)] });
      return res.end();
    } catch { return fail(); }
  }
  if (req.method === 'GET' && path === '/api/customer/session') { const profile = await customerSession(req); return send(res, { authenticated: !!profile, profile }); }
  if (req.method === 'POST' && path === '/api/customer/password-reset/request') {
    if (!process.env.RESEND_API_KEY || !process.env.RESET_EMAIL_FROM || !process.env.PUBLIC_SITE_URL) return send(res, { error: 'Email password recovery is not configured yet. Contact the store for help.' }, 503);
    const input = await body(req); const email = String(input.email ?? '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return send(res, { error: 'Enter a valid email address' }, 400);
    const { rows } = await pool.query('SELECT id FROM customer_accounts WHERE email=$1', [email]);
    if (rows.length) {
      const recent = await pool.query("SELECT 1 FROM password_resets WHERE user_id=$1 AND created_at > now() - interval '5 minutes' LIMIT 1", [rows[0].id]);
      if (!recent.rows.length) {
        const token = randomBytes(32).toString('hex'); const hash = createHash('sha256').update(token).digest('hex');
        const site = new URL(process.env.PUBLIC_SITE_URL); const resetUrl = new URL('/reset-password', site); resetUrl.searchParams.set('token', token);
        await pool.query("INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')", [hash, rows[0].id]);
        try {
          const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: process.env.RESET_EMAIL_FROM, to: [email], subject: 'Reset your Yours CayCi password', text: `Use this link to reset your password. It expires in 30 minutes:\n${resetUrl.toString()}\nIf you did not request this, ignore this message.` }) });
          if (!response.ok) throw new Error(`Resend returned ${response.status}`);
        } catch (error) {
          await pool.query('DELETE FROM password_resets WHERE token_hash=$1', [hash]);
          console.error('Password reset delivery failed:', error);
          // Return the same response for known and unknown email addresses.
        }
      }
    }
    return send(res, { ok: true, message: 'If an account has that email, a reset link has been sent.' });
  }
  if (req.method === 'POST' && path === '/api/customer/password-reset/confirm') {
    const input = await body(req); const token = String(input.token ?? ''), password = input.password;
    if (!/^[a-f0-9]{64}$/.test(token) || typeof password !== 'string' || password.length < 8 || password.length > 128) return send(res, { error: 'Invalid or expired link, or password must be 8–128 characters' }, 400);
    const hash = createHash('sha256').update(token).digest('hex'); const client = await pool.connect();
    try { await client.query('BEGIN'); const { rows } = await client.query('SELECT user_id FROM password_resets WHERE token_hash=$1 AND expires_at>now() FOR UPDATE', [hash]); if (!rows.length) { await client.query('ROLLBACK'); return send(res, { error: 'Reset link is invalid or expired' }, 400); } await client.query('UPDATE customer_accounts SET password_hash=$1 WHERE id=$2', [passwordHash(password), rows[0].user_id]); await client.query('DELETE FROM password_resets WHERE user_id=$1', [rows[0].user_id]); await client.query('COMMIT'); return send(res, { ok: true }); } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  if (req.method === 'POST' && path === '/api/customer/signup') {
    const input = await body(req); const profile = profileFields(input); const email = String(input.email ?? '').trim().toLowerCase(); const password = input.password;
    const key = phoneKey(profile.phone);
    if ((email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)) || !key || typeof password !== 'string' || password.length < 8 || password.length > 128 || !validProfile(profile)) return send(res, { error: 'Enter a valid email or Myanmar phone, password (8–128 characters), name, city/town and delivery address' }, 400);
    try {
      const { rows } = await pool.query('INSERT INTO customer_accounts (email,password_hash,name,phone,phone_key,city,delivery_address) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id::text, email, name, phone, city, delivery_address AS "deliveryAddress"', [email || null,passwordHash(password),profile.name,profile.phone,key,profile.city,profile.deliveryAddress]);
      return send(res, { profile: rows[0] }, 201, { 'Set-Cookie': authCookie(rows[0].id) });
    } catch (error) { if ((error as { code?: string }).code === '23505') return send(res, { error: 'An account with this email or phone already exists' }, 409); throw error; }
  }
  if (req.method === 'POST' && path === '/api/customer/login') {
    const key = req.socket.remoteAddress ?? 'unknown'; const attempt = customerAttempts.get(key);
    if (attempt && attempt.count >= 8 && attempt.until > Date.now()) return send(res, { error: 'Try again later' }, 429);
    const input = await body(req); const identifier = String(input.identifier ?? input.email ?? '').trim().toLowerCase(); const password = input.password;
    const { rows } = await pool.query('SELECT id::text, email, password_hash, name, phone, city, delivery_address AS "deliveryAddress" FROM customer_accounts WHERE email = $1 OR phone_key = $2 LIMIT 1', [identifier,phoneKey(identifier)]);
    if (typeof password !== 'string' || !rows[0] || !verifyPassword(password, rows[0].password_hash)) { customerAttempts.set(key, { count: (attempt?.until ?? 0) > Date.now() ? attempt!.count + 1 : 1, until: Date.now() + 15 * 60 * 1000 }); return send(res, { error: 'Invalid email/phone or password' }, 401); }
    customerAttempts.delete(key); const { password_hash: _hash, ...profile } = rows[0]; return send(res, { profile }, 200, { 'Set-Cookie': authCookie(profile.id) });
  }
  if (req.method === 'POST' && path === '/api/customer/logout') return send(res, { ok: true }, 200, { 'Set-Cookie': 'yc_customer=; HttpOnly; SameSite=Lax; Path=/api; Max-Age=0' });
  if (path.startsWith('/api/customer/')) {
    const profile = await customerSession(req); if (!profile) return send(res, { error: 'Sign in to continue' }, 401);
    if (req.method === 'PATCH' && path === '/api/customer/profile') {
      const input = await body(req); const fields = profileFields(input); const email = optionalEmail(input); const key = phoneKey(fields.phone); if (!validProfile(fields) || !key || !validEmail(email)) return send(res, { error: 'Enter a valid email, name, Myanmar phone, city/town and delivery address' }, 400);
      try { const { rows } = await pool.query('UPDATE customer_accounts SET email=$1, name=$2, phone=$3, phone_key=$4, city=$5, delivery_address=$6 WHERE id=$7 RETURNING id::text, email, name, phone, city, delivery_address AS "deliveryAddress"', [email,fields.name,fields.phone,key,fields.city,fields.deliveryAddress,profile.id]); return send(res, { profile: rows[0] }); }
      catch (error) { if ((error as { code?: string }).code === '23505') return send(res, { error: 'That email or phone number is already used by another account' }, 409); throw error; }
    }
    if (req.method === 'GET' && path === '/api/customer/orders') {
      const { rows } = await pool.query(`SELECT o.id, o.customer_name AS customer, o.customer_phone AS phone, o.delivery_address AS address, o.customer_note AS note, o.total_ks AS total, o.status, o.cancel_requested AS "cancelRequested", o.created_at AS "createdAt", COALESCE(json_agg(json_build_object('tone', i.product_tone, 'variant', i.variant_index, 'quantity', i.quantity)) FILTER (WHERE i.order_id IS NOT NULL), '[]') AS items FROM orders o LEFT JOIN order_items i ON i.order_id = o.id WHERE o.user_id = $1 GROUP BY o.id ORDER BY o.created_at DESC`, [profile.id]);
      return send(res, rows);
    }
  }
  if (req.method === 'POST' && path === '/api/orders') {
    const profile = await customerSession(req); if (!profile) return send(res, { error: 'Sign in to place an order' }, 401);
    const input = await body(req); if (!Array.isArray(input.items) || !input.items.length || !validProfile(profile)) return send(res, { error: 'Complete your profile and add an item to your cart' }, 400);
    try { return send(res, await placeOrder(profile.name, profile.phone, `${profile.deliveryAddress}, ${profile.city}`, typeof input.note === 'string' ? input.note.trim() : '', input.items as Item[], profile.id), 201); } catch (error) { return send(res, { error: (error as Error).message }, 400); }
  }
  const publicOrder = path.match(/^\/api\/orders\/(\d+)$/);
  if (publicOrder) {
    const profile = await customerSession(req); if (!profile) return send(res, { error: 'Sign in to view this order' }, 401);
    const owned = await pool.query('SELECT 1 FROM orders WHERE id=$1 AND user_id=$2', [publicOrder[1],profile.id]); if (!owned.rows.length) return send(res, { error: 'Order not found' }, 404);
    if (req.method === 'GET') { const { rows } = await pool.query('SELECT o.id, o.customer_name AS customer, o.customer_phone AS phone, o.delivery_address AS address, o.customer_note AS note, o.total_ks AS total, o.status, o.cancel_requested AS "cancelRequested", o.created_at AS "createdAt", COALESCE(json_agg(json_build_object(\'tone\', i.product_tone, \'variant\', i.variant_index, \'quantity\', i.quantity)) FILTER (WHERE i.order_id IS NOT NULL), \'[]\') AS items FROM orders o LEFT JOIN order_items i ON i.order_id = o.id WHERE o.id = $1 GROUP BY o.id', [publicOrder[1]]); return send(res, rows[0]); }
    if (req.method === 'POST') { const input = await body(req); if (!['cancel','delivery_change','other'].includes(String(input.type)) || typeof input.message !== 'string' || !input.message.trim()) return send(res, { error: 'Request type and message are required' }, 400); await pool.query('INSERT INTO order_requests (order_id, request_type, message) VALUES ($1, $2, $3)', [publicOrder[1], input.type, input.message.trim()]); if (input.type === 'cancel') await pool.query("UPDATE orders SET cancel_requested = true, status = 'Cancelled' WHERE id = $1 AND status NOT IN ('Shipped','Delivered')", [publicOrder[1]]); return send(res, { ok: true }, 201); }
  }
  if (req.method === 'POST' && path === '/api/developer/login') {
    if (!superadminPasscode) return send(res, { error: 'Developer access is not configured' }, 503);
    const key = staffIpKey('developer', req);
    if (await staffLocked('developer', key)) return send(res, { error: 'Try again later' }, 429);
    const input = await body(req);
    if (typeof input.passcode !== 'string' || input.passcode.length > 128 || !safeEqual(input.passcode, superadminPasscode)) { await staffFailed('developer', key); recordEvent({ eventType: 'developer_login_failed', req, status: 401 }); return send(res, { error: 'Invalid developer passcode' }, 401); }
    await pool.query('DELETE FROM staff_login_attempts WHERE role=$1 AND key_hash=$2', ['developer', key]);
    recordEvent({ eventType: 'developer_login', req, status: 200 });
    return send(res, { ok: true }, 200, { 'Set-Cookie': await issueStaffSession('developer') });
  }
  if (req.method === 'GET' && path === '/api/developer/session') return send(res, { configured: !!superadminPasscode, authenticated: await developer(req) });
  if (req.method === 'POST' && path === '/api/developer/logout') { await revokeStaffSession('developer', req); return send(res, { ok: true }, 200, { 'Set-Cookie': clearStaffCookie('developer') }); }
  if (path.startsWith('/api/developer/') && !await developer(req)) return send(res, { error: 'Developer access required' }, 401);
  if (req.method === 'GET' && path === '/api/developer/maintenance') { const { rows } = await pool.query("SELECT value FROM admin_settings WHERE key = 'maintenance_mode'"); return send(res, { enabled: rows[0]?.value === 'on' }); }
  if (req.method === 'PATCH' && path === '/api/developer/maintenance') { const input = await body(req); if (typeof input.enabled !== 'boolean') return send(res, { error: 'enabled must be boolean' }, 400); await pool.query("INSERT INTO admin_settings(key,value) VALUES('maintenance_mode',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [input.enabled ? 'on' : 'off']); recordEvent({ eventType: 'maintenance', req, message: input.enabled ? 'enabled' : 'disabled' }); return send(res, { enabled: input.enabled }); }
  if (req.method === 'GET' && path === '/api/developer/users') {
    const url = new URL(req.url ?? '/', 'http://localhost'); const page = Math.max(1, Math.min(100000, Number.parseInt(url.searchParams.get('page') ?? '1', 10) || 1));
    const [{ rows }, count] = await Promise.all([pool.query('SELECT id::text, email, name, phone, city, delivery_address AS "deliveryAddress", created_at AS "createdAt" FROM customer_accounts ORDER BY created_at DESC, id DESC LIMIT 25 OFFSET $1', [(page - 1) * 25]), pool.query('SELECT count(*)::int AS total FROM customer_accounts')]);
    return send(res, { users: rows, page, total: count.rows[0].total, pageSize: 25 });
  }
  if (req.method === 'GET' && path === '/api/developer/capacity') {
    const [connections, throughput, tables, database, configured] = await Promise.all([
      pool.query("SELECT current_setting('max_connections')::int AS max, (SELECT count(*)::int FROM pg_stat_activity WHERE datname = current_database()) AS active"),
      pool.query("SELECT count(*) FILTER (WHERE event_type='request')::int AS requests_hour, count(*) FILTER (WHERE event_type='request' AND created_at>=now()-interval '1 minute')::int AS requests_minute, count(*) FILTER (WHERE event_type='error')::int AS errors_hour FROM system_events WHERE created_at >= now() - interval '1 hour'"),
      pool.query("SELECT relname AS name, pg_total_relation_size(relid)::bigint AS bytes FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 8"),
      pool.query('SELECT pg_database_size(current_database())::bigint AS bytes'),
      pool.query("SELECT key,value FROM admin_settings WHERE key IN ('capacity_storage_limit_mb','capacity_requests_per_minute_limit')")
    ]);
    const values = Object.fromEntries(configured.rows.map(row => [row.key, Number(row.value)]));
    return send(res, { connections: connections.rows[0], throughput: throughput.rows[0], databaseBytes: database.rows[0].bytes, tables: tables.rows, limits: { storageMb: values.capacity_storage_limit_mb || null, requestsPerMinute: values.capacity_requests_per_minute_limit || null }, loggingMode: await getRequestLogging(), note: 'Connection limit comes from Postgres. Storage and request thresholds are operator alerts, not measured hard limits. Confirm quotas in Neon and Vercel, and use a load test to find safe concurrency.' });
  }
  if (req.method === 'PATCH' && path === '/api/developer/capacity') {
    const input = await body(req);
    const valid = (value: unknown) => value === null || (typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 1_000_000);
    if (!valid(input.storageMb) || !valid(input.requestsPerMinute)) return send(res, { error: 'Thresholds must be whole numbers from 1 to 1,000,000 or blank' }, 400);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const [key,value] of [['capacity_storage_limit_mb',input.storageMb],['capacity_requests_per_minute_limit',input.requestsPerMinute]]) {
        if (value === null) await client.query('DELETE FROM admin_settings WHERE key=$1', [key]);
        else await client.query('INSERT INTO admin_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [key,String(value)]);
      }
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
    recordEvent({ eventType: 'capacity_thresholds_changed', req, status: 200 });
    return send(res, { limits: { storageMb: input.storageMb, requestsPerMinute: input.requestsPerMinute } });
  }
  if (req.method === 'GET' && path === '/api/developer/request-logs') {
    const days = Number(new URL(req.url ?? '/', 'http://localhost').searchParams.get('days') ?? 30);
    if (!Number.isInteger(days) || days < 7 || days > 365) return send(res, { error: 'Choose 7–365 days' }, 400);
    const { rows } = await pool.query("SELECT count(*)::int AS count, COALESCE(sum(pg_column_size(e)),0)::bigint AS estimated_bytes FROM system_events e WHERE event_type='request' AND created_at<now()-($1::int*interval '1 day')", [days]);
    return send(res, { days, eligibleCount: rows[0].count, estimatedBytes: rows[0].estimated_bytes, batchSize: 1000 });
  }
  if (req.method === 'DELETE' && path === '/api/developer/request-logs') {
    const input = await body(req); const days = Number(input.days);
    if (!Number.isInteger(days) || days < 7 || days > 365 || input.confirm !== 'DELETE REQUEST LOGS') return send(res, { error: 'Confirm cleanup and choose 7–365 days' }, 400);
    const { rows } = await pool.query("WITH doomed AS (SELECT id FROM system_events WHERE event_type='request' AND created_at<now()-($1::int*interval '1 day') ORDER BY created_at LIMIT 1000) DELETE FROM system_events e USING doomed WHERE e.id=doomed.id RETURNING e.id", [days]);
    recordEvent({ eventType: 'request_logs_deleted', req, message: `${rows.length} request logs older than ${days} days` });
    return send(res, { deleted: rows.length, batchSize: 1000 });
  }
  if (req.method === 'PATCH' && path === '/api/developer/request-logging') {
    const input = await body(req);
    if (input.mode !== 'full' && input.mode !== 'errors-only') return send(res, { error: 'Invalid logging mode' }, 400);
    await pool.query("INSERT INTO admin_settings(key,value) VALUES('request_logging',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [input.mode]);
    requestLogging = input.mode; requestLoggingExpires = Date.now() + 30_000;
    recordEvent({ eventType: 'request_logging_changed', req, message: input.mode });
    return send(res, { mode: input.mode });
  }
  if (req.method === 'GET' && path === '/api/developer/metrics') {
    const [users, activity, storage, busy, errors, orders] = await Promise.all([
      pool.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE created_at >= current_date)::int AS today, count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS month FROM customer_accounts`),
      pool.query(`SELECT count(DISTINCT user_id)::int AS active FROM system_events WHERE event_type = 'request' AND user_id IS NOT NULL AND created_at >= now() - interval '15 minutes'`),
      pool.query(`SELECT pg_database_size(current_database())::bigint AS database_bytes, COALESCE((SELECT sum(length(images::text)) FROM products),0)::bigint AS product_image_bytes, COALESCE((SELECT sum(length(value)) FROM admin_settings),0)::bigint AS settings_bytes`),
      pool.query(`SELECT extract(hour from created_at)::int AS hour, count(*)::int AS requests FROM system_events WHERE event_type = 'request' AND created_at >= now() - interval '30 days' GROUP BY 1 ORDER BY requests DESC LIMIT 8`),
      pool.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE created_at >= current_date)::int AS today FROM system_events WHERE event_type = 'error'`),
      pool.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE created_at >= current_date)::int AS today FROM orders`)
    ]);
    return send(res, { users: users.rows[0], activeUsers15m: activity.rows[0].active, storage: storage.rows[0], busyHours: busy.rows, errors: errors.rows[0], orders: orders.rows[0], loggingMode: await getRequestLogging(), generatedAt: new Date().toISOString() });
  }
  if (req.method === 'GET' && path === '/api/developer/logs') {
    const { rows } = await pool.query(`SELECT id, event_type AS "eventType", method, path, status, message, created_at AS "createdAt" FROM system_events ORDER BY created_at DESC LIMIT 100`);
    return send(res, rows);
  }
  if (req.method === 'POST' && path === '/api/admin/login') {
    const key = staffIpKey('admin', req);
    if (await staffLocked('admin', key)) return send(res, { error: 'Try again later' }, 429);
    await refreshAdminPasscode();
    const input = await body(req);
    if (typeof input.passcode !== 'string' || input.passcode.length > 128 || !await verifyStaffPasscode(input.passcode, passcode)) {
      await staffFailed('admin', key); recordEvent({ eventType: 'admin_login_failed', req, status: 401 });
      return send(res, { error: 'Invalid passcode' }, 401);
    }
    await pool.query('DELETE FROM staff_login_attempts WHERE role=$1 AND key_hash=$2', ['admin', key]);
    recordEvent({ eventType: 'admin_login', req, status: 200 });
    return send(res, { ok: true }, 200, { 'Set-Cookie': await issueStaffSession('admin') });
  }
  if (req.method === 'GET' && path === '/api/admin/session') return send(res, { authenticated: await admin(req) });
  if (req.method === 'POST' && path === '/api/admin/logout') { await revokeStaffSession('admin', req); return send(res, { ok: true }, 200, { 'Set-Cookie': clearStaffCookie('admin') }); }
  if (path.startsWith('/api/admin/') && !await admin(req)) return send(res, { error: 'Unauthorized' }, 401);
  if (req.method === 'PATCH' && path === '/api/admin/banner') { const input = await body(req); const validView=(view:unknown)=>{const item=view as Record<string,unknown>;return !!item&&['cover','contain'].includes(String(item.fit))&&['top','center','bottom'].includes(String(item.position))&&Number.isInteger(item.zoom)&&Number(item.zoom)>=100&&Number(item.zoom)<=180&&Number.isFinite(Number(item.x))&&Number(item.x)>=0&&Number(item.x)<=100&&Number.isFinite(Number(item.y))&&Number(item.y)>=0&&Number(item.y)<=100}; const mobile=typeof input.mobile==='string'?input.mobile:input.desktop; if (typeof input.desktop !== 'string' || !input.desktop.startsWith('data:image/') || typeof mobile !== 'string' || !mobile.startsWith('data:image/') || !validView(input.desktopView) || !validView(input.mobileView)) return send(res, { error: 'Banner image and view settings are required' }, 400); const desktopView=input.desktopView as {fit:string;position:string;zoom:number;x:number;y:number},mobileView=input.mobileView as {fit:string;position:string;zoom:number;x:number;y:number}; await pool.query('INSERT INTO admin_settings(key,value) VALUES ($1,$2),($3,$4),($5,$6),($7,$8),($9,$10),($11,$12),($13,$14),($15,$16),($17,$18),($19,$20),($21,$22),($23,$24),($25,$26) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['store_banner_desktop',input.desktop,'store_banner_mobile',mobile,'store_banner_desktop_view',desktopView.fit,'store_banner_mobile_view',mobileView.fit,'store_banner_desktop_position',desktopView.position,'store_banner_mobile_position',mobileView.position,'store_banner_desktop_zoom',String(desktopView.zoom),'store_banner_mobile_zoom',String(mobileView.zoom),'store_banner_desktop_x',String(desktopView.x),'store_banner_desktop_y',String(desktopView.y),'store_banner_mobile_x',String(mobileView.x),'store_banner_mobile_y',String(mobileView.y)]); return send(res, { desktop: input.desktop, mobile, desktopView, mobileView }); }
  if (req.method === 'GET' && path === '/api/admin/orders') {
    const { rows } = await pool.query(`SELECT o.id, o.customer_name AS customer, o.customer_phone AS phone, o.delivery_address AS address, o.customer_note AS note, o.total_ks AS total, o.status, o.cancel_requested AS "cancelRequested", o.created_at AS "createdAt", COALESCE(json_agg(json_build_object('tone', i.product_tone, 'variant', i.variant_index, 'quantity', i.quantity)) FILTER (WHERE i.order_id IS NOT NULL), '[]') AS items FROM orders o LEFT JOIN order_items i ON i.order_id = o.id GROUP BY o.id ORDER BY o.created_at DESC LIMIT 100`);
    return send(res, rows);
  }
  const orderMatch = path.match(/^\/api\/admin\/orders\/(\d+)$/);
  if (req.method === 'PATCH' && orderMatch) {
    const input = await body(req);
    if (!['Confirmed', 'Shipped', 'Processing', 'Delivered', 'Cancelled'].includes(String(input.status))) return send(res, { error: 'Invalid status' }, 400);
    const { rows } = await pool.query('UPDATE orders SET status = $1 WHERE id = $2 RETURNING id, status', [input.status, orderMatch[1]]);
    return rows.length ? send(res, rows[0]) : send(res, { error: 'Order not found' }, 404);
  }
  if (req.method === 'GET' && path === '/api/admin/requests') { const { rows } = await pool.query('SELECT * FROM order_requests WHERE status = \'Open\' ORDER BY created_at DESC'); return send(res, rows); }
  const passcodePath = path === '/api/admin/passcode';
  if (req.method === 'PATCH' && passcodePath) { const input = await body(req); if (typeof input.current !== 'string' || !await verifyStaffPasscode(input.current, passcode) || typeof input.next !== 'string' || input.next.length < 12 || input.next.length > 128) return send(res, { error: 'New passcode must be 12–128 characters and current passcode must match' }, 400); const hashed = await hashStaffPasscode(input.next); await pool.query('INSERT INTO admin_settings(key,value) VALUES (\'passcode\',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [hashed]); passcode = hashed; await pool.query("DELETE FROM staff_sessions WHERE role='admin'"); recordEvent({ eventType: 'admin_passcode_changed', req, status: 200 }); return send(res, { ok: true }, 200, { 'Set-Cookie': await issueStaffSession('admin') }); }
  const coverMatch = path.match(/^\/api\/admin\/products\/([^/]+)\/cover$/);
  if (req.method === 'PATCH' && coverMatch) { const input = await body(req); if (!['cover','contain'].includes(String(input.fit)) || !['top','center','bottom'].includes(String(input.position)) || !Number.isInteger(input.zoom) || Number(input.zoom) < 100 || Number(input.zoom) > 200) return send(res, { error: 'Invalid cover view' }, 400); await pool.query('UPDATE products SET cover_fit = $1, cover_position = $2, cover_zoom = $3 WHERE tone = $4', [input.fit, input.position, input.zoom, decodeURIComponent(coverMatch[1])]); return send(res, { ok: true }); }
  const safeProductPath = path.match(/^\/api\/admin\/products\/([^/]+)$/);
  if (req.method === 'PATCH' && safeProductPath) {
    const input = await body(req); const tone = decodeURIComponent(safeProductPath[1]);
    if (typeof input.name !== 'string' || !input.name.trim() || typeof input.description !== 'string' || !Array.isArray(input.images) || !Array.isArray(input.prices)) return send(res, { error: 'Name, description, photos and variants are required' }, 400);
    const client = await pool.connect();
    try { await client.query('BEGIN'); await client.query('UPDATE products SET name = $1, description = $2, images = $3, price_note = $4 WHERE tone = $5', [input.name.trim(), input.description, JSON.stringify(input.images), input.priceNote ?? null, tone]); const indexes = input.prices.map((_: unknown, index: number) => index); for (const [index, variant] of input.prices.entries()) { if (typeof variant.label !== 'string' || typeof variant.fit !== 'string' || !Number.isInteger(Number(variant.price)) || Number(variant.price) < 0) throw new Error('Invalid variant'); await client.query('INSERT INTO product_variants(product_tone,variant_index,size_group,label,fit,price_ks) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(product_tone,variant_index) DO UPDATE SET size_group=excluded.size_group,label=excluded.label,fit=excluded.fit,price_ks=excluded.price_ks', [tone,index,variant.group === 'Plus Size' ? 'Plus Size' : 'Free Size',variant.label,variant.fit,Number(variant.price)]); } if (indexes.length) await client.query('DELETE FROM product_variants v WHERE v.product_tone = $1 AND NOT (v.variant_index = ANY($2::int[])) AND NOT EXISTS (SELECT 1 FROM order_items i WHERE i.product_tone = v.product_tone AND i.variant_index = v.variant_index)', [tone,indexes]); await client.query('COMMIT'); return send(res, { ok: true }); } catch (error) { await client.query('ROLLBACK'); return send(res, { error: (error as Error).message }, 400); } finally { client.release(); }
  }
  const productPath = path.match(/^\/api\/admin\/products\/([^/]+)$/);
  if (req.method === 'PATCH' && productPath) {
    const input = await body(req); const tone = decodeURIComponent(productPath[1]);
    if (typeof input.name !== 'string' || !input.name.trim() || typeof input.description !== 'string' || !Array.isArray(input.images) || !Array.isArray(input.prices)) return send(res, { error: 'Name, description, photos and variants are required' }, 400);
    const client = await pool.connect();
    try { await client.query('BEGIN'); await client.query('UPDATE products SET name = $1, description = $2, images = $3, price_note = $4 WHERE tone = $5', [input.name.trim(), input.description, JSON.stringify(input.images), input.priceNote ?? null, tone]); await client.query('DELETE FROM product_variants WHERE product_tone = $1', [tone]); for (const [index, v] of input.prices.entries()) { if (typeof v.label !== 'string' || typeof v.fit !== 'string' || !Number.isInteger(Number(v.price)) || Number(v.price) < 0) throw new Error('Invalid variant'); await client.query('INSERT INTO product_variants(product_tone,variant_index,size_group,label,fit,price_ks) VALUES($1,$2,$3,$4,$5,$6)', [tone,index,v.group === 'Plus Size' ? 'Plus Size' : 'Free Size',v.label,v.fit,Number(v.price)]); } await client.query('COMMIT'); return send(res, { ok: true }); } catch (error) { await client.query('ROLLBACK'); return send(res, { error: (error as Error).message }, 400); } finally { client.release(); }
  }
  if (req.method === 'DELETE' && productPath) { const input = await body(req); if (input.confirm !== 'DELETE') return send(res, { error: 'Type DELETE to confirm' }, 400); await pool.query('DELETE FROM products WHERE tone = $1', [decodeURIComponent(productPath[1])]); return send(res, { ok: true }); }
  if (req.method === 'POST' && path === '/api/admin/products') { const input = await body(req); if (typeof input.tone !== 'string' || typeof input.name !== 'string' || !Array.isArray(input.prices)) return send(res, { error: 'Product name, tone and prices are required' }, 400); await pool.query('INSERT INTO products(tone,name,description,images,price_note) VALUES($1,$2,$3,$4,$5)', [input.tone, input.name, input.description ?? '', JSON.stringify(input.images ?? []), input.priceNote ?? null]); for (const [index, v] of input.prices.entries()) await pool.query('INSERT INTO product_variants(product_tone,variant_index,size_group,label,fit,price_ks) VALUES($1,$2,$3,$4,$5,$6)', [input.tone,index,v.group,v.label,v.fit,v.price]); return send(res, { ok: true }, 201); }
  const variantMatch = path.match(/^\/api\/admin\/products\/([^/]+)\/variants\/(\d+)$/);
  if (req.method === 'PATCH' && variantMatch) {
    const input = await body(req);
    if (!Number.isInteger(input.price) || Number(input.price) < 0 || Number(input.price) > 100_000_000) return send(res, { error: 'Invalid price' }, 400);
    const { rows } = await pool.query('UPDATE product_variants SET price_ks = $1 WHERE product_tone = $2 AND variant_index = $3 RETURNING product_tone, variant_index, price_ks', [input.price, decodeURIComponent(variantMatch[1]), Number(variantMatch[2])]);
    return rows.length ? send(res, rows[0]) : send(res, { error: 'Variant not found' }, 404);
  }
  send(res, { error: 'Not found' }, 404);
}

export async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  try { await route(req, res); try { if (await getRequestLogging() === 'full') recordEvent({ eventType: 'request', req, status: res.statusCode }); } catch (error) { console.error('Request logging setting unavailable:', error); } } catch (error) { console.error(error); recordEvent({ eventType: 'error', req, status: 500, message: (error as Error).message }); if (!res.headersSent) send(res, { error: 'Server error' }, 500); }
}

const server = createServer((req, res) => { handleRequest(req, res); });
if (!process.env.VERCEL && process.env.NODE_ENV !== 'test') server.listen(Number(process.env.PORT || 8787), '127.0.0.1', () => console.log('API ready'));

export async function seedCatalog() {
  for (const product of catalog) {
    await pool.query('INSERT INTO products (tone, name, description, images, price_note) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tone) DO NOTHING', [product.tone, product.name, product.description, JSON.stringify(product.images), product.priceNote ?? null]);
    for (const [index, variant] of product.prices.entries()) await pool.query('INSERT INTO product_variants (product_tone, variant_index, size_group, label, fit, price_ks) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (product_tone, variant_index) DO NOTHING', [product.tone, index, variant.group, variant.label, variant.fit, Number(variant.price.replace(/[^0-9]/g, ''))]);
  }
}
