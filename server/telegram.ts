import { createHmac, timingSafeEqual } from 'node:crypto';

export function telegramIdentity(raw: string, token: string, now = Date.now()) {
  if (!raw || raw.length > 16384) throw Error('Invalid Telegram sign-in');
  const data = new URLSearchParams(raw);
  if (new Set(data.keys()).size !== [...data.keys()].length) throw Error('Invalid Telegram sign-in');
  const hash = data.get('hash') || '';
  if (!/^[a-f0-9]{64}$/i.test(hash)) throw Error('Invalid Telegram signature');
  data.delete('hash');
  const check = [...data.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, value]) => `${key}=${value}`).join('\n');
  const secret = createHmac('sha256', 'WebAppData').update(token).digest();
  const expected = createHmac('sha256', secret).update(check).digest();
  if (!timingSafeEqual(expected, Buffer.from(hash, 'hex'))) throw Error('Invalid Telegram signature');
  const age = now / 1000 - Number(data.get('auth_date'));
  if (!Number.isFinite(age) || age < -30 || age > 600) throw Error('Reopen the Mini App to sign in');
  const user = JSON.parse(data.get('user') || 'null');
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0 || typeof user.first_name !== 'string') throw Error('Invalid Telegram user');
  return { id: String(user.id), name: [user.first_name, typeof user.last_name === 'string' ? user.last_name : ''].filter(Boolean).join(' ').slice(0, 120) };
}
