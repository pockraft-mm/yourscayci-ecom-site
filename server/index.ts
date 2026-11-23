import { loadEnvFile } from 'node:process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import pg from 'pg';
import { products as catalog } from '../src/products.js';
import { authorizationUrl, exchangeIdentity, providerConfig, type Provider } from './social.js';

try { loadEnvFile('.env'); } catch { /* optional */ }
try { loadEnvFile('.env.local'); } catch { /* optional */ }
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL?.replace('sslmode=require', 'sslmode=verify-full'), max: 5, ssl: { rejectUnauthorized: true } });
let passcode = process.env.ADMIN_PASSCODE ?? '';
const sessionSecret = process.env.SESSION_SECRET ?? '';
if (!process.env.DATABASE_URL || !passcode || !sessionSecret) throw new Error('DATABASE_URL, ADMIN_PASSCODE and SESSION_SECRET are required');
const loginAttempts = new Map<string, { count: number; until: number }>();
const ready = pool.query("ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_fit text NOT NULL DEFAULT 'cover' CHECK (cover_fit IN ('cover', 'contain')); ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_position text NOT NULL DEFAULT 'center' CHECK (cover_position IN ('top', 'center', 'bottom')); ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_zoom integer NOT NULL DEFAULT 100 CHECK (cover_zoom BETWEEN 100 AND 200); CREATE TABLE IF NOT EXISTS customer_accounts (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text UNIQUE, password_hash text NOT NULL, name text NOT NULL, phone text NOT NULL, city text NOT NULL, delivery_address text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())").then(() => pool.query("ALTER TABLE customer_accounts ALTER COLUMN email DROP NOT NULL; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS phone_key text UNIQUE; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS telegram_id text UNIQUE; ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS tiktok_id text UNIQUE")).then(() => pool.query("CREATE INDEX IF NOT EXISTS orders_user_date_idx ON orders (user_id, created_at DESC)")).then(() => pool.query("SELECT value FROM admin_settings WHERE key = 'passcode'")).then(({ rows }) => { if (rows[0]?.value) passcode = rows[0].value; });

type Item = { tone: string; variant: number; quantity: number };
const send = (res: ServerResponse, value: unknown, status = 200, headers: Record<string, string> = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(value)); };
const safeEqual = (a: string, b: string) => { const left = createHmac('sha256', sessionSecret).update(a).digest(); const right = createHmac('sha256', sessionSecret).update(b).digest(); return timingSafeEqual(left, right); };
const sign = (value: string) => createHmac('sha256', sessionSecret).update(value).digest('hex');
const admin = (req: IncomingMessage) => { const cookie = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('yc_admin='))?.slice(9); if (!cookie) return false; const [expiry, nonce, mac] = cookie.split('.'); return !!expiry && !!nonce && !!mac && Number(expiry) > Date.now() && safeEqual(mac, sign(`${expiry}.${nonce}`)); };
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
  await customerReady;
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;
  if (req.method === 'GET' && path === '/api/products') return send(res, await listProducts());
  if (req.method === 'GET' && path === '/api/store/banner') { const { rows } = await pool.query('SELECT key, value FROM admin_settings WHERE key IN ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)', ['store_banner_desktop','store_banner_mobile','store_banner','store_banner_desktop_view','store_banner_mobile_view','store_banner_desktop_position','store_banner_mobile_position','store_banner_desktop_zoom','store_banner_mobile_zoom','store_banner_desktop_x','store_banner_desktop_y','store_banner_mobile_x','store_banner_mobile_y']); const values = Object.fromEntries(rows.map(row => [row.key, row.value])); const view=(key:string,positionKey:string,zoomKey:string,xKey:string,yKey:string)=>({ fit: values[key] === 'contain' ? 'contain' : 'cover', position: ['top','center','bottom'].includes(values[positionKey]) ? values[positionKey] : 'center', zoom: Math.min(180,Math.max(100,Number(values[zoomKey]||100))), x: Math.min(100,Math.max(0,Number(values[xKey]||50))), y: Math.min(100,Math.max(0,Number(values[yKey]||50))) }); return send(res, { desktop: values.store_banner_desktop ?? values.store_banner ?? null, mobile: values.store_banner_mobile ?? values.store_banner_desktop ?? values.store_banner ?? null, desktopView: view('store_banner_desktop_view','store_banner_desktop_position','store_banner_desktop_zoom','store_banner_desktop_x','store_banner_desktop_y'), mobileView: view('store_banner_mobile_view','store_banner_mobile_position','store_banner_mobile_zoom','store_banner_mobile_x','store_banner_mobile_y') }); }
  if (req.method === 'GET' && path === '/api/customer/providers') return send(res, { telegram: !!providerConfig('telegram'), tiktok: !!providerConfig('tiktok') });
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
      const fields = profileFields(await body(req)); const key = phoneKey(fields.phone); if (!validProfile(fields) || !key) return send(res, { error: 'Enter a name, Myanmar phone, city/town and delivery address' }, 400);
      try { const { rows } = await pool.query('UPDATE customer_accounts SET name=$1, phone=$2, phone_key=$3, city=$4, delivery_address=$5 WHERE id=$6 RETURNING id::text, email, name, phone, city, delivery_address AS "deliveryAddress"', [fields.name,fields.phone,key,fields.city,fields.deliveryAddress,profile.id]); return send(res, { profile: rows[0] }); }
      catch (error) { if ((error as { code?: string }).code === '23505') return send(res, { error: 'This phone number is already used by another account' }, 409); throw error; }
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
  if (req.method === 'POST' && path === '/api/admin/login') {
    const address = req.socket.remoteAddress ?? 'unknown';
    const attempts = loginAttempts.get(address);
    if (attempts && attempts.count >= 5 && attempts.until > Date.now()) return send(res, { error: 'Try again later' }, 429);
    const input = await body(req);
    if (typeof input.passcode !== 'string' || !safeEqual(input.passcode, passcode)) {
      loginAttempts.set(address, { count: (attempts?.until ?? 0) > Date.now() ? attempts!.count + 1 : 1, until: Date.now() + 15 * 60 * 1000 });
      return send(res, { error: 'Invalid passcode' }, 401);
    }
    loginAttempts.delete(address);
    const expiry = String(Date.now() + 8 * 60 * 60 * 1000); const token = `${expiry}.${randomBytes(16).toString('hex')}`;
    return send(res, { ok: true }, 200, { 'Set-Cookie': `yc_admin=${token}.${sign(token)}; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=28800${process.env.NODE_ENV === 'production' ? '; Secure' : ''}` });
  }
  if (req.method === 'GET' && path === '/api/admin/session') return send(res, { authenticated: admin(req) });
  if (req.method === 'POST' && path === '/api/admin/logout') return send(res, { ok: true }, 200, { 'Set-Cookie': 'yc_admin=; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=0' });
  if (path.startsWith('/api/admin/') && !admin(req)) return send(res, { error: 'Unauthorized' }, 401);
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
  if (req.method === 'PATCH' && passcodePath) { const input = await body(req); if (typeof input.current !== 'string' || !safeEqual(input.current, passcode) || typeof input.next !== 'string' || input.next.length < 8) return send(res, { error: 'Invalid passcode change' }, 400); passcode = input.next; await pool.query('INSERT INTO admin_settings(key,value) VALUES (\'passcode\',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [passcode]); return send(res, { ok: true }); }
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
  try { await route(req, res); } catch (error) { console.error(error); if (!res.headersSent) send(res, { error: 'Server error' }, 500); }
}

const server = createServer((req, res) => { handleRequest(req, res); });
if (!process.env.VERCEL && process.env.NODE_ENV !== 'test') server.listen(Number(process.env.PORT || 8787), '127.0.0.1', () => console.log('API ready'));

export async function seedCatalog() {
  for (const product of catalog) {
    await pool.query('INSERT INTO products (tone, name, description, images, price_note) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tone) DO NOTHING', [product.tone, product.name, product.description, JSON.stringify(product.images), product.priceNote ?? null]);
    for (const [index, variant] of product.prices.entries()) await pool.query('INSERT INTO product_variants (product_tone, variant_index, size_group, label, fit, price_ks) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (product_tone, variant_index) DO NOTHING', [product.tone, index, variant.group, variant.label, variant.fit, Number(variant.price.replace(/[^0-9]/g, ''))]);
  }
}
