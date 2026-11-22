import { loadEnvFile } from 'node:process';
import { randomUUID } from 'node:crypto';

try { loadEnvFile('.env'); } catch { /* optional */ }
try { loadEnvFile('.env.local'); } catch { /* optional */ }
if (!process.env.ADMIN_PASSCODE) throw new Error('ADMIN_PASSCODE is required');

const base = `http://127.0.0.1:${process.env.PORT || 8787}`;
const request = async (path: string, options?: RequestInit) => {
  const response = await fetch(base + path, options);
  const result = await response.json() as Record<string, any>;
  return { response, result };
};
const unauthenticated = await request('/api/admin/orders');
if (unauthenticated.response.status !== 401) throw new Error('Admin orders were accessible without a session');
const catalog = await request('/api/products');
if (!catalog.response.ok || !Array.isArray(catalog.result) || catalog.result.length < 6) throw new Error('Catalog read failed');
const product = catalog.result.find((item: { tone: string }) => item.tone === 'Skin');
if (!product?.prices?.[0]) throw new Error('Skin product variant is missing');
const password = randomUUID()+randomUUID();
const signup = await request('/api/customer/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: `mvp-${randomUUID()}@example.invalid`, password, name: 'MVP verification', phone: '09789910866', city: 'Mandalay', deliveryAddress: 'Verification address' }) });
const customerCookie = signup.response.headers.get('set-cookie')?.split(';')[0];
if (signup.response.status !== 201 || !customerCookie) throw new Error('Customer sign-up failed');
const phoneLogin = await request('/api/customer/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: '+959789910866', password }) });
if (!phoneLogin.response.ok || !phoneLogin.response.headers.get('set-cookie')) throw new Error('Phone and password sign-in failed');
const profile = await request('/api/customer/profile', { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: customerCookie }, body: JSON.stringify({ name: 'MVP verification', phone: '09789910866', city: 'Yangon', deliveryAddress: 'Updated verification address' }) });
if (!profile.response.ok || profile.result.profile.city !== 'Yangon') throw new Error('Profile update failed');
const placed = await request('/api/orders', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: customerCookie }, body: JSON.stringify({ items: [{ tone: 'Skin', variant: 0, quantity: 1 }] }) });
if (placed.response.status !== 201 || placed.result.status !== 'Pending' || placed.result.total !== 25500) throw new Error('Customer order failed');
const myOrders = await request('/api/customer/orders', { headers: { Cookie: customerCookie } });
if (!myOrders.response.ok || !myOrders.result.some((item: { id: string }) => String(item.id) === String(placed.result.id))) throw new Error('Customer order history failed');
const login = await request('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passcode: process.env.ADMIN_PASSCODE }) });
const cookie = login.response.headers.get('set-cookie')?.split(';')[0];
if (!login.response.ok || !cookie) throw new Error('Admin sign-in failed');
const confirmed = await request(`/api/admin/orders/${placed.result.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: JSON.stringify({ status: 'Confirmed' }) });
if (!confirmed.response.ok || confirmed.result.status !== 'Confirmed') throw new Error('Admin confirmation failed');
const orders = await request('/api/admin/orders', { headers: { Cookie: cookie } });
if (!orders.response.ok || !orders.result.some((item: { id: string; status: string }) => String(item.id) === String(placed.result.id) && item.status === 'Confirmed')) throw new Error('Confirmed order was not readable');
console.log(`MVP verified: catalog=${catalog.result.length}, signup=201, profile=200, order=${placed.result.id}, history=200, total=${placed.result.total} Ks, status=Confirmed, unauthorized access=401`);
