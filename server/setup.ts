import { loadEnvFile } from 'node:process';
import { spawnSync } from 'node:child_process';

try { loadEnvFile('.env'); } catch { /* optional */ }
try { loadEnvFile('.env.local'); } catch { /* optional */ }
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');

const directUrl = process.env.DATABASE_URL.replace('-pooler.', '.');
const migration = spawnSync('psql', [directUrl, '-v', 'ON_ERROR_STOP=1', '-f', 'migrations/001_shop.sql'], { stdio: ['inherit', 'pipe', 'pipe'], encoding: 'utf8' });
if (migration.error || migration.status !== 0) {
  console.error(migration.error?.message || migration.stderr.replaceAll(directUrl, '[redacted]'));
  process.exit(1);
}
process.env.NODE_ENV = 'test';
const { seedCatalog } = await import('./index.js');
await seedCatalog();
console.log('Schema applied and catalog seeded');
process.exit(0);
