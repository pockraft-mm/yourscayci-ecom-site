import { defineConfig } from 'vite';

export default defineConfig({
  publicDir: 'context/data-from-landing-site',
  server: { proxy: { '/api': 'http://127.0.0.1:8787' } },
});
