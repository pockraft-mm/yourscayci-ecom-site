import { defineConfig } from '@neon/config/v1';

export default defineConfig({
  auth: true,
  buckets: {
    'product-images': { access: 'public_read' },
  },
});
