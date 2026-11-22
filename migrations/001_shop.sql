CREATE TABLE IF NOT EXISTS products (
  tone text PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  images jsonb NOT NULL DEFAULT '[]'::jsonb,
  price_note text
);
ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_fit text NOT NULL DEFAULT 'cover' CHECK (cover_fit IN ('cover', 'contain'));
ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_position text NOT NULL DEFAULT 'center' CHECK (cover_position IN ('top', 'center', 'bottom'));
ALTER TABLE products ADD COLUMN IF NOT EXISTS cover_zoom integer NOT NULL DEFAULT 100 CHECK (cover_zoom BETWEEN 100 AND 200);

CREATE TABLE IF NOT EXISTS product_variants (
  product_tone text NOT NULL REFERENCES products(tone),
  variant_index integer NOT NULL CHECK (variant_index >= 0),
  size_group text NOT NULL CHECK (size_group IN ('Free Size', 'Plus Size')),
  label text NOT NULL,
  fit text NOT NULL,
  price_ks integer NOT NULL CHECK (price_ks >= 0),
  PRIMARY KEY (product_tone, variant_index)
);

CREATE TABLE IF NOT EXISTS orders (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_name text NOT NULL,
  user_id text,
  total_ks integer NOT NULL CHECK (total_ks >= 0),
  status text NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Confirmed', 'Processing', 'Delivered')),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_status_check;
ALTER TABLE orders ADD CONSTRAINT orders_status_check CHECK (status IN ('Pending', 'Confirmed', 'Shipped', 'Processing', 'Delivered', 'Cancelled'));
ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_phone text NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_address text NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_note text NOT NULL DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS cancel_requested boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS orders_user_date_idx ON orders (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS order_items (
  order_id bigint NOT NULL REFERENCES orders(id),
  product_tone text NOT NULL REFERENCES products(tone),
  variant_index integer NOT NULL,
  quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  unit_price_ks integer NOT NULL CHECK (unit_price_ks >= 0),
  FOREIGN KEY (product_tone, variant_index) REFERENCES product_variants(product_tone, variant_index)
);

CREATE TABLE IF NOT EXISTS order_requests (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_id bigint NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  request_type text NOT NULL CHECK (request_type IN ('cancel', 'delivery_change', 'other')),
  message text NOT NULL,
  status text NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Resolved', 'Rejected')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_settings (key text PRIMARY KEY, value text NOT NULL);

CREATE TABLE IF NOT EXISTS customer_accounts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email text UNIQUE,
  password_hash text NOT NULL,
  name text NOT NULL,
  phone text NOT NULL,
  city text NOT NULL,
  delivery_address text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE customer_accounts ALTER COLUMN email DROP NOT NULL;
ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS phone_key text UNIQUE;
ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS telegram_id text UNIQUE;
ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS tiktok_id text UNIQUE;
