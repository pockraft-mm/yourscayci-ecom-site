# Yours CayCi E-commerce MVP

Yours CayCi is a simple TypeScript storefront and order-management system for Myanmar customers. It has separate customer routes and a hidden admin route, with Neon Postgres as the source of truth.

## Current Progress

- Customer shop, product detail pages, cart, checkout, invoice, and My Orders are implemented.
- Customers can create an account with email or Myanmar phone + password, save delivery details, place orders, request cancellation, and view order status.
- Admin authentication, product CRUD, product variants, image uploads, cover-photo controls, order details, date sorting, status updates, and reports are implemented.
- Neon database setup and Vercel deployment are connected. The production API route is working.
- Telegram sign-in is paused. Its server-side OAuth code remains optional and is hidden unless its credentials are configured.

## Local Development

```bash
npm install
npm run db:setup     # apply schema and seed the catalog
npm run dev          # Vite frontend + TypeScript API
npm run check        # type-check both client and server
npm run build        # production build
npm run verify:mvp   # signup → order → admin confirmation check
```

Required ignored environment values are in `.env.example`: `DATABASE_URL`, `ADMIN_PASSCODE`, and a long `SESSION_SECRET`. Never commit `.env`, `.env.local`, database URLs, or provider secrets.

## Production Workflow

Vercel builds with `npm run build`; Neon provides `DATABASE_URL`. After changing schema or environment variables, redeploy and run `npm run verify:mvp` against a safe environment. The admin portal is available through the private admin URL configured by the application, not the customer navigation.

## Paused Telegram Sign-in

No Telegram setup is required while this feature is paused. If resumed, register the production origin and callback in BotFather Login Widget, then add `TELEGRAM_CLIENT_ID`, `TELEGRAM_CLIENT_SECRET`, and `TELEGRAM_REDIRECT_URI` to Vercel. The Bot API token alone is not sufficient for the current OIDC implementation. Test login, callback validation, account creation, and incomplete-profile completion before enabling it for customers.

## Known Limitations and Capacity

This is an MVP, not a load-tested production platform. There is no measured hard user limit. Until load testing, plan conservatively for about 25 concurrent active users and a small catalog; the database pool is configured with five connections per server process. Image storage, email/SMS notifications, payment processing, audit logs, automated backups, and advanced analytics are not complete. Multiple server instances also make in-memory rate-limit counters approximate rather than shared.

## Recommended Next Features

1. Add managed authentication with password reset, email verification, and optional phone OTP.
2. Move all product media to durable object storage with validation, resizing, and CDN delivery.
3. Add order notifications, payment integration, delivery fees, inventory, and immutable order history.
4. Add shared rate limiting, CSRF protection, structured logs, monitoring, automated database migrations, backups, and a staging branch.
5. Run a load test at 25, 50, and 100 concurrent users before increasing the supported capacity.
