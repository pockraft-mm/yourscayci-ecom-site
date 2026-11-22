# Repository Guidelines

## Project Structure & Module Organization

This repository is the YoursCayCi e-commerce project. The current checkout contains no implementation files yet; organize the application around the project specification in the linked Google Doc:

- `src/` — customer-facing storefront and reusable UI components.
- `src/pages/` — route-level screens such as Home, Shop, Product Detail, Cart, Checkout, Account, and informational pages.
- `src/admin/` — admin login, dashboard, product, inventory, order, customer, invoice, and settings screens.
- `src/services/` or `src/lib/` — API, authentication, storage, and business logic integrations.
- `public/` — static assets and product media that do not require bundling.
- `tests/` — unit, integration, and end-to-end tests.
- `supabase/` or `migrations/` — database schema and migration files, if the chosen backend uses them.

Keep feature-specific components close to their page or feature; keep shared primitives in a clearly named common directory.

## Build, Test, and Development Commands

No package manifest or scripts are present yet. Once the app scaffold is added, document the canonical commands here and in `package.json`. Expected examples are `npm install`, `npm run dev` for local development, `npm run build` for a production build, `npm run lint` for static checks, and `npm test` for the test suite. Do not claim a command is supported until it exists in the project scripts.

## Coding Style & Naming Conventions

Use two spaces for indentation, semicolons where the formatter requires them, and the repository formatter/linter as the source of truth. Name React components and page files in PascalCase (`ProductDetail.tsx`), utilities in camelCase (`formatCurrency.ts`), and database fields/tables in snake_case (`created_at`, `order_items`). Prefer explicit, small modules and avoid putting data-access logic directly in presentation components.

## Testing Guidelines

Add tests alongside new behavior under `tests/` or the project’s established test convention. Cover checkout totals, authentication boundaries, inventory/order transitions, and API error states. Use descriptive names such as `product-detail.spec.tsx`; include regression coverage for bug fixes.

## Commit & Pull Request Guidelines

The checkout has no readable commit history yet, so use imperative, concise subjects such as `Add product detail route` or `Fix cart total calculation`. Keep commits focused. Pull requests should explain the user-facing change, list validation commands, link the relevant task or specification, and include screenshots or a short recording for storefront/admin UI changes. Call out schema or environment-variable changes explicitly.

## Security & Configuration

Never commit passwords, API keys, tokens, or production customer data. Store local secrets in ignored environment files, validate authentication and authorization on the server, and treat product/customer/order data as sensitive. Database migrations must preserve the documented relationships and constraints.
