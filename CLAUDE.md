# Casa Bruja — ERP Hub

The unified portal + login + admin for the whole Casa Bruja ERP. Users
log in here once and get a JWT cookie valid across every `.casabruja.com`
subdomain (facturación, brewery, compras, recibos).

## Stack
- **Plain Node.js** (no TypeScript, no build step)
- `server.js` = single file, uses `node:http`, `postgres`, `bcryptjs`
- Static HTML pages served directly: `login.html`, `index.html`, `admin.html`, `junta.html`
- Runs on Railway → auto-deploys on push to `main`

## Entry points
- `server.js` — HTTP router, auth, admin API, Sala de Junta API
- `login.html` — email+password + legacy password-only toggle
- `index.html` — portal tiles, filtered by `permissions._apps` cookie
- `admin.html` — users, permissions, board-room editor, KPI snapshot
- `junta.html` — public board-room presentation (token-gated)

## Key paths in server.js
- `/api/login` — dual-path (email+password via app_users, or legacy APP_PASSWORD)
- `/api/logout` — clears cookies on `.casabruja.com`, SSO-wide logout
- `/api/me` — returns current user from JWT + DB
- `/api/admin/*` — users/snapshots/board-room (role=admin only)
- `/api/junta/<token>` — public board data

## Auth model
- JWT cookie `app_session_id` (HS256, `JWT_SECRET` shared across all apps)
- Meta cookie `cb_session_meta` (non-httpOnly, base64 JSON with role + permissions)
- `COOKIE_DOMAIN=.casabruja.com` → cookie flows to siblings
- `permissions._apps.<key>` = "view" | "edit" | "none" gates app access
- Section-level perms (e.g. `permissions.cierre_caja`) override app-level in siblings
- `role=admin` or `legacy=true` bypass all per-app/section gates

## Database
- Shared Supabase PG (project `mcuxvoyrhfwafoxvxinm`)
- Main table for this repo: `app_users` (id, email, password_hash, role, permissions JSONB, active, must_change)
- Also reads `sales_line_items`, `csv_records`, `supplier_invoices`, `purchase_orders` for admin KPI cards + junta payload
- `board_room` — singleton table for Sala de Junta content + access_token

## Conventions
- No local build. Don't try `npm run build` — this repo has no TS toolchain
- Commits: push to main → Railway auto-deploys (~60–90s)
- Never commit with `--no-verify` unless explicitly told
- Dialogs in admin.html use `.dialog-body` + `.dialog-actions` pattern for sticky bottom actions

## Gotchas
- `app.set("trust proxy", true)` was THE fix for Railway login cookies — `sameSite=none` needs `secure=true`, which needs trust-proxy (sibling apps already use this)
- When adding sections to `SECTIONS_BY_APP`, the sibling app's own server/client must also handle the new section_key before it actually gates anything
- Admin `/admin/users/delete` blocks self-delete via session.userId check

## Recent migrations
- **2026-04-23** — Unified email+password login; tile filtering via `permissions._apps`; `cb_session_meta` cookie
- **2026-04-24** — Sticky dialog action row (Guardar was scrolling off); logout button with SSO-wide cookie clearing; section-level perms for brewery + recibos

## External systems
- Railway (project `industrious-luck`, service `erp-hub`)
- Supabase PG
- GitHub: `jonathancasabruja/erp-hub`
