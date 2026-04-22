import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac, timingSafeEqual } from "node:crypto";
import postgres from "postgres";
import bcrypt from "bcryptjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = resolve(__dirname);
const PORT = Number(process.env.PORT) || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "default-dev-secret-change-me";
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN?.trim() || ""; // e.g. ".casabruja.com"
const COOKIE_NAME = "app_session_id";
const ADMIN_PASSWORD = process.env.APP_PASSWORD;
const ACCOUNTANT_PASSWORD = process.env.ACCOUNTANT_PASSWORD;
const ONE_YEAR = 60 * 60 * 24 * 365;

// ─── JWT (HS256) — wire-compatible with the other apps' jose-based tokens ──

function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(s) {
  // Pad and convert to base64
  let padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";
  return Buffer.from(padded, "base64");
}

function signJWT(payload, expiresInSec = ONE_YEAR) {
  const iat = Math.floor(Date.now() / 1000);
  const body = { ...payload, exp: iat + expiresInSec };
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(body));
  const data = `${h}.${p}`;
  const sig = b64urlEncode(createHmac("sha256", JWT_SECRET).update(data).digest());
  return `${data}.${sig}`;
}

function verifyJWT(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const expected = b64urlEncode(createHmac("sha256", JWT_SECRET).update(`${h}.${p}`).digest());
  const a = Buffer.from(expected);
  const b = Buffer.from(s);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(b64urlDecode(p).toString("utf-8"));
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join("=") ?? "");
  }
  return out;
}

function setSessionCookie(res, token) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    `Max-Age=${ONE_YEAR}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ];
  if (COOKIE_DOMAIN) parts.push(`Domain=${COOKIE_DOMAIN}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return timingSafeEqual(ba, bb);
}

// ─── Admin KPI queries ─────────────────────────────────────────────────────
// Read-only snapshots from the shared Supabase DB. Auth-gated to admin
// sessions only (checked in the request handler before these run).

const DATABASE_URL = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL;
let _sql = null;
function getSql() {
  if (_sql) return _sql;
  if (!DATABASE_URL) return null;
  _sql = postgres(DATABASE_URL, {
    ssl: { rejectUnauthorized: false },
    max: 3,
    prepare: false,
    fetch_types: false,
  });
  return _sql;
}

/** YYYY-MM-DD in Panama (UTC-5). */
function panamaToday() {
  const now = new Date(Date.now() - 5 * 60 * 60 * 1000);
  return now.toISOString().slice(0, 10);
}

/** First day of the current Panama month. */
function panamaMonthStart() {
  const today = panamaToday();
  return today.slice(0, 7) + "-01";
}

/** First day of the current Panama year. */
function panamaYearStart() {
  return panamaToday().slice(0, 4) + "-01-01";
}

async function adminSalesSnapshot() {
  const sql = getSql();
  if (!sql) return null;
  const today = panamaToday();
  const monthStart = panamaMonthStart();
  const yearStart = panamaYearStart();

  // csv_records is the authoritative totals source (matches Jean's CSV
  // uploads + the Dashboard summary cards). sales_line_items gives
  // per-customer breakdown but csv_records has the dollars right.
  const [mtd, ytd, topMonth, totalCustomers] = await Promise.all([
    sql`
      SELECT
        COALESCE(SUM(subtotal), 0)::float AS total,
        COALESCE(SUM(subtotal) FILTER (WHERE type = 'Taproom'), 0)::float AS taproom,
        COALESCE(SUM(subtotal) FILTER (WHERE type <> 'Taproom'), 0)::float AS distribucion,
        COUNT(*)::int AS invoices
      FROM csv_records
      WHERE "fileDate" >= ${monthStart} AND "fileDate" <= ${today}
    `,
    sql`
      SELECT
        COALESCE(SUM(subtotal), 0)::float AS total,
        COALESCE(SUM(subtotal) FILTER (WHERE type = 'Taproom'), 0)::float AS taproom,
        COALESCE(SUM(subtotal) FILTER (WHERE type <> 'Taproom'), 0)::float AS distribucion,
        COUNT(*)::int AS invoices
      FROM csv_records
      WHERE "fileDate" >= ${yearStart} AND "fileDate" <= ${today}
    `,
    sql`
      SELECT
        s.customer_code,
        COALESCE(cn.friendly_name, cn.razon_social, s.customer_code) AS name,
        SUM(s.line_total)::float AS revenue,
        COUNT(DISTINCT s.invoice_number)::int AS invoices
      FROM sales_line_items s
      LEFT JOIN customer_names cn ON cn.customer_code = s.customer_code
      WHERE s.sale_date >= ${monthStart}
        AND s.sale_date <= ${today}
        AND s.customer_code IS NOT NULL
        AND s.source_order_id IS NULL
      GROUP BY s.customer_code, cn.friendly_name, cn.razon_social
      ORDER BY revenue DESC
      LIMIT 10
    `,
    sql`
      SELECT COUNT(DISTINCT customer_code)::int AS c
      FROM sales_line_items
      WHERE sale_date >= ${yearStart}
        AND customer_code IS NOT NULL
        AND source_order_id IS NULL
    `,
  ]);

  return {
    asOf: today,
    mtd: mtd[0],
    ytd: ytd[0],
    topCustomersThisMonth: topMonth,
    customersThisYear: totalCustomers[0]?.c ?? 0,
  };
}

async function adminInvoiceLibrarySnapshot() {
  const sql = getSql();
  if (!sql) return null;
  const [byCategory, recentOverrides, total] = await Promise.all([
    sql`
      SELECT category::text AS category, COUNT(*)::int AS c, COALESCE(SUM(total_amount), 0)::float AS total
      FROM supplier_invoices
      GROUP BY category
      ORDER BY total DESC
    `,
    sql`
      SELECT COUNT(*)::int AS c
      FROM supplier_invoices
      WHERE category_was_manual = true
    `,
    sql`SELECT COUNT(*)::int AS c FROM supplier_invoices`,
  ]);
  return {
    total: total[0]?.c ?? 0,
    manualOverrides: recentOverrides[0]?.c ?? 0,
    byCategory,
  };
}

// ─── App users (shared with facturacion via same Supabase DB) ──────────────
// The canonical schema lives in facturacion-cb/server/appUsersDb.ts. We
// mirror the shape here so the hub can manage users without round-tripping
// through facturacion's tRPC. Both services read/write the same table.

// Sections grouped by the app they belong to. The UI uses this shape to
// render per-app permission cards with quick-grant (sin acceso / ver /
// editar) that also cascade to the sections within, OR expand to
// fine-grained per-section control.
//
// Keep in sync with facturacion-cb/server/appUsersDb.ts SECTION_KEYS —
// right now only facturación has wired-up sections; other apps only
// check the _apps[app] level.
const SECTIONS_BY_APP = {
  facturacion: [
    { key: "pedidos", label: "Pedidos" },
    { key: "ruteo", label: "Ruteo (Kanban)" },
    { key: "dashboard", label: "Dashboard de ventas" },
    { key: "historial", label: "Historial" },
    { key: "clientes", label: "Clientes" },
    { key: "precios_cliente", label: "Precios por cliente" },
    { key: "aliases", label: "Aliases de cerveza" },
    { key: "facturador", label: "Facturador ERP" },
    { key: "repositorio_facturas", label: "Repositorio facturas" },
  ],
  compras: [
    // Sections defined for consistency; enforcement wired as compras grows.
    { key: "purchase_orders", label: "Órdenes de compra" },
    { key: "cost_invoices", label: "Fletes y gastos" },
    { key: "invoice_library", label: "Repositorio de facturas" },
    { key: "personal_eventual", label: "Personal eventual" },
    { key: "servicios_profesionales", label: "Servicios profesionales" },
  ],
  brewery: [],
  recibos: [],
};

const APP_KEYS = ["facturacion", "brewery", "compras", "recibos"];
const APP_LABELS = {
  facturacion: "Facturación",
  brewery: "Brewery",
  compras: "Compras & Personal",
  recibos: "Recibos Banco",
};
// Flat union of all section keys across apps — the server accepts any of
// these in the permissions payload.
const SECTION_KEYS = Object.values(SECTIONS_BY_APP).flatMap((s) => s.map((x) => x.key));

async function adminListUsers() {
  const sql = getSql();
  if (!sql) return null;
  const rows = await sql`
    SELECT id, email, display_name, role, permissions, active, must_change,
           created_at, updated_at
    FROM app_users
    ORDER BY role DESC, email ASC
  `;
  return rows.map((r) => ({
    id: r.id,
    email: r.email,
    displayName: r.display_name,
    role: r.role,
    permissions: r.permissions || {},
    active: r.active,
    mustChange: r.must_change,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

async function adminCreateUser(input) {
  const sql = getSql();
  if (!sql) return null;
  const { email, password, displayName, role, permissions, mustChange } = input;
  if (!email || !password || !displayName) throw new Error("email, password, displayName required");
  const hash = await bcrypt.hash(password, 10);
  const [row] = await sql`
    INSERT INTO app_users (email, password_hash, display_name, role, permissions, active, must_change)
    VALUES (${email.toLowerCase()}, ${hash}, ${displayName},
            ${role || "user"}, ${sql.json(permissions || {})}, true, ${mustChange !== false})
    RETURNING id, email, display_name, role, permissions, active, must_change
  `;
  return row;
}

async function adminUpdateUser(id, patch) {
  const sql = getSql();
  if (!sql) return null;
  // Build a snake_case object of only the fields the caller sent. Passing
  // it through sql() generates the SET list safely.
  const updates = {};
  if (patch.email !== undefined) updates.email = patch.email.toLowerCase();
  if (patch.displayName !== undefined) updates.display_name = patch.displayName;
  if (patch.role !== undefined) updates.role = patch.role;
  if (patch.permissions !== undefined) updates.permissions = patch.permissions;
  if (patch.active !== undefined) updates.active = patch.active;
  if (patch.mustChange !== undefined) updates.must_change = patch.mustChange;
  if (Object.keys(updates).length === 0) return null;
  updates.updated_at = new Date();
  const [row] = await sql`
    UPDATE app_users SET ${sql(updates)}
    WHERE id = ${id}
    RETURNING id, email, display_name, role, permissions, active, must_change
  `;
  return row;
}

async function adminResetUserPassword(id, newPassword, mustChange = true) {
  const sql = getSql();
  if (!sql) return null;
  const hash = await bcrypt.hash(newPassword, 10);
  const [row] = await sql`
    UPDATE app_users
    SET password_hash = ${hash}, must_change = ${mustChange}, updated_at = NOW()
    WHERE id = ${id}
    RETURNING id
  `;
  return row ? { ok: true } : null;
}

async function adminDeleteUser(id) {
  const sql = getSql();
  if (!sql) return null;
  const [row] = await sql`DELETE FROM app_users WHERE id = ${id} RETURNING id`;
  return row ? { ok: true } : null;
}

async function adminPoSnapshot() {
  const sql = getSql();
  if (!sql) return null;
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const rows = await sql`
    SELECT
      status::text AS status,
      COUNT(*)::int AS c,
      COALESCE(SUM(total), 0)::float AS total
    FROM purchase_orders
    WHERE created_at >= ${thirtyDaysAgo}
    GROUP BY status
    ORDER BY c DESC
  `;
  return { last30Days: rows };
}

// ─── Static + routing ──────────────────────────────────────────────────────

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
};

async function serveFile(res, absPath) {
  try {
    const s = await stat(absPath);
    const target = s.isDirectory() ? join(absPath, "index.html") : absPath;
    const body = await readFile(target);
    res.writeHead(200, {
      "content-type": MIME[extname(target)] || "application/octet-stream",
      "cache-control": "public, max-age=60",
    });
    res.end(body);
    return true;
  } catch {
    return false;
  }
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString("utf-8");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;

    // POST /api/login — issue the shared JWT cookie
    if (req.method === "POST" && path === "/api/login") {
      if (!ADMIN_PASSWORD) {
        res.writeHead(500, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "APP_PASSWORD not configured" }));
      }
      const body = await readJsonBody(req);
      if (!body) {
        res.writeHead(400, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "Invalid JSON" }));
      }
      const pw = typeof body.password === "string" ? body.password : "";
      let role = null;
      if (safeEqual(pw, ADMIN_PASSWORD)) role = "admin";
      else if (ACCOUNTANT_PASSWORD && safeEqual(pw, ACCOUNTANT_PASSWORD)) role = "accountant";
      if (!role) {
        res.writeHead(401, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "Contraseña incorrecta" }));
      }
      const name = (typeof body.name === "string" && body.name.trim()) ||
        (role === "accountant" ? "Contador" : "Usuario");
      const openId = `local_${role}_${name.toLowerCase().replace(/\s+/g, "_")}`;
      const token = signJWT({ openId, appId: "casabruja-erp", name, role });
      setSessionCookie(res, token);
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ success: true, user: { name, role } }));
    }

    // GET /login — serve the login page (always, no auth)
    if (path === "/login") {
      const served = await serveFile(res, join(ROOT, "login.html"));
      if (!served) {
        res.writeHead(500);
        res.end("login page missing");
      }
      return;
    }

    // Static assets and files with extensions pass through without auth
    const isAsset = /\.[a-zA-Z0-9]+$/.test(path) || path.startsWith("/assets/");
    if (isAsset) {
      const served = await serveFile(res, join(ROOT, path));
      if (!served) {
        res.writeHead(404);
        res.end("not found");
      }
      return;
    }

    // Auth gate for the hub itself
    const cookies = parseCookies(req.headers.cookie);
    const session = verifyJWT(cookies[COOKIE_NAME]);
    if (!session) {
      res.writeHead(302, { location: "/login" });
      return res.end();
    }

    // ─── Admin-only API ───────────────────────────────────────────────
    // These sit behind the session auth + require role=admin. Everything
    // non-destructive is a GET; user CRUD uses POST with JSON bodies.
    if (path.startsWith("/api/admin/")) {
      if (session.role !== "admin") {
        res.writeHead(403, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "admin only" }));
      }
      try {
        // ─── KPI snapshots (GET) ─────────────────────────────────────
        if (req.method === "GET") {
          let data = null;
          if (path === "/api/admin/sales-snapshot") data = await adminSalesSnapshot();
          else if (path === "/api/admin/invoice-library-snapshot") data = await adminInvoiceLibrarySnapshot();
          else if (path === "/api/admin/po-snapshot") data = await adminPoSnapshot();
          else if (path === "/api/admin/users") data = await adminListUsers();
          else if (path === "/api/admin/meta")
            data = {
              apps: APP_KEYS,
              appLabels: APP_LABELS,
              sectionsByApp: SECTIONS_BY_APP,
              // Legacy flat list kept for any caller still expecting it.
              sections: SECTION_KEYS,
            };
          else {
            res.writeHead(404, { "content-type": "application/json" });
            return res.end(JSON.stringify({ error: "unknown admin endpoint" }));
          }
          if (data === null) {
            res.writeHead(503, { "content-type": "application/json" });
            return res.end(JSON.stringify({ error: "DATABASE_URL not configured" }));
          }
          res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          return res.end(JSON.stringify(data));
        }

        // ─── User CRUD (POST) ───────────────────────────────────────
        if (req.method === "POST") {
          const body = await readJsonBody(req);
          if (!body) {
            res.writeHead(400, { "content-type": "application/json" });
            return res.end(JSON.stringify({ error: "Invalid JSON" }));
          }
          let data = null;
          if (path === "/api/admin/users/create") data = await adminCreateUser(body);
          else if (path === "/api/admin/users/update") {
            const { id, ...patch } = body;
            if (!id) throw new Error("id required");
            data = await adminUpdateUser(id, patch);
          } else if (path === "/api/admin/users/reset-password") {
            if (!body.id || !body.newPassword) throw new Error("id + newPassword required");
            data = await adminResetUserPassword(body.id, body.newPassword, body.mustChange ?? true);
          } else if (path === "/api/admin/users/delete") {
            if (!body.id) throw new Error("id required");
            // Don't let an admin delete themselves by accident.
            if (String(body.id) === String(session.userId)) throw new Error("No puedes eliminar tu propia cuenta.");
            data = await adminDeleteUser(body.id);
          } else {
            res.writeHead(404, { "content-type": "application/json" });
            return res.end(JSON.stringify({ error: "unknown admin endpoint" }));
          }
          res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          return res.end(JSON.stringify(data ?? { ok: true }));
        }

        res.writeHead(405, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "method not allowed" }));
      } catch (err) {
        console.error("[hub] admin API error:", err);
        res.writeHead(500, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: err?.message || "query failed" }));
      }
    }

    // /admin — admin-only dashboard page
    if (path === "/admin" || path === "/admin/") {
      if (session.role !== "admin") {
        res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
        return res.end("Solo administradores.");
      }
      const served = await serveFile(res, join(ROOT, "admin.html"));
      if (!served) {
        res.writeHead(500);
        res.end("admin page missing");
      }
      return;
    }

    // Authenticated → serve the portal
    const served = await serveFile(res, join(ROOT, "index.html"));
    if (!served) {
      res.writeHead(500);
      res.end("portal missing");
    }
  } catch (err) {
    console.error("[hub] handler error:", err);
    res.writeHead(500, { "content-type": "text/plain" });
    res.end("Internal error");
  }
});

server.listen(PORT, () => {
  console.log(`Hub listening on http://localhost:${PORT}/`);
  if (!ADMIN_PASSWORD) console.warn("APP_PASSWORD not set — login will refuse all credentials");
  if (!COOKIE_DOMAIN) console.warn("COOKIE_DOMAIN not set — cookie will be host-only (no SSO)");
});
