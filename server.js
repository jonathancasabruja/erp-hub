import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac, timingSafeEqual } from "node:crypto";

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
