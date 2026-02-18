/**
 * meraki-sms-splash - single-file server.js (FIXED: base_grant_url missing)
 * - Fix: Meraki params are embedded into forms as hidden inputs
 * - Fix: Parses Meraki params from BOTH return_url and direct query params
 * - Fix: Caches ctx by marker + mac + ip for fallback
 *
 * ENV:
 *   PORT=8080
 *   DATABASE_URL=postgres://...
 *   REDIS_URL=redis://... (optional)
 *   OTP_MODE=screen|sms
 *   OTP_TTL_SECONDS=180
 *   RL_MAC_SECONDS=30
 *   RL_PHONE_SECONDS=60
 *   MAX_WRONG_ATTEMPTS=5
 *   LOCK_SECONDS=600
 *   KVKK_VERSION=2026-02-12-placeholder
 *   TZ=Europe/Istanbul
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   DAILY_HMAC_KEY=... (optional but recommended)
 */

"use strict";

const http = require("http");
const url = require("url");
const crypto = require("crypto");
const { Pool } = require("pg");

// Optional ioredis
let Redis = null;
try {
  Redis = require("ioredis");
} catch (_) {
  Redis = null;
}

// -------------------- ENV --------------------
const ENV = {
  OTP_MODE: (process.env.OTP_MODE || "screen").toLowerCase(),
  OTP_TTL_SECONDS: parseInt(process.env.OTP_TTL_SECONDS || "180", 10),
  RL_MAC_SECONDS: parseInt(process.env.RL_MAC_SECONDS || "30", 10),
  RL_PHONE_SECONDS: parseInt(process.env.RL_PHONE_SECONDS || "60", 10),
  MAX_WRONG_ATTEMPTS: parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10),
  LOCK_SECONDS: parseInt(process.env.LOCK_SECONDS || "600", 10),
  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",
  TZ: process.env.TZ || "Europe/Istanbul",
  ADMIN_USER: process.env.ADMIN_USER || "",
  ADMIN_PASS: process.env.ADMIN_PASS || "",
  DAILY_HMAC_KEY: process.env.DAILY_HMAC_KEY || "",
  PORT: parseInt(process.env.PORT || "8080", 10),
  DATABASE_URL: process.env.DATABASE_URL || "",
  REDIS_URL: process.env.REDIS_URL || "",
  PUBLIC_IP: process.env.PUBLIC_IP || "",
};

function safeLogEnv() {
  console.log("ENV:", {
    OTP_MODE: ENV.OTP_MODE,
    OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
    RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
    RL_PHONE_SECONDS: ENV.RL_PHONE_SECONDS,
    MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
    LOCK_SECONDS: ENV.LOCK_SECONDS,
    KVKK_VERSION: ENV.KVKK_VERSION,
    TZ: ENV.TZ,
    DB_SET: !!ENV.DATABASE_URL,
    REDIS_SET: !!ENV.REDIS_URL,
    ADMIN_USER_SET: !!ENV.ADMIN_USER,
    ADMIN_PASS_SET: !!ENV.ADMIN_PASS,
    DAILY_HMAC_SET: !!ENV.DAILY_HMAC_KEY,
    PUBLIC_IP: ENV.PUBLIC_IP || undefined,
  });
}
safeLogEnv();

// -------------------- Utilities --------------------
function nowISO() {
  return new Date().toISOString();
}
function sha256hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function hmacHex(key, msg) {
  return crypto.createHmac("sha256", key).update(String(msg)).digest("hex");
}
function randDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += String(Math.floor(Math.random() * 10));
  return out;
}
function normalizePhone(p) {
  const s = String(p || "").trim();
  if (!s) return "";
  const digits = s.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) return "+" + digits.slice(1).replace(/[^\d]/g, "");
  return digits.replace(/[^\d]/g, "");
}
function normalizeMac(m) {
  const s = String(m || "").trim().toLowerCase();
  if (!s) return "";
  const cleaned = s.replace(/[^0-9a-f]/g, "");
  if (cleaned.length !== 12) return "";
  return cleaned.match(/.{1,2}/g).join(":");
}
function parseJsonBody(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (d) => (buf += d));
    req.on("end", () => {
      if (!buf) return resolve({});
      try {
        resolve(JSON.parse(buf));
      } catch {
        resolve({});
      }
    });
  });
}
function parseForm(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (d) => (buf += d));
    req.on("end", () => {
      const out = {};
      buf.split("&").forEach((kvp) => {
        if (!kvp) return;
        const [k, v] = kvp.split("=");
        const key = decodeURIComponent(k || "").replace(/\+/g, " ");
        const val = decodeURIComponent(v || "").replace(/\+/g, " ");
        out[key] = val;
      });
      resolve(out);
    });
  });
}
function send(res, status, body, headers = {}) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": b.length,
    ...headers,
  });
  res.end(b);
}
function sendHtml(res, status, html) {
  const b = Buffer.from(String(html));
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": b.length,
  });
  res.end(b);
}
function sendJson(res, status, obj, headers = {}) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": b.length,
    ...headers,
  });
  res.end(b);
}
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function getClientIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  if (xf) return xf.split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "";
}

// Basic Auth without deps
function basicAuth(req) {
  const h = req.headers["authorization"] || "";
  if (!h.startsWith("Basic ")) return null;
  const raw = Buffer.from(h.slice(6), "base64").toString("utf8");
  const idx = raw.indexOf(":");
  if (idx < 0) return null;
  return { user: raw.slice(0, idx), pass: raw.slice(idx + 1) };
}
function requireAdmin(req, res) {
  if (!ENV.ADMIN_USER || !ENV.ADMIN_PASS) {
    send(res, 500, "ADMIN_USER / ADMIN_PASS not set");
    return false;
  }
  const c = basicAuth(req);
  if (!c || c.user !== ENV.ADMIN_USER || c.pass !== ENV.ADMIN_PASS) {
    res.writeHead(401, { "WWW-Authenticate": 'Basic realm="admin"' });
    res.end("Unauthorized");
    return false;
  }
  return true;
}

// -------------------- Meraki parsing --------------------
function parseMerakiReturnUrl(returnUrl) {
  let ru = null;
  try {
    ru = new URL(returnUrl);
  } catch {
    return { ru: null, ctx: {} };
  }
  const q = ru.searchParams;
  const ctx = {
    gateway_id: q.get("gateway_id") || "",
    node_id: q.get("node_id") || "",
    client_ip: q.get("client_ip") || "",
    client_mac: normalizeMac(q.get("client_mac") || ""),
    node_mac: normalizeMac(q.get("node_mac") || ""),
    continue_url: q.get("continue_url") || "",
    base_grant_url: q.get("base_grant_url") || "",
    user_continue_url: q.get("user_continue_url") || "",
  };

  // Derive base_grant_url if not provided
  if (!ctx.base_grant_url) {
    try {
      const u2 = new URL(ru.toString());
      if (u2.pathname.endsWith("/grant")) {
        ctx.base_grant_url = u2.origin + u2.pathname;
      } else if (u2.pathname.includes("/splash/")) {
        const p = u2.pathname.replace(/\/$/, "");
        ctx.base_grant_url = u2.origin + p + "/grant";
      }
    } catch {}
  }

  return { ru, ctx };
}

function parseMerakiDirectQuery(q) {
  // Many Meraki deployments send these directly on splash URL
  const ctx = {
    gateway_id: (q.gateway_id || q.gw_id || "").toString(),
    node_id: (q.node_id || "").toString(),
    client_ip: (q.client_ip || "").toString(),
    client_mac: normalizeMac((q.client_mac || "").toString()),
    node_mac: normalizeMac((q.node_mac || "").toString()),
    continue_url: (q.continue_url || q.user_continue_url || "").toString(),
    base_grant_url: (q.base_grant_url || "").toString(),
    user_continue_url: (q.user_continue_url || "").toString(),
  };

  // Sometimes Meraki uses "base_grant_url" as full grant endpoint already
  // If base_grant_url is empty but we have something like "base_url" or "grant_url"
  if (!ctx.base_grant_url && q.grant_url) ctx.base_grant_url = String(q.grant_url);

  // normalize again
  ctx.client_mac = normalizeMac(ctx.client_mac);
  ctx.node_mac = normalizeMac(ctx.node_mac);

  return ctx;
}

function mergeCtx(a, b) {
  // prefer a fields, fill from b
  const out = { ...(b || {}) };
  for (const k of Object.keys(a || {})) {
    if (a[k] !== undefined && a[k] !== null && String(a[k]).length) out[k] = a[k];
  }
  // normalize macs
  out.client_mac = normalizeMac(out.client_mac || "");
  out.node_mac = normalizeMac(out.node_mac || "");
  return out;
}

function buildGrantRedirect(ctx) {
  if (!ctx || !ctx.base_grant_url) return null;
  let g;
  try {
    g = new URL(ctx.base_grant_url);
  } catch {
    return null;
  }
  const add = (k, v) => {
    if (v !== undefined && v !== null && String(v).length) g.searchParams.set(k, String(v));
  };

  add("gateway_id", ctx.gateway_id);
  add("node_id", ctx.node_id);
  add("client_ip", ctx.client_ip);
  add("client_mac", ctx.client_mac);
  add("node_mac", ctx.node_mac);

  // continue_url very important for some clients
  if (ctx.continue_url) add("continue_url", ctx.continue_url);

  return g.toString();
}

// -------------------- KV store (Redis or memory) --------------------
class MemoryKV {
  constructor() {
    this.m = new Map();
  }
  async get(key) {
    const v = this.m.get(key);
    if (!v) return null;
    if (v.exp && Date.now() > v.exp) {
      this.m.delete(key);
      return null;
    }
    return v.val;
  }
  async setex(key, ttlSeconds, val) {
    this.m.set(key, { val, exp: Date.now() + ttlSeconds * 1000 });
  }
  async del(key) {
    this.m.delete(key);
  }
}

let kv = new MemoryKV();
let redis = null;

async function initKV() {
  if (Redis && ENV.REDIS_URL) {
    try {
      redis = new Redis(ENV.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
      await redis.connect();
      kv = {
        get: async (k) => await redis.get(k),
        setex: async (k, ttl, v) => await redis.setex(k, ttl, v),
        del: async (k) => await redis.del(k),
      };
      console.log("REDIS: connected");
      return;
    } catch (e) {
      console.log("REDIS: failed, fallback to memory:", e && e.message);
      redis = null;
      kv = new MemoryKV();
    }
  } else {
    console.log("REDIS: not configured, using memory");
  }
}

// -------------------- Postgres --------------------
const pool = ENV.DATABASE_URL
  ? new Pool({
      connectionString: ENV.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
    })
  : null;

async function qRows(text, params) {
  if (!pool) return [];
  const r = await pool.query(text, params);
  return r.rows || [];
}
async function qExec(text, params) {
  if (!pool) return;
  await pool.query(text, params);
}

async function ensureTables() {
  if (!pool) {
    console.log("DATABASE: not configured");
    return;
  }
  await qExec(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      full_name TEXT,
      phone TEXT,
      kvkk_accepted BOOLEAN,
      kvkk_version TEXT,
      marker TEXT,
      client_mac TEXT,
      client_ip TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      user_continue_url TEXT,
      continue_url TEXT,
      user_agent TEXT,
      accept_language TEXT,
      extra TEXT,
      meta JSONB
    );
  `);

  await qExec(`
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      record_count INTEGER NOT NULL,
      day_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await qExec(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      prev_day_hash TEXT,
      chain_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await qExec(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      payload JSONB NOT NULL,
      signature TEXT,
      algo TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  console.log("DATABASE: table ready");
}

async function ensureColumn(table, col, typeSql) {
  try {
    await qExec(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${col} ${typeSql};`);
  } catch (_) {}
}

async function logAccess(event, data) {
  if (!pool) return;

  await ensureColumn("access_logs", "accept_language", "TEXT");
  await ensureColumn("access_logs", "continue_url", "TEXT");
  await ensureColumn("access_logs", "user_continue_url", "TEXT");
  await ensureColumn("access_logs", "base_grant_url", "TEXT");
  await ensureColumn("access_logs", "meta", "JSONB");

  const row = {
    event: event || "UNKNOWN",
    first_name: data.first_name || null,
    last_name: data.last_name || null,
    full_name: data.full_name || null,
    phone: data.phone || null,
    kvkk_accepted: typeof data.kvkk_accepted === "boolean" ? data.kvkk_accepted : null,
    kvkk_version: data.kvkk_version || ENV.KVKK_VERSION || null,
    marker: data.marker || null,
    client_mac: data.client_mac || null,
    client_ip: data.client_ip || null,
    ssid: data.ssid || null,
    ap_name: data.ap_name || null,
    base_grant_url: data.base_grant_url || null,
    user_continue_url: data.user_continue_url || null,
    continue_url: data.continue_url || null,
    user_agent: data.user_agent || null,
    accept_language: data.accept_language || null,
    extra: data.extra || null,
    meta: data.meta || {},
  };

  const cols = Object.keys(row);
  const vals = cols.map((_, i) => `$${i + 1}`);
  const params = cols.map((k) => (k === "meta" ? JSON.stringify(row[k] || {}) : row[k]));

  try {
    await qExec(`INSERT INTO access_logs(${cols.join(",")}) VALUES(${vals.join(",")})`, params);
  } catch (e) {
    console.log("DB LOG ERROR:", e && e.message);
  }
}

// -------------------- OTP + rate limiting --------------------
function keyOtp(marker) {
  return `otp:${marker}`;
}
function keyMac(mac) {
  return `rl:mac:${mac}`;
}
function keyPhone(phone) {
  return `rl:phone:${phone}`;
}
function keyLock(marker) {
  return `lock:${marker}`;
}

async function isRateLimited(mac, phone) {
  if (mac) {
    const v = await kv.get(keyMac(mac));
    if (v) return { ok: false, why: "mac", ttl: ENV.RL_MAC_SECONDS };
  }
  if (phone) {
    const v = await kv.get(keyPhone(phone));
    if (v) return { ok: false, why: "phone", ttl: ENV.RL_PHONE_SECONDS };
  }
  return { ok: true };
}
async function setRate(mac, phone) {
  if (mac) await kv.setex(keyMac(mac), ENV.RL_MAC_SECONDS, "1");
  if (phone) await kv.setex(keyPhone(phone), ENV.RL_PHONE_SECONDS, "1");
}
async function isLocked(marker) {
  const v = await kv.get(keyLock(marker));
  return !!v;
}
async function lockMarker(marker) {
  await kv.setex(keyLock(marker), ENV.LOCK_SECONDS, "1");
}

// -------------------- Daily chain / package (optional endpoints used in admin) --------------------
function dateToYMDInTZ(date, tz) {
  try {
    const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" });
    return fmt.format(date);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

async function buildDaily(dayStr, tz) {
  await ensureColumn("daily_hashes", "tz", "TEXT");
  await ensureColumn("daily_chains", "tz", "TEXT");
  await ensureColumn("daily_packages", "tz", "TEXT");

  const rows = await qRows(
    `
    SELECT id, created_at, event, first_name, last_name, full_name, phone,
           marker, client_mac, client_ip, ssid, ap_name, base_grant_url,
           user_continue_url, continue_url, kvkk_version, kvkk_accepted, meta
    FROM access_logs
    WHERE (created_at AT TIME ZONE $2)::date = $1::date
    ORDER BY id ASC
    `,
    [dayStr, tz]
  );

  const record_count = rows.length;
  const lines = rows.map((r) => JSON.stringify({
    id: r.id,
    created_at: new Date(r.created_at).toISOString(),
    event: r.event,
    full_name: r.full_name || null,
    first_name: r.first_name || null,
    last_name: r.last_name || null,
    phone: r.phone || null,
    marker: r.marker || null,
    client_mac: r.client_mac || null,
    client_ip: r.client_ip || null,
    ssid: r.ssid || null,
    ap_name: r.ap_name || null,
    base_grant_url: r.base_grant_url || null,
    user_continue_url: r.user_continue_url || null,
    continue_url: r.continue_url || null,
    kvkk_version: r.kvkk_version || null,
    kvkk_accepted: typeof r.kvkk_accepted === "boolean" ? r.kvkk_accepted : null,
    meta: r.meta || {},
  }));

  const day_hash = sha256hex(lines.join("\n"));
  const prev = await qRows(`SELECT day_hash FROM daily_hashes WHERE day = ($1::date - INTERVAL '1 day')::date`, [dayStr]);
  const prev_day_hash = prev[0] ? prev[0].day_hash : null;
  const chain_hash = sha256hex(`${prev_day_hash || ""}|${dayStr}|${tz}|${record_count}|${day_hash}`);

  await qExec(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash)
    VALUES($1::date, $2, $3, $4)
    ON CONFLICT (day) DO UPDATE SET tz=EXCLUDED.tz, record_count=EXCLUDED.record_count, day_hash=EXCLUDED.day_hash
    `,
    [dayStr, tz, record_count, day_hash]
  );
  await qExec(
    `
    INSERT INTO daily_chains(day, tz, prev_day_hash, chain_hash)
    VALUES($1::date, $2, $3, $4)
    ON CONFLICT (day) DO UPDATE SET tz=EXCLUDED.tz, prev_day_hash=EXCLUDED.prev_day_hash, chain_hash=EXCLUDED.chain_hash
    `,
    [dayStr, tz, prev_day_hash, chain_hash]
  );

  const payload = { day: dayStr, tz, record_count, day_hash, prev_day_hash, chain_hash, generated_at: nowISO() };
  let signature = null, algo = null;
  if (ENV.DAILY_HMAC_KEY) {
    signature = hmacHex(ENV.DAILY_HMAC_KEY, JSON.stringify(payload));
    algo = "HMAC-SHA256";
  }

  await qExec(
    `
    INSERT INTO daily_packages(day, tz, payload, signature, algo)
    VALUES($1::date, $2, $3::jsonb, $4, $5)
    ON CONFLICT (day) DO UPDATE SET tz=EXCLUDED.tz, payload=EXCLUDED.payload, signature=EXCLUDED.signature, algo=EXCLUDED.algo
    `,
    [dayStr, tz, JSON.stringify(payload), signature, algo]
  );

  return { ...payload, signature, algo };
}

// -------------------- Admin UI --------------------
function adminLayout(title, body) {
  const css = `
  body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#e6eefc}
  a{color:#9cc3ff;text-decoration:none}
  .wrap{max-width:1100px;margin:24px auto;padding:0 16px}
  .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:16px;box-shadow:0 10px 40px rgba(0,0,0,.2)}
  h1{margin:0 0 10px;font-size:26px}
  .muted{opacity:.8}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
  th{font-weight:600;text-align:left;opacity:.85}
  .topbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px}
  .btn{display:inline-block;padding:8px 12px;border-radius:10px;background:#6d57ff;color:white;font-weight:600}
  input{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);border-radius:10px;color:#fff;padding:8px 10px}
  .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  `;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title><style>${css}</style></head><body>
  <div class="wrap"><div class="card">${body}</div></div></body></html>`;
}

async function renderAdminLogs(req, res, query) {
  const limit = Math.max(1, Math.min(1000, parseInt(query.limit || "200", 10)));
  const tz = (query.tz || ENV.TZ || "UTC").trim();

  const rows = await qRows(
    `
    SELECT id, created_at, event, full_name, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
    FROM access_logs
    ORDER BY id DESC
    LIMIT $1
    `,
    [limit]
  );

  const fmt = (dt) => {
    try {
      return new Intl.DateTimeFormat("tr-TR", {
        timeZone: tz,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date(dt));
    } catch {
      return new Date(dt).toISOString();
    }
  };

  if ((query.format || "").toLowerCase() === "json") return sendJson(res, 200, rows);

  const body = `
    <div class="topbar">
      <div>
        <h1>/admin/logs</h1>
        <div class="muted">limit=${limit} • tz=${escapeHtml(tz)} • <a href="/admin/logs?limit=${limit}&tz=${encodeURIComponent(tz)}&format=json">JSON</a></div>
      </div>
      <div class="row">
        <form method="GET" action="/admin/logs" class="row">
          <input name="limit" value="${limit}" style="width:110px" />
          <input name="tz" value="${escapeHtml(tz)}" style="width:180px" />
          <button class="btn" type="submit">Refresh</button>
        </form>
        <a class="btn" href="/admin/daily">Daily</a>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>marker</th><th>kvkk</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map((r) => {
          const name = r.full_name || [r.first_name, r.last_name].filter(Boolean).join(" ");
          return `<tr>
            <td>${r.id}</td>
            <td>${escapeHtml(fmt(r.created_at))}</td>
            <td>${escapeHtml(r.event)}</td>
            <td>${escapeHtml(name || "")}</td>
            <td>${escapeHtml(r.phone || "")}</td>
            <td>${escapeHtml(r.client_mac || "")}</td>
            <td>${escapeHtml(r.client_ip || "")}</td>
            <td>${escapeHtml(r.marker || "")}</td>
            <td>${escapeHtml(r.kvkk_version || "")}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
  return sendHtml(res, 200, adminLayout("admin logs", body));
}

async function renderAdminDailyIndex(req, res) {
  const tz = ENV.TZ || "UTC";
  const today = dateToYMDInTZ(new Date(), tz);
  const body = `
    <div class="topbar">
      <div>
        <h1>/admin/daily</h1>
        <div class="muted">TZ default: ${escapeHtml(tz)}</div>
      </div>
      <div class="row"><a class="btn" href="/admin/logs">Logs</a></div>
    </div>
    <div class="row" style="margin-top:10px">
      <a class="btn" href="/admin/daily/build?day=${today}">Build today (${today})</a>
    </div>
  `;
  sendHtml(res, 200, adminLayout("daily", body));
}

// -------------------- Splash page (FIX: include ctx hidden fields) --------------------
function splashPage({ marker, message, showOtp, otp, ctx }) {
  const hidden = (k, v) =>
    `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v || "")}"/>`;

  const otpBlock =
    showOtp && otp
      ? `<div style="margin-top:14px;padding:12px;border-radius:12px;background:rgba(255,255,255,.08);display:inline-block">
          <div style="opacity:.85;font-size:13px">OTP (screen mode)</div>
          <div style="font-size:28px;font-weight:800;letter-spacing:2px">${escapeHtml(otp)}</div>
        </div>`
      : "";

  // ctx fields we must carry to /otp/request AND /otp/verify
  const ctxHidden =
    hidden("base_grant_url", ctx.base_grant_url || "") +
    hidden("continue_url", ctx.continue_url || "") +
    hidden("user_continue_url", ctx.user_continue_url || "") +
    hidden("gateway_id", ctx.gateway_id || "") +
    hidden("node_id", ctx.node_id || "") +
    hidden("node_mac", ctx.node_mac || "") +
    hidden("client_ip", ctx.client_ip || "") +
    hidden("client_mac", ctx.client_mac || "");

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WiFi Login</title>
  <style>
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#e6eefc}
    .wrap{max-width:900px;margin:30px auto;padding:0 16px}
    .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:18px;box-shadow:0 10px 40px rgba(0,0,0,.2)}
    h1{margin:0 0 8px;font-size:26px}
    label{display:block;margin:10px 0 6px;opacity:.85}
    input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#fff;font-size:16px}
    button{margin-top:12px;background:#6d57ff;border:0;color:white;padding:12px 14px;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer}
    .muted{opacity:.75;font-size:13px}
  </style></head><body>
  <div class="wrap"><div class="card">
    <h1>WiFi Giriş</h1>
    <div class="muted">${escapeHtml(message || "")}</div>

    <form method="POST" action="/otp/request">
      <input type="hidden" name="marker" value="${escapeHtml(marker || "")}"/>
      ${ctxHidden}
      <label>Ad</label><input name="first_name" placeholder="Ad" />
      <label>Soyad</label><input name="last_name" placeholder="Soyad" />
      <label>Telefon</label><input name="phone" placeholder="05xxxxxxxxx" />
      <label><input type="checkbox" name="kvkk_accepted" value="1" checked /> KVKK metnini okudum, kabul ediyorum</label>
      <div class="muted">KVKK versiyon: ${escapeHtml(ENV.KVKK_VERSION)}</div>
      <button type="submit">OTP Gönder</button>
    </form>

    ${otpBlock}

    <hr style="border:0;border-top:1px solid rgba(255,255,255,.10);margin:18px 0" />

    <form method="POST" action="/otp/verify">
      <label>OTP</label><input name="otp" placeholder="6 haneli kod" />
      <input type="hidden" name="marker" value="${escapeHtml(marker || "")}"/>
      ${ctxHidden}
      <button type="submit">Doğrula ve Bağlan</button>
    </form>

  </div></div>
  </body></html>`;
}

// -------------------- Routes --------------------
async function handle(req, res) {
  const u = url.parse(req.url, true);
  const path = u.pathname || "/";
  const q = u.query || {};

  if (path === "/" || path === "/health") return send(res, 200, "ok");

  // Admin
  if (path.startsWith("/admin")) {
    if (!requireAdmin(req, res)) return;

    if (path === "/admin" || path === "/admin/") {
      res.writeHead(302, { Location: "/admin/logs" });
      return res.end();
    }
    if (path === "/admin/logs") return await renderAdminLogs(req, res, q);
    if (path === "/admin/daily" || path === "/admin/daily/") return await renderAdminDailyIndex(req, res);
    if (path === "/admin/daily/build") {
      const day = (q.day || "").toString().trim();
      const tz = (q.tz || ENV.TZ || "UTC").toString().trim();
      if (!day) return send(res, 400, "missing ?day=YYYY-MM-DD");
      try {
        const out = await buildDaily(day, tz);
        return sendJson(res, 200, out);
      } catch (e) {
        return send(res, 500, "daily build error: " + (e && e.message));
      }
    }
    return send(res, 404, "Not Found");
  }

  // Splash (FIX: parse ctx robustly + cache)
  if (path === "/splash") {
    const return_url = (q.return_url || "").toString();

    const ctxDirect = parseMerakiDirectQuery(q);
    const ctxFromReturn = return_url ? parseMerakiReturnUrl(return_url).ctx : {};
    const ctx = mergeCtx(ctxDirect, ctxFromReturn);

    // derive base_grant_url if still missing but request itself looks like /splash/<id>
    if (!ctx.base_grant_url) {
      try {
        const full = new URL((req.headers["x-forwarded-proto"] || "https") + "://" + req.headers.host + req.url);
        if (full.pathname.includes("/splash/")) {
          const p = full.pathname.replace(/\/$/, "");
          ctx.base_grant_url = full.origin + p + "/grant";
        }
      } catch {}
    }

    // extra fallback: try from referer query (some clients)
    if (!ctx.base_grant_url) {
      const ref = (req.headers["referer"] || "").toString();
      if (ref.includes("base_grant_url=") || ref.includes("client_mac=")) {
        try {
          const rr = new URL(ref);
          const rctx = parseMerakiDirectQuery(Object.fromEntries(rr.searchParams.entries()));
          const rctx2 = rr.searchParams.get("return_url")
            ? parseMerakiReturnUrl(rr.searchParams.get("return_url")).ctx
            : {};
          const merged = mergeCtx(rctx, rctx2);
          Object.assign(ctx, mergeCtx(merged, ctx));
        } catch {}
      }
    }

    const marker = randDigits(6);

    // cache ctx by marker + by mac/ip for fallback
    const cacheObj = { ctx, return_url };
    await kv.setex(`ctx:marker:${marker}`, ENV.OTP_TTL_SECONDS * 2, JSON.stringify(cacheObj));
    if (ctx.client_mac) await kv.setex(`ctx:mac:${ctx.client_mac}`, ENV.OTP_TTL_SECONDS * 6, JSON.stringify(cacheObj));
    if (ctx.client_ip) await kv.setex(`ctx:ip:${ctx.client_ip}`, ENV.OTP_TTL_SECONDS * 6, JSON.stringify(cacheObj));

    const hasBaseGrant = !!ctx.base_grant_url;
    const hasContinue = !!ctx.continue_url;
    const hasClientMac = !!ctx.client_mac;

    console.log("SPLASH_OPEN", { hasBaseGrant, hasContinue, hasClientMac, mode: ENV.OTP_MODE });

    await logAccess("SPLASH_OPEN", {
      marker,
      kvkk_version: ENV.KVKK_VERSION,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || return_url || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: {
        gateway_id: ctx.gateway_id || null,
        node_id: ctx.node_id || null,
        node_mac: ctx.node_mac || null,
        public_ip: ENV.PUBLIC_IP || null,
      },
    });

    const html = splashPage({
      marker,
      message: "Telefonunu yaz, OTP ile doğrula.",
      showOtp: false,
      otp: "",
      ctx,
    });
    return sendHtml(res, 200, html);
  }

  // OTP request
  if (path === "/otp/request" && req.method === "POST") {
    const ct = (req.headers["content-type"] || "").toString();
    const data = ct.includes("application/json") ? await parseJsonBody(req) : await parseForm(req);

    const marker = String(data.marker || "").trim() || randDigits(6);

    const first_name = String(data.first_name || "").trim() || null;
    const last_name = String(data.last_name || "").trim() || null;
    const full_name = [first_name, last_name].filter(Boolean).join(" ") || null;
    const phone = normalizePhone(data.phone || "");
    const kvkk_accepted = !!data.kvkk_accepted;

    // IMPORTANT FIX: read ctx from hidden fields first
    const ctxFromForm = mergeCtx(
      {
        base_grant_url: (data.base_grant_url || "").toString(),
        continue_url: (data.continue_url || "").toString(),
        user_continue_url: (data.user_continue_url || "").toString(),
        gateway_id: (data.gateway_id || "").toString(),
        node_id: (data.node_id || "").toString(),
        node_mac: (data.node_mac || "").toString(),
        client_ip: (data.client_ip || "").toString(),
        client_mac: (data.client_mac || "").toString(),
      },
      {}
    );

    // KV fallback by marker/mac/ip
    let cached = null;
    const rawMarker = await kv.get(`ctx:marker:${marker}`);
    if (rawMarker) {
      try { cached = JSON.parse(rawMarker); } catch {}
    }
    if (!cached && ctxFromForm.client_mac) {
      const rawMac = await kv.get(`ctx:mac:${ctxFromForm.client_mac}`);
      if (rawMac) { try { cached = JSON.parse(rawMac); } catch {} }
    }
    if (!cached && ctxFromForm.client_ip) {
      const rawIp = await kv.get(`ctx:ip:${ctxFromForm.client_ip}`);
      if (rawIp) { try { cached = JSON.parse(rawIp); } catch {} }
    }

    const ctx = mergeCtx(ctxFromForm, (cached && cached.ctx) || {});
    const client_mac = ctx.client_mac || "";
    const client_ip = ctx.client_ip || getClientIp(req) || "";

    // rate limit
    const rl = await isRateLimited(client_mac, phone);
    if (!rl.ok) {
      await logAccess("OTP_RATE_LIMIT", {
        marker, phone, full_name, client_mac, client_ip,
        kvkk_accepted, kvkk_version: ENV.KVKK_VERSION,
        meta: { why: rl.why, ttl: rl.ttl },
      });
      return sendJson(res, 429, { ok: false, error: "rate_limited", why: rl.why });
    }
    await setRate(client_mac, phone);

    const otp = randDigits(6);
    const rec = {
      marker,
      otp,
      phone,
      first_name,
      last_name,
      full_name,
      kvkk_accepted,
      kvkk_version: ENV.KVKK_VERSION,
      wrong: 0,
      created_at: nowISO(),
      client_mac,
      client_ip,
      ctx,
    };
    await kv.setex(keyOtp(marker), ENV.OTP_TTL_SECONDS, JSON.stringify(rec));

    console.log("OTP_CREATED", { marker, last4: phone ? phone.slice(-4) : null, client_mac });
    await logAccess("OTP_CREATED", {
      marker, phone, first_name, last_name, full_name,
      kvkk_accepted, kvkk_version: ENV.KVKK_VERSION,
      client_mac, client_ip,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || (cached && cached.return_url) || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: { mode: ENV.OTP_MODE },
    });

    if (ENV.OTP_MODE === "screen") {
      console.log("OTP_SCREEN_CODE", { marker, otp });
      const html = splashPage({
        marker,
        message: "OTP oluşturuldu. Aşağıdaki kodu girerek bağlan.",
        showOtp: true,
        otp,
        ctx,
      });
      return sendHtml(res, 200, html);
    }

    // sms mode placeholder
    return sendJson(res, 200, { ok: true, marker });
  }

  // OTP verify
  if (path === "/otp/verify" && req.method === "POST") {
    const ct = (req.headers["content-type"] || "").toString();
    const data = ct.includes("application/json") ? await parseJsonBody(req) : await parseForm(req);

    const marker = String(data.marker || "").trim();
    const otp = String(data.otp || "").trim();
    if (!marker || !otp) return sendJson(res, 400, { ok: false, error: "missing_marker_or_otp" });

    if (await isLocked(marker)) {
      await logAccess("OTP_LOCKED", { marker, meta: { reason: "locked" } });
      return sendJson(res, 423, { ok: false, error: "locked" });
    }

    const raw = await kv.get(keyOtp(marker));
    if (!raw) {
      await logAccess("OTP_NOT_FOUND", { marker, meta: { reason: "expired_or_missing" } });
      return sendJson(res, 404, { ok: false, error: "otp_not_found" });
    }

    let rec = null;
    try { rec = JSON.parse(raw); } catch {}
    if (!rec) return sendJson(res, 500, { ok: false, error: "bad_otp_record" });

    if (String(rec.otp) !== otp) {
      rec.wrong = (rec.wrong || 0) + 1;
      await kv.setex(keyOtp(marker), ENV.OTP_TTL_SECONDS, JSON.stringify(rec));
      await logAccess("OTP_WRONG", { marker, phone: rec.phone || null, client_mac: rec.client_mac || null, meta: { wrong: rec.wrong } });

      if (rec.wrong >= ENV.MAX_WRONG_ATTEMPTS) {
        await lockMarker(marker);
        await logAccess("OTP_LOCKED", { marker, meta: { wrong: rec.wrong } });
        return sendJson(res, 423, { ok: false, error: "locked" });
      }
      return sendJson(res, 401, { ok: false, error: "wrong_otp", wrong: rec.wrong });
    }

    console.log("OTP_VERIFY_OK", { marker, client_mac: rec.client_mac || "" });

    // FIX: also read ctx from hidden fields on verify page (in case rec.ctx missing)
    const ctxFromForm = mergeCtx(
      {
        base_grant_url: (data.base_grant_url || "").toString(),
        continue_url: (data.continue_url || "").toString(),
        user_continue_url: (data.user_continue_url || "").toString(),
        gateway_id: (data.gateway_id || "").toString(),
        node_id: (data.node_id || "").toString(),
        node_mac: (data.node_mac || "").toString(),
        client_ip: (data.client_ip || "").toString(),
        client_mac: (data.client_mac || "").toString(),
      },
      {}
    );

    // KV fallback by marker/mac/ip
    let cached = null;
    const rawMarker = await kv.get(`ctx:marker:${marker}`);
    if (rawMarker) { try { cached = JSON.parse(rawMarker); } catch {} }
    if (!cached && (ctxFromForm.client_mac || rec.client_mac)) {
      const mac = ctxFromForm.client_mac || rec.client_mac;
      const rawMac = await kv.get(`ctx:mac:${mac}`);
      if (rawMac) { try { cached = JSON.parse(rawMac); } catch {} }
    }
    if (!cached && (ctxFromForm.client_ip || rec.client_ip)) {
      const ip = ctxFromForm.client_ip || rec.client_ip;
      const rawIp = await kv.get(`ctx:ip:${ip}`);
      if (rawIp) { try { cached = JSON.parse(rawIp); } catch {} }
    }

    const ctx = mergeCtx(ctxFromForm, mergeCtx(rec.ctx || {}, (cached && cached.ctx) || {}));
    // Ensure mac/ip not empty
    if (!ctx.client_mac) ctx.client_mac = rec.client_mac || "";
    if (!ctx.client_ip) ctx.client_ip = rec.client_ip || getClientIp(req) || "";

    await logAccess("OTP_VERIFIED", {
      marker,
      phone: rec.phone || null,
      first_name: rec.first_name || null,
      last_name: rec.last_name || null,
      full_name: rec.full_name || null,
      kvkk_accepted: !!rec.kvkk_accepted,
      kvkk_version: rec.kvkk_version || ENV.KVKK_VERSION,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || (cached && cached.return_url) || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: { mode: ENV.OTP_MODE },
    });

    await kv.del(keyOtp(marker));

    const redirect = buildGrantRedirect(ctx);
    if (redirect) {
      console.log("GRANT_CLIENT_REDIRECT:", redirect);
      await logAccess("GRANT_CLIENT_REDIRECT", {
        marker,
        phone: rec.phone || null,
        full_name: rec.full_name || null,
        client_mac: ctx.client_mac || null,
        client_ip: ctx.client_ip || null,
        base_grant_url: ctx.base_grant_url || null,
        continue_url: ctx.continue_url || null,
        meta: { redirect },
      });
      res.writeHead(302, { Location: redirect });
      return res.end();
    }

    // If still missing, explicitly show debug to user (screen) and log
    await logAccess("GRANT_MISSING_CTX", { marker, meta: { ctx } });
    return sendHtml(res, 200, adminLayout("Grant missing", `
      <h1>GRANT başarısız</h1>
      <div class="muted">base_grant_url hala yok. Bu Meraki tarafında splash parametreleri gelmedi demektir.</div>
      <pre style="white-space:pre-wrap;background:rgba(255,255,255,.08);padding:12px;border-radius:12px;margin-top:12px">${escapeHtml(JSON.stringify(ctx, null, 2))}</pre>
      <div style="margin-top:12px" class="muted">Log: event=GRANT_MISSING_CTX</div>
    `));
  }

  return send(res, 404, "Not Found");
}

// -------------------- Boot --------------------
async function main() {
  await initKV();
  if (pool) {
    try {
      await pool.query("SELECT 1");
      console.log("DATABASE: connected");
    } catch (e) {
      console.log("DATABASE: connect failed:", e && e.message);
    }
    await ensureTables();
  }

  const server = http.createServer(async (req, res) => {
    try {
      await handle(req, res);
    } catch (e) {
      console.error("UNCAUGHT:", e && e.stack ? e.stack : e);
      try { send(res, 500, "internal error"); } catch {}
    }
  });

  server.listen(ENV.PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
}

main().catch((e) => {
  console.error("BOOT FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
