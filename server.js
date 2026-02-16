/**
 * meraki-sms-splash - single-file server.js
 * - No "basic-auth" dependency (manual basic auth)
 * - No "ioredis" dependency (in-memory rate limit + OTP store)
 * - Uses only: built-in node modules + "pg"
 *
 * ENV:
 *   PORT=8080
 *   DATABASE_URL=postgres://...
 *   TZ=Europe/Istanbul
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   OTP_MODE=screen|sms  (screen shows otp on page)
 *   OTP_TTL_SECONDS=180
 *   RL_MAC_SECONDS=30
 *   RL_PHONE_SECONDS=60
 *   MAX_WRONG_ATTEMPTS=5
 *   LOCK_SECONDS=600
 *   KVKK_VERSION=2026-02-12-placeholder
 *   DAILY_HMAC_SECRET=... (required for daily signing)
 */

"use strict";

const http = require("http");
const { URL } = require("url");
const crypto = require("crypto");
const querystring = require("querystring");
const { Pool } = require("pg");

// ------------------ ENV ------------------
const PORT = parseInt(process.env.PORT || "8080", 10);
const TZ = process.env.TZ || "Europe/Istanbul";
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen|sms
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);
const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ""; // required for 5651 daily signing

const DB_SET = !!process.env.DATABASE_URL;

console.log("ENV:", {
  OTP_MODE,
  OTP_TTL_SECONDS,
  RL_MAC_SECONDS,
  RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS,
  KVKK_VERSION,
  TZ,
  DB_SET,
  ADMIN_USER_SET: !!ADMIN_USER,
  ADMIN_PASS_SET: !!ADMIN_PASS,
  DAILY_HMAC_SET: !!DAILY_HMAC_SECRET,
});

// ------------------ DB ------------------
const pool = DB_SET ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 }) : null;

async function qRows(text, params) {
  const r = await pool.query(text, params);
  return r.rows;
}

let accessLogsCols = null; // Set of column names
let dailyHashesCols = null;
let dailyPackagesCols = null;

async function loadTableColumns(tableName) {
  const rows = await qRows(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = $1
    `,
    [tableName]
  );
  return new Set(rows.map((r) => r.column_name));
}

async function ensureTables() {
  // access_logs: we won't enforce schema; you already have it.
  // We WILL create daily_* tables if missing (safe).
  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day date NOT NULL,
      tz text NOT NULL,
      record_count int NOT NULL,
      day_hash text NOT NULL,
      prev_day_hash text,
      chain_hash text NOT NULL,
      algo text NOT NULL DEFAULT 'sha256',
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day, tz)
    );
    `,
    []
  );

  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_packages (
      day date NOT NULL,
      tz text NOT NULL,
      package_json jsonb NOT NULL,
      hmac text NOT NULL,
      algo text NOT NULL DEFAULT 'hmac-sha256',
      signed_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day, tz)
    );
    `,
    []
  );

  // Optional: daily_chains for history (not required, but you had it)
  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_chains (
      day date NOT NULL,
      tz text NOT NULL,
      chain_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day, tz)
    );
    `,
    []
  );
}

async function initDb() {
  if (!pool) return;
  try {
    await pool.query("SELECT 1");
    console.log("DATABASE: connected");
    await ensureTables();
    console.log("DATABASE: table ready");
    accessLogsCols = await loadTableColumns("access_logs");
    dailyHashesCols = await loadTableColumns("daily_hashes");
    dailyPackagesCols = await loadTableColumns("daily_packages");
  } catch (e) {
    console.error("DATABASE INIT ERROR:", e);
    throw e;
  }
}

// Build dynamic insert for access_logs
function buildAccessLogInsert(payload) {
  // payload keys should match intended columns.
  // We'll only include columns that exist in access_logs.
  const cols = [];
  const vals = [];
  const params = [];

  for (const [k, v] of Object.entries(payload)) {
    if (accessLogsCols && accessLogsCols.has(k)) {
      cols.push(k);
      vals.push(`$${vals.length + 1}`);
      params.push(v);
    }
  }

  // If no columns match, skip
  if (!cols.length) return null;

  // jsonb handling if meta exists
  // If meta exists and is object, we pass JSON string; pg will cast if column is jsonb
  return {
    sql: `INSERT INTO access_logs(${cols.join(", ")}) VALUES(${vals.join(", ")})`,
    params,
  };
}

async function logAccess(event, ctx) {
  if (!pool || !accessLogsCols) return;

  // prefer storing extra fields in meta json if meta column exists
  const metaObj = {
    user_agent: ctx.user_agent || null,
    accept_language: ctx.accept_language || null,
    referrer: ctx.referrer || null,
    rawQuery: ctx.rawQuery || null,
    public_ip: ctx.public_ip || null,
    mode: ctx.mode || null,
  };

  const payload = {
    event,
    created_at: ctx.created_at || new Date().toISOString(),
    first_name: ctx.first_name || null,
    last_name: ctx.last_name || null,
    phone: ctx.phone || null,
    client_mac: ctx.client_mac || null,
    client_ip: ctx.client_ip || null,
    ssid: ctx.ssid || null,
    ap_name: ctx.ap_name || null,
    base_grant_url: ctx.base_grant_url || null,
    continue_url: ctx.continue_url || null,
    marker: ctx.marker || null,
    kvkk_accepted: typeof ctx.kvkk_accepted === "boolean" ? ctx.kvkk_accepted : null,
    kvkk_version: ctx.kvkk_version || KVKK_VERSION,
    // If you have these columns they will be used, else dropped automatically:
    gateway_id: ctx.gateway_id || null,
    node_id: ctx.node_id || null,
    node_mac: ctx.node_mac || null,
    user_continue_url: ctx.user_continue_url || null,
    full_name: ctx.full_name || null,
    meta: accessLogsCols.has("meta") ? JSON.stringify(metaObj) : undefined,
  };

  const ins = buildAccessLogInsert(payload);
  if (!ins) return;

  try {
    await qRows(ins.sql, ins.params);
  } catch (e) {
    // Don't crash app for logging schema drift
    console.error("DB LOG ERROR:", e.message);
  }
}

// ------------------ In-memory stores (OTP + rate limit) ------------------
const otpStore = new Map(); // marker -> { otp, exp, phone, first_name, last_name, mac, ip, lockUntil, wrongCount }
const rateStore = new Map(); // key -> { count, resetAt }

function nowMs() {
  return Date.now();
}

function genMarker() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function rateHit(key, windowSeconds, limit) {
  const t = nowMs();
  const row = rateStore.get(key);
  if (!row || t >= row.resetAt) {
    rateStore.set(key, { count: 1, resetAt: t + windowSeconds * 1000 });
    return { ok: true, remaining: limit - 1 };
  }
  row.count += 1;
  if (row.count > limit) return { ok: false, remaining: 0 };
  return { ok: true, remaining: limit - row.count };
}

function safeStr(x, max = 500) {
  if (x === undefined || x === null) return "";
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function parseCookies(req) {
  const h = req.headers["cookie"] || "";
  const out = {};
  h.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i > -1) {
      const k = part.slice(0, i).trim();
      const v = decodeURIComponent(part.slice(i + 1).trim());
      out[k] = v;
    }
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  let c = `${name}=${encodeURIComponent(value)}`;
  if (opts.httpOnly) c += "; HttpOnly";
  if (opts.sameSite) c += `; SameSite=${opts.sameSite}`;
  if (opts.path) c += `; Path=${opts.path}`;
  if (opts.maxAge) c += `; Max-Age=${opts.maxAge}`;
  res.setHeader("Set-Cookie", c);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

// ------------------ Basic Auth (no dependency) ------------------
function unauthorized(res) {
  res.statusCode = 401;
  res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
  res.end("Unauthorized");
}

function requireAdmin(req, res) {
  if (!ADMIN_USER || !ADMIN_PASS) return unauthorized(res);
  const h = req.headers["authorization"] || "";
  if (!h.startsWith("Basic ")) return unauthorized(res);

  const b64 = h.slice(6).trim();
  let userpass = "";
  try {
    userpass = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return unauthorized(res);
  }
  const idx = userpass.indexOf(":");
  if (idx < 0) return unauthorized(res);
  const user = userpass.slice(0, idx);
  const pass = userpass.slice(idx + 1);
  if (user !== ADMIN_USER || pass !== ADMIN_PASS) return unauthorized(res);
  return true;
}

// ------------------ HTML helpers ------------------
function htmlEscape(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function layout(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${htmlEscape(title)}</title>
<style>
  :root { color-scheme: dark; }
  body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1020;color:#e7eaf0}
  .wrap{max-width:980px;margin:0 auto;padding:24px}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:18px;backdrop-filter: blur(10px)}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  input,button{border-radius:10px;border:1px solid rgba(255,255,255,.12);padding:10px 12px;background:rgba(0,0,0,.25);color:#e7eaf0}
  button{cursor:pointer;background:#5865f2;border-color:#5865f2}
  a{color:#9db2ff}
  table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left;vertical-align:top}
  th{font-weight:600;color:#cdd3ff}
  .muted{opacity:.75;font-size:12px}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(88,101,242,.18);border:1px solid rgba(88,101,242,.35);font-size:12px}
  .otp{font-size:28px;letter-spacing:3px;font-weight:800}
</style>
</head>
<body>
<div class="wrap">
  ${body}
</div>
</body>
</html>`;
}

function splashPage(ctx) {
  const hasContinue = !!ctx.continue_url;
  const hasClientMac = !!ctx.client_mac;
  const hasBaseGrant = !!ctx.base_grant_url;

  console.log("SPLASH_OPEN", { hasBaseGrant, hasContinue, hasClientMac, mode: OTP_MODE });

  const info = `
    <div class="muted">
      KVKK version: <span class="pill">${htmlEscape(KVKK_VERSION)}</span> ·
      TZ: <span class="pill">${htmlEscape(TZ)}</span>
    </div>
    <div class="muted" style="margin-top:8px">
      client_mac: <b>${htmlEscape(ctx.client_mac || "-")}</b> · client_ip: <b>${htmlEscape(ctx.client_ip || "-")}</b>
    </div>
  `;

  const otpBlock = (ctx.otp && OTP_MODE === "screen")
    ? `<div style="margin-top:14px" class="card">
         <div class="muted">OTP (ekranda gösterim modu)</div>
         <div class="otp">${htmlEscape(ctx.otp)}</div>
       </div>`
    : "";

  return layout("Meraki SMS Splash", `
    <div class="card">
      <h2 style="margin:0 0 10px 0">İnternet Erişimi</h2>
      ${info}
      <form method="POST" action="/otp/request" style="margin-top:14px">
        <div class="row">
          <input name="first_name" placeholder="Ad" required value="${htmlEscape(ctx.first_name || "")}"/>
          <input name="last_name" placeholder="Soyad" required value="${htmlEscape(ctx.last_name || "")}"/>
          <input name="phone" placeholder="Telefon (05xx...)" required value="${htmlEscape(ctx.phone || "")}"/>
        </div>
        <div style="margin-top:10px" class="row">
          <label class="muted"><input type="checkbox" name="kvkk" value="1" required/> KVKK metnini okudum, kabul ediyorum.</label>
        </div>
        <div style="margin-top:12px" class="row">
          <button type="submit">OTP Talep Et</button>
          <span class="muted">OTP TTL: ${OTP_TTL_SECONDS}s</span>
        </div>
      </form>

      ${otpBlock}

      <form method="POST" action="/otp/verify" style="margin-top:14px">
        <div class="row">
          <input name="otp" placeholder="OTP" inputmode="numeric" required/>
          <button type="submit">Bağlan</button>
        </div>
      </form>

      <div class="muted" style="margin-top:10px">
        Not: Bu servis logları 5651 uyumu için günlük hash+chain+HMAC ile paketleyebilir.
      </div>
    </div>
  `);
}

function adminLogsPage(rows, params) {
  const { limit, tz } = params;
  return layout("/admin/logs", `
    <div class="card">
      <h2 style="margin:0 0 10px 0">/admin/logs</h2>
      <div class="muted">limit=${htmlEscape(limit)} · tz=${htmlEscape(tz)} · <a href="/admin/logs?format=json&limit=${encodeURIComponent(limit)}&tz=${encodeURIComponent(tz)}">JSON</a></div>
      <div class="row" style="margin-top:10px">
        <form method="GET" action="/admin/logs" class="row">
          <input name="limit" value="${htmlEscape(limit)}" style="width:120px"/>
          <input name="tz" value="${htmlEscape(tz)}" style="width:220px"/>
          <button type="submit">Refresh</button>
        </form>
        <a href="/admin/daily/build?day=${new Date().toISOString().slice(0,10)}" class="pill">Daily</a>
      </div>

      <table>
        <thead>
          <tr>
            <th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>marker</th><th>kvkk</th>
          </tr>
        </thead>
        <tbody>
        ${rows
          .map((r) => {
            const nm = [r.first_name, r.last_name].filter(Boolean).join(" ");
            const dt = r.created_at ? new Date(r.created_at).toLocaleString("tr-TR", { timeZone: tz }) : "-";
            return `<tr>
              <td>${htmlEscape(r.id ?? "")}</td>
              <td>${htmlEscape(dt)}</td>
              <td>${htmlEscape(r.event ?? "")}</td>
              <td>${htmlEscape(nm)}</td>
              <td>${htmlEscape(r.phone ?? "")}</td>
              <td>${htmlEscape(r.client_mac ?? "")}</td>
              <td>${htmlEscape(r.client_ip ?? "")}</td>
              <td>${htmlEscape(r.marker ?? "")}</td>
              <td>${htmlEscape(r.kvkk_version ?? "")}</td>
            </tr>`;
          })
          .join("")}
        </tbody>
      </table>
    </div>
  `);
}

// ------------------ Meraki Grant ------------------
function buildGrantUrl(ctx) {
  // Meraki expects GET to /grant with required params.
  // We will redirect user to base_grant_url + forwarded original params.
  // base_grant_url sample: https://eu.network-auth.com/splash/.../grant
  const base = ctx.base_grant_url;
  if (!base) return null;

  const u = new URL(base);

  // Forward common required params if present
  const forwardKeys = ["gateway_id", "node_id", "client_ip", "client_mac", "node_mac", "continue_url"];
  for (const k of forwardKeys) {
    if (ctx[k]) u.searchParams.set(k, ctx[k]);
  }
  return u.toString();
}

// ------------------ Daily 5651 (hash + chain + HMAC) ------------------
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}
function hmacSha256Hex(secret, s) {
  return crypto.createHmac("sha256", secret).update(s).digest("hex");
}

async function buildDaily(dayStr, tz) {
  if (!DAILY_HMAC_SECRET) {
    return { error: "DAILY_HMAC_SECRET missing" };
  }
  // Validate day
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dayStr)) {
    return { error: "invalid day format, use YYYY-MM-DD" };
  }

  // Pull logs for that day in tz
  // created_at is timestamptz (per your screenshot)
  // Filter: (created_at AT TIME ZONE tz)::date = day::date
  const logs = await qRows(
    `
    SELECT *
    FROM access_logs
    WHERE ((created_at AT TIME ZONE $1)::date = $2::date)
    ORDER BY created_at ASC, id ASC
    `,
    [tz, dayStr]
  );

  // Canonical JSON lines (stable order)
  const canonical = logs.map((r) => {
    // Keep minimal but useful 5651-ish fields (expand if you want)
    const obj = {
      id: r.id ?? null,
      created_at: r.created_at ?? null,
      event: r.event ?? null,
      phone: r.phone ?? null,
      first_name: r.first_name ?? null,
      last_name: r.last_name ?? null,
      client_mac: r.client_mac ?? null,
      client_ip: r.client_ip ?? null,
      marker: r.marker ?? null,
      kvkk_version: r.kvkk_version ?? null,
    };
    return JSON.stringify(obj);
  });

  const dayPayload = canonical.join("\n");
  const dayHash = sha256Hex(dayPayload);

  const prev = await qRows(
    `
    SELECT day_hash, chain_hash
    FROM daily_hashes
    WHERE tz = $1 AND day < $2::date
    ORDER BY day DESC
    LIMIT 1
    `,
    [tz, dayStr]
  );

  const prevDayHash = prev[0]?.day_hash || null;
  const prevChainHash = prev[0]?.chain_hash || null;

  // Chain ties days together
  const chainInput = JSON.stringify({
    day: dayStr,
    tz,
    day_hash: dayHash,
    prev_chain_hash: prevChainHash,
  });
  const chainHash = sha256Hex(chainInput);

  // Package signed with HMAC (placeholder for real e-imza / KEP / TSA)
  const packageObj = {
    day: dayStr,
    tz,
    record_count: logs.length,
    day_hash: dayHash,
    prev_day_hash: prevDayHash,
    chain_hash: chainHash,
    algo: "sha256",
    generated_at: new Date().toISOString(),
  };
  const packageJson = JSON.stringify(packageObj);
  const hmac = hmacSha256Hex(DAILY_HMAC_SECRET, packageJson);

  // Upsert daily_hashes + daily_packages + daily_chains
  await qRows(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash, prev_day_hash, chain_hash)
    VALUES($1::date, $2, $3, $4, $5, $6)
    ON CONFLICT (day, tz) DO UPDATE SET
      record_count=EXCLUDED.record_count,
      day_hash=EXCLUDED.day_hash,
      prev_day_hash=EXCLUDED.prev_day_hash,
      chain_hash=EXCLUDED.chain_hash,
      created_at=now()
    `,
    [dayStr, tz, logs.length, dayHash, prevDayHash, chainHash]
  );

  await qRows(
    `
    INSERT INTO daily_packages(day, tz, package_json, hmac)
    VALUES($1::date, $2, $3::jsonb, $4)
    ON CONFLICT (day, tz) DO UPDATE SET
      package_json=EXCLUDED.package_json,
      hmac=EXCLUDED.hmac,
      signed_at=now()
    `,
    [dayStr, tz, packageJson, hmac]
  );

  await qRows(
    `
    INSERT INTO daily_chains(day, tz, chain_hash)
    VALUES($1::date, $2, $3)
    ON CONFLICT (day, tz) DO UPDATE SET chain_hash=EXCLUDED.chain_hash, created_at=now()
    `,
    [dayStr, tz, chainHash]
  );

  return {
    day: dayStr,
    tz,
    record_count: logs.length,
    day_hash: dayHash,
    prev_day_hash: prevDayHash,
    chain_hash: chainHash,
    hmac,
  };
}

async function verifyDaily(dayStr, tz) {
  if (!DAILY_HMAC_SECRET) return { error: "DAILY_HMAC_SECRET missing" };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dayStr)) return { error: "invalid day format, use YYYY-MM-DD" };

  const storedHash = await qRows(
    `SELECT * FROM daily_hashes WHERE day=$1::date AND tz=$2 LIMIT 1`,
    [dayStr, tz]
  );
  const storedPkg = await qRows(
    `SELECT * FROM daily_packages WHERE day=$1::date AND tz=$2 LIMIT 1`,
    [dayStr, tz]
  );

  if (!storedHash[0] || !storedPkg[0]) {
    return { ok: false, error: "no stored daily_hashes/daily_packages for that day" };
  }

  // Recompute day_hash from access_logs
  const logs = await qRows(
    `
    SELECT *
    FROM access_logs
    WHERE ((created_at AT TIME ZONE $1)::date = $2::date)
    ORDER BY created_at ASC, id ASC
    `,
    [tz, dayStr]
  );

  const canonical = logs.map((r) => {
    const obj = {
      id: r.id ?? null,
      created_at: r.created_at ?? null,
      event: r.event ?? null,
      phone: r.phone ?? null,
      first_name: r.first_name ?? null,
      last_name: r.last_name ?? null,
      client_mac: r.client_mac ?? null,
      client_ip: r.client_ip ?? null,
      marker: r.marker ?? null,
      kvkk_version: r.kvkk_version ?? null,
    };
    return JSON.stringify(obj);
  });

  const dayPayload = canonical.join("\n");
  const recomputedDayHash = sha256Hex(dayPayload);

  // Validate package HMAC
  const pkgJson = storedPkg[0].package_json; // pg returns object
  const pkgStr = JSON.stringify(pkgJson);
  const recomputedHmac = hmacSha256Hex(DAILY_HMAC_SECRET, pkgStr);

  const okDayHash = recomputedDayHash === storedHash[0].day_hash;
  const okHmac = recomputedHmac === storedPkg[0].hmac;

  return {
    ok: okDayHash && okHmac,
    day: dayStr,
    tz,
    record_count: logs.length,
    stored_day_hash: storedHash[0].day_hash,
    recomputed_day_hash: recomputedDayHash,
    day_hash_match: okDayHash,
    stored_hmac: storedPkg[0].hmac,
    recomputed_hmac: recomputedHmac,
    hmac_match: okHmac,
  };
}

// ------------------ Routing ------------------
async function handle(req, res) {
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const path = urlObj.pathname;
    const method = req.method || "GET";

    // Health
    if (path === "/healthz") {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // Admin routes
    if (path.startsWith("/admin")) {
      if (!requireAdmin(req, res)) return;

      // /admin/logs
      if (path === "/admin/logs" && method === "GET") {
        const limit = Math.max(1, Math.min(1000, parseInt(urlObj.searchParams.get("limit") || "200", 10)));
        const tz = urlObj.searchParams.get("tz") || TZ;
        const format = (urlObj.searchParams.get("format") || "html").toLowerCase();

        const rows = pool
          ? await qRows(
              `
              SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
              FROM access_logs
              ORDER BY created_at DESC, id DESC
              LIMIT $1
              `,
              [limit]
            )
          : [];

        if (format === "json") {
          res.statusCode = 200;
          res.setHeader("content-type", "application/json; charset=utf-8");
          res.end(JSON.stringify(rows));
          return;
        }

        res.statusCode = 200;
        res.setHeader("content-type", "text/html; charset=utf-8");
        res.end(adminLogsPage(rows, { limit, tz }));
        return;
      }

      // /admin/daily/build?day=YYYY-MM-DD
      if (path === "/admin/daily/build" && method === "GET") {
        const day = urlObj.searchParams.get("day") || new Date().toISOString().slice(0, 10);
        const tz = urlObj.searchParams.get("tz") || TZ;

        try {
          const out = await buildDaily(day, tz);
          res.statusCode = out.error ? 400 : 200;
          res.setHeader("content-type", "application/json; charset=utf-8");
          res.end(JSON.stringify(out, null, 2));
        } catch (e) {
          console.error("daily build error", e);
          res.statusCode = 500;
          res.setHeader("content-type", "text/plain; charset=utf-8");
          res.end("daily build error: " + e.message);
        }
        return;
      }

      // /admin/daily/verify?day=YYYY-MM-DD
      if (path === "/admin/daily/verify" && method === "GET") {
        const day = urlObj.searchParams.get("day") || new Date().toISOString().slice(0, 10);
        const tz = urlObj.searchParams.get("tz") || TZ;

        try {
          const out = await verifyDaily(day, tz);
          res.statusCode = out.error ? 400 : 200;
          res.setHeader("content-type", "application/json; charset=utf-8");
          res.end(JSON.stringify(out, null, 2));
        } catch (e) {
          console.error("daily verify error", e);
          res.statusCode = 500;
          res.setHeader("content-type", "text/plain; charset=utf-8");
          res.end("daily verify error: " + e.message);
        }
        return;
      }

      res.statusCode = 404;
      res.end("Not found");
      return;
    }

    // Splash entry (Meraki lands here)
    if ((path === "/" || path === "/splash") && method === "GET") {
      const cookies = parseCookies(req);
      const marker = cookies.marker || genMarker();

      const ctx = {
        marker,
        // Meraki query params (may come as base_grant_url / continue_url / client_mac / client_ip / etc.)
        base_grant_url:
          urlObj.searchParams.get("base_grant_url") ||
          urlObj.searchParams.get("base_grant") ||
          urlObj.searchParams.get("base_grant_url[]") ||
          "",
        continue_url: urlObj.searchParams.get("continue_url") || "",
        client_mac: urlObj.searchParams.get("client_mac") || "",
        client_ip: urlObj.searchParams.get("client_ip") || "",
        gateway_id: urlObj.searchParams.get("gateway_id") || "",
        node_id: urlObj.searchParams.get("node_id") || "",
        node_mac: urlObj.searchParams.get("node_mac") || "",
        ssid: urlObj.searchParams.get("ssid") || "",
        ap_name: urlObj.searchParams.get("ap_name") || "",
        user_continue_url: urlObj.searchParams.get("user_continue_url") || "",
        user_agent: safeStr(req.headers["user-agent"], 300),
        accept_language: safeStr(req.headers["accept-language"], 120),
        referrer: safeStr(req.headers["referer"], 300),
        rawQuery: safeStr(urlObj.search, 600),
        public_ip: safeStr(req.headers["x-forwarded-for"] || "", 100).split(",")[0].trim(),
        mode: OTP_MODE,
      };

      setCookie(res, "marker", marker, { path: "/", httpOnly: true, sameSite: "Lax", maxAge: 7 * 24 * 3600 });

      await logAccess("SPLASH_OPEN", ctx);

      // If OTP already created and mode=screen, show it
      const existing = otpStore.get(marker);
      if (existing && existing.exp > nowMs() && OTP_MODE === "screen") {
        ctx.otp = existing.otp;
      }

      res.statusCode = 200;
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(splashPage(ctx));
      return;
    }

    // POST /otp/request
    if (path === "/otp/request" && method === "POST") {
      const cookies = parseCookies(req);
      const marker = cookies.marker || genMarker();

      const body = await readBody(req);
      const form = querystring.parse(body);

      const first_name = safeStr(form.first_name, 60).trim();
      const last_name = safeStr(form.last_name, 60).trim();
      const phone = safeStr(form.phone, 30).trim();
      const kvkkAccepted = form.kvkk === "1";

      // Context from query cookie is limited; store minimal
      const sess = otpStore.get(marker) || {};
      const client_mac = sess.client_mac || "";
      const macKey = `mac:${client_mac || "unknown"}`;
      const phoneKey = `phone:${phone || "unknown"}`;

      // Rate limits
      const rlMac = rateHit(macKey, RL_MAC_SECONDS, 5);
      const rlPhone = rateHit(phoneKey, RL_PHONE_SECONDS, 5);
      if (!rlMac.ok || !rlPhone.ok) {
        res.statusCode = 429;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("Rate limit exceeded. Please try again later.");
        return;
      }

      const otp = genOtp();
      const exp = nowMs() + OTP_TTL_SECONDS * 1000;

      otpStore.set(marker, {
        ...sess,
        otp,
        exp,
        phone,
        first_name,
        last_name,
        wrongCount: 0,
        lockUntil: 0,
      });

      console.log("OTP_CREATED", { marker, last4: phone.slice(-4), client_mac: sess.client_mac || "" });

      // Log
      await logAccess("OTP_CREATED", {
        marker,
        phone,
        first_name,
        last_name,
        client_mac: sess.client_mac || null,
        client_ip: sess.client_ip || null,
        base_grant_url: sess.base_grant_url || null,
        continue_url: sess.continue_url || null,
        kvkk_accepted: kvkkAccepted,
        kvkk_version: KVKK_VERSION,
        user_agent: safeStr(req.headers["user-agent"], 300),
        accept_language: safeStr(req.headers["accept-language"], 120),
        referrer: safeStr(req.headers["referer"], 300),
        rawQuery: "",
        public_ip: safeStr(req.headers["x-forwarded-for"] || "", 100).split(",")[0].trim(),
        mode: OTP_MODE,
      });

      if (OTP_MODE === "screen") {
        console.log("OTP_SCREEN_CODE", { marker, otp });
      } else {
        // SMS mode placeholder — you can wire your smsService here if needed
        console.log("OTP_SMS_MODE: send via SMS provider (not implemented in single-file)");
      }

      // Redirect back to splash showing OTP if screen mode
      res.statusCode = 302;
      res.setHeader("location", "/");
      res.end();
      return;
    }

    // POST /otp/verify
    if (path === "/otp/verify" && method === "POST") {
      const cookies = parseCookies(req);
      const marker = cookies.marker || "";

      const sess = otpStore.get(marker);
      if (!sess) {
        res.statusCode = 400;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("Session not found. Please request OTP again.");
        return;
      }

      if (sess.lockUntil && nowMs() < sess.lockUntil) {
        res.statusCode = 403;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("Locked due to too many wrong attempts. Try later.");
        return;
      }

      if (sess.exp < nowMs()) {
        res.statusCode = 400;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("OTP expired. Please request again.");
        return;
      }

      const body = await readBody(req);
      const form = querystring.parse(body);
      const otp = safeStr(form.otp, 10).trim();

      if (otp !== sess.otp) {
        sess.wrongCount = (sess.wrongCount || 0) + 1;
        if (sess.wrongCount >= MAX_WRONG_ATTEMPTS) {
          sess.lockUntil = nowMs() + LOCK_SECONDS * 1000;
        }
        otpStore.set(marker, sess);

        res.statusCode = 401;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("Wrong OTP.");
        return;
      }

      console.log("OTP_VERIFY_OK", { marker, client_mac: sess.client_mac || "" });

      await logAccess("OTP_VERIFIED", {
        marker,
        phone: sess.phone,
        first_name: sess.first_name,
        last_name: sess.last_name,
        full_name: [sess.first_name, sess.last_name].filter(Boolean).join(" "),
        client_mac: sess.client_mac || null,
        client_ip: sess.client_ip || null,
        base_grant_url: sess.base_grant_url || null,
        continue_url: sess.continue_url || null,
        kvkk_accepted: true,
        kvkk_version: KVKK_VERSION,
        user_agent: safeStr(req.headers["user-agent"], 300),
        accept_language: safeStr(req.headers["accept-language"], 120),
        referrer: safeStr(req.headers["referer"], 300),
        rawQuery: "",
        public_ip: safeStr(req.headers["x-forwarded-for"] || "", 100).split(",")[0].trim(),
        mode: OTP_MODE,
      });

      // Build grant redirect URL
      const ctx = {
        base_grant_url: sess.base_grant_url,
        continue_url: sess.continue_url,
        client_mac: sess.client_mac,
        client_ip: sess.client_ip,
        gateway_id: sess.gateway_id,
        node_id: sess.node_id,
        node_mac: sess.node_mac,
      };
      const grantUrl = buildGrantUrl(ctx);

      if (!grantUrl) {
        res.statusCode = 200;
        res.setHeader("content-type", "text/plain; charset=utf-8");
        res.end("OTP verified but base_grant_url missing.");
        return;
      }

      console.log("GRANT_CLIENT_REDIRECT:", grantUrl);
      await logAccess("GRANT_CLIENT_REDIRECT", {
        marker,
        phone: sess.phone,
        first_name: sess.first_name,
        last_name: sess.last_name,
        client_mac: sess.client_mac || null,
        client_ip: sess.client_ip || null,
        base_grant_url: sess.base_grant_url || null,
        continue_url: sess.continue_url || null,
        kvkk_version: KVKK_VERSION,
        user_agent: safeStr(req.headers["user-agent"], 300),
        accept_language: safeStr(req.headers["accept-language"], 120),
        referrer: safeStr(req.headers["referer"], 300),
        rawQuery: "",
        public_ip: safeStr(req.headers["x-forwarded-for"] || "", 100).split(",")[0].trim(),
        mode: OTP_MODE,
      });

      res.statusCode = 302;
      res.setHeader("location", grantUrl);
      res.end();
      return;
    }

    // On every request, capture base_grant_url etc into session (so POSTs have them)
    // (This runs as fallback if not matched earlier)
    if (method === "GET") {
      const cookies = parseCookies(req);
      const marker = cookies.marker || "";
      if (marker) {
        const sess = otpStore.get(marker) || {};
        // Try pick meraki params from current URL too (helps when Meraki calls with /?.... each time)
        const base_grant_url =
          urlObj.searchParams.get("base_grant_url") ||
          urlObj.searchParams.get("base_grant") ||
          sess.base_grant_url ||
          "";
        const continue_url = urlObj.searchParams.get("continue_url") || sess.continue_url || "";
        const client_mac = urlObj.searchParams.get("client_mac") || sess.client_mac || "";
        const client_ip = urlObj.searchParams.get("client_ip") || sess.client_ip || "";
        const gateway_id = urlObj.searchParams.get("gateway_id") || sess.gateway_id || "";
        const node_id = urlObj.searchParams.get("node_id") || sess.node_id || "";
        const node_mac = urlObj.searchParams.get("node_mac") || sess.node_mac || "";

        otpStore.set(marker, {
          ...sess,
          base_grant_url,
          continue_url,
          client_mac,
          client_ip,
          gateway_id,
          node_id,
          node_mac,
        });
      }
    }

    // Default 404
    res.statusCode = 404;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Not found");
  } catch (e) {
    console.error("Unhandled error:", e);
    res.statusCode = 500;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Internal error: " + e.message);
  }
}

// ------------------ Start ------------------
(async () => {
  if (pool) await initDb();

  const server = http.createServer(handle);
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
