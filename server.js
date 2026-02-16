/**
 * meraki-sms-splash - single-file server.js
 * - No express, no basic-auth dependency.
 * - Optional ioredis. If missing, falls back to in-memory store.
 * - Postgres schema drift tolerant: inserts only existing columns.
 * - Admin UI: /admin/logs (HTML) + /admin/logs?format=json
 * - Daily chain/hmac: /admin/daily/build?day=YYYY-MM-DD + /admin/daily/verify?day=YYYY-MM-DD
 *
 * Env:
 *  - PORT (default 8080)
 *  - TZ (default Europe/Istanbul)
 *  - DATABASE_URL (required)
 *  - REDIS_URL (optional)
 *  - OTP_MODE (screen|sms) default screen
 *  - OTP_TTL_SECONDS (default 180)
 *  - MAX_WRONG_ATTEMPTS (default 5)
 *  - LOCK_SECONDS (default 600)
 *  - RL_MAC_SECONDS (default 30)
 *  - RL_PHONE_SECONDS (default 60)
 *  - ADMIN_USER, ADMIN_PASS (required for /admin/*)
 *  - DAILY_HMAC_SECRET (required for daily signing endpoints)
 *
 * Meraki query params:
 *  - base_grant_url, continue_url, user_continue_url, client_mac, client_ip, node_mac, gateway_id, node_id, etc.
 */

"use strict";

const http = require("http");
const { URL } = require("url");
const crypto = require("crypto");
const os = require("os");

let Pool;
try {
  ({ Pool } = require("pg"));
} catch (e) {
  console.error("FATAL: 'pg' module missing. Install with: npm i pg");
  process.exit(1);
}

// Optional redis
let RedisCtor = null;
try {
  RedisCtor = require("ioredis");
} catch (_) {
  RedisCtor = null;
}

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || "8080", 10);
const TZ = process.env.TZ || "Europe/Istanbul";

const DATABASE_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || "";

const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen|sms
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ""; // required for /admin/daily/*

const ENV_SUMMARY = {
  OTP_MODE,
  OTP_TTL_SECONDS,
  RL_MAC_SECONDS,
  RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS,
  KVKK_VERSION: process.env.KVKK_VERSION || null,
  TZ,
  DB_SET: !!DATABASE_URL,
  REDIS_SET: !!REDIS_URL,
  ADMIN_USER_SET: !!ADMIN_USER,
  ADMIN_PASS_SET: !!ADMIN_PASS,
  DAILY_HMAC_SET: !!DAILY_HMAC_SECRET,
};

console.log("ENV:", ENV_SUMMARY);

// -------------------- UTIL --------------------
function nowMs() {
  return Date.now();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function safeJson(obj) {
  return JSON.stringify(obj, (k, v) => (v === undefined ? null : v));
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hmacSha256Hex(secret, input) {
  return crypto.createHmac("sha256", secret).update(input).digest("hex");
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function formatIstanbul(ts) {
  // returns "DD.MM.YYYY HH:mm:ss"
  const dt = new Date(ts);
  // Use Intl in requested TZ
  const parts = new Intl.DateTimeFormat("tr-TR", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(dt);
  const get = (type) => parts.find((p) => p.type === type)?.value || "";
  return `${get("day")}.${get("month")}.${get("year")} ${get("hour")}:${get("minute")}:${get("second")}`;
}

function parseBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 2 * 1024 * 1024) {
        // 2MB limit
        data = data.slice(0, 2 * 1024 * 1024);
      }
    });
    req.on("end", () => resolve(data));
  });
}

function send(res, status, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    "content-type": headers["content-type"] || "text/plain; charset=utf-8",
    "content-length": buf.length,
    ...headers,
  });
  res.end(buf);
}

function sendJson(res, status, obj, headers = {}) {
  send(res, status, safeJson(obj), {
    "content-type": "application/json; charset=utf-8",
    ...headers,
  });
}

function redirect(res, url, status = 302) {
  res.writeHead(status, { Location: url });
  res.end();
}

function getClientIp(req) {
  // Prefer X-Forwarded-For (Railway/Proxy), else socket
  const xff = (req.headers["x-forwarded-for"] || "").toString();
  if (xff) {
    return xff.split(",")[0].trim() || "";
  }
  const ra = req.socket?.remoteAddress || "";
  return ra;
}

function basicAuthOk(req) {
  // If admin creds not set, deny (safer)
  if (!ADMIN_USER || !ADMIN_PASS) return false;

  const auth = (req.headers.authorization || "").toString();
  if (!auth.startsWith("Basic ")) return false;
  const b64 = auth.slice("Basic ".length).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8");
  } catch (_) {
    return false;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  const u = decoded.slice(0, idx);
  const p = decoded.slice(idx + 1);
  // constant time compare
  const uOk = crypto.timingSafeEqual(Buffer.from(u), Buffer.from(ADMIN_USER));
  const pOk = crypto.timingSafeEqual(Buffer.from(p), Buffer.from(ADMIN_PASS));
  return uOk && pOk;
}

function requireAdmin(req, res) {
  if (basicAuthOk(req)) return true;
  res.writeHead(401, {
    "WWW-Authenticate": 'Basic realm="admin", charset="UTF-8"',
    "content-type": "text/plain; charset=utf-8",
  });
  res.end("Unauthorized");
  return false;
}

function qIdent(name) {
  return '"' + String(name).replaceAll('"', '""') + '"';
}

// -------------------- KV STORE (Redis optional) --------------------
class MemoryStore {
  constructor() {
    this.map = new Map(); // key -> { value, expMs }
    setInterval(() => this.gc(), 30_000).unref?.();
  }
  gc() {
    const t = nowMs();
    for (const [k, v] of this.map.entries()) {
      if (v.expMs && v.expMs <= t) this.map.delete(k);
    }
  }
  async get(key) {
    const v = this.map.get(key);
    if (!v) return null;
    if (v.expMs && v.expMs <= nowMs()) {
      this.map.delete(key);
      return null;
    }
    return v.value;
  }
  async setex(key, ttlSec, value) {
    this.map.set(key, { value, expMs: nowMs() + ttlSec * 1000 });
  }
  async del(key) {
    this.map.delete(key);
  }
  async incr(key, ttlSec) {
    const cur = await this.get(key);
    const n = cur ? parseInt(cur, 10) + 1 : 1;
    await this.setex(key, ttlSec, String(n));
    return n;
  }
}

let kv = new MemoryStore();
let redis = null;

async function initRedis() {
  if (!REDIS_URL || !RedisCtor) {
    if (REDIS_URL && !RedisCtor) {
      console.warn("REDIS_URL set but ioredis is not installed. Falling back to MemoryStore.");
    }
    console.log("REDIS: (memory)");
    return;
  }
  try {
    redis = new RedisCtor(REDIS_URL, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
    });
    await redis.connect();
    console.log("REDIS: connected");
    kv = {
      get: (k) => redis.get(k),
      setex: (k, t, v) => redis.setex(k, t, v),
      del: (k) => redis.del(k),
      incr: async (k, ttlSec) => {
        const n = await redis.incr(k);
        if (n === 1) await redis.expire(k, ttlSec);
        return n;
      },
    };
  } catch (e) {
    console.warn("REDIS: connect failed, using MemoryStore", e?.message || e);
    kv = new MemoryStore();
  }
}

// -------------------- DB --------------------
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;

async function qRows(sql, params) {
  if (!pool) throw new Error("DATABASE_URL not set");
  const r = await pool.query(sql, params);
  return r.rows || [];
}

async function loadTableColumns(table) {
  const rows = await qRows(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name=$1
    `,
    [table]
  );
  return new Set(rows.map((r) => r.column_name));
}

async function ensureTableAccessLogs() {
  // Access logs table with broad schema; tolerate older tables by not dropping anything.
  await qRows(
    `
    CREATE TABLE IF NOT EXISTS access_logs (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      event text NOT NULL,
      first_name text,
      last_name text,
      full_name text,
      phone text,
      client_mac text,
      client_ip text,
      ssid text,
      ap_name text,
      base_grant_url text,
      continue_url text,
      user_continue_url text,
      gateway_id text,
      node_id text,
      node_mac text,
      user_agent text,
      accept_language text,
      marker text,
      kvkk_accepted bool,
      kvkk_version text,
      meta jsonb
    )
    `,
    []
  );
}

async function ensureDailyTablesAndMigrate() {
  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day date NOT NULL,
      tz text,
      record_count int NOT NULL,
      day_hash text NOT NULL,
      prev_day_hash text,
      chain_hash text NOT NULL,
      algo text NOT NULL DEFAULT 'sha256',
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day)
    )
    `,
    []
  );

  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_packages (
      day date NOT NULL,
      tz text,
      package_json jsonb NOT NULL,
      hmac text NOT NULL,
      algo text NOT NULL DEFAULT 'hmac-sha256',
      signed_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day)
    )
    `,
    []
  );

  await qRows(
    `
    CREATE TABLE IF NOT EXISTS daily_chains (
      day date NOT NULL,
      tz text,
      chain_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (day)
    )
    `,
    []
  );

  // MIGRATION: add tz columns if missing, backfill nulls
  await qRows(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS tz text`, []);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS tz text`, []);
  await qRows(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS tz text`, []);

  await qRows(`UPDATE daily_hashes SET tz=$1 WHERE tz IS NULL`, [TZ]);
  await qRows(`UPDATE daily_packages SET tz=$1 WHERE tz IS NULL`, [TZ]);
  await qRows(`UPDATE daily_chains SET tz=$1 WHERE tz IS NULL`, [TZ]);
}

async function getPrimaryKeyConstraint(tableName) {
  const rows = await qRows(
    `
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = $1::regclass
      AND contype = 'p'
    LIMIT 1
    `,
    [tableName]
  );
  return rows[0]?.conname || null;
}

let accessCols = new Set();
let dailyHashesPk = null;
let dailyPackagesPk = null;
let dailyChainsPk = null;

async function initDb() {
  if (!pool) throw new Error("DATABASE_URL not set");

  await qRows("SELECT 1", []);
  console.log("DATABASE: connected");

  await ensureTableAccessLogs();
  await ensureDailyTablesAndMigrate();

  accessCols = await loadTableColumns("access_logs");

  dailyHashesPk = await getPrimaryKeyConstraint("daily_hashes");
  dailyPackagesPk = await getPrimaryKeyConstraint("daily_packages");
  dailyChainsPk = await getPrimaryKeyConstraint("daily_chains");

  console.log("DATABASE: table ready");
}

// Insert access log with only existing columns
async function insertAccessLog(evt) {
  // evt: {event, first_name, ... meta}
  const cols = [];
  const vals = [];
  const args = [];
  let i = 1;

  // canonical known columns
  const candidates = [
    "event",
    "first_name",
    "last_name",
    "full_name",
    "phone",
    "client_mac",
    "client_ip",
    "ssid",
    "ap_name",
    "base_grant_url",
    "continue_url",
    "user_continue_url",
    "gateway_id",
    "node_id",
    "node_mac",
    "user_agent",
    "accept_language",
    "marker",
    "kvkk_accepted",
    "kvkk_version",
    "meta",
  ];

  for (const c of candidates) {
    if (!accessCols.has(c)) continue;
    if (!(c in evt)) continue;
    cols.push(qIdent(c));
    vals.push(`$${i}${c === "meta" ? "::jsonb" : ""}`);
    args.push(c === "meta" ? evt[c] : evt[c]);
    i++;
  }

  if (!cols.length) return;

  const sql = `INSERT INTO access_logs(${cols.join(",")}) VALUES(${vals.join(",")})`;
  try {
    await qRows(sql, args);
  } catch (e) {
    console.error("DB LOG ERROR:", e?.message || e);
  }
}

// -------------------- OTP / STATE --------------------
function normalizePhone(p) {
  let s = String(p || "").trim();
  // keep + and digits
  s = s.replace(/[^\d+]/g, "");
  // convert leading 0 to +90 if desired? Keep as-is to avoid legal/log mismatch.
  return s;
}

function normalizeMac(m) {
  return String(m || "")
    .trim()
    .toLowerCase()
    .replace(/[^0-9a-f:]/g, "");
}

function randomMarker() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function randomOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function otpKey(marker) {
  return `otp:${marker}`;
}
function otpWrongKey(marker) {
  return `otpwrong:${marker}`;
}
function otpLockKey(marker) {
  return `otplock:${marker}`;
}
function rlMacKey(mac) {
  return `rl:mac:${mac}`;
}
function rlPhoneKey(phone) {
  return `rl:phone:${phone}`;
}

// OTP record shape:
// { otp, phone, client_mac, created_at, full_name, first_name, last_name, kvkk_accepted, kvkk_version, ctx }
async function createOtpRecord({ phone, client_mac, full_name, first_name, last_name, kvkk_accepted, kvkk_version, ctx }) {
  const marker = randomMarker();
  const otp = randomOtp6();

  const rec = {
    otp,
    phone,
    client_mac,
    created_at: new Date().toISOString(),
    full_name: full_name || null,
    first_name: first_name || null,
    last_name: last_name || null,
    kvkk_accepted: kvkk_accepted === true,
    kvkk_version: kvkk_version || null,
    ctx: ctx || {},
  };

  await kv.setex(otpKey(marker), OTP_TTL_SECONDS, safeJson(rec));
  await kv.del(otpWrongKey(marker));
  await kv.del(otpLockKey(marker));
  return { marker, otp };
}

async function verifyOtp(marker, otp) {
  const lock = await kv.get(otpLockKey(marker));
  if (lock) return { ok: false, reason: "locked" };

  const raw = await kv.get(otpKey(marker));
  if (!raw) return { ok: false, reason: "expired" };

  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "invalid_state" };
  }

  if (String(rec.otp) !== String(otp)) {
    const wrong = await kv.incr(otpWrongKey(marker), OTP_TTL_SECONDS);
    if (wrong >= MAX_WRONG_ATTEMPTS) {
      await kv.setex(otpLockKey(marker), LOCK_SECONDS, "1");
      return { ok: false, reason: "locked" };
    }
    return { ok: false, reason: "wrong" };
  }

  // success: clear otp record
  await kv.del(otpKey(marker));
  await kv.del(otpWrongKey(marker));
  await kv.del(otpLockKey(marker));
  return { ok: true, rec };
}

// -------------------- HTML UI --------------------
function adminLogsHtml({ rows, limit, tz }) {
  // Minimal dark UI (no external assets)
  const esc = (s) =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");

  const header = `
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>/admin/logs</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#0b1220; color:#e5e7eb; }
    .wrap { max-width: 1200px; margin: 24px auto; padding: 0 16px; }
    h1 { font-size: 26px; margin: 0 0 10px; }
    .top { display:flex; gap:10px; align-items:center; justify-content:space-between; flex-wrap:wrap; margin-bottom: 12px; }
    .pill { color:#a5b4fc; font-size: 12px; }
    .btn { background:#4f46e5; border:0; color:white; padding:10px 12px; border-radius:10px; cursor:pointer; text-decoration:none; display:inline-block; font-weight:600;}
    .btn.secondary { background:#334155; }
    .card { background: rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.06); border-radius: 16px; overflow:hidden; }
    table { width:100%; border-collapse: collapse; }
    th, td { text-align:left; padding: 10px 10px; border-bottom:1px solid rgba(255,255,255,0.06); font-size: 13px; vertical-align: top;}
    th { font-size: 12px; text-transform: lowercase; letter-spacing: .02em; color:#cbd5e1; background: rgba(255,255,255,0.02); }
    tr:hover td { background: rgba(79,70,229,0.06); }
    .controls { display:flex; gap:10px; align-items:center; }
    input { background: rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.08); color:#e5e7eb; padding:10px 10px; border-radius: 10px; width: 120px;}
    a { color:#93c5fd; text-decoration: none; }
    .muted { color:#94a3b8; font-size:12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>/admin/logs</h1>
        <div class="muted">limit=${esc(limit)} • tz=${esc(tz)} • <a href="/admin/logs?limit=${esc(limit)}&tz=${encodeURIComponent(
    tz
  )}&format=json">JSON</a></div>
      </div>
      <div class="controls">
        <input id="limit" value="${esc(limit)}" />
        <a class="btn secondary" id="refresh" href="#">Refresh</a>
        <a class="btn" href="/admin/daily/ui">Daily</a>
      </div>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>marker</th><th>kvkk</th>
          </tr>
        </thead>
        <tbody>
`;

  const body = rows
    .map((r) => {
      const name = [r.first_name, r.last_name].filter(Boolean).join(" ") || r.full_name || "";
      const t = r.created_at ? formatIstanbul(new Date(r.created_at).getTime()) : "";
      return `<tr>
        <td>${esc(r.id)}</td>
        <td>${esc(t)}</td>
        <td>${esc(r.event)}</td>
        <td>${esc(name)}</td>
        <td>${esc(r.phone || "")}</td>
        <td>${esc(r.client_mac || "")}</td>
        <td>${esc(r.client_ip || "")}</td>
        <td>${esc(r.marker || "")}</td>
        <td>${esc(r.kvkk_version || "")}</td>
      </tr>`;
    })
    .join("\n");

  const footer = `
        </tbody>
      </table>
    </div>
  </div>

<script>
  const limitEl = document.getElementById('limit');
  const refresh = document.getElementById('refresh');
  refresh.addEventListener('click', (e) => {
    e.preventDefault();
    const lim = encodeURIComponent(limitEl.value || '200');
    const url = '/admin/logs?limit=' + lim + '&tz=${encodeURIComponent(tz)}';
    location.href = url;
  });
</script>
</body>
</html>
`;
  return header + body + footer;
}

function dailyUiHtml() {
  return `<!doctype html>
<html lang="tr"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>/admin/daily</title>
<style>
  :root{color-scheme:dark;}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#e5e7eb}
  .wrap{max-width:900px;margin:24px auto;padding:0 16px}
  .card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px}
  h1{margin:0 0 10px;font-size:26px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  input{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);color:#e5e7eb;padding:10px;border-radius:10px}
  .btn{background:#4f46e5;border:0;color:#fff;padding:10px 12px;border-radius:10px;cursor:pointer;text-decoration:none;font-weight:600}
  .btn.secondary{background:#334155}
  pre{white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,.3);padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.06)}
  .muted{color:#94a3b8;font-size:12px}
</style>
</head><body>
<div class="wrap">
  <h1>/admin/daily</h1>
  <div class="muted">TZ=${TZ} • build/verify/export</div>
  <div class="card">
    <div class="row">
      <input id="day" placeholder="YYYY-MM-DD" style="width:160px"/>
      <a class="btn" id="build" href="#">Build</a>
      <a class="btn secondary" id="verify" href="#">Verify</a>
      <a class="btn secondary" id="export" href="#">Export JSON</a>
      <a class="btn secondary" href="/admin/logs">Back</a>
    </div>
    <div style="height:12px"></div>
    <pre id="out">Ready.</pre>
  </div>
</div>
<script>
  const out = document.getElementById('out');
  const day = document.getElementById('day');
  function pickDay(){
    const v = (day.value || '').trim();
    if(!v) {
      const d=new Date();
      const y=d.getFullYear();
      const m=String(d.getMonth()+1).padStart(2,'0');
      const dd=String(d.getDate()).padStart(2,'0');
      return y+'-'+m+'-'+dd;
    }
    return v;
  }
  async function run(path){
    out.textContent='Loading...';
    const resp = await fetch(path);
    const txt = await resp.text();
    out.textContent = txt;
  }
  document.getElementById('build').onclick=(e)=>{e.preventDefault(); run('/admin/daily/build?day='+encodeURIComponent(pickDay()));}
  document.getElementById('verify').onclick=(e)=>{e.preventDefault(); run('/admin/daily/verify?day='+encodeURIComponent(pickDay()));}
  document.getElementById('export').onclick=(e)=>{e.preventDefault(); run('/admin/daily/export?day='+encodeURIComponent(pickDay()));}
</script>
</body></html>`;
}

// -------------------- Meraki helpers --------------------
function getMerakiCtx(u) {
  // Keep all query params for logging/meta, but normalize main ones.
  const qp = u.searchParams;
  const ctx = {};
  for (const [k, v] of qp.entries()) ctx[k] = v;

  const base_grant_url = qp.get("base_grant_url") || "";
  const continue_url = qp.get("continue_url") || "";
  const user_continue_url = qp.get("user_continue_url") || qp.get("user_continue_url") || "";
  const client_mac = normalizeMac(qp.get("client_mac") || "");
  const client_ip = (qp.get("client_ip") || "").trim(); // stored as text

  return { ctx, base_grant_url, continue_url, user_continue_url, client_mac, client_ip };
}

function buildMerakiGrantRedirect(u, marker) {
  // base_grant_url already points to .../grant? or .../grant
  // We construct a URL that includes the meraki required query params (as received)
  const qp = u.searchParams;

  const base = qp.get("base_grant_url");
  if (!base) return null;

  let grantUrl;
  try {
    grantUrl = new URL(base);
  } catch {
    // some deployments pass base_grant_url already encoded
    try {
      grantUrl = new URL(decodeURIComponent(base));
    } catch {
      return null;
    }
  }

  // Pass through required params if present
  const passthrough = ["gateway_id", "node_id", "client_ip", "client_mac", "node_mac", "continue_url"];
  for (const k of passthrough) {
    const v = qp.get(k);
    if (v) grantUrl.searchParams.set(k, v);
  }

  // Always include continue_url if present
  if (qp.get("continue_url")) grantUrl.searchParams.set("continue_url", qp.get("continue_url"));

  // Helpful marker
  if (marker) grantUrl.searchParams.set("marker", String(marker));

  return grantUrl.toString();
}

// -------------------- Daily build/verify --------------------
function isYmd(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(s || ""));
}

async function fetchLogsForDay(dayStr, tz) {
  // Compare in DB with timezone conversion
  // created_at is timestamptz. (created_at AT TIME ZONE tz) is timestamp
  const rows = await qRows(
    `
    SELECT id, created_at, event, first_name, last_name, full_name, phone, client_mac, client_ip, marker, kvkk_version, meta
    FROM access_logs
    WHERE (created_at AT TIME ZONE $2) >= ($1::date)
      AND (created_at AT TIME ZONE $2) <  ($1::date + INTERVAL '1 day')
    ORDER BY id ASC
    `,
    [dayStr, tz]
  );
  return rows;
}

function canonicalLogLine(r) {
  // Stable serialization for hashing: order keys strictly
  const obj = {
    id: r.id ?? null,
    created_at: r.created_at ? new Date(r.created_at).toISOString() : null,
    event: r.event ?? null,
    first_name: r.first_name ?? null,
    last_name: r.last_name ?? null,
    full_name: r.full_name ?? null,
    phone: r.phone ?? null,
    client_mac: r.client_mac ?? null,
    client_ip: r.client_ip ?? null,
    marker: r.marker ?? null,
    kvkk_version: r.kvkk_version ?? null,
    meta: r.meta ?? null,
  };
  return JSON.stringify(obj);
}

async function buildDaily(dayStr, tz) {
  if (!DAILY_HMAC_SECRET) {
    return { error: "DAILY_HMAC_SECRET is not set" };
  }
  if (!isYmd(dayStr)) {
    return { error: "invalid day format (YYYY-MM-DD)" };
  }

  // ensure migration once more (safe)
  await ensureDailyTablesAndMigrate();
  dailyHashesPk = dailyHashesPk || (await getPrimaryKeyConstraint("daily_hashes"));
  dailyPackagesPk = dailyPackagesPk || (await getPrimaryKeyConstraint("daily_packages"));
  dailyChainsPk = dailyChainsPk || (await getPrimaryKeyConstraint("daily_chains"));

  const logs = await fetchLogsForDay(dayStr, tz);
  const lines = logs.map(canonicalLogLine);
  const dayPayload = lines.join("\n");
  const dayHash = sha256Hex(dayPayload);

  // prev day hash (latest older record)
  const prev = await qRows(
    `
    SELECT day_hash, chain_hash
    FROM daily_hashes
    WHERE (tz = $1 OR tz IS NULL) AND day < $2::date
    ORDER BY day DESC
    LIMIT 1
    `,
    [tz, dayStr]
  );
  const prevDayHash = prev[0]?.day_hash || null;
  const prevChainHash = prev[0]?.chain_hash || null;

  // chain_hash = sha256(prev_chain_hash + "\n" + day + "\n" + day_hash)
  const chainInput = [prevChainHash || "", dayStr, dayHash].join("\n");
  const chainHash = sha256Hex(chainInput);

  // package_json includes logs and hashes (for export / 5651 workflow)
  const packageObj = {
    day: dayStr,
    tz,
    generated_at: new Date().toISOString(),
    record_count: logs.length,
    day_hash: dayHash,
    prev_day_hash: prevDayHash,
    chain_hash: chainHash,
    algo: "sha256",
    records: logs.map((r) => ({
      id: r.id,
      created_at: r.created_at ? new Date(r.created_at).toISOString() : null,
      event: r.event,
      first_name: r.first_name,
      last_name: r.last_name,
      full_name: r.full_name,
      phone: r.phone,
      client_mac: r.client_mac,
      client_ip: r.client_ip,
      marker: r.marker,
      kvkk_version: r.kvkk_version,
      meta: r.meta,
    })),
  };

  const packageJson = JSON.stringify(packageObj);
  const hmac = hmacSha256Hex(DAILY_HMAC_SECRET, packageJson);

  // Upsert using PK constraint (works regardless of PK columns)
  const pkH = dailyHashesPk ? `ON CONFLICT ON CONSTRAINT ${qIdent(dailyHashesPk)}` : "ON CONFLICT (day)";
  const pkP = dailyPackagesPk ? `ON CONFLICT ON CONSTRAINT ${qIdent(dailyPackagesPk)}` : "ON CONFLICT (day)";
  const pkC = dailyChainsPk ? `ON CONFLICT ON CONSTRAINT ${qIdent(dailyChainsPk)}` : "ON CONFLICT (day)";

  await qRows(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash, prev_day_hash, chain_hash)
    VALUES($1::date, $2, $3, $4, $5, $6)
    ${pkH}
    DO UPDATE SET
      tz=EXCLUDED.tz,
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
    ${pkP}
    DO UPDATE SET
      tz=EXCLUDED.tz,
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
    ${pkC}
    DO UPDATE SET
      tz=EXCLUDED.tz,
      chain_hash=EXCLUDED.chain_hash,
      created_at=now()
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
  if (!DAILY_HMAC_SECRET) return { error: "DAILY_HMAC_SECRET is not set" };
  if (!isYmd(dayStr)) return { error: "invalid day format (YYYY-MM-DD)" };

  // must exist
  const pkgRows = await qRows(
    `
    SELECT day, tz, package_json, hmac
    FROM daily_packages
    WHERE day = $1::date
    LIMIT 1
    `,
    [dayStr]
  );
  if (!pkgRows.length) return { error: "daily package not found (run build first)" };

  const pkg = pkgRows[0];
  const pkgJsonString = typeof pkg.package_json === "string" ? pkg.package_json : JSON.stringify(pkg.package_json);
  const expectedHmac = hmacSha256Hex(DAILY_HMAC_SECRET, pkgJsonString);
  const hmacOk = crypto.timingSafeEqual(Buffer.from(expectedHmac), Buffer.from(pkg.hmac || ""));

  // Also recompute day_hash & chain_hash from access_logs and compare
  const logs = await fetchLogsForDay(dayStr, tz);
  const lines = logs.map(canonicalLogLine);
  const dayPayload = lines.join("\n");
  const dayHash = sha256Hex(dayPayload);

  const prev = await qRows(
    `
    SELECT day_hash, chain_hash
    FROM daily_hashes
    WHERE (tz = $1 OR tz IS NULL) AND day < $2::date
    ORDER BY day DESC
    LIMIT 1
    `,
    [tz, dayStr]
  );
  const prevChainHash = prev[0]?.chain_hash || "";
  const recomputedChain = sha256Hex([prevChainHash, dayStr, dayHash].join("\n"));

  const dh = await qRows(
    `SELECT day_hash, chain_hash, record_count FROM daily_hashes WHERE day=$1::date LIMIT 1`,
    [dayStr]
  );
  if (!dh.length) return { error: "daily_hashes row missing" };

  return {
    day: dayStr,
    tz,
    record_count_db: dh[0].record_count,
    record_count_recomputed: logs.length,
    day_hash_db: dh[0].day_hash,
    day_hash_recomputed: dayHash,
    chain_hash_db: dh[0].chain_hash,
    chain_hash_recomputed: recomputedChain,
    hmac_db: pkg.hmac,
    hmac_recomputed: expectedHmac,
    ok: hmacOk && dh[0].day_hash === dayHash && dh[0].chain_hash === recomputedChain && dh[0].record_count === logs.length,
    checks: {
      hmac_ok: hmacOk,
      day_hash_ok: dh[0].day_hash === dayHash,
      chain_hash_ok: dh[0].chain_hash === recomputedChain,
      count_ok: dh[0].record_count === logs.length,
    },
  };
}

async function exportDaily(dayStr) {
  if (!isYmd(dayStr)) return { error: "invalid day format (YYYY-MM-DD)" };
  const pkgRows = await qRows(
    `SELECT day, tz, package_json, hmac, algo, signed_at FROM daily_packages WHERE day=$1::date LIMIT 1`,
    [dayStr]
  );
  if (!pkgRows.length) return { error: "daily package not found" };
  return pkgRows[0];
}

// -------------------- ROUTES --------------------
async function handle(req, res) {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const path = u.pathname;

  // Health
  if (path === "/healthz") return send(res, 200, "ok");

  // Root splash (simple)
  if (path === "/" || path === "/splash") {
    const { base_grant_url, continue_url, client_mac } = getMerakiCtx(u);

    const mode = OTP_MODE;
    console.log("SPLASH_OPEN", {
      hasBaseGrant: !!base_grant_url,
      hasContinue: !!continue_url,
      hasClientMac: !!client_mac,
      mode,
    });

    // Log splash open
    await insertAccessLog({
      event: "SPLASH_OPEN",
      client_mac: client_mac || null,
      client_ip: getClientIp(req) || null,
      base_grant_url: base_grant_url || null,
      continue_url: continue_url || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      kvkk_version: process.env.KVKK_VERSION || null,
      meta: { mode, referrer: req.headers.referer || null },
    });

    return send(res, 200, splashHtml(u), { "content-type": "text/html; charset=utf-8" });
  }

  // OTP create
  if (path === "/otp/request" && req.method === "POST") {
    const body = await parseBody(req);
    let data = {};
    try {
      data = JSON.parse(body || "{}");
    } catch {
      data = {};
    }

    const phone = normalizePhone(data.phone || "");
    const first_name = (data.first_name || "").trim() || null;
    const last_name = (data.last_name || "").trim() || null;
    const full_name = (data.full_name || "").trim() || [first_name, last_name].filter(Boolean).join(" ") || null;
    const kvkk_accepted = data.kvkk_accepted === true;
    const kvkk_version = process.env.KVKK_VERSION || data.kvkk_version || null;

    // Context (carry forward meraki params)
    const returnUrl = (data.return_url || "").trim();
    let ru;
    try {
      ru = new URL(returnUrl);
    } catch {
      ru = null;
    }
    const ctx = ru ? getMerakiCtx(ru).ctx : {};

    const client_mac = normalizeMac((data.client_mac || "").trim() || ctx.client_mac || "");

    // Rate limiting
    if (client_mac) {
      const n = await kv.incr(rlMacKey(client_mac), RL_MAC_SECONDS);
      if (n > 3) return sendJson(res, 429, { ok: false, error: "rate_limited_mac" });
    }
    if (phone) {
      const n = await kv.incr(rlPhoneKey(phone), RL_PHONE_SECONDS);
      if (n > 3) return sendJson(res, 429, { ok: false, error: "rate_limited_phone" });
    }

    const { marker, otp } = await createOtpRecord({
      phone,
      client_mac,
      full_name,
      first_name,
      last_name,
      kvkk_accepted,
      kvkk_version,
      ctx,
    });

    console.log("OTP_CREATED", { marker, last4: phone ? phone.slice(-4) : null, client_mac: client_mac || null });
    if (OTP_MODE === "screen") {
      console.log("OTP_SCREEN_CODE", { marker, otp });
    }

    await insertAccessLog({
      event: "OTP_CREATED",
      first_name,
      last_name,
      full_name,
      phone: phone || null,
      client_mac: client_mac || null,
      client_ip: getClientIp(req) || null,
      marker,
      kvkk_accepted,
      kvkk_version,
      meta: { otp_mode: OTP_MODE },
    });

    // In screen mode we return otp (for UI to show). In sms mode we'd integrate smsService.js.
    return sendJson(res, 200, {
      ok: true,
      marker,
      ...(OTP_MODE === "screen" ? { otp } : {}),
    });
  }

  // OTP verify
  if (path === "/otp/verify" && req.method === "POST") {
    const body = await parseBody(req);
    let data = {};
    try {
      data = JSON.parse(body || "{}");
    } catch {
      data = {};
    }

    const marker = String(data.marker || "").trim();
    const otp = String(data.otp || "").trim();
    const return_url = String(data.return_url || "").trim();

    const r = await verifyOtp(marker, otp);
    if (!r.ok) {
      await insertAccessLog({
        event: "OTP_VERIFY_FAIL",
        marker: marker || null,
        client_ip: getClientIp(req) || null,
        meta: { reason: r.reason },
      });
      return sendJson(res, 400, { ok: false, reason: r.reason });
    }

    const rec = r.rec || {};
    console.log("OTP_VERIFY_OK", { marker, client_mac: rec.client_mac || null });

    await insertAccessLog({
      event: "OTP_VERIFIED",
      marker: marker || null,
      first_name: rec.first_name || null,
      last_name: rec.last_name || null,
      full_name: rec.full_name || null,
      phone: rec.phone || null,
      client_mac: rec.client_mac || null,
      client_ip: getClientIp(req) || null,
      kvkk_accepted: rec.kvkk_accepted === true,
      kvkk_version: rec.kvkk_version || null,
      meta: { otp_mode: OTP_MODE },
    });

    // Build meraki grant redirect
    let ru;
    try {
      ru = new URL(return_url);
    } catch {
      ru = null;
    }

    if (!ru) {
      return sendJson(res, 200, { ok: true, redirect: null, note: "no return_url" });
    }

    const grant = buildMerakiGrantRedirect(ru, marker);
    if (!grant) {
      return sendJson(res, 200, { ok: true, redirect: null, note: "no base_grant_url" });
    }

    await insertAccessLog({
      event: "GRANT_CLIENT_REDIRECT",
      marker: marker || null,
      phone: rec.phone || null,
      client_mac: rec.client_mac || null,
      client_ip: getClientIp(req) || null,
      base_grant_url: (ru.searchParams.get("base_grant_url") || "") || null,
      continue_url: (ru.searchParams.get("continue_url") || "") || null,
      user_continue_url: (ru.searchParams.get("user_continue_url") || "") || null,
      gateway_id: (ru.searchParams.get("gateway_id") || "") || null,
      node_id: (ru.searchParams.get("node_id") || "") || null,
      node_mac: (ru.searchParams.get("node_mac") || "") || null,
      meta: { redirect: grant },
    });

    console.log("GRANT_CLIENT_REDIRECT:", grant);
    return sendJson(res, 200, { ok: true, redirect: grant });
  }

  // Admin UI
  if (path.startsWith("/admin")) {
    if (!requireAdmin(req, res)) return;

    if (path === "/admin/logs") {
      const limit = Math.max(1, Math.min(1000, parseInt(u.searchParams.get("limit") || "200", 10)));
      const tz = u.searchParams.get("tz") || TZ;
      const format = (u.searchParams.get("format") || "").toLowerCase();

      const rows = await qRows(
        `
        SELECT id, created_at, event, first_name, last_name, full_name, phone, client_mac, client_ip, marker, kvkk_version, meta
        FROM access_logs
        ORDER BY id DESC
        LIMIT $1
        `,
        [limit]
      );

      if (format === "json") return sendJson(res, 200, rows);

      return send(res, 200, adminLogsHtml({ rows, limit, tz }), { "content-type": "text/html; charset=utf-8" });
    }

    if (path === "/admin/daily/ui") {
      return send(res, 200, dailyUiHtml(), { "content-type": "text/html; charset=utf-8" });
    }

    if (path === "/admin/daily/build") {
      const day = u.searchParams.get("day") || "";
      const out = await buildDaily(day, TZ);
      if (out.error) return send(res, 400, `daily build error: ${out.error}`, { "content-type": "text/plain; charset=utf-8" });
      return sendJson(res, 200, out);
    }

    if (path === "/admin/daily/verify") {
      const day = u.searchParams.get("day") || "";
      const out = await verifyDaily(day, TZ);
      if (out.error) return send(res, 400, `daily verify error: ${out.error}`, { "content-type": "text/plain; charset=utf-8" });
      return sendJson(res, 200, out);
    }

    if (path === "/admin/daily/export") {
      const day = u.searchParams.get("day") || "";
      const out = await exportDaily(day);
      if (out.error) return send(res, 404, `daily export error: ${out.error}`, { "content-type": "text/plain; charset=utf-8" });
      return sendJson(res, 200, out);
    }

    return send(res, 404, "Not Found");
  }

  // Fallback
  return send(res, 404, "Not Found");
}

// -------------------- Splash HTML --------------------
function splashHtml(u) {
  // Keep the full current URL as return_url so OTP verify can reconstruct meraki params
  const returnUrl = u.toString();
  const kvkkVer = process.env.KVKK_VERSION || "unknown";
  const mode = OTP_MODE;

  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Wi-Fi Giriş</title>
  <style>
    :root{color-scheme:dark;}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#e5e7eb}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{width:100%;max-width:520px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:18px;padding:18px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
    h1{margin:0 0 10px;font-size:22px}
    .muted{color:#94a3b8;font-size:12px;line-height:1.4}
    label{display:block;margin-top:12px;color:#cbd5e1;font-size:13px}
    input{width:100%;box-sizing:border-box;margin-top:6px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);color:#e5e7eb;padding:12px;border-radius:12px}
    .row{display:flex;gap:10px}
    .btn{margin-top:14px;width:100%;background:#4f46e5;border:0;color:#fff;padding:12px 14px;border-radius:12px;font-weight:700;cursor:pointer}
    .btn.secondary{background:#334155}
    .ok{color:#86efac}
    .err{color:#fca5a5}
    .box{margin-top:12px;padding:12px;border-radius:12px;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.06);white-space:pre-wrap;word-break:break-word}
    a{color:#93c5fd;text-decoration:none}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Wi-Fi Giriş</h1>
    <div class="muted">KVKK: ${kvkkVer} • OTP_MODE: ${mode}</div>

    <label>Telefon</label>
    <input id="phone" placeholder="05xx..." autocomplete="tel"/>

    <div class="row">
      <div style="flex:1">
        <label>Ad</label>
        <input id="first_name" placeholder="Ad"/>
      </div>
      <div style="flex:1">
        <label>Soyad</label>
        <input id="last_name" placeholder="Soyad"/>
      </div>
    </div>

    <label style="display:flex;gap:8px;align-items:center;margin-top:14px">
      <input id="kvkk" type="checkbox" style="width:auto;margin:0"/>
      <span class="muted">KVKK metnini okudum, kabul ediyorum.</span>
    </label>

    <button class="btn" id="req">Kod Gönder</button>

    <div id="otpBox" style="display:none">
      <label>OTP</label>
      <input id="otp" placeholder="6 haneli kod" inputmode="numeric"/>
      <button class="btn secondary" id="ver">Doğrula ve Bağlan</button>
    </div>

    <div class="box" id="out">Hazır.</div>
  </div>
</div>

<script>
  const out = document.getElementById('out');
  const otpBox = document.getElementById('otpBox');
  let marker = null;
  const returnUrl = ${JSON.stringify(returnUrl)};

  function set(msg, cls){
    out.className = 'box ' + (cls || '');
    out.textContent = msg;
  }

  document.getElementById('req').onclick = async () => {
    set('İşleniyor...');
    const phone = document.getElementById('phone').value;
    const first_name = document.getElementById('first_name').value;
    const last_name = document.getElementById('last_name').value;
    const kvkk_accepted = document.getElementById('kvkk').checked;

    const resp = await fetch('/otp/request', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({ phone, first_name, last_name, kvkk_accepted, return_url: returnUrl })
    });

    const txt = await resp.text();
    if(!resp.ok){
      set('Hata: ' + txt, 'err');
      return;
    }
    const data = JSON.parse(txt);
    marker = data.marker;
    otpBox.style.display = 'block';
    if(data.otp){
      set('Kod: ' + data.otp + '\\n(OTP_MODE=screen)', 'ok');
    } else {
      set('Kod gönderildi. Lütfen SMS içindeki kodu gir.', 'ok');
    }
  };

  document.getElementById('ver').onclick = async () => {
    if(!marker){ set('Önce kod iste.', 'err'); return; }
    set('Doğrulanıyor...');
    const otp = document.getElementById('otp').value;
    const resp = await fetch('/otp/verify', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({ marker, otp, return_url: returnUrl })
    });
    const txt = await resp.text();
    if(!resp.ok){
      set('Hata: ' + txt, 'err');
      return;
    }
    const data = JSON.parse(txt);
    if(data.redirect){
      set('Bağlanılıyor...', 'ok');
      location.href = data.redirect;
    } else {
      set('Doğrulandı ama redirect yok. (base_grant_url yok olabilir)', 'err');
    }
  };
</script>
</body>
</html>`;
}

// -------------------- STARTUP --------------------
async function main() {
  await initRedis();
  await initDb();

  const server = http.createServer((req, res) => {
    // Basic CORS for admin fetch usage (optional)
    res.setHeader("x-powered-by", "meraki-sms-splash");
    handle(req, res).catch((err) => {
      console.error("REQ ERROR:", err);
      // Never crash; return 500
      try {
        send(res, 500, "Internal Server Error");
      } catch (_) {}
    });
  });

  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });

  // Graceful
  process.on("SIGTERM", async () => {
    try {
      await pool?.end?.();
    } catch (_) {}
    try {
      await redis?.quit?.();
    } catch (_) {}
    process.exit(0);
  });
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
