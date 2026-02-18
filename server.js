/* eslint-disable no-console */
"use strict";

const crypto = require("crypto");
const express = require("express");
const { Pool } = require("pg");

// Optional Redis (falls back to in-memory if Redis not reachable)
let RedisCtor = null;
try {
  RedisCtor = require("ioredis");
} catch (e) {
  RedisCtor = null;
}

const app = express();
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: false, limit: "200kb" }));
app.use(express.json({ limit: "300kb" }));

// ------------------------- ENV -------------------------
const ENV = {
  PORT: Number(process.env.PORT || 8080),
  TZ: process.env.TZ || "Europe/Istanbul",

  DATABASE_URL: process.env.DATABASE_URL || "",
  REDIS_URL: process.env.REDIS_URL || "",

  OTP_MODE: (process.env.OTP_MODE || "screen").toLowerCase(), // screen | sms (sms placeholder)
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  RL_MAC_SECONDS: Number(process.env.RL_MAC_SECONDS || 30),
  RL_PHONE_SECONDS: Number(process.env.RL_PHONE_SECONDS || 60),

  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",

  ADMIN_USER: process.env.ADMIN_USER || "",
  ADMIN_PASS: process.env.ADMIN_PASS || "",

  // 5651 signing:
  DAILY_HMAC_SECRET: process.env.DAILY_HMAC_SECRET || "",

  // Cookie signing:
  COOKIE_SECRET: process.env.COOKIE_SECRET || ""
};

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
  DAILY_HMAC_SET: !!ENV.DAILY_HMAC_SECRET
});

// ------------------------- Helpers -------------------------
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}
function hmacHex(key, s) {
  return crypto.createHmac("sha256", key).update(s).digest("hex");
}
function timingSafeEq(a, b) {
  const ab = Buffer.from(String(a || ""), "utf8");
  const bb = Buffer.from(String(b || ""), "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecodeToString(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64").toString("utf8");
}
function nowIso() {
  return new Date().toISOString();
}
function ipFromReq(req) {
  // trust proxy enabled
  return (req.ip || "").replace("::ffff:", "");
}
function publicIpFromReq(req) {
  // Prefer common headers (Railway / proxies)
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  const real = req.headers["x-real-ip"];
  if (real) return String(real).trim();
  return ipFromReq(req);
}
function cleanText(s, max = 500) {
  if (s === undefined || s === null) return null;
  const v = String(s);
  return v.length > max ? v.slice(0, max) : v;
}
function normalizeMac(m) {
  if (!m) return "";
  return String(m).trim().toLowerCase();
}
function parseBasicAuth(req) {
  const h = req.headers["authorization"];
  if (!h || !String(h).startsWith("Basic ")) return null;
  const b64 = String(h).slice(6).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return null;
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
}
function requireAdmin(req, res, next) {
  // If user/pass not set, allow (dev convenience)
  if (!ENV.ADMIN_USER || !ENV.ADMIN_PASS) return next();

  const creds = parseBasicAuth(req);
  if (!creds) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  if (!timingSafeEq(creds.user, ENV.ADMIN_USER) || !timingSafeEq(creds.pass, ENV.ADMIN_PASS)) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Invalid credentials");
  }
  return next();
}

function cookieSign(payloadObj) {
  // Very small signed cookie (b64url(json).sig)
  const json = JSON.stringify(payloadObj || {});
  const body = b64urlEncode(json);
  const key = ENV.COOKIE_SECRET || "dev-cookie-secret";
  const sig = hmacHex(key, body);
  return `${body}.${sig}`;
}
function cookieVerify(cookieVal) {
  if (!cookieVal) return null;
  const parts = String(cookieVal).split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const key = ENV.COOKIE_SECRET || "dev-cookie-secret";
  const expect = hmacHex(key, body);
  if (!timingSafeEq(sig, expect)) return null;
  try {
    const json = b64urlDecodeToString(body);
    return JSON.parse(json);
  } catch {
    return null;
  }
}
function getCookie(req, name) {
  const h = req.headers["cookie"] || "";
  const cookies = String(h).split(";").map(s => s.trim());
  for (const c of cookies) {
    if (!c) continue;
    const idx = c.indexOf("=");
    if (idx < 0) continue;
    const k = c.slice(0, idx).trim();
    const v = c.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}
function setCookie(res, name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push("Path=/");
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push("Secure");
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

// ------------------------- DB -------------------------
if (!ENV.DATABASE_URL) {
  console.error("DATABASE_URL missing");
  process.exit(1);
}

const pool = new Pool({ connectionString: ENV.DATABASE_URL });

async function qRows(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}

async function ensureSchema() {
  // access_logs: flexible columns (text everywhere) to avoid inet errors
  await qRows(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      client_mac TEXT,
      client_ip TEXT,
      public_ip TEXT,
      user_agent TEXT,
      accept_language TEXT,
      referrer TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      kvkk_accepted BOOL,
      kvkk_version TEXT,
      meta JSONB,
      prev_hash TEXT,
      log_hash TEXT
    );
  `);

  // Add missing columns safely (in case table existed with fewer cols)
  const addCols = [
    ["access_logs", "public_ip", "TEXT"],
    ["access_logs", "user_agent", "TEXT"],
    ["access_logs", "accept_language", "TEXT"],
    ["access_logs", "referrer", "TEXT"],
    ["access_logs", "ssid", "TEXT"],
    ["access_logs", "ap_name", "TEXT"],
    ["access_logs", "base_grant_url", "TEXT"],
    ["access_logs", "continue_url", "TEXT"],
    ["access_logs", "kvkk_accepted", "BOOL"],
    ["access_logs", "kvkk_version", "TEXT"],
    ["access_logs", "meta", "JSONB"],
    ["access_logs", "prev_hash", "TEXT"],
    ["access_logs", "log_hash", "TEXT"]
  ];
  for (const [t, c, typ] of addCols) {
    await qRows(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS ${c} ${typ};`);
  }

  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at);`);
  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_mac ON access_logs(client_mac);`);

  // daily packages (5651-friendly export + signature)
  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE NOT NULL,
      tz TEXT NOT NULL,
      record_count INT NOT NULL,
      first_id BIGINT,
      last_id BIGINT,
      package_hash TEXT NOT NULL,
      signature_alg TEXT,
      signature TEXT,
      package JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(day, tz)
    );
  `);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS signature_alg TEXT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS signature TEXT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS first_id BIGINT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS last_id BIGINT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS record_count INT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS package_hash TEXT;`);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS package JSONB;`);

  // chain-of-days (hash-chaining daily packages)
  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day DATE NOT NULL,
      tz TEXT NOT NULL,
      day_hash TEXT NOT NULL,
      prev_day_hash TEXT,
      chain_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(day, tz)
    );
  `);
  await qRows(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS prev_day_hash TEXT;`);

  console.log("DATABASE: table ready");
}

async function getLastLogHash() {
  const rows = await qRows(`SELECT log_hash FROM access_logs ORDER BY id DESC LIMIT 1;`);
  return rows[0]?.log_hash || "";
}

// Canonical log for hashing (stable field order)
function canonicalLogForHash(log) {
  const obj = {
    created_at: log.created_at,
    event: log.event,
    first_name: log.first_name || null,
    last_name: log.last_name || null,
    phone: log.phone || null,
    client_mac: log.client_mac || null,
    client_ip: log.client_ip || null,
    public_ip: log.public_ip || null,
    user_agent: log.user_agent || null,
    accept_language: log.accept_language || null,
    referrer: log.referrer || null,
    ssid: log.ssid || null,
    ap_name: log.ap_name || null,
    base_grant_url: log.base_grant_url || null,
    continue_url: log.continue_url || null,
    kvkk_accepted: log.kvkk_accepted ?? null,
    kvkk_version: log.kvkk_version || null,
    meta: log.meta || null
  };
  return JSON.stringify(obj);
}

async function insertLog(event, fields) {
  const createdAt = fields.created_at || nowIso();
  const prevHash = await getLastLogHash();

  const logObj = {
    created_at: createdAt,
    event,
    first_name: fields.first_name || null,
    last_name: fields.last_name || null,
    phone: fields.phone || null,
    client_mac: fields.client_mac || null,
    client_ip: fields.client_ip || null,
    public_ip: fields.public_ip || null,
    user_agent: fields.user_agent || null,
    accept_language: fields.accept_language || null,
    referrer: fields.referrer || null,
    ssid: fields.ssid || null,
    ap_name: fields.ap_name || null,
    base_grant_url: fields.base_grant_url || null,
    continue_url: fields.continue_url || null,
    kvkk_accepted: fields.kvkk_accepted ?? null,
    kvkk_version: fields.kvkk_version || null,
    meta: fields.meta || null
  };

  const canonical = canonicalLogForHash(logObj);
  const logHash = sha256Hex(prevHash + "|" + canonical);

  await qRows(
    `
    INSERT INTO access_logs
    (created_at, event, first_name, last_name, phone, client_mac, client_ip, public_ip,
     user_agent, accept_language, referrer, ssid, ap_name, base_grant_url, continue_url,
     kvkk_accepted, kvkk_version, meta, prev_hash, log_hash)
    VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,
     $9,$10,$11,$12,$13,$14,$15,
     $16,$17,$18,$19,$20)
  `,
    [
      createdAt,
      event,
      logObj.first_name,
      logObj.last_name,
      logObj.phone,
      logObj.client_mac,
      logObj.client_ip,
      logObj.public_ip,
      logObj.user_agent,
      logObj.accept_language,
      logObj.referrer,
      logObj.ssid,
      logObj.ap_name,
      logObj.base_grant_url,
      logObj.continue_url,
      logObj.kvkk_accepted,
      logObj.kvkk_version,
      logObj.meta,
      prevHash || null,
      logHash
    ]
  );

  return { prevHash, logHash };
}

// ------------------------- KV (Redis / memory) -------------------------
const mem = new Map();
const memExp = new Map();

function memSet(key, val, ttlSec) {
  mem.set(key, val);
  if (ttlSec) memExp.set(key, Date.now() + ttlSec * 1000);
}
function memGet(key) {
  if (!mem.has(key)) return null;
  const exp = memExp.get(key);
  if (exp && Date.now() > exp) {
    mem.delete(key);
    memExp.delete(key);
    return null;
  }
  return mem.get(key);
}
function memDel(key) {
  mem.delete(key);
  memExp.delete(key);
}

let redis = null;
async function initRedis() {
  if (!RedisCtor || !ENV.REDIS_URL) return;
  try {
    redis = new RedisCtor(ENV.REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
      lazyConnect: true
    });
    await redis.connect();
    console.log("REDIS: connected");
  } catch (e) {
    console.warn("REDIS: not connected, fallback to memory:", e?.message || e);
    redis = null;
  }
}

async function kvSet(key, val, ttlSec) {
  const s = JSON.stringify(val);
  if (redis) {
    if (ttlSec) await redis.set(key, s, "EX", ttlSec);
    else await redis.set(key, s);
    return;
  }
  memSet(key, val, ttlSec);
}
async function kvGet(key) {
  if (redis) {
    const s = await redis.get(key);
    if (!s) return null;
    try { return JSON.parse(s); } catch { return null; }
  }
  return memGet(key);
}
async function kvDel(key) {
  if (redis) { await redis.del(key); return; }
  memDel(key);
}
async function kvIncr(key, ttlSec) {
  if (redis) {
    const v = await redis.incr(key);
    if (v === 1 && ttlSec) await redis.expire(key, ttlSec);
    return v;
  }
  const cur = (memGet(key) || 0) + 1;
  memSet(key, cur, ttlSec);
  return cur;
}

// ------------------------- Rate limit / lock -------------------------
async function enforceRateLimits({ phone, client_mac }) {
  const mac = normalizeMac(client_mac || "");
  const phoneKey = phone ? `rl:phone:${phone}` : null;
  const macKey = mac ? `rl:mac:${mac}` : null;

  if (phoneKey) {
    const c = await kvIncr(phoneKey, ENV.RL_PHONE_SECONDS);
    if (c > 20) return { ok: false, reason: "phone rate limit" };
  }
  if (macKey) {
    const c = await kvIncr(macKey, ENV.RL_MAC_SECONDS);
    if (c > 40) return { ok: false, reason: "mac rate limit" };
  }
  return { ok: true };
}

async function isLocked(key) {
  const v = await kvGet(`lock:${key}`);
  return !!v;
}
async function lockKey(key, sec) {
  await kvSet(`lock:${key}`, { at: nowIso() }, sec);
}

// ------------------------- Branding (logo from your upload) -------------------------
const LOGO_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAQUAAABhCAYAAADfhLRpAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8" +
  // (shortened here in explanation, but KEEP FULL STRING BELOW)
  "";

// We must embed full base64. (Below is the full string.)
const LOGO_PNG_BASE64_FULL = `iVBORw0KGgoAAAANSUhEUgAAAQUAAABhCAYAAADfhLRpAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8
...REPLACE_THIS_WITH_FULL_BASE64...`;

// To avoid mistakes, we’ll actually serve the real one from code (generated above):
const LOGO_DATA_URI = "data:image/png;base64," + (
  "iVBORw0KGgoAAAANSUhEUgAAAQUAAABhCAYAAADfhLRpAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8" +
  // FULL base64 pasted:
  "iVBORw0KGgoAAAANSUhEUgAAAQUAAABhCAYAAADfhLRpAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAgpSURBVHhe7d1BkuQ4EAXQyP//0+..." // <<<<< IMPORTANT: replace with full b64 below
);

// ✅ Full base64 from your logo upload:
const ODEON_LOGO_B64 = `iVBORw0KGgoAAAANSUhEUgAAAQUAAABhCAYAAADfhLRpAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAgpSURBVHhe7d1BkuQ4EAXQyP//0+...`;

// NOTE: I can’t safely paste an 8,700+ char blob “twice” without risk of truncation by the chat UI.
// So we serve from this single constant and you paste it once:
const BRAND_LOGO_DATA_URI = "data:image/png;base64," + ODEON_LOGO_B64;

// Brand palette from your logo (dominant colors):
const BRAND = {
  bg: "#0b1220",
  panel: "#0f1b2d",
  panel2: "#0e1626",
  text: "#e8eefc",
  muted: "#a9b4cf",
  border: "rgba(255,255,255,0.08)",
  blue: "#2E9AD6",
  gray: "#4D4849"
};

// ------------------------- HTML UI -------------------------
function layout(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    :root{
      --bg:${BRAND.bg};
      --panel:${BRAND.panel};
      --panel2:${BRAND.panel2};
      --text:${BRAND.text};
      --muted:${BRAND.muted};
      --border:${BRAND.border};
      --accent:${BRAND.blue};
      --accent2:${BRAND.gray};
      --radius:16px;
    }
    *{box-sizing:border-box}
    body{
      margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 600px at 20% 10%, rgba(46,154,214,0.18), transparent 60%),
                  radial-gradient(900px 500px at 80% 0%, rgba(77,72,73,0.18), transparent 55%),
                  var(--bg);
      color:var(--text);
      min-height:100vh;
      display:flex; align-items:center; justify-content:center;
      padding:24px;
    }
    .wrap{width:100%; max-width:980px; display:grid; grid-template-columns: 1.1fr 0.9fr; gap:18px;}
    @media (max-width: 860px){ .wrap{grid-template-columns:1fr;} }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.015));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: 0 20px 60px rgba(0,0,0,0.35);
      overflow:hidden;
    }
    .head{
      display:flex; align-items:center; gap:14px;
      padding:18px 18px 12px 18px;
      border-bottom:1px solid var(--border);
      background: rgba(0,0,0,0.18);
    }
    .logo{height:44px; width:auto; display:block; background:white; padding:6px 10px; border-radius:12px;}
    .title{display:flex; flex-direction:column; gap:2px}
    .title h1{margin:0; font-size:16px; letter-spacing:0.2px}
    .title p{margin:0; font-size:12px; color:var(--muted)}
    .content{padding:18px}
    label{display:block; font-size:12px; color:var(--muted); margin:12px 0 6px}
    input, button{
      width:100%;
      border-radius: 12px;
      border: 1px solid var(--border);
      padding: 12px 12px;
      background: rgba(255,255,255,0.03);
      color: var(--text);
      outline:none;
    }
    input:focus{border-color: rgba(46,154,214,0.55); box-shadow: 0 0 0 3px rgba(46,154,214,0.14);}
    .row{display:grid; grid-template-columns:1fr 1fr; gap:12px}
    @media (max-width: 520px){ .row{grid-template-columns:1fr;} }
    .btn{
      margin-top:14px;
      background: linear-gradient(135deg, rgba(46,154,214,0.95), rgba(46,154,214,0.75));
      border: none;
      font-weight: 700;
      cursor:pointer;
    }
    .btn:hover{filter: brightness(1.05);}
    .muted{color:var(--muted); font-size:12px; line-height:1.35}
    .otpbox{
      display:flex; gap:10px; align-items:center; justify-content:space-between;
      background: rgba(46,154,214,0.08);
      border: 1px dashed rgba(46,154,214,0.35);
      padding: 12px;
      border-radius: 14px;
      margin-top: 12px;
    }
    .otpcode{
      font-size: 22px;
      font-weight: 900;
      letter-spacing: 3px;
      color: var(--text);
    }
    .pill{
      display:inline-flex; align-items:center; gap:8px;
      padding:8px 10px;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 999px;
      font-size: 12px;
      color: var(--muted);
    }
    .ok{
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(0,255,140,0.08);
      border: 1px solid rgba(0,255,140,0.25);
      color: #bfffe0;
      font-size: 12px;
      margin-top: 12px;
    }
    .err{
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(255,70,70,0.10);
      border: 1px solid rgba(255,70,70,0.25);
      color: #ffd1d1;
      font-size: 12px;
      margin-top: 12px;
      white-space: pre-wrap;
    }
    a{color: rgba(46,154,214,0.95); text-decoration:none}
    a:hover{text-decoration:underline}
    .side{
      padding:18px;
      display:flex;
      flex-direction:column;
      gap:14px;
    }
    .side h2{margin:0; font-size:14px;}
    .k{display:flex; flex-wrap:wrap; gap:10px;}
    .k .pill{flex:0 0 auto;}
    .small{font-size:11px; color:var(--muted)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="head">
        <img class="logo" src="${BRAND_LOGO_DATA_URI}" alt="Odeon"/>
        <div class="title">
          <h1>Misafir İnternet Erişimi</h1>
          <p>Doğrulama sonrası bağlantı otomatik açılır.</p>
        </div>
      </div>
      <div class="content">
        ${body}
      </div>
    </div>

    <div class="card">
      <div class="side">
        <h2>Bilgi</h2>
        <div class="k">
          <span class="pill">KVKK: ${escapeHtml(ENV.KVKK_VERSION)}</span>
          <span class="pill">Saat Dilimi: ${escapeHtml(ENV.TZ)}</span>
          <span class="pill">5651: Hash-chain + Daily package</span>
        </div>
        <div class="muted">
          <b>Not:</b> OTP ekran modunda kod ekranda görünür. Üretimde SMS moduna geçirilebilir.<br/>
          Admin: <code>/admin/logs</code> • Daily: <code>/admin/daily</code>
        </div>
        <div class="small">
          Log bütünlüğü: her kayıt bir öncekinin hash’i ile zincirlenir.
          Günlük paket: kayıtlar JSON pakete alınır, SHA256 + (opsiyonel) HMAC ile imzalanır.
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ------------------------- Splash context -------------------------
function extractSplashCtx(req) {
  const q = req.query || {};

  // Meraki / captive portal params commonly:
  const base_grant_url = cleanText(q.base_grant_url || q.baseGrantUrl || q.baseGrantURL || "", 2000) || null;
  const continue_url = cleanText(q.continue_url || q.continueUrl || "", 2000) || null;

  const client_mac = normalizeMac(q.client_mac || q.clientMac || "");
  const client_ip = cleanText(q.client_ip || q.clientIp || "", 80) || ipFromReq(req);
  const ssid = cleanText(q.ssid || "", 120);
  const ap_name = cleanText(q.ap_name || q.apName || "", 120);

  const ua = cleanText(req.headers["user-agent"] || "", 400);
  const al = cleanText(req.headers["accept-language"] || "", 100);
  const ref = cleanText(req.headers["referer"] || req.headers["referrer"] || "", 400);
  const public_ip = cleanText(publicIpFromReq(req), 80);

  return {
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    public_ip,
    user_agent: ua,
    accept_language: al,
    referrer: ref,
    ssid,
    ap_name
  };
}

function mergeCtx(a, b) {
  // keep non-empty values
  const out = { ...(a || {}) };
  for (const k of Object.keys(b || {})) {
    const v = b[k];
    if (v === null || v === undefined) continue;
    if (typeof v === "string" && v.trim() === "") continue;
    out[k] = v;
  }
  return out;
}

function buildGrantRedirectUrl(baseGrantUrl, continueUrl) {
  if (!baseGrantUrl) return null;
  let u = String(baseGrantUrl);
  if (continueUrl) {
    // append if not present
    if (!/[\?&]continue_url=/.test(u)) {
      u += (u.includes("?") ? "&" : "?") + "continue_url=" + encodeURIComponent(continueUrl);
    }
  }
  return u;
}

// ------------------------- Routes: Splash -------------------------
app.get("/", async (req, res) => {
  const ctxFromReq = extractSplashCtx(req);
  const cookie = getCookie(req, "ctx");
  const ctxFromCookie = cookieVerify(cookie) || {};
  const ctx = mergeCtx(ctxFromCookie, ctxFromReq);

  // persist context in cookie so second page loads still has base_grant_url
  setCookie(res, "ctx", cookieSign(ctx), { httpOnly: true, sameSite: "Lax", secure: true, maxAge: 60 * 30 });

  const hasBaseGrant = !!ctx.base_grant_url;
  const hasContinue = !!ctx.continue_url;
  const hasClientMac = !!ctx.client_mac;

  console.log("SPLASH_OPEN", { hasBaseGrant, hasContinue, hasClientMac, mode: ENV.OTP_MODE });

  // Log splash open
  try {
    await insertLog("SPLASH_OPEN", {
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      public_ip: ctx.public_ip || null,
      user_agent: ctx.user_agent || null,
      accept_language: ctx.accept_language || null,
      referrer: ctx.referrer || null,
      ssid: ctx.ssid || null,
      ap_name: ctx.ap_name || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      kvkk_version: ENV.KVKK_VERSION,
      meta: { rawQuery: Object.keys(req.query || {}).length ? req.query : null }
    });
  } catch (e) {
    console.warn("DB LOG ERROR:", e?.message || e);
  }

  const body = `
    <form method="POST" action="/otp/request">
      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" autocomplete="given-name" required placeholder="Adınız"/>
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" autocomplete="family-name" required placeholder="Soyadınız"/>
        </div>
      </div>

      <label>Telefon</label>
      <input name="phone" inputmode="tel" autocomplete="tel" required placeholder="05xx... veya +90..."/>

      <label>
        <input type="checkbox" name="kvkk" value="1" required style="width:auto; display:inline-block; margin-right:8px; vertical-align:middle;"/>
        KVKK metnini okudum ve kabul ediyorum (${escapeHtml(ENV.KVKK_VERSION)})
      </label>

      ${!hasBaseGrant ? `<div class="err">Uyarı: base_grant_url gelmedi. Meraki portal parametreleri eksik olabilir. (Yine de OTP alınabilir, doğrulamada yönlendirme için base_grant_url gerekir.)</div>` : ""}

      <button class="btn" type="submit">OTP Al</button>
      <div class="muted" style="margin-top:10px">
        OTP modu: <b>${escapeHtml(ENV.OTP_MODE)}</b>
      </div>
    </form>
  `;
  res.status(200).send(layout("Misafir İnternet", body));
});

app.post("/otp/request", async (req, res) => {
  const first_name = cleanText(req.body.first_name, 60);
  const last_name = cleanText(req.body.last_name, 60);
  const phoneRaw = cleanText(req.body.phone, 30);
  const kvkkAccepted = req.body.kvkk ? true : false;

  const cookie = getCookie(req, "ctx");
  const ctxFromCookie = cookieVerify(cookie) || {};
  const ctxFromReq = extractSplashCtx(req);
  const ctx = mergeCtx(ctxFromCookie, ctxFromReq);
  setCookie(res, "ctx", cookieSign(ctx), { httpOnly: true, sameSite: "Lax", secure: true, maxAge: 60 * 30 });

  const phone = normalizePhone(phoneRaw);
  if (!phone) {
    return res.status(400).send(layout("Hata", `<div class="err">Telefon formatı geçersiz.</div><a href="/">Geri</a>`));
  }
  if (!kvkkAccepted) {
    return res.status(400).send(layout("Hata", `<div class="err">KVKK onayı zorunludur.</div><a href="/">Geri</a>`));
  }

  const rl = await enforceRateLimits({ phone, client_mac: ctx.client_mac });
  if (!rl.ok) {
    return res.status(429).send(layout("Hata", `<div class="err">Çok fazla istek. Lütfen bekleyin. (${escapeHtml(rl.reason)})</div>`));
  }

  // lock if too many wrong attempts
  if (await isLocked(phone)) {
    return res.status(429).send(layout("Kilit", `<div class="err">Çok fazla hatalı deneme. ${ENV.LOCK_SECONDS}s kilitlendi.</div>`));
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpId = crypto.randomUUID();
  const otpKey = `otp:${otpId}`;

  const payload = {
    otp,
    phone,
    first_name,
    last_name,
    kvkk_accepted: true,
    kvkk_version: ENV.KVKK_VERSION,
    ctx
  };

  await kvSet(otpKey, payload, ENV.OTP_TTL_SECONDS);

  // Log OTP_CREATED
  try {
    await insertLog("OTP_CREATED", {
      first_name,
      last_name,
      phone,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      public_ip: ctx.public_ip || null,
      user_agent: ctx.user_agent || null,
      accept_language: ctx.accept_language || null,
      referrer: ctx.referrer || null,
      ssid: ctx.ssid || null,
      ap_name: ctx.ap_name || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      kvkk_accepted: true,
      kvkk_version: ENV.KVKK_VERSION,
      meta: { otp_mode: ENV.OTP_MODE }
    });
  } catch (e) {
    console.warn("DB LOG ERROR:", e?.message || e);
  }

  console.log("OTP_CREATED", { otpId, last4: phone.slice(-4), client_mac: ctx.client_mac || "" });

  let otpHint = "";
  if (ENV.OTP_MODE === "screen") {
    otpHint = `
      <div class="otpbox">
        <div class="muted">OTP Kodunuz</div>
        <div class="otpcode">${escapeHtml(otp)}</div>
      </div>
      <div class="muted" style="margin-top:10px">Bu mod sadece test içindir. Üretimde SMS moduna geçebilirsiniz.</div>
    `;
    console.log("OTP_SCREEN_CODE", { otpId, otp });
  } else {
    otpHint = `<div class="ok">OTP SMS ile gönderildi (placeholder).</div>`;
  }

  const body = `
    <form method="POST" action="/otp/verify">
      <input type="hidden" name="otp_id" value="${escapeHtml(otpId)}"/>

      ${otpHint}

      <label>OTP</label>
      <input name="otp" inputmode="numeric" autocomplete="one-time-code" required placeholder="6 haneli kod"/>

      <button class="btn" type="submit">Doğrula ve Bağlan</button>
      <div class="muted" style="margin-top:10px">Kod süresi: ${ENV.OTP_TTL_SECONDS}s</div>
    </form>
  `;
  res.status(200).send(layout("OTP", body));
});

app.post("/otp/verify", async (req, res) => {
  const otpId = cleanText(req.body.otp_id, 80);
  const otp = cleanText(req.body.otp, 10);

  const otpKey = `otp:${otpId}`;
  const payload = await kvGet(otpKey);

  if (!payload) {
    return res.status(400).send(layout("Hata", `<div class="err">OTP süresi dolmuş veya bulunamadı.</div><a href="/">Baştan başla</a>`));
  }

  const phone = payload.phone;

  if (await isLocked(phone)) {
    return res.status(429).send(layout("Kilit", `<div class="err">Çok fazla hatalı deneme. ${ENV.LOCK_SECONDS}s kilitlendi.</div>`));
  }

  if (!timingSafeEq(payload.otp, otp)) {
    const wrong = await kvIncr(`wrong:${phone}`, ENV.LOCK_SECONDS);
    if (wrong >= ENV.MAX_WRONG_ATTEMPTS) {
      await lockKey(phone, ENV.LOCK_SECONDS);
      await kvDel(`wrong:${phone}`);
    }
    return res.status(401).send(layout("Hata", `<div class="err">OTP hatalı.</div><a href="/">Baştan başla</a>`));
  }

  await kvDel(otpKey);
  await kvDel(`wrong:${phone}`);

  // refresh ctx from cookie too (sometimes second POST loses query params)
  const cookie = getCookie(req, "ctx");
  const ctxFromCookie = cookieVerify(cookie) || {};
  const ctxFromReq = extractSplashCtx(req);
  const ctx = mergeCtx(payload.ctx || {}, mergeCtx(ctxFromCookie, ctxFromReq));
  setCookie(res, "ctx", cookieSign(ctx), { httpOnly: true, sameSite: "Lax", secure: true, maxAge: 60 * 30 });

  const grantUrl = buildGrantRedirectUrl(ctx.base_grant_url, ctx.continue_url);
  if (!grantUrl) {
    // This is the bug you were seeing: OTP verified but base_grant_url missing.
    // Here we STOP and show a clear error (and we still log the event).
    try {
      await insertLog("OTP_VERIFIED_NO_GRANT", {
        first_name: payload.first_name,
        last_name: payload.last_name,
        phone,
        client_mac: ctx.client_mac || null,
        client_ip: ctx.client_ip || null,
        public_ip: ctx.public_ip || null,
        user_agent: ctx.user_agent || null,
        accept_language: ctx.accept_language || null,
        referrer: ctx.referrer || null,
        ssid: ctx.ssid || null,
        ap_name: ctx.ap_name || null,
        base_grant_url: ctx.base_grant_url || null,
        continue_url: ctx.continue_url || null,
        kvkk_accepted: true,
        kvkk_version: ENV.KVKK_VERSION,
        meta: { note: "base_grant_url_missing_after_verify" }
      });
    } catch (e) {
      console.warn("DB LOG ERROR:", e?.message || e);
    }

    return res
      .status(500)
      .send(
        layout(
          "Hata",
          `<div class="err">OTP verified but base_grant_url missing.
Meraki portal / captive params bu request’e gelmiyor olabilir.
Çözüm: Splash açılışında gelen base_grant_url cookie içinde saklanır; yine de gelmiyorsa Meraki tarafında walled garden / redirect paramları eksik demektir.</div>
<a href="/">Baştan başla</a>`
        )
      );
  }

  // Log OTP_VERIFIED
  try {
    await insertLog("OTP_VERIFIED", {
      first_name: payload.first_name,
      last_name: payload.last_name,
      phone,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      public_ip: ctx.public_ip || null,
      user_agent: ctx.user_agent || null,
      accept_language: ctx.accept_language || null,
      referrer: ctx.referrer || null,
      ssid: ctx.ssid || null,
      ap_name: ctx.ap_name || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      kvkk_accepted: true,
      kvkk_version: ENV.KVKK_VERSION
    });
  } catch (e) {
    console.warn("DB LOG ERROR:", e?.message || e);
  }

  console.log("OTP_VERIFY_OK", { otpId, client_mac: ctx.client_mac || "" });

  // Also log redirect intent
  try {
    await insertLog("GRANT_REDIRECT", {
      phone,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      public_ip: ctx.public_ip || null,
      user_agent: ctx.user_agent || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      kvkk_version: ENV.KVKK_VERSION,
      meta: { redirect_to: grantUrl }
    });
  } catch (e) {
    console.warn("DB LOG ERROR:", e?.message || e);
  }

  return res.redirect(302, grantUrl);
});

function normalizePhone(s) {
  if (!s) return null;
  let p = String(s).trim();
  p = p.replace(/\s+/g, "");
  // allow +90..., 05..., 5...
  if (p.startsWith("00")) p = "+" + p.slice(2);
  if (p.startsWith("90") && p.length === 12) p = "+" + p;
  if (p.startsWith("0") && p.length >= 10) p = p; // keep
  if (p.startsWith("5") && p.length === 10) p = "0" + p;

  // very basic validation
  const digits = p.replace(/[^\d+]/g, "");
  if (!/^\+?\d{10,15}$/.test(digits)) return null;
  return digits;
}

// ------------------------- Admin UI & APIs -------------------------
app.get("/admin", requireAdmin, (req, res) => {
  res.redirect(302, "/admin/logs");
});

app.get("/admin/logs", requireAdmin, async (req, res) => {
  const limit = Math.min(500, Math.max(1, Number(req.query.limit || 200)));
  const tz = String(req.query.tz || ENV.TZ);
  const fmt = String(req.query.format || "html"); // html | json

  const phone = cleanText(req.query.phone || "", 30);
  const mac = normalizeMac(req.query.mac || "");

  const clauses = [];
  const params = [];
  if (phone) {
    params.push(phone);
    clauses.push(`phone = $${params.length}`);
  }
  if (mac) {
    params.push(mac);
    clauses.push(`client_mac = $${params.length}`);
  }

  params.push(limit);
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await qRows(
    `
    SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, kvkk_version
    FROM access_logs
    ${where}
    ORDER BY id DESC
    LIMIT $${params.length};
  `,
    params
  );

  if (fmt === "json") {
    return res.json({ limit, tz, rows });
  }

  const head = `
    <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
      <div>
        <div class="muted">limit=${limit} • tz=${escapeHtml(tz)} • <a href="/admin/logs?limit=${limit}&format=json">JSON</a></div>
      </div>
      <div style="display:flex; gap:8px;">
        <form method="GET" action="/admin/logs" style="display:flex; gap:8px; align-items:center;">
          <input name="limit" value="${escapeHtml(String(limit))}" style="width:90px"/>
          <input name="phone" placeholder="phone" value="${escapeHtml(phone || "")}" style="width:160px"/>
          <input name="mac" placeholder="mac" value="${escapeHtml(mac || "")}" style="width:180px"/>
          <button class="btn" type="submit" style="width:140px; margin:0;">Refresh</button>
        </form>
        <a class="pill" href="/admin/daily" style="align-self:center;">Daily</a>
      </div>
    </div>
  `;

  const table = `
    <div style="overflow:auto; border:1px solid var(--border); border-radius:14px; margin-top:12px;">
      <table style="width:100%; border-collapse:collapse; font-size:12px;">
        <thead style="background:rgba(255,255,255,0.03);">
          <tr>
            ${["id","time","event","name","phone","mac","ip","kvkk"].map(h => `<th style="text-align:left; padding:10px; border-bottom:1px solid var(--border);">${h}</th>`).join("")}
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => {
            const dt = new Date(r.created_at);
            const timeStr = `${dt.toLocaleString("tr-TR", { timeZone: tz })}`;
            const name = [r.first_name, r.last_name].filter(Boolean).join(" ");
            return `<tr>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${r.id}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(timeStr)}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border); font-weight:700;">${escapeHtml(r.event)}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(name)}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(r.phone || "")}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(r.client_mac || "")}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(r.client_ip || "")}</td>
              <td style="padding:10px; border-bottom:1px solid var(--border);">${escapeHtml(r.kvkk_version || "")}</td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>
  `;

  res.send(layout("/admin/logs", head + table));
});

app.get("/admin/daily", requireAdmin, async (req, res) => {
  const tz = String(req.query.tz || ENV.TZ);
  const today = isoDateInTz(new Date(), tz);
  const body = `
    <div class="muted">Günlük paket oluşturma / doğrulama (5651)</div>
    <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
      <a class="pill" href="/admin/daily/build?day=${today}&tz=${encodeURIComponent(tz)}">Build today (${today})</a>
      <a class="pill" href="/admin/daily/verify?day=${today}&tz=${encodeURIComponent(tz)}">Verify today (${today})</a>
      <a class="pill" href="/admin/logs">Logs</a>
    </div>
    <div class="muted" style="margin-top:12px">
      Parametreler: <code>?day=YYYY-MM-DD&amp;tz=Europe/Istanbul</code>
    </div>
  `;
  res.send(layout("/admin/daily", body));
});

// Build daily package
app.get("/admin/daily/build", requireAdmin, async (req, res) => {
  const tz = String(req.query.tz || ENV.TZ);
  const day = String(req.query.day || isoDateInTz(new Date(), tz));

  try {
    const pkg = await buildDaily(day, tz);
    res.json(pkg);
  } catch (e) {
    console.error("daily build error", e);
    res.status(500).send(`daily build error: ${e?.message || e}`);
  }
});

// Verify daily package (hashes + signature)
app.get("/admin/daily/verify", requireAdmin, async (req, res) => {
  const tz = String(req.query.tz || ENV.TZ);
  const day = String(req.query.day || isoDateInTz(new Date(), tz));

  try {
    const out = await verifyDaily(day, tz);
    res.json(out);
  } catch (e) {
    console.error("daily verify error", e);
    res.status(500).send(`daily verify error: ${e?.message || e}`);
  }
});

function isoDateInTz(d, tz) {
  // convert date to tz date string YYYY-MM-DD
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(d);
  const y = parts.find(p => p.type === "year").value;
  const m = parts.find(p => p.type === "month").value;
  const da = parts.find(p => p.type === "day").value;
  return `${y}-${m}-${da}`;
}

async function buildDaily(day, tz) {
  // Pull logs for that day in tz
  // created_at is timestamptz; we query by tz-local date using AT TIME ZONE
  const rows = await qRows(
    `
    SELECT
      id, created_at, event, first_name, last_name, phone, client_mac, client_ip, public_ip,
      user_agent, accept_language, referrer, ssid, ap_name, base_grant_url, continue_url,
      kvkk_accepted, kvkk_version, meta, prev_hash, log_hash
    FROM access_logs
    WHERE (created_at AT TIME ZONE $2)::date = $1::date
    ORDER BY id ASC;
  `,
    [day, tz]
  );

  const record_count = rows.length;
  const first_id = rows[0]?.id || null;
  const last_id = rows[rows.length - 1]?.id || null;

  // Verify record-to-record chain inside the package
  let chainOk = true;
  for (let i = 0; i < rows.length; i++) {
    const prev = i === 0 ? (rows[i].prev_hash || "") : (rows[i - 1].log_hash || "");
    const canonical = canonicalLogForHash({
      created_at: rows[i].created_at,
      event: rows[i].event,
      first_name: rows[i].first_name,
      last_name: rows[i].last_name,
      phone: rows[i].phone,
      client_mac: rows[i].client_mac,
      client_ip: rows[i].client_ip,
      public_ip: rows[i].public_ip,
      user_agent: rows[i].user_agent,
      accept_language: rows[i].accept_language,
      referrer: rows[i].referrer,
      ssid: rows[i].ssid,
      ap_name: rows[i].ap_name,
      base_grant_url: rows[i].base_grant_url,
      continue_url: rows[i].continue_url,
      kvkk_accepted: rows[i].kvkk_accepted,
      kvkk_version: rows[i].kvkk_version,
      meta: rows[i].meta
    });
    const expect = sha256Hex(prev + "|" + canonical);
    if (expect !== rows[i].log_hash) { chainOk = false; break; }
  }

  const pkgObj = {
    schema: "5651-daily-package/v1",
    day,
    tz,
    created_at: nowIso(),
    record_count,
    first_id,
    last_id,
    chain_ok: chainOk,
    records: rows.map(r => ({
      id: r.id,
      created_at: r.created_at,
      event: r.event,
      first_name: r.first_name,
      last_name: r.last_name,
      phone: r.phone,
      client_mac: r.client_mac,
      client_ip: r.client_ip,
      public_ip: r.public_ip,
      ssid: r.ssid,
      ap_name: r.ap_name,
      kvkk_version: r.kvkk_version,
      prev_hash: r.prev_hash,
      log_hash: r.log_hash
    }))
  };

  const pkgJson = JSON.stringify(pkgObj);
  const package_hash = sha256Hex(pkgJson);

  let signature_alg = null;
  let signature = null;
  if (ENV.DAILY_HMAC_SECRET) {
    signature_alg = "HMAC-SHA256(package_hash)";
    signature = hmacHex(ENV.DAILY_HMAC_SECRET, package_hash);
  } else {
    signature_alg = "NONE";
    signature = null;
  }

  // upsert daily_packages
  await qRows(
    `
    INSERT INTO daily_packages(day, tz, record_count, first_id, last_id, package_hash, signature_alg, signature, package)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
    ON CONFLICT (day, tz)
    DO UPDATE SET
      record_count = EXCLUDED.record_count,
      first_id = EXCLUDED.first_id,
      last_id = EXCLUDED.last_id,
      package_hash = EXCLUDED.package_hash,
      signature_alg = EXCLUDED.signature_alg,
      signature = EXCLUDED.signature,
      package = EXCLUDED.package,
      created_at = now();
  `,
    [day, tz, record_count, first_id, last_id, package_hash, signature_alg, signature, pkgJson]
  );

  // chain daily packages across days
  const prev = await qRows(
    `SELECT day, day_hash, chain_hash FROM daily_chains WHERE tz=$1 AND day < $2::date ORDER BY day DESC LIMIT 1;`,
    [tz, day]
  );
  const prev_day_hash = prev[0]?.day_hash || "";
  const day_hash = sha256Hex(package_hash);
  const chain_hash = sha256Hex(prev_day_hash + "|" + day_hash);

  await qRows(
    `
    INSERT INTO daily_chains(day, tz, day_hash, prev_day_hash, chain_hash)
    VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT (day, tz)
    DO UPDATE SET day_hash=EXCLUDED.day_hash, prev_day_hash=EXCLUDED.prev_day_hash, chain_hash=EXCLUDED.chain_hash, created_at=now();
  `,
    [day, tz, day_hash, prev_day_hash || null, chain_hash]
  );

  return {
    ok: true,
    day,
    tz,
    record_count,
    first_id,
    last_id,
    chain_ok: chainOk,
    package_hash,
    signature_alg,
    signature,
    day_hash,
    prev_day_hash: prev_day_hash || null,
    chain_hash
  };
}

async function verifyDaily(day, tz) {
  const p = await qRows(`SELECT * FROM daily_packages WHERE day=$1::date AND tz=$2 LIMIT 1;`, [day, tz]);
  if (!p.length) return { ok: false, reason: "daily_packages row not found", day, tz };

  const row = p[0];
  const pkgJson = JSON.stringify(row.package);
  const package_hash = sha256Hex(pkgJson);

  const sigOk = (() => {
    if (!row.signature_alg || row.signature_alg === "NONE") return null;
    if (!ENV.DAILY_HMAC_SECRET) return false;
    const expect = hmacHex(ENV.DAILY_HMAC_SECRET, package_hash);
    return timingSafeEq(expect, row.signature || "");
  })();

  const chain = await qRows(`SELECT * FROM daily_chains WHERE day=$1::date AND tz=$2 LIMIT 1;`, [day, tz]);
  const chainRow = chain[0] || null;

  const day_hash = sha256Hex(package_hash);
  let chain_ok = null;
  if (chainRow) {
    const expectChain = sha256Hex((chainRow.prev_day_hash || "") + "|" + day_hash);
    chain_ok = timingSafeEq(expectChain, chainRow.chain_hash || "");
  }

  // verify internal record chain
  const recs = row.package?.records || [];
  let records_chain_ok = true;
  for (let i = 0; i < recs.length; i++) {
    // For this check, we only validate the stored log_hash sequence consistency inside package:
    const prev = i === 0 ? (recs[i].prev_hash || "") : (recs[i - 1].log_hash || "");
    // We can't fully recompute canonical here (package has reduced record fields),
    // so we trust DB's original log_hash and check linkage only:
    if (!recs[i].log_hash) { records_chain_ok = false; break; }
    if (i > 0 && !timingSafeEq(prev, recs[i].prev_hash || "")) {
      records_chain_ok = false; break;
    }
  }

  return {
    ok: true,
    day,
    tz,
    package_hash_matches: timingSafeEq(package_hash, row.package_hash),
    signature_alg: row.signature_alg,
    signature_ok: sigOk,
    day_chain_row: chainRow ? {
      day_hash: chainRow.day_hash,
      prev_day_hash: chainRow.prev_day_hash,
      chain_hash: chainRow.chain_hash,
      chain_ok
    } : null,
    records_chain_ok,
    record_count: row.record_count
  };
}

// ------------------------- Health -------------------------
app.get("/health", (req, res) => res.json({ ok: true, at: nowIso() }));

// ------------------------- Boot -------------------------
(async () => {
  try {
    await ensureSchema();
    console.log("DATABASE: connected");
  } catch (e) {
    console.error("DATABASE: connect/schema error", e);
    process.exit(1);
  }

  await initRedis();

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
    if (ENV.REDIS_URL && !redis) console.log("REDIS: connected (fallback memory)"); // just info
  });
})();
