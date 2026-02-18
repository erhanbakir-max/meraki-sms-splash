/**
 * meraki-sms-splash - single-file server.js (CommonJS)
 * - Express splash page (Meraki)
 * - OTP MODE: screen (SMS later)
 * - Redis store (ioredis) for OTP state / rate limits
 * - Postgres (pg) for 5651-like access logs + daily signature placeholder
 * - Admin UI: /admin/logs (Basic Auth)
 *
 * ENV required:
 *   PORT (optional)
 *   TZ=Europe/Istanbul (optional)
 *   OTP_MODE=screen
 *   REDIS_URL or REDIS_PUBLIC_URL
 *   DATABASE_URL
 *   ADMIN_USER, ADMIN_PASS
 *   DAILY_HMAC_KEY (optional but recommended for daily signature placeholder)
 *   KVKK_VERSION (optional)
 *
 * Meraki params expected in query:
 *   base_grant_url, user_continue_url (or continue_url), client_mac, client_ip, ap_name, ssid_name, node_mac, gateway_id
 */

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const { Pool } = require("pg");
let Redis;
try {
  Redis = require("ioredis");
} catch (e) {
  Redis = null;
}

const app = express();
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));

// static for logo
const publicDir = path.join(__dirname, "public");
if (fs.existsSync(publicDir)) {
  app.use("/public", express.static(publicDir, { maxAge: "1h" }));
}

// -------------------- ENV --------------------
const ENV = {
  PORT: parseInt(process.env.PORT || "8080", 10),
  TZ: process.env.TZ || "Europe/Istanbul",

  OTP_MODE: (process.env.OTP_MODE || "screen").toLowerCase(), // screen | sms (later)
  OTP_TTL_SECONDS: parseInt(process.env.OTP_TTL_SECONDS || "180", 10),

  RL_MAC_SECONDS: parseInt(process.env.RL_MAC_SECONDS || "30", 10),
  RL_PHONE_SECONDS: parseInt(process.env.RL_PHONE_SECONDS || "60", 10),
  MAX_WRONG_ATTEMPTS: parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10),
  LOCK_SECONDS: parseInt(process.env.LOCK_SECONDS || "600", 10),

  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",

  ADMIN_USER: process.env.ADMIN_USER || "",
  ADMIN_PASS: process.env.ADMIN_PASS || "",

  DAILY_HMAC_KEY: process.env.DAILY_HMAC_KEY || "",

  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "",
  DATABASE_URL: process.env.DATABASE_URL || "",
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
  DAILY_HMAC_SET: !!ENV.DAILY_HMAC_KEY,
});

// -------------------- Helpers --------------------
function nowISO() {
  return new Date().toISOString();
}

function safeStr(v, max = 5000) {
  if (v === undefined || v === null) return "";
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function normalizeMac(mac) {
  if (!mac) return "";
  return String(mac).trim().toLowerCase();
}

function normalizePhoneTR(input) {
  // Accept: 5XXXXXXXXX (10 digits) or 05XXXXXXXXX or +905XXXXXXXXX or 90...
  let s = (input || "").toString().trim();
  s = s.replace(/[^\d]/g, "");
  if (s.startsWith("90") && s.length === 12) s = s.slice(2);
  if (s.startsWith("0") && s.length === 11) s = s.slice(1);
  // now expected 10 digits starting with 5
  if (s.length !== 10) return { ok: false, cleaned: s, reason: "len" };
  if (!s.startsWith("5")) return { ok: false, cleaned: s, reason: "prefix" };
  return { ok: true, cleaned: s };
}

function randomOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function randomMarker() {
  // purely internal correlation id
  return String(Math.floor(100000 + Math.random() * 900000));
}

function sha256hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hmacHex(key, input) {
  return crypto.createHmac("sha256", key).update(input).digest("hex");
}

// -------------------- Redis --------------------
let redis = null;

async function initRedis() {
  if (!ENV.REDIS_URL || !Redis) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing). Running WITHOUT persistent store.");
    return;
  }
  redis = new Redis(ENV.REDIS_URL, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
    lazyConnect: true,
  });
  await redis.connect();
  console.log("REDIS: connected");
}

async function rGet(key) {
  if (!redis) return null;
  return await redis.get(key);
}
async function rSet(key, value, ttlSec) {
  if (!redis) return null;
  if (ttlSec) return await redis.set(key, value, "EX", ttlSec);
  return await redis.set(key, value);
}
async function rDel(key) {
  if (!redis) return null;
  return await redis.del(key);
}
async function rIncr(key, ttlSec) {
  if (!redis) return 0;
  const v = await redis.incr(key);
  if (v === 1 && ttlSec) await redis.expire(key, ttlSec);
  return v;
}

// -------------------- Postgres --------------------
let pool = null;

async function initDb() {
  if (!ENV.DATABASE_URL) {
    console.log("DATABASE: not configured (DATABASE_URL missing). Running WITHOUT DB logging.");
    return;
  }
  pool = new Pool({
    connectionString: ENV.DATABASE_URL,
    ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
    max: 5,
  });

  await pool.query("SELECT 1");
  console.log("DATABASE: connected");

  // Create base tables (text-based to avoid inet issues)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      client_mac TEXT,
      client_ip TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      marker TEXT,
      phone TEXT,
      full_name TEXT,
      kvkk_version TEXT,
      tz TEXT,
      accept_language TEXT,
      user_agent TEXT,
      meta JSONB DEFAULT '{}'::jsonb
    );
  `);

  // Auto-migrate columns for older deployments (your errors: ts, accept_language, continue_url...)
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ts TIMESTAMPTZ NOT NULL DEFAULT now();`);
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS continue_url TEXT;`);
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS accept_language TEXT;`);
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS user_agent TEXT;`);
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS tz TEXT;`);
  await pool.query(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS meta JSONB DEFAULT '{}'::jsonb;`);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(ts DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_mac ON access_logs(client_mac);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_signatures (
      day DATE PRIMARY KEY,
      tz TEXT,
      rows_count BIGINT NOT NULL DEFAULT 0,
      digest_sha256 TEXT NOT NULL,
      hmac_sha256 TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`ALTER TABLE daily_signatures ADD COLUMN IF NOT EXISTS tz TEXT;`);
  await pool.query(`ALTER TABLE daily_signatures ADD COLUMN IF NOT EXISTS hmac_sha256 TEXT;`);
  await pool.query(`ALTER TABLE daily_signatures ADD COLUMN IF NOT EXISTS digest_sha256 TEXT;`);
  await pool.query(`ALTER TABLE daily_signatures ADD COLUMN IF NOT EXISTS rows_count BIGINT NOT NULL DEFAULT 0;`);

  console.log("DATABASE: table ready");
}

async function dbLog(event, ctx, extraMeta = {}) {
  if (!pool) return;
  try {
    const meta = Object.assign({}, extraMeta || {});
    const q = `
      INSERT INTO access_logs(
        event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url,
        marker, phone, full_name, kvkk_version, tz, accept_language, user_agent, meta
      )
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)
    `;
    const vals = [
      safeStr(event, 200),
      safeStr(ctx.client_mac || "", 64) || null,
      safeStr(ctx.client_ip || "", 128) || null,
      safeStr(ctx.ssid || "", 256) || null,
      safeStr(ctx.ap_name || "", 256) || null,
      safeStr(ctx.base_grant_url || "", 2000) || null,
      safeStr(ctx.continue_url || "", 2000) || null,
      safeStr(ctx.marker || "", 64) || null,
      safeStr(ctx.phone || "", 32) || null,
      safeStr(ctx.full_name || "", 256) || null,
      safeStr(ctx.kvkk_version || ENV.KVKK_VERSION, 128) || null,
      safeStr(ENV.TZ, 64) || null,
      safeStr(ctx.accept_language || "", 512) || null,
      safeStr(ctx.user_agent || "", 1024) || null,
      JSON.stringify(meta),
    ];
    await pool.query(q, vals);
  } catch (e) {
    console.error("DB LOG ERROR:", e?.message || e);
  }
}

// -------------------- Admin Auth (NO basic-auth dependency) --------------------
function adminAuth(req, res, next) {
  const u = ENV.ADMIN_USER;
  const p = ENV.ADMIN_PASS;
  if (!u || !p) return res.status(503).send("Admin disabled: ADMIN_USER/ADMIN_PASS not set");

  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const b64 = hdr.slice(6);
  const raw = Buffer.from(b64, "base64").toString("utf8");
  const idx = raw.indexOf(":");
  const user = idx >= 0 ? raw.slice(0, idx) : raw;
  const pass = idx >= 0 ? raw.slice(idx + 1) : "";

  if (user === u && pass === p) return next();
  res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
  return res.status(401).send("Invalid credentials");
}

// -------------------- Meraki context extraction --------------------
function getSplashCtx(req) {
  // Meraki sends params via query, sometimes in body depending on config
  const q = Object.assign({}, req.query, req.body || {});
  const ctx = {
    base_grant_url: safeStr(q.base_grant_url || q.baseGrantUrl || "", 2000),
    continue_url: safeStr(q.user_continue_url || q.continue_url || q.continueUrl || "", 2000),
    client_mac: normalizeMac(q.client_mac || q.clientMac || ""),
    client_ip: safeStr(q.client_ip || q.clientIp || "", 128),
    ap_name: safeStr(q.ap_name || q.apName || "", 256),
    ssid: safeStr(q.ssid_name || q.ssid || q.ssidName || "", 256),
    node_mac: normalizeMac(q.node_mac || q.nodeMac || ""),
    gateway_id: safeStr(q.gateway_id || q.gatewayId || "", 64),
    user_agent: safeStr(req.headers["user-agent"] || "", 1024),
    accept_language: safeStr(req.headers["accept-language"] || "", 512),
    mode: safeStr(q.mode || "", 64),
  };
  // Meraki sometimes doesn't send client_mac or base_grant_url on some OS captive probes
  return ctx;
}

function hasBaseGrant(ctx) {
  return !!(ctx.base_grant_url && ctx.base_grant_url.startsWith("http"));
}

function buildGrantRedirect(ctx) {
  // In your final working setup: redirect to base_grant_url and include required params
  // Some deployments use base_grant_url already includes query; handle safely.
  const base = ctx.base_grant_url;
  if (!base) return "";

  const u = new URL(base);
  // Ensure continue_url if present
  if (ctx.continue_url) u.searchParams.set("continue_url", ctx.continue_url);

  // Ensure client params if known (Meraki grant endpoints sometimes validate these)
  if (ctx.gateway_id) u.searchParams.set("gateway_id", ctx.gateway_id);
  if (ctx.client_ip) u.searchParams.set("client_ip", ctx.client_ip);
  if (ctx.client_mac) u.searchParams.set("client_mac", ctx.client_mac);
  if (ctx.node_mac) u.searchParams.set("node_mac", ctx.node_mac);

  return u.toString();
}

// -------------------- OTP Store keys --------------------
function kOtp(marker) { return `otp:${marker}`; }
function kOtpMac(mac) { return `otp_by_mac:${mac}`; }
function kWrong(marker) { return `wrong:${marker}`; }
function kLock(marker) { return `lock:${marker}`; }
function kRlMac(mac) { return `rl_mac:${mac}`; }
function kRlPhone(phone) { return `rl_phone:${phone}`; }

// -------------------- UI HTML --------------------
function layout(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  :root{
    --bg:#0b1220;
    --card:#0f1a2b;
    --muted:#9fb2c8;
    --text:#e8f0ff;
    --line:rgba(255,255,255,.10);
    --brand:#1cc7b6;
    --brand2:#2b6cff;
    --danger:#ff5a6b;
  }
  *{box-sizing:border-box}
  body{
    margin:0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial;
    background: radial-gradient(1200px 700px at 20% 10%, rgba(43,108,255,.35), transparent 60%),
                radial-gradient(900px 600px at 80% 30%, rgba(28,199,182,.25), transparent 60%),
                var(--bg);
    color:var(--text);
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:24px;
  }
  .wrap{width:100%; max-width:420px;}
  .card{
    background: rgba(15,26,43,.88);
    border:1px solid var(--line);
    border-radius:16px;
    padding:22px;
    box-shadow: 0 20px 60px rgba(0,0,0,.35);
    backdrop-filter: blur(8px);
  }
  .brand{
    display:flex; align-items:center; gap:12px; margin-bottom:14px;
  }
  .logo{
    width:44px; height:44px; border-radius:12px;
    background: rgba(255,255,255,.06);
    border:1px solid var(--line);
    display:flex; align-items:center; justify-content:center;
    overflow:hidden;
  }
  .logo img{width:100%; height:100%; object-fit:contain; padding:6px;}
  h1{font-size:18px; margin:0;}
  .sub{margin:0; color:var(--muted); font-size:13px; line-height:1.4}
  .hr{height:1px; background:var(--line); margin:16px 0;}
  label{display:block; font-size:13px; color:var(--muted); margin:12px 0 6px}
  input{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid var(--line);
    background: rgba(255,255,255,.04);
    color:var(--text);
    outline:none;
  }
  input:focus{border-color: rgba(28,199,182,.55); box-shadow:0 0 0 4px rgba(28,199,182,.12)}
  .row{display:flex; gap:10px}
  .row > div{flex:1}
  .btn{
    width:100%;
    margin-top:14px;
    padding:12px 14px;
    border-radius:12px;
    border:0;
    color:#061018;
    background: linear-gradient(90deg, var(--brand), var(--brand2));
    font-weight:700;
    cursor:pointer;
  }
  .btn:disabled{opacity:.5; cursor:not-allowed}
  .tiny{font-size:12px; color:var(--muted); margin-top:10px}
  .danger{color:var(--danger); font-weight:600}
  .ok{color:var(--brand); font-weight:700}
  .kvkk{
    border:1px solid var(--line);
    border-radius:12px;
    padding:10px;
    background: rgba(255,255,255,.03);
    max-height:140px;
    overflow:auto;
    color:var(--muted);
    font-size:12px;
    line-height:1.4;
  }
  .check{display:flex; gap:10px; align-items:flex-start; margin-top:10px; color:var(--muted); font-size:12px;}
  .check input{width:16px; height:16px; margin-top:2px;}
  .otpbox{
    margin-top:10px;
    padding:12px;
    border-radius:12px;
    border:1px dashed rgba(28,199,182,.6);
    background: rgba(28,199,182,.08);
    text-align:center;
    font-size:22px;
    letter-spacing:4px;
    font-weight:800;
  }
  .footer{margin-top:14px; text-align:center; color:rgba(255,255,255,.35); font-size:11px}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="brand">
        <div class="logo">
          <img src="/public/logo.png" onerror="this.style.display='none';" alt="logo">
        </div>
        <div>
          <h1>${title}</h1>
          <p class="sub">Misafir Wi-Fi erişimi</p>
        </div>
      </div>
      ${body}
      <div class="footer">© Odeon Technology</div>
    </div>
  </div>
</body>
</html>`;
}

function kvkkPlaceholder() {
  return `<div class="kvkk">
<strong>KVKK Aydınlatma Metni (Placeholder)</strong><br><br>
Bu metin örnektir. Kurumsal KVKK metni onaylandığında buraya eklenecektir.
Kişisel veriler (Ad Soyad, Telefon, MAC, IP, zaman damgası vb.) 5651/kvkk gereklilikleri kapsamında işlenebilir.
</div>`;
}

function renderSplash(ctx, state) {
  // state: {step, error, otp, markerHidden}
  const errHtml = state.error ? `<p class="danger">${state.error}</p>` : "";
  const step = state.step || "form"; // form | otp
  const showOtp = state.otp ? `<div class="otpbox">${state.otp}</div><div class="tiny">OTP kodunu bu ekrandan gir.</div>` : "";
  const kvkk = kvkkPlaceholder();

  const hiddenInputs = `
    <input type="hidden" name="base_grant_url" value="${escapeHtml(ctx.base_grant_url)}">
    <input type="hidden" name="continue_url" value="${escapeHtml(ctx.continue_url)}">
    <input type="hidden" name="client_mac" value="${escapeHtml(ctx.client_mac)}">
    <input type="hidden" name="client_ip" value="${escapeHtml(ctx.client_ip)}">
    <input type="hidden" name="ap_name" value="${escapeHtml(ctx.ap_name)}">
    <input type="hidden" name="ssid" value="${escapeHtml(ctx.ssid)}">
    <input type="hidden" name="node_mac" value="${escapeHtml(ctx.node_mac)}">
    <input type="hidden" name="gateway_id" value="${escapeHtml(ctx.gateway_id)}">
  `;

  if (step === "otp") {
    return layout("Doğrulama", `
      <p class="sub">Telefon numaran için doğrulama kodu üretildi.</p>
      ${errHtml}
      ${showOtp}
      <div class="hr"></div>
      <form method="POST" action="/verify">
        ${hiddenInputs}
        <label>OTP Kodu</label>
        <input name="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="6 haneli kod" required>
        <input type="hidden" name="marker" value="${escapeHtml(state.marker || "")}">
        <button class="btn" type="submit">Bağlan</button>
        <div class="tiny">Kod süresi: ${ENV.OTP_TTL_SECONDS} sn</div>
      </form>
    `);
  }

  // form step
  return layout("Giriş", `
    <p class="sub">Bilgileri doldur ve KVKK onayını vererek internete bağlan.</p>
    ${errHtml}
    <div class="hr"></div>
    <form method="POST" action="/start">
      ${hiddenInputs}
      <div class="row">
        <div>
          <label>Ad Soyad</label>
          <input name="full_name" autocomplete="name" placeholder="Ad Soyad" required>
        </div>
      </div>
      <label>Cep Telefonu</label>
      <input name="phone" inputmode="tel" autocomplete="tel" placeholder="5XXXXXXXXX" required>
      <label>KVKK</label>
      ${kvkk}
      <div class="check">
        <input type="checkbox" name="kvkk_ok" value="1" required>
        <div>KVKK metnini okudum, anladım ve onaylıyorum.</div>
      </div>
      <button class="btn" type="submit">Devam</button>
      <div class="tiny">SMS devrede değilse OTP bu ekranda gösterilir.</div>
    </form>
  `);
}

function escapeHtml(s) {
  return (s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// -------------------- Core flows --------------------
async function rateLimitOrThrow(ctx, phoneClean) {
  if (!redis) return; // best-effort
  const mac = ctx.client_mac || "";
  if (mac) {
    const hits = await rIncr(kRlMac(mac), ENV.RL_MAC_SECONDS);
    if (hits > 3) throw new Error("Çok hızlı deneme. Lütfen birkaç saniye bekleyin.");
  }
  if (phoneClean) {
    const hits2 = await rIncr(kRlPhone(phoneClean), ENV.RL_PHONE_SECONDS);
    if (hits2 > 3) throw new Error("Çok hızlı deneme. Lütfen kısa süre bekleyin.");
  }
}

async function isLocked(marker) {
  if (!redis) return false;
  const v = await rGet(kLock(marker));
  return !!v;
}

async function lockMarker(marker) {
  if (!redis) return;
  await rSet(kLock(marker), "1", ENV.LOCK_SECONDS);
}

async function wrongAttempt(marker) {
  if (!redis) return 0;
  const n = await rIncr(kWrong(marker), ENV.LOCK_SECONDS);
  return n;
}

async function saveOtp(marker, payload) {
  if (!redis) return;
  await rSet(kOtp(marker), JSON.stringify(payload), ENV.OTP_TTL_SECONDS);
  if (payload.client_mac) {
    await rSet(kOtpMac(payload.client_mac), marker, ENV.OTP_TTL_SECONDS);
  }
}

async function loadOtp(marker) {
  if (!redis) return null;
  const raw = await rGet(kOtp(marker));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function deleteOtp(marker, clientMac) {
  if (!redis) return;
  await rDel(kOtp(marker));
  await rDel(kWrong(marker));
  await rDel(kLock(marker));
  if (clientMac) await rDel(kOtpMac(clientMac));
}

// -------------------- Routes --------------------
app.get("/", async (req, res) => {
  const ctx = getSplashCtx(req);

  const has = {
    hasBaseGrant: hasBaseGrant(ctx),
    hasContinue: !!ctx.continue_url,
    hasClientMac: !!ctx.client_mac,
    mode: ctx.mode || "screen",
  };
  console.log("SPLASH_OPEN", has);

  await dbLog("SPLASH_OPEN", ctx, { has });

  // Some OS captive probes do not have base_grant_url; show minimal page anyway
  return res.send(renderSplash(ctx, { step: "form" }));
});

app.post("/start", async (req, res) => {
  const ctx = getSplashCtx(req);
  ctx.continue_url = safeStr(req.body.continue_url || ctx.continue_url || "", 2000);
  ctx.base_grant_url = safeStr(req.body.base_grant_url || ctx.base_grant_url || "", 2000);
  ctx.client_mac = normalizeMac(req.body.client_mac || ctx.client_mac || "");
  ctx.client_ip = safeStr(req.body.client_ip || ctx.client_ip || "", 128);
  ctx.ap_name = safeStr(req.body.ap_name || ctx.ap_name || "", 256);
  ctx.ssid = safeStr(req.body.ssid || ctx.ssid || "", 256);
  ctx.node_mac = normalizeMac(req.body.node_mac || ctx.node_mac || "");
  ctx.gateway_id = safeStr(req.body.gateway_id || ctx.gateway_id || "", 64);

  const full_name = safeStr(req.body.full_name || "", 256).trim();
  const phoneRaw = safeStr(req.body.phone || "", 64);
  const kvkk_ok = req.body.kvkk_ok === "1" || req.body.kvkk_ok === "on" || req.body.kvkk_ok === "true";

  if (!kvkk_ok) {
    await dbLog("START_FAIL", ctx, { reason: "kvkk_not_accepted" });
    return res.status(400).send(renderSplash(ctx, { step: "form", error: "KVKK onayı zorunludur." }));
  }

  if (!full_name) {
    await dbLog("START_FAIL", ctx, { reason: "name_missing" });
    return res.status(400).send(renderSplash(ctx, { step: "form", error: "Ad Soyad gerekli." }));
  }

  const p = normalizePhoneTR(phoneRaw);
  if (!p.ok) {
    await dbLog("START_FAIL", ctx, { reason: "phone_invalid", phoneRaw });
    return res.status(400).send(renderSplash(ctx, { step: "form", error: "Telefon formatı hatalı. Örn: 5XXXXXXXXX" }));
  }

  const phone = p.cleaned;
  const marker = randomMarker();
  const otp = randomOtp6();

  try {
    await rateLimitOrThrow(ctx, phone);
  } catch (e) {
    await dbLog("START_RL_BLOCK", ctx, { phone_last4: phone.slice(-4), err: e.message });
    return res.status(429).send(renderSplash(ctx, { step: "form", error: e.message }));
  }

  // Save state in redis
  await saveOtp(marker, {
    otp,
    created_at: nowISO(),
    client_mac: ctx.client_mac || "",
    client_ip: ctx.client_ip || "",
    base_grant_url: ctx.base_grant_url || "",
    continue_url: ctx.continue_url || "",
    full_name,
    phone,
    kvkk_version: ENV.KVKK_VERSION,
    ssid: ctx.ssid || "",
    ap_name: ctx.ap_name || "",
    node_mac: ctx.node_mac || "",
    gateway_id: ctx.gateway_id || "",
  });

  await dbLog("OTP_CREATED", ctx, { marker, phone_last4: phone.slice(-4) });

  if (ENV.OTP_MODE === "screen") {
    console.log("OTP_SCREEN_CODE", { marker, otp });
    await dbLog("OTP_SCREEN_CODE", ctx, { marker });
    return res.send(renderSplash(ctx, { step: "otp", otp, marker }));
  }

  // SMS mode can be wired later
  await dbLog("OTP_MODE_UNSUPPORTED", ctx, { mode: ENV.OTP_MODE });
  return res.status(501).send(renderSplash(ctx, { step: "form", error: "SMS modu henüz devrede değil." }));
});

app.post("/verify", async (req, res) => {
  const ctx = getSplashCtx(req);
  ctx.continue_url = safeStr(req.body.continue_url || ctx.continue_url || "", 2000);
  ctx.base_grant_url = safeStr(req.body.base_grant_url || ctx.base_grant_url || "", 2000);
  ctx.client_mac = normalizeMac(req.body.client_mac || ctx.client_mac || "");
  ctx.client_ip = safeStr(req.body.client_ip || ctx.client_ip || "", 128);
  ctx.ap_name = safeStr(req.body.ap_name || ctx.ap_name || "", 256);
  ctx.ssid = safeStr(req.body.ssid || ctx.ssid || "", 256);
  ctx.node_mac = normalizeMac(req.body.node_mac || ctx.node_mac || "");
  ctx.gateway_id = safeStr(req.body.gateway_id || ctx.gateway_id || "", 64);

  const marker = safeStr(req.body.marker || "", 64);
  const otpIn = safeStr(req.body.otp || "", 16).replace(/[^\d]/g, "");

  if (!marker) {
    await dbLog("VERIFY_FAIL", ctx, { reason: "marker_missing" });
    return res.status(400).send(renderSplash(ctx, { step: "form", error: "Oturum bilgisi eksik. Lütfen tekrar deneyin." }));
  }

  if (await isLocked(marker)) {
    await dbLog("VERIFY_LOCKED", ctx, { marker });
    return res.status(429).send(renderSplash(ctx, { step: "otp", marker, error: "Çok fazla hatalı deneme. Lütfen bekleyin." }));
  }

  const st = await loadOtp(marker);
  if (!st) {
    await dbLog("VERIFY_FAIL", ctx, { marker, reason: "otp_missing_or_expired" });
    return res.status(400).send(renderSplash(ctx, { step: "form", error: "Kod süresi doldu. Lütfen yeniden başlatın." }));
  }

  if (otpIn !== st.otp) {
    const n = await wrongAttempt(marker);
    await dbLog("VERIFY_WRONG", ctx, { marker, wrong: n });
    if (n >= ENV.MAX_WRONG_ATTEMPTS) {
      await lockMarker(marker);
      return res.status(429).send(renderSplash(ctx, { step: "otp", marker, error: "Çok fazla hatalı giriş. Kilitlendi." }));
    }
    return res.status(400).send(renderSplash(ctx, { step: "otp", marker, error: "OTP hatalı. Tekrar deneyin." }));
  }

  // Verified OK
  await dbLog("OTP_VERIFY_OK", ctx, { marker, phone_last4: st.phone ? String(st.phone).slice(-4) : null });

  // Must have base_grant_url to proceed
  const base = st.base_grant_url || ctx.base_grant_url || "";
  if (!base || !String(base).startsWith("http")) {
    await dbLog("GRANT_MISSING_BASE", ctx, { marker });
    // show success but cannot grant
    return res.status(200).send(layout("Tamam", `
      <p class="danger">OTP doğrulandı fakat Meraki base_grant_url gelmedi.</p>
      <p class="sub">Bu genelde cihazın captive portal probe isteğinde Meraki parametrelerini göndermemesi / yanlış URL çağrısı nedeniyle olur.</p>
    `));
  }

  // Build redirect to Meraki grant (client-side redirect works best)
  const grantCtx = {
    base_grant_url: base,
    continue_url: st.continue_url || ctx.continue_url || "",
    client_mac: st.client_mac || ctx.client_mac || "",
    client_ip: st.client_ip || ctx.client_ip || "",
    node_mac: st.node_mac || ctx.node_mac || "",
    gateway_id: st.gateway_id || ctx.gateway_id || "",
  };
  const redirectUrl = buildGrantRedirect(grantCtx);

  await dbLog("GRANT_CLIENT_REDIRECT", ctx, { marker, redirectUrl });

  // Clean OTP
  await deleteOtp(marker, st.client_mac);

  // Redirect page
  return res.status(200).send(`<!doctype html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=${escapeHtml(redirectUrl)}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OK</title>
</head>
<body style="font-family:system-ui;background:#0b1220;color:#e8f0ff;display:flex;align-items:center;justify-content:center;min-height:100vh;">
  <div style="text-align:center;">
    <div style="font-size:18px;font-weight:700;margin-bottom:8px;">OK</div>
    <div style="opacity:.7;font-size:13px;">Yönlendiriliyorsunuz…</div>
  </div>
  <script>location.replace(${JSON.stringify(redirectUrl)});</script>
</body></html>`);
});

// -------------------- Admin UI --------------------
function renderAdminLogsPage(rows) {
  const trs = rows.map(r => {
    const ts = escapeHtml(r.ts ? new Date(r.ts).toISOString() : "");
    return `<tr>
      <td>${ts}</td>
      <td>${escapeHtml(r.event || "")}</td>
      <td>${escapeHtml(r.client_mac || "")}</td>
      <td>${escapeHtml(r.client_ip || "")}</td>
      <td>${escapeHtml(r.phone || "")}</td>
      <td>${escapeHtml(r.full_name || "")}</td>
      <td>${escapeHtml(r.ssid || "")}</td>
      <td>${escapeHtml(r.ap_name || "")}</td>
      <td style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(r.base_grant_url || "")}</td>
    </tr>`;
  }).join("");

  return `<!doctype html>
<html lang="tr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Logs</title>
<style>
  body{font-family:system-ui;margin:0;background:#0b1220;color:#e8f0ff;padding:18px}
  .top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
  a{color:#1cc7b6}
  table{width:100%;border-collapse:collapse;background:#0f1a2b;border:1px solid rgba(255,255,255,.12);border-radius:12px;overflow:hidden}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.10);font-size:12px;vertical-align:top}
  th{color:#9fb2c8;text-align:left;background:rgba(255,255,255,.03)}
  tr:hover td{background:rgba(255,255,255,.02)}
  .muted{color:#9fb2c8;font-size:12px}
</style>
</head>
<body>
  <div class="top">
    <div>
      <div style="font-weight:800;font-size:16px">5651 Loglar</div>
      <div class="muted">Son 200 kayıt</div>
    </div>
    <div>
      <a href="/admin/daily">Daily Signature</a>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Zaman (UTC)</th><th>Event</th><th>MAC</th><th>IP</th><th>Telefon</th><th>Ad Soyad</th><th>SSID</th><th>AP</th><th>Grant</th>
      </tr>
    </thead>
    <tbody>
      ${trs || `<tr><td colspan="9" class="muted">Kayıt yok</td></tr>`}
    </tbody>
  </table>
</body></html>`;
}

app.get("/admin/logs", adminAuth, async (req, res) => {
  if (!pool) return res.status(503).send("DB not configured");
  try {
    const rs = await pool.query(`
      SELECT ts, event, client_mac, client_ip, phone, full_name, ssid, ap_name, base_grant_url
      FROM access_logs
      ORDER BY ts DESC
      LIMIT 200
    `);
    return res.send(renderAdminLogsPage(rs.rows));
  } catch (e) {
    console.error("ADMIN_LOGS_ERROR:", e?.message || e);
    return res.status(500).send("Admin logs error (DB schema). Check server logs.");
  }
});

// -------------------- Daily signature placeholder --------------------
async function buildDaily(dayISO) {
  if (!pool) throw new Error("DB not configured");
  const day = dayISO ? new Date(dayISO) : new Date();
  // normalize to date string YYYY-MM-DD in TZ terms is complex; we keep UTC date for placeholder
  const d = day.toISOString().slice(0, 10);

  // Build digest from ordered rows for that day (UTC day)
  const rs = await pool.query(`
    SELECT ts, event, client_mac, client_ip, phone, full_name, ssid, ap_name, base_grant_url, continue_url, marker, kvkk_version
    FROM access_logs
    WHERE ts >= $1::timestamptz AND ts < ($1::timestamptz + interval '1 day')
    ORDER BY ts ASC, id ASC
  `, [d]);

  const lines = rs.rows.map(r => [
    r.ts ? new Date(r.ts).toISOString() : "",
    safeStr(r.event, 200),
    safeStr(r.client_mac, 64),
    safeStr(r.client_ip, 128),
    safeStr(r.phone, 32),
    safeStr(r.full_name, 256),
    safeStr(r.ssid, 128),
    safeStr(r.ap_name, 128),
    safeStr(r.base_grant_url, 300),
    safeStr(r.continue_url, 300),
    safeStr(r.marker, 64),
    safeStr(r.kvkk_version, 64),
  ].join("|")).join("\n");

  const digest = sha256hex(lines);
  const hmac = ENV.DAILY_HMAC_KEY ? hmacHex(ENV.DAILY_HMAC_KEY, digest) : null;

  await pool.query(`
    INSERT INTO daily_signatures(day, tz, rows_count, digest_sha256, hmac_sha256)
    VALUES($1::date, $2, $3, $4, $5)
    ON CONFLICT(day) DO UPDATE SET
      tz=EXCLUDED.tz,
      rows_count=EXCLUDED.rows_count,
      digest_sha256=EXCLUDED.digest_sha256,
      hmac_sha256=EXCLUDED.hmac_sha256,
      created_at=now()
  `, [d, ENV.TZ, rs.rowCount, digest, hmac]);

  return { day: d, rows: rs.rowCount, digest, hmac };
}

async function verifyDaily(dayISO) {
  if (!pool) throw new Error("DB not configured");
  const d = (dayISO ? new Date(dayISO) : new Date()).toISOString().slice(0, 10);
  const sig = await pool.query(`SELECT day, digest_sha256, hmac_sha256, rows_count, created_at FROM daily_signatures WHERE day=$1::date`, [d]);
  if (sig.rowCount === 0) return { ok: false, reason: "no_signature", day: d };

  const built = await buildDaily(d);
  const okDigest = built.digest === sig.rows[0].digest_sha256;
  const okHmac = ENV.DAILY_HMAC_KEY ? (built.hmac === sig.rows[0].hmac_sha256) : true;
  return { ok: okDigest && okHmac, day: d, okDigest, okHmac, built, stored: sig.rows[0] };
}

function renderDailyPage(info, verifyInfo) {
  const hmacLine = ENV.DAILY_HMAC_KEY ? `<div><b>HMAC:</b> ${escapeHtml(info.hmac || "")}</div>` : `<div class="muted">DAILY_HMAC_KEY yok → sadece digest üretilir.</div>`;
  const verifyBox = verifyInfo ? `
    <hr/>
    <div><b>Verify:</b> ${verifyInfo.ok ? "✅ OK" : "❌ FAIL"}</div>
    <div class="muted">Digest: ${verifyInfo.okDigest ? "OK" : "Mismatch"} | HMAC: ${verifyInfo.okHmac ? "OK" : "Mismatch/Disabled"}</div>
  ` : "";

  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Daily Signature</title>
<style>
  body{font-family:system-ui;margin:0;background:#0b1220;color:#e8f0ff;padding:18px}
  a{color:#1cc7b6}
  .card{background:#0f1a2b;border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:14px;max-width:720px}
  .muted{color:#9fb2c8;font-size:12px}
  input,button{padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.03);color:#e8f0ff}
  button{cursor:pointer;background:linear-gradient(90deg,#1cc7b6,#2b6cff);border:0;color:#061018;font-weight:800}
</style>
</head><body>
  <div style="margin-bottom:12px"><a href="/admin/logs">← Logs</a></div>
  <div class="card">
    <div style="font-weight:900;font-size:16px;margin-bottom:8px">Daily Signature (Placeholder)</div>
    <div class="muted">5651 için günlük hash/imza yaklaşımı (dış sistem/sertifika entegrasyonu daha sonra).</div>
    <hr/>
    <div><b>Day:</b> ${escapeHtml(info.day)}</div>
    <div><b>Rows:</b> ${escapeHtml(String(info.rows))}</div>
    <div><b>Digest:</b> ${escapeHtml(info.digest)}</div>
    ${hmacLine}
    ${verifyBox}
    <hr/>
    <form method="POST" action="/admin/daily/build">
      <div class="muted">Belirli gün için üret (YYYY-MM-DD)</div>
      <input name="day" placeholder="2026-02-12" />
      <button type="submit">Build</button>
    </form>
    <div style="height:10px"></div>
    <form method="POST" action="/admin/daily/verify">
      <div class="muted">Belirli gün için doğrula (YYYY-MM-DD)</div>
      <input name="day" placeholder="2026-02-12" />
      <button type="submit">Verify</button>
    </form>
  </div>
</body></html>`;
}

app.get("/admin/daily", adminAuth, async (req, res) => {
  try {
    const info = await buildDaily(new Date().toISOString().slice(0, 10));
    return res.send(renderDailyPage(info, null));
  } catch (e) {
    console.error("DAILY_PAGE_ERROR:", e?.message || e);
    return res.status(500).send("Daily error");
  }
});

app.post("/admin/daily/build", adminAuth, async (req, res) => {
  try {
    const day = safeStr(req.body.day || "", 32) || new Date().toISOString().slice(0, 10);
    const info = await buildDaily(day);
    return res.send(renderDailyPage(info, null));
  } catch (e) {
    console.error("DAILY_BUILD_ERROR:", e?.message || e);
    return res.status(500).send("Daily build error");
  }
});

app.post("/admin/daily/verify", adminAuth, async (req, res) => {
  try {
    const day = safeStr(req.body.day || "", 32) || new Date().toISOString().slice(0, 10);
    const built = await buildDaily(day);
    const v = await verifyDaily(day);
    return res.send(renderDailyPage(built, v));
  } catch (e) {
    console.error("DAILY_VERIFY_ERROR:", e?.message || e);
    return res.status(500).send("Daily verify error");
  }
});

// -------------------- Cron endpoints (Plan B will call this) --------------------
function cronAuth(req, res, next) {
  const secret = process.env.CRON_SECRET || "";
  if (!secret) return res.status(503).send("CRON_SECRET not set");
  const h = req.headers.authorization || "";
  if (h === `Bearer ${secret}`) return next();
  return res.status(401).send("Unauthorized");
}

app.post("/cron/daily", cronAuth, async (req, res) => {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const info = await buildDaily(day);
    await dbLog("CRON_DAILY_OK", {}, { day, rows: info.rows });
    return res.json({ ok: true, day, rows: info.rows, digest: info.digest });
  } catch (e) {
    console.error("CRON_DAILY_ERROR:", e?.message || e);
    await dbLog("CRON_DAILY_FAIL", {}, { err: e?.message || String(e) });
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// -------------------- Health --------------------
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: nowISO(), redis: !!redis, db: !!pool });
});

// -------------------- Start --------------------
(async () => {
  try {
    await initRedis();
  } catch (e) {
    console.error("REDIS INIT ERROR:", e?.message || e);
  }
  try {
    await initDb();
  } catch (e) {
    console.error("DB INIT ERROR:", e?.message || e);
  }

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
