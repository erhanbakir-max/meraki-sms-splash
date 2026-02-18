/**
 * meraki-sms-splash - single file server.js (CommonJS)
 * - OTP (screen mode)
 * - 5651-style access logs in Postgres (access_logs)
 * - Daily hash chain + HMAC signing (daily_hashes, daily_chains, daily_packages)
 * - Admin UI (/admin/logs + /admin/daily/...)
 * - Sade UI + logo.png (root) serve
 *
 * ENV:
 *   PORT=8080
 *   DATABASE_URL=postgres://...
 *   REDIS_URL=redis://...            (optional; varsa kullanır)
 *   TZ=Europe/Istanbul              (default)
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   OTP_MODE=screen                 (default)
 *   OTP_TTL_SECONDS=180
 *   DAILY_HMAC_SECRET=...           (daily imza için; yoksa daily imza çalışır ama "not set" görünür)
 *
 * Notes:
 * - "marker" kaldırıldı: UI'da yok. DB'de request_id tutuluyor.
 */

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");

// Redis opsiyonel: ioredis varsa kullanır, yoksa memory fallback
let Redis = null;
try {
  Redis = require("ioredis");
} catch (e) {
  Redis = null;
}

const app = express();
app.disable("x-powered-by");

// ---------- ENV ----------
const PORT = parseInt(process.env.PORT || "8080", 10);
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRESQL_URL;
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_TLS_URL || process.env.REDIS_CONNECTION_STRING;
const TZ = process.env.TZ || "Europe/Istanbul";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const OTP_MODE = process.env.OTP_MODE || "screen";
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ""; // 5651 imza placeholder -> HMAC
const DAILY_HMAC_SET = !!DAILY_HMAC_SECRET;

const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);

const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

console.log("ENV:", {
  OTP_MODE,
  OTP_TTL_SECONDS,
  RL_MAC_SECONDS,
  RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS,
  KVKK_VERSION,
  TZ,
  DB_SET: !!DATABASE_URL,
  REDIS_SET: !!REDIS_URL,
  ADMIN_USER_SET: !!ADMIN_USER,
  ADMIN_PASS_SET: !!ADMIN_PASS,
  DAILY_HMAC_SET,
});

// ---------- middleware ----------
app.use(express.urlencoded({ extended: false, limit: "256kb" }));
app.use(express.json({ limit: "256kb" }));

// Static: logo.png repo root'unda (sen ekledin)
app.get("/logo.png", (req, res) => {
  const p = path.join(process.cwd(), "logo.png");
  if (!fs.existsSync(p)) return res.status(404).send("logo.png not found");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(p);
});

// health
app.get("/healthz", (req, res) => res.status(200).send("ok"));

// ---------- DB ----------
if (!DATABASE_URL) {
  console.error("DATABASE_URL missing!");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 8,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function q(sql, params) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function ensureSchema() {
  // access_logs (5651-like)
  await q(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      event text NOT NULL,
      first_name text,
      last_name text,
      phone text,
      kvkk_accepted boolean,
      kvkk_version text,
      client_mac text,
      client_ip text,
      ssid text,
      ap_name text,
      base_grant_url text,
      continue_url text,
      user_continue_url text,
      user_agent text,
      accept_language text,
      public_ip text,
      request_id text,
      meta jsonb
    );
  `);

  // Kolon eksikleri için (senin hataların buradan geliyordu)
  const cols = [
    ["first_name", "text"],
    ["last_name", "text"],
    ["phone", "text"],
    ["kvkk_accepted", "boolean"],
    ["kvkk_version", "text"],
    ["client_mac", "text"],
    ["client_ip", "text"],
    ["ssid", "text"],
    ["ap_name", "text"],
    ["base_grant_url", "text"],
    ["continue_url", "text"],
    ["user_continue_url", "text"],
    ["user_agent", "text"],
    ["accept_language", "text"],
    ["public_ip", "text"],
    ["request_id", "text"],
    ["meta", "jsonb"],
  ];
  for (const [name, type] of cols) {
    await q(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ${name} ${type};`);
  }

  // Günlük paketler (ham kayıt snapshot) - package yerine package_json kullanıyoruz
  await q(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      day date NOT NULL,
      tz text NOT NULL,
      record_count int NOT NULL,
      package_json jsonb NOT NULL,
      UNIQUE(day, tz)
    );
  `);
  await q(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS package_json jsonb;`);
  await q(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS day date;`);
  await q(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS tz text;`);
  await q(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS record_count int;`);

  // Günlük hash (day_hash)
  await q(`
    CREATE TABLE IF NOT EXISTS daily_hashes (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      day date NOT NULL,
      tz text NOT NULL,
      record_count int NOT NULL,
      day_hash text NOT NULL,
      algo text NOT NULL DEFAULT 'sha256',
      UNIQUE(day, tz)
    );
  `);
  await q(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS day date;`);
  await q(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS tz text;`);
  await q(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS record_count int;`);
  await q(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS day_hash text;`);
  await q(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS algo text;`);

  // Chain hash (prev + day_hash) + imza (HMAC)
  await q(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      day date NOT NULL,
      tz text NOT NULL,
      prev_chain_hash text,
      chain_hash text NOT NULL,
      signature_hmac text,
      signer text,
      algo text NOT NULL DEFAULT 'sha256',
      UNIQUE(day, tz)
    );
  `);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS day date;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS tz text;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS prev_chain_hash text;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS chain_hash text;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS signature_hmac text;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS signer text;`);
  await q(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS algo text;`);

  // Performans indexleri
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_mac ON access_logs(client_mac);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(client_ip);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_event ON access_logs(event);`);

  console.log("DATABASE: table ready");
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hmacHex(secret, input) {
  return crypto.createHmac("sha256", secret).update(input).digest("hex");
}

// ---------- Redis / Memory fallback ----------
const mem = new Map(); // key -> {value, exp}
function memSet(key, value, ttlSeconds) {
  mem.set(key, { value, exp: Date.now() + ttlSeconds * 1000 });
}
function memGet(key) {
  const v = mem.get(key);
  if (!v) return null;
  if (Date.now() > v.exp) {
    mem.delete(key);
    return null;
  }
  return v.value;
}
function memDel(key) {
  mem.delete(key);
}

let redis = null;
if (Redis && REDIS_URL) {
  try {
    redis = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 2,
      connectTimeout: 4000,
      lazyConnect: true,
    });
    redis.on("error", () => {});
    redis.connect().then(() => console.log("REDIS: connected")).catch(() => {
      console.log("REDIS: failed, using memory fallback");
      redis = null;
    });
  } catch (e) {
    redis = null;
  }
} else {
  if (REDIS_URL && !Redis) console.log("REDIS: ioredis not installed, using memory fallback");
}

// KV helpers
async function kvSet(key, obj, ttlSeconds) {
  const payload = JSON.stringify(obj);
  if (redis) {
    await redis.set(key, payload, "EX", ttlSeconds);
  } else {
    memSet(key, obj, ttlSeconds);
  }
}
async function kvGet(key) {
  if (redis) {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  return memGet(key);
}
async function kvDel(key) {
  if (redis) {
    await redis.del(key);
  } else {
    memDel(key);
  }
}

// ---------- utils ----------
function nowIso() {
  return new Date().toISOString();
}

function safeText(v, max = 5000) {
  if (v === undefined || v === null) return null;
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

// Captive portal param varyasyonları (Meraki benzeri)
function pickFirst(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && String(obj[k]).trim() !== "") return String(obj[k]);
  }
  return "";
}

function getClientMac(req) {
  const q = req.query || {};
  const b = req.body || {};
  const v = pickFirst(
    { ...q, ...b },
    ["client_mac", "clientMac", "clientmac", "mac", "client-mac"]
  );
  // bazen URL encode vs
  return v ? v.replace(/%3A/gi, ":").trim() : "";
}

function getClientIp(req) {
  const q = req.query || {};
  const b = req.body || {};
  const v = pickFirst(
    { ...q, ...b },
    ["client_ip", "clientIp", "ip", "clientip", "client-ip"]
  );
  return v ? v.trim() : "";
}

function getBaseGrantUrl(req) {
  const q = req.query || {};
  const b = req.body || {};
  const v = pickFirst(
    { ...q, ...b },
    ["base_grant_url", "baseGrantUrl", "base_grant", "base_grant", "baseGrant", "base_url", "baseUrl"]
  );
  return v ? v.trim() : "";
}

function getContinueUrl(req) {
  const q = req.query || {};
  const b = req.body || {};
  const v = pickFirst(
    { ...q, ...b },
    ["continue_url", "continueUrl", "continue", "user_continue_url", "userContinueUrl"]
  );
  return v ? v.trim() : "";
}

function getSsid(req) {
  const q = req.query || {};
  return pickFirst(q, ["ssid", "network", "network_name"]) || "";
}

function getApName(req) {
  const q = req.query || {};
  return pickFirst(q, ["ap_name", "apName", "node_id", "node_mac", "ap"]) || "";
}

function getPublicIp(req) {
  // Railway arkasında gerçek client public ip genelde header'da
  const h = req.headers || {};
  return safeText(h["x-forwarded-for"] || h["x-real-ip"] || "");
}

function getAcceptLanguage(req) {
  return safeText(req.headers["accept-language"] || "");
}

function getUserAgent(req) {
  return safeText(req.headers["user-agent"] || "");
}

function constantTimeEq(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

// ---------- Basic Auth (no dependency) ----------
function requireAdminAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send("ADMIN_USER / ADMIN_PASS not set");
  }
  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const raw = Buffer.from(hdr.slice(6), "base64").toString("utf8");
  const idx = raw.indexOf(":");
  const u = idx >= 0 ? raw.slice(0, idx) : raw;
  const p = idx >= 0 ? raw.slice(idx + 1) : "";
  if (!constantTimeEq(u, ADMIN_USER) || !constantTimeEq(p, ADMIN_PASS)) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Invalid credentials");
  }
  next();
}

// ---------- Rate limiting + lock (KV) ----------
async function isLockedPhone(phone) {
  if (!phone) return false;
  const k = `lock:phone:${phone}`;
  const v = await kvGet(k);
  return !!v;
}
async function lockPhone(phone) {
  if (!phone) return;
  const k = `lock:phone:${phone}`;
  await kvSet(k, { locked_at: nowIso() }, LOCK_SECONDS);
}
async function bumpWrong(phone) {
  if (!phone) return 0;
  const k = `wrong:phone:${phone}`;
  const cur = (await kvGet(k)) || { n: 0 };
  const n = (cur.n || 0) + 1;
  await kvSet(k, { n }, LOCK_SECONDS);
  return n;
}
async function clearWrong(phone) {
  if (!phone) return;
  const k = `wrong:phone:${phone}`;
  await kvDel(k);
}

// basit per key throttling
async function rateLimit(key, seconds) {
  const k = `rl:${key}`;
  const cur = await kvGet(k);
  if (cur) return false;
  await kvSet(k, { at: nowIso() }, seconds);
  return true;
}

// ---------- Logging ----------
async function logEvent(event, fields) {
  try {
    const {
      first_name,
      last_name,
      phone,
      kvkk_accepted,
      kvkk_version,
      client_mac,
      client_ip,
      ssid,
      ap_name,
      base_grant_url,
      continue_url,
      user_continue_url,
      user_agent,
      accept_language,
      public_ip,
      request_id,
      meta,
    } = fields || {};

    await q(
      `
      INSERT INTO access_logs
      (event, first_name, last_name, phone, kvkk_accepted, kvkk_version, client_mac, client_ip, ssid, ap_name,
       base_grant_url, continue_url, user_continue_url, user_agent, accept_language, public_ip, request_id, meta)
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
       $11,$12,$13,$14,$15,$16,$17,$18)
      `,
      [
        event,
        safeText(first_name),
        safeText(last_name),
        safeText(phone),
        kvkk_accepted === undefined ? null : !!kvkk_accepted,
        safeText(kvkk_version),
        safeText(client_mac),
        safeText(client_ip),
        safeText(ssid),
        safeText(ap_name),
        safeText(base_grant_url),
        safeText(continue_url),
        safeText(user_continue_url),
        safeText(user_agent),
        safeText(accept_language),
        safeText(public_ip),
        safeText(request_id),
        meta ? JSON.stringify(meta) : null,
      ]
    );
  } catch (e) {
    console.log("DB LOG ERROR:", e.message);
  }
}

// ---------- UI (Odeon teması - sade) ----------
function themeCss() {
  // logo'daki mavi tonlara yakın, sade koyu tema
  return `
  :root{
    --bg:#0b1220;
    --card:#111a2c;
    --muted:#8aa0c6;
    --text:#e9f0ff;
    --line:rgba(255,255,255,.08);
    --accent:#2a79ff;
    --accent2:#0ea5ff;
    --danger:#ff4d4d;
    --ok:#22c55e;
  }
  *{box-sizing:border-box}
  body{
    margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    background: radial-gradient(1200px 800px at 20% 10%, rgba(42,121,255,.18), transparent 60%),
                radial-gradient(900px 700px at 80% 20%, rgba(14,165,255,.14), transparent 55%),
                var(--bg);
    color:var(--text);
  }
  a{color:var(--accent2); text-decoration:none}
  .wrap{min-height:100vh; display:flex; align-items:center; justify-content:center; padding:28px}
  .card{
    width: min(520px, 100%);
    background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
    border: 1px solid var(--line);
    border-radius: 18px;
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
    padding: 22px;
  }
  .brand{display:flex; align-items:center; gap:12px; margin-bottom:14px}
  .brand img{height:34px; width:auto; display:block}
  .brand .t{display:flex; flex-direction:column; line-height:1.1}
  .brand .t .h{font-weight:700; font-size:16px}
  .brand .t .s{font-size:12px; color:var(--muted)}
  h1{margin:10px 0 6px; font-size:20px}
  p{margin:0 0 14px; color:var(--muted); font-size:13px; line-height:1.45}
  .row{display:flex; gap:10px}
  label{display:block; font-size:12px; color:var(--muted); margin:10px 0 6px}
  input{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid var(--line);
    background: rgba(0,0,0,.18);
    color: var(--text);
    outline:none;
  }
  input:focus{border-color: rgba(42,121,255,.65); box-shadow: 0 0 0 3px rgba(42,121,255,.15)}
  .btn{
    margin-top:14px;
    width:100%;
    padding:12px 14px;
    border-radius:12px;
    border:1px solid rgba(42,121,255,.55);
    background: linear-gradient(180deg, rgba(42,121,255,.95), rgba(14,165,255,.85));
    color:white;
    font-weight:700;
    cursor:pointer;
  }
  .btn:active{transform: translateY(1px)}
  .tiny{font-size:12px; color:var(--muted); margin-top:10px}
  .pill{display:inline-block; padding:6px 10px; border-radius:999px; border:1px solid var(--line); background:rgba(0,0,0,.18); color:var(--muted); font-size:12px}
  .ok{color:var(--ok)}
  .err{color:var(--danger)}
  /* admin */
  .adminWrap{padding:18px}
  .topbar{display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:14px}
  .topbar .left{display:flex; align-items:center; gap:10px}
  .topbar img{height:26px}
  table{width:100%; border-collapse:collapse; overflow:hidden; border-radius:14px; border:1px solid var(--line); background:rgba(0,0,0,.15)}
  th,td{padding:10px 10px; border-bottom:1px solid var(--line); font-size:12px; text-align:left; vertical-align:top}
  th{color:var(--muted); font-weight:700}
  tr:hover td{background:rgba(255,255,255,.03)}
  .controls{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
  .controls input{width:120px; padding:10px}
  .controls .btn2{
    padding:10px 12px; border-radius:10px; border:1px solid var(--line);
    background: rgba(0,0,0,.22); color:var(--text); cursor:pointer;
  }
  .controls .btn2:hover{border-color: rgba(42,121,255,.45)}
  `;
}

function pageShell(title, bodyHtml) {
  return `<!doctype html>
  <html lang="tr">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${title}</title>
      <style>${themeCss()}</style>
    </head>
    <body>${bodyHtml}</body>
  </html>`;
}

// ---------- OTP helpers ----------
function genOtp() {
  // 6 digit
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, "0");
}

function normalizePhone(p) {
  if (!p) return "";
  let s = String(p).trim();
  s = s.replace(/\s+/g, "");
  // çok basit normalize: +90 yoksa ekleme yapmıyorum, senin SMS servisinde farklı olabilir
  return s;
}

async function createOtpContext(ctx) {
  // otp_id: random id
  const otp_id = crypto.randomBytes(10).toString("hex");
  const otp = genOtp();

  const payload = {
    ...ctx,
    otp,
    created_at: Date.now(),
  };

  await kvSet(`otp:${otp_id}`, payload, OTP_TTL_SECONDS);
  return { otp_id, otp };
}

async function getOtpContext(otp_id) {
  return await kvGet(`otp:${otp_id}`);
}

async function consumeOtp(otp_id) {
  await kvDel(`otp:${otp_id}`);
}

// ---------- Splash endpoints ----------
app.get("/", async (req, res) => {
  const request_id = crypto.randomBytes(8).toString("hex");

  const base_grant_url = getBaseGrantUrl(req);
  const continue_url = getContinueUrl(req);

  const client_mac = getClientMac(req);
  const client_ip = getClientIp(req);
  const ssid = getSsid(req);
  const ap_name = getApName(req);

  const hasBaseGrant = !!base_grant_url;
  const hasContinue = !!continue_url;
  const hasClientMac = !!client_mac;

  console.log("SPLASH_OPEN", { hasBaseGrant, hasContinue, hasClientMac, mode: OTP_MODE });

  await logEvent("SPLASH_OPEN", {
    kvkk_version: KVKK_VERSION,
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url,
    user_agent: getUserAgent(req),
    accept_language: getAcceptLanguage(req),
    public_ip: getPublicIp(req),
    request_id,
    meta: {
      query: req.query || {},
      path: req.originalUrl,
    },
  });

  const body = `
  <div class="wrap">
    <div class="card">
      <div class="brand">
        <img src="/logo.png" alt="Odeon" onerror="this.style.display='none'"/>
        <div class="t">
          <div class="h">Misafir Wi-Fi</div>
          <div class="s">Odeon Technology</div>
        </div>
      </div>

      <h1>Oturum aç</h1>
      <p>Telefon numaranı gir. Ekranda doğrulama kodu görünecek ve onayladıktan sonra internete yönlendirileceksin.</p>

      ${!hasBaseGrant ? `<p class="err">Uyarı: base_grant_url gelmedi (Meraki tarafı). Yine de test için OTP üretebilirsin.</p>` : ""}

      <form method="POST" action="/otp/start">
        <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}"/>
        <input type="hidden" name="continue_url" value="${escapeHtml(continue_url)}"/>
        <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}"/>
        <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}"/>
        <input type="hidden" name="ssid" value="${escapeHtml(ssid)}"/>
        <input type="hidden" name="ap_name" value="${escapeHtml(ap_name)}"/>

        <label>Ad</label>
        <input name="first_name" autocomplete="given-name" />

        <label>Soyad</label>
        <input name="last_name" autocomplete="family-name" />

        <label>Telefon</label>
        <input name="phone" inputmode="tel" placeholder="05xx..." required />

        <label style="margin-top:12px; display:flex; gap:10px; align-items:flex-start">
          <input type="checkbox" name="kvkk_accepted" value="1" style="width:auto; margin-top:4px" required />
          <span style="font-size:12px; color:var(--muted)">KVKK metnini okudum, kabul ediyorum. (Versiyon: <span class="pill">${escapeHtml(
            KVKK_VERSION
          )}</span>)</span>
        </label>

        <button class="btn" type="submit">Kodu Göster</button>
      </form>

      <div class="tiny">Sorun olursa IT ekibine iletin.</div>
    </div>
  </div>
  `;
  res.status(200).send(pageShell("Wi-Fi Login", body));
});

app.post("/otp/start", async (req, res) => {
  const request_id = crypto.randomBytes(8).toString("hex");

  const first_name = safeText(req.body.first_name || "");
  const last_name = safeText(req.body.last_name || "");
  const phone = normalizePhone(req.body.phone || "");
  const kvkk_accepted = req.body.kvkk_accepted === "1" || req.body.kvkk_accepted === "true";

  const base_grant_url = safeText(req.body.base_grant_url || "");
  const continue_url = safeText(req.body.continue_url || "");
  const client_mac = safeText(req.body.client_mac || getClientMac(req));
  const client_ip = safeText(req.body.client_ip || getClientIp(req));
  const ssid = safeText(req.body.ssid || "");
  const ap_name = safeText(req.body.ap_name || "");

  if (!phone) return res.status(400).send("phone required");
  if (!kvkk_accepted) return res.status(400).send("kvkk required");

  // lock / rate limit
  if (await isLockedPhone(phone)) {
    return res.status(429).send("Telefon geçici olarak kilitli. Biraz sonra tekrar deneyin.");
  }
  const okPhone = await rateLimit(`phone:${phone}`, RL_PHONE_SECONDS);
  if (!okPhone) return res.status(429).send("Çok sık deneme. Lütfen bekleyin.");

  if (client_mac) {
    const okMac = await rateLimit(`mac:${client_mac}`, RL_MAC_SECONDS);
    if (!okMac) return res.status(429).send("Çok sık deneme. Lütfen bekleyin.");
  }

  const { otp_id, otp } = await createOtpContext({
    first_name,
    last_name,
    phone,
    kvkk_accepted: true,
    kvkk_version: KVKK_VERSION,
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    ssid,
    ap_name,
    user_agent: getUserAgent(req),
    accept_language: getAcceptLanguage(req),
    public_ip: getPublicIp(req),
    request_id,
  });

  console.log("OTP_CREATED", { otp_id, last4: phone.slice(-4), client_mac: client_mac || "" });
  if (OTP_MODE === "screen") console.log("OTP_SCREEN_CODE", { otp_id, otp });

  await logEvent("OTP_CREATED", {
    first_name,
    last_name,
    phone,
    kvkk_accepted: true,
    kvkk_version: KVKK_VERSION,
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url,
    user_agent: getUserAgent(req),
    accept_language: getAcceptLanguage(req),
    public_ip: getPublicIp(req),
    request_id,
    meta: { otp_id },
  });

  // Screen mode: OTP’yi göster + verify formu
  const body = `
  <div class="wrap">
    <div class="card">
      <div class="brand">
        <img src="/logo.png" alt="Odeon" onerror="this.style.display='none'"/>
        <div class="t">
          <div class="h">Doğrulama</div>
          <div class="s">Tek kullanımlık kod</div>
        </div>
      </div>

      <h1>Kodunuz</h1>
      <p>Bu kod ${OTP_TTL_SECONDS} saniye geçerli.</p>

      <div style="display:flex; justify-content:center; margin:16px 0 8px">
        <div style="
          font-size:34px; letter-spacing:6px; font-weight:800;
          padding:12px 14px; border-radius:14px;
          border:1px solid var(--line);
          background:rgba(0,0,0,.18);
        ">${otp}</div>
      </div>

      <form method="POST" action="/otp/verify">
        <input type="hidden" name="otp_id" value="${escapeHtml(otp_id)}"/>
        <label>Doğrulama Kodu</label>
        <input name="otp" inputmode="numeric" placeholder="6 haneli" required />

        <button class="btn" type="submit">Doğrula ve Bağlan</button>
      </form>

      <div class="tiny">
        Bağlantı sonrası otomatik yönlendirme olur.
      </div>
    </div>
  </div>
  `;
  return res.status(200).send(pageShell("OTP", body));
});

app.post("/otp/verify", async (req, res) => {
  const otp_id = safeText(req.body.otp_id || "");
  const otp_in = safeText(req.body.otp || "").replace(/\s+/g, "");

  if (!otp_id || !otp_in) return res.status(400).send("missing otp");

  const ctx = await getOtpContext(otp_id);
  if (!ctx) return res.status(400).send("OTP expired. Back and retry.");

  const phone = ctx.phone || "";
  if (await isLockedPhone(phone)) {
    return res.status(429).send("Telefon geçici olarak kilitli. Biraz sonra tekrar deneyin.");
  }

  if (ctx.otp !== otp_in) {
    const wrong = await bumpWrong(phone);
    if (wrong >= MAX_WRONG_ATTEMPTS) await lockPhone(phone);

    await logEvent("OTP_VERIFY_FAIL", {
      first_name: ctx.first_name,
      last_name: ctx.last_name,
      phone: ctx.phone,
      kvkk_accepted: true,
      kvkk_version: ctx.kvkk_version,
      client_mac: ctx.client_mac,
      client_ip: ctx.client_ip,
      ssid: ctx.ssid,
      ap_name: ctx.ap_name,
      base_grant_url: ctx.base_grant_url,
      continue_url: ctx.continue_url,
      user_agent: ctx.user_agent,
      accept_language: ctx.accept_language,
      public_ip: ctx.public_ip,
      request_id: ctx.request_id,
      meta: { otp_id, wrong_attempts: wrong },
    });

    return res.status(401).send("Wrong code.");
  }

  // OK
  await clearWrong(phone);
  await consumeOtp(otp_id);

  console.log("OTP_VERIFY_OK", { otp_id, client_mac: ctx.client_mac || "" });

  await logEvent("OTP_VERIFIED", {
    first_name: ctx.first_name,
    last_name: ctx.last_name,
    phone: ctx.phone,
    kvkk_accepted: true,
    kvkk_version: ctx.kvkk_version,
    client_mac: ctx.client_mac,
    client_ip: ctx.client_ip,
    ssid: ctx.ssid,
    ap_name: ctx.ap_name,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url,
    user_continue_url: ctx.continue_url,
    user_agent: ctx.user_agent,
    accept_language: ctx.accept_language,
    public_ip: ctx.public_ip,
    request_id: ctx.request_id,
    meta: { otp_id },
  });

  // Meraki grant redirect
  if (!ctx.base_grant_url) {
    // Senin yaşadığın hata: artık context kaybolmaz, ama gerçekten gelmediyse kullanıcıya net söyleyelim
    return res.status(200).send("OTP verified but base_grant_url missing.");
  }

  const grantUrl = new URL(ctx.base_grant_url);
  // continue_url varsa ekle
  if (ctx.continue_url) grantUrl.searchParams.set("continue_url", ctx.continue_url);

  const final = grantUrl.toString();
  await logEvent("GRANT_CLIENT_REDIRECT", {
    phone: ctx.phone,
    client_mac: ctx.client_mac,
    client_ip: ctx.client_ip,
    kvkk_version: ctx.kvkk_version,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url,
    user_agent: ctx.user_agent,
    accept_language: ctx.accept_language,
    public_ip: ctx.public_ip,
    request_id: ctx.request_id,
    meta: { final },
  });

  console.log("GRANT_CLIENT_REDIRECT:", final);
  return res.redirect(302, final);
});

// ---------- Admin: logs UI ----------
app.get("/admin/logs", requireAdminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10), 1000);
  const tz = safeText(req.query.tz || TZ) || TZ;
  const format = String(req.query.format || "html");
  const day = safeText(req.query.day || "");

  // filtreler (son 24 saat / telefon / mac / ip)
  const phone = safeText(req.query.phone || "");
  const mac = safeText(req.query.mac || "");
  const ip = safeText(req.query.ip || "");
  const lastHours = Math.min(parseInt(req.query.hours || "24", 10), 168);

  const where = [];
  const params = [];
  let pi = 1;

  if (day) {
    // Türkiye saatine göre gün filtresi: created_at AT TIME ZONE
    where.push(`(created_at AT TIME ZONE $${pi++})::date = $${pi++}::date`);
    params.push(tz, day);
  } else {
    where.push(`created_at >= now() - ($${pi++}::int || ' hours')::interval`);
    params.push(lastHours);
  }
  if (phone) {
    where.push(`phone = $${pi++}`);
    params.push(phone);
  }
  if (mac) {
    where.push(`client_mac = $${pi++}`);
    params.push(mac);
  }
  if (ip) {
    where.push(`client_ip = $${pi++}`);
    params.push(ip);
  }

  const sql = `
    SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, kvkk_version
    FROM access_logs
    ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY id DESC
    LIMIT $${pi++}
  `;
  params.push(limit);

  const r = await q(sql, params);
  const rows = r.rows || [];

  if (format === "json") {
    return res.json({ limit, tz, rows });
  }

  const header = `
  <div class="adminWrap">
    <div class="topbar">
      <div class="left">
        <img src="/logo.png" alt="Odeon" onerror="this.style.display='none'"/>
        <div>
          <div style="font-weight:800">/admin/logs</div>
          <div style="font-size:12px; color:var(--muted)">limit=${limit} • tz=${escapeHtml(tz)} • hours=${lastHours}</div>
        </div>
      </div>
      <div class="controls">
        <form method="GET" action="/admin/logs" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center">
          <input name="limit" value="${escapeHtml(limit)}" />
          <input name="hours" value="${escapeHtml(lastHours)}" />
          <input name="phone" placeholder="telefon" value="${escapeHtml(phone)}" />
          <input name="mac" placeholder="mac" value="${escapeHtml(mac)}" />
          <input name="ip" placeholder="ip" value="${escapeHtml(ip)}" />
          <input name="day" placeholder="YYYY-MM-DD" value="${escapeHtml(day)}" />
          <input name="tz" value="${escapeHtml(tz)}" />
          <button class="btn2" type="submit">Refresh</button>
          <a class="btn2" href="/admin/daily">Daily</a>
          <a class="btn2" href="/admin/logs?format=json&limit=${limit}&hours=${lastHours}&tz=${encodeURIComponent(
            tz
          )}">JSON</a>
        </form>
      </div>
    </div>
  `;

  const table = `
    <table>
      <thead>
        <tr>
          <th>id</th>
          <th>time</th>
          <th>event</th>
          <th>name</th>
          <th>phone</th>
          <th>mac</th>
          <th>ip</th>
          <th>kvkk</th>
        </tr>
      </thead>
      <tbody>
        ${rows
          .map((x) => {
            const d = new Date(x.created_at);
            const name = [x.first_name, x.last_name].filter(Boolean).join(" ");
            return `<tr>
              <td>${escapeHtml(x.id)}</td>
              <td>${escapeHtml(formatTrTime(d, tz))}</td>
              <td>${escapeHtml(x.event)}</td>
              <td>${escapeHtml(name)}</td>
              <td>${escapeHtml(x.phone || "")}</td>
              <td>${escapeHtml(x.client_mac || "")}</td>
              <td>${escapeHtml(x.client_ip || "")}</td>
              <td>${escapeHtml(x.kvkk_version || "")}</td>
            </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  `;

  const foot = `
    <div style="margin-top:12px; font-size:12px; color:var(--muted)">
      5651: Günlük paket + hash-chain için <a href="/admin/daily">/admin/daily</a>
    </div>
  </div>`;

  return res.send(pageShell("Admin Logs", header + table + foot));
});

app.get("/admin/daily", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const today = new Date();
  const day = safeText(req.query.day || toISODate(today, tz));

  const body = `
  <div class="adminWrap">
    <div class="topbar">
      <div class="left">
        <img src="/logo.png" alt="Odeon" onerror="this.style.display='none'"/>
        <div>
          <div style="font-weight:800">/admin/daily</div>
          <div style="font-size:12px; color:var(--muted)">tz=${escapeHtml(tz)} • day=${escapeHtml(day)}</div>
        </div>
      </div>
      <div class="controls">
        <a class="btn2" href="/admin/logs">Logs</a>
      </div>
    </div>

    <div class="card" style="max-width:820px">
      <h1 style="margin-top:0">Günlük Paket / Hash / İmza</h1>
      <p>5651 için “değişmezlik” sağlamak adına: o günün kayıtları paketlenir, satır hash’leri ile day_hash üretilir, bir önceki gün ile zincirlenir (chain_hash) ve istenirse HMAC ile imzalanır.</p>

      <form method="GET" action="/admin/daily/build" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center">
        <input name="day" value="${escapeHtml(day)}" />
        <input name="tz" value="${escapeHtml(tz)}" />
        <button class="btn2" type="submit">Build</button>
        <a class="btn2" href="/admin/daily/verify?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Verify</a>
        <a class="btn2" href="/admin/daily/download?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Download</a>
      </form>

      <div class="tiny">DAILY_HMAC_SECRET: ${DAILY_HMAC_SET ? `<span class="ok">set</span>` : `<span class="err">not set</span>`}</div>
    </div>
  </div>
  `;
  res.send(pageShell("Daily", body));
});

// Build daily package + hash + chain + signature
app.get("/admin/daily/build", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required (YYYY-MM-DD)");

  try {
    const result = await buildDaily(day, tz);
    return res.json(result);
  } catch (e) {
    console.log("daily build error", e);
    return res.status(500).send("daily build error: " + e.message);
  }
});

app.get("/admin/daily/verify", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required (YYYY-MM-DD)");

  try {
    const result = await verifyDaily(day, tz);
    return res.json(result);
  } catch (e) {
    console.log("daily verify error", e);
    return res.status(500).send("daily verify error: " + e.message);
  }
});

app.get("/admin/daily/download", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required (YYYY-MM-DD)");

  try {
    const out = await exportDaily(day, tz);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="daily-${day}-${tz}.json"`);
    return res.send(JSON.stringify(out, null, 2));
  } catch (e) {
    return res.status(500).send("download error: " + e.message);
  }
});

// ---------- Daily builder / verifier ----------
function rowCanonical(r) {
  // 5651’de kritik alanlar: zaman + event + kimlik + mac/ip + meta
  // created_at kesin string olarak
  const obj = {
    id: r.id,
    created_at: new Date(r.created_at).toISOString(),
    event: r.event || "",
    first_name: r.first_name || "",
    last_name: r.last_name || "",
    phone: r.phone || "",
    client_mac: r.client_mac || "",
    client_ip: r.client_ip || "",
    ssid: r.ssid || "",
    ap_name: r.ap_name || "",
    kvkk_version: r.kvkk_version || "",
    base_grant_url: r.base_grant_url || "",
    continue_url: r.continue_url || "",
    public_ip: r.public_ip || "",
    user_agent: r.user_agent || "",
    accept_language: r.accept_language || "",
    request_id: r.request_id || "",
    meta: r.meta || null,
  };
  return JSON.stringify(obj);
}

async function getRowsForDay(day, tz) {
  // created_at'ı tz'e göre güne çevirip filtreliyoruz
  const sql = `
    SELECT *
    FROM access_logs
    WHERE (created_at AT TIME ZONE $1)::date = $2::date
    ORDER BY id ASC
  `;
  const r = await q(sql, [tz, day]);
  return r.rows || [];
}

async function buildDaily(day, tz) {
  const rows = await getRowsForDay(day, tz);

  // satır hashleri
  const row_hashes = rows.map((r) => sha256Hex(rowCanonical(r)));

  // day_hash: tüm satır hashlerini sırayla birleştir + sha
  const day_hash = sha256Hex(row_hashes.join("\n"));

  // prev chain: bir önceki gün için kayıt (yoksa null)
  const prev = await q(
    `SELECT chain_hash FROM daily_chains WHERE (day::date) = ($1::date - interval '1 day')::date AND tz = $2 LIMIT 1`,
    [day, tz]
  );
  const prev_chain_hash = prev.rows[0] ? prev.rows[0].chain_hash : null;

  const chain_hash = sha256Hex((prev_chain_hash || "") + "|" + day_hash);

  const signature_hmac = DAILY_HMAC_SET ? hmacHex(DAILY_HMAC_SECRET, chain_hash) : null;
  const signer = DAILY_HMAC_SET ? "HMAC-SHA256" : null;

  // paket kaydı
  const package_json = {
    day,
    tz,
    record_count: rows.length,
    algo: "sha256",
    day_hash,
    prev_chain_hash,
    chain_hash,
    signature_hmac,
    signer,
    generated_at: nowIso(),
    rows: rows.map((r, i) => ({
      ...r,
      row_hash: row_hashes[i],
    })),
  };

  // upsert daily_packages
  await q(
    `
    INSERT INTO daily_packages(day, tz, record_count, package_json)
    VALUES ($1::date, $2, $3, $4::jsonb)
    ON CONFLICT(day, tz)
    DO UPDATE SET record_count=EXCLUDED.record_count, package_json=EXCLUDED.package_json, created_at=now()
    `,
    [day, tz, rows.length, JSON.stringify(package_json)]
  );

  // upsert daily_hashes
  await q(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash, algo)
    VALUES ($1::date, $2, $3, $4, 'sha256')
    ON CONFLICT(day, tz)
    DO UPDATE SET record_count=EXCLUDED.record_count, day_hash=EXCLUDED.day_hash, created_at=now(), algo='sha256'
    `,
    [day, tz, rows.length, day_hash]
  );

  // upsert daily_chains
  await q(
    `
    INSERT INTO daily_chains(day, tz, prev_chain_hash, chain_hash, signature_hmac, signer, algo)
    VALUES ($1::date, $2, $3, $4, $5, $6, 'sha256')
    ON CONFLICT(day, tz)
    DO UPDATE SET prev_chain_hash=EXCLUDED.prev_chain_hash, chain_hash=EXCLUDED.chain_hash, signature_hmac=EXCLUDED.signature_hmac, signer=EXCLUDED.signer, created_at=now(), algo='sha256'
    `,
    [day, tz, prev_chain_hash, chain_hash, signature_hmac, signer]
  );

  return {
    ok: true,
    day,
    tz,
    record_count: rows.length,
    day_hash,
    prev_day_chain_hash: prev_chain_hash,
    chain_hash,
    signature_hmac,
    signer,
  };
}

async function verifyDaily(day, tz) {
  // DB'deki kayıtları tekrar hesapla, DB'deki daily_* ile karşılaştır
  const rows = await getRowsForDay(day, tz);
  const row_hashes = rows.map((r) => sha256Hex(rowCanonical(r)));
  const day_hash_calc = sha256Hex(row_hashes.join("\n"));

  const dh = await q(`SELECT day_hash, record_count FROM daily_hashes WHERE day::date=$1::date AND tz=$2 LIMIT 1`, [
    day,
    tz,
  ]);
  const dc = await q(
    `SELECT prev_chain_hash, chain_hash, signature_hmac, signer FROM daily_chains WHERE day::date=$1::date AND tz=$2 LIMIT 1`,
    [day, tz]
  );

  const db_day_hash = dh.rows[0] ? dh.rows[0].day_hash : null;
  const db_record_count = dh.rows[0] ? dh.rows[0].record_count : null;

  const prev_chain_hash = dc.rows[0] ? dc.rows[0].prev_chain_hash : null;
  const chain_hash_db = dc.rows[0] ? dc.rows[0].chain_hash : null;
  const sig_db = dc.rows[0] ? dc.rows[0].signature_hmac : null;

  const chain_hash_calc = sha256Hex((prev_chain_hash || "") + "|" + day_hash_calc);
  const sig_calc = DAILY_HMAC_SET ? hmacHex(DAILY_HMAC_SECRET, chain_hash_calc) : null;

  return {
    ok: true,
    day,
    tz,
    record_count_calc: rows.length,
    record_count_db: db_record_count,
    day_hash_calc,
    day_hash_db,
    day_hash_match: !!db_day_hash && db_day_hash === day_hash_calc,
    chain_hash_calc,
    chain_hash_db,
    chain_hash_match: !!chain_hash_db && chain_hash_db === chain_hash_calc,
    signature_db: sig_db,
    signature_calc: sig_calc,
    signature_match: !!sig_db && !!sig_calc && sig_db === sig_calc,
    note: DAILY_HMAC_SET ? "HMAC signature verified (if match=true)" : "DAILY_HMAC_SECRET not set; signature check skipped",
  };
}

async function exportDaily(day, tz) {
  // İndirilebilir paket: daily_packages varsa onu döndür, yoksa build edip döndür
  const r = await q(`SELECT package_json FROM daily_packages WHERE day::date=$1::date AND tz=$2 LIMIT 1`, [day, tz]);
  if (r.rows[0] && r.rows[0].package_json) return r.rows[0].package_json;
  await buildDaily(day, tz);
  const r2 = await q(`SELECT package_json FROM daily_packages WHERE day::date=$1::date AND tz=$2 LIMIT 1`, [day, tz]);
  return r2.rows[0] ? r2.rows[0].package_json : { error: "package not found" };
}

// ---------- helpers ----------
function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTrTime(d, tz) {
  try {
    // basit format: DD.MM.YYYY HH:mm:ss (tz)
    const parts = new Intl.DateTimeFormat("tr-TR", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d);
    const get = (t) => parts.find((p) => p.type === t)?.value || "";
    return `${get("day")}.${get("month")}.${get("year")} ${get("hour")}:${get("minute")}:${get("second")}`;
  } catch {
    return d.toISOString();
  }
}

function toISODate(d, tz) {
  // tz'e göre bugün YYYY-MM-DD
  try {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(d);
    const y = parts.find((p) => p.type === "year")?.value || "1970";
    const m = parts.find((p) => p.type === "month")?.value || "01";
    const da = parts.find((p) => p.type === "day")?.value || "01";
    return `${y}-${m}-${da}`;
  } catch {
    return d.toISOString().slice(0, 10);
  }
}

// ---------- start ----------
(async () => {
  try {
    await ensureSchema();
    console.log("DATABASE: connected");
  } catch (e) {
    console.error("DB init failed:", e);
    process.exit(1);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
