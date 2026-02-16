/**
 * meraki-sms-splash - single file server.js
 * Features:
 * - Meraki Splash (GET /): captures base_grant_url, continue_url, client_mac, client_ip, gateway/node ids
 * - OTP (mode=screen): generates OTP, shows on UI (also logs OTP_SCREEN_CODE)
 * - Postgres logging (5651-ish): access_logs table, append-only, meta json
 * - Admin UI:
 *    - GET /admin/logs (HTML table)  /admin/logs?format=json
 *    - GET /admin/daily/build?day=YYYY-MM-DD
 *    - GET /admin/daily/export?day=YYYY-MM-DD&format=csv|json
 *    - GET /admin/daily/verify?day=YYYY-MM-DD
 * - Daily hash chain + signature:
 *    - day_hash = SHA256(canonical-json-lines of that day’s records)
 *    - chain_hash = SHA256(prev_chain_hash + "\n" + day_hash)  (prev from previous day row)
 *    - signature:
 *        - if DAILY_HMAC_SECRET set: HMAC-SHA256(chain_hash)
 *        - else: null (placeholder)
 *
 * ENV:
 * - PORT=8080
 * - TZ=Europe/Istanbul
 * - DATABASE_URL=postgres://...
 * - REDIS_URL=redis://... (optional)
 * - OTP_MODE=screen (default)
 * - OTP_TTL_SECONDS=180
 * - RL_MAC_SECONDS=30
 * - RL_PHONE_SECONDS=60
 * - MAX_WRONG_ATTEMPTS=5
 * - LOCK_SECONDS=600
 * - KVKK_VERSION=2026-02-12-placeholder
 * - ADMIN_USER=admin
 * - ADMIN_PASS=strongpassword
 * - DAILY_HMAC_SECRET=...   (recommended for “imza”)
 */

"use strict";

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

// ioredis optional (do NOT crash if missing)
let Redis = null;
try {
  // eslint-disable-next-line import/no-extraneous-dependencies
  Redis = require("ioredis");
} catch (e) {
  Redis = null;
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));

// -------------------- ENV --------------------
const ENV = {
  PORT: parseInt(process.env.PORT || "8080", 10),
  TZ: process.env.TZ || "Europe/Istanbul",
  OTP_MODE: process.env.OTP_MODE || "screen",
  OTP_TTL_SECONDS: parseInt(process.env.OTP_TTL_SECONDS || "180", 10),
  RL_MAC_SECONDS: parseInt(process.env.RL_MAC_SECONDS || "30", 10),
  RL_PHONE_SECONDS: parseInt(process.env.RL_PHONE_SECONDS || process.env.RL_MSISDN_SECONDS || "60", 10),
  MAX_WRONG_ATTEMPTS: parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10),
  LOCK_SECONDS: parseInt(process.env.LOCK_SECONDS || "600", 10),
  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",
  ADMIN_USER: process.env.ADMIN_USER || "",
  ADMIN_PASS: process.env.ADMIN_PASS || "",
  DATABASE_URL: process.env.DATABASE_URL || "",
  REDIS_URL: process.env.REDIS_URL || "",
  DAILY_HMAC_SECRET: process.env.DAILY_HMAC_SECRET || "",
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
  ADMIN_USER_SET: !!ENV.ADMIN_USER,
  ADMIN_PASS_SET: !!ENV.ADMIN_PASS,
  REDIS_SET: !!ENV.REDIS_URL,
  DB_SET: !!ENV.DATABASE_URL,
  DAILY_HMAC_SET: !!ENV.DAILY_HMAC_SECRET,
});

// -------------------- helpers --------------------
function sha256Hex(bufOrStr) {
  return crypto.createHash("sha256").update(bufOrStr).digest("hex");
}
function hmacSha256Hex(secret, msg) {
  return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}
function nowIso() {
  return new Date().toISOString();
}
function toDayStr(date = new Date()) {
  return date.toISOString().slice(0, 10);
}
function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}
function escHtml(s) {
  return safeStr(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
function fmtTimeTR(iso, tz) {
  try {
    return new Date(iso).toLocaleString("tr-TR", { timeZone: tz });
  } catch {
    return safeStr(iso);
  }
}
function randomDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += Math.floor(Math.random() * 10);
  return out;
}
function normalizePhone(p) {
  const raw = safeStr(p).trim();
  if (!raw) return "";
  // keep + and digits
  let cleaned = raw.replace(/[^\d+]/g, "");
  // if starts with 0 and length 11 -> TR local 0XXXXXXXXXX => +90XXXXXXXXXX
  if (cleaned.startsWith("0") && cleaned.length === 11) cleaned = "+90" + cleaned.slice(1);
  // if starts with 90 and no plus
  if (/^90\d{10}$/.test(cleaned)) cleaned = "+" + cleaned;
  // if starts with 5XXXXXXXXX (10 digits) => assume TR mobile
  if (/^5\d{9}$/.test(cleaned)) cleaned = "+90" + cleaned;
  return cleaned;
}
function last4(phone) {
  const d = safeStr(phone).replace(/[^\d]/g, "");
  return d.slice(-4);
}
function getClientPublicIP(req) {
  // behind proxy - Railway sets x-forwarded-for
  const xf = req.headers["x-forwarded-for"];
  if (xf) return safeStr(xf).split(",")[0].trim();
  return safeStr(req.socket?.remoteAddress || "");
}

// -------------------- Postgres --------------------
let pool = null;

async function qRows(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}
async function qExec(sql, params = []) {
  await pool.query(sql, params);
}

async function ensureDb() {
  if (!ENV.DATABASE_URL) throw new Error("DATABASE_URL missing");
  pool = new Pool({
    connectionString: ENV.DATABASE_URL,
    ssl: ENV.DATABASE_URL.includes("sslmode=") ? undefined : { rejectUnauthorized: false },
    max: 5,
  });

  await qExec("SELECT 1");
  console.log("DATABASE: connected");

  // access logs table
  await qExec(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      first_name TEXT NULL,
      last_name TEXT NULL,
      phone TEXT NULL,
      kvkk_accepted BOOLEAN NULL,
      kvkk_version TEXT NULL,
      marker TEXT NULL,
      client_mac TEXT NULL,
      client_ip TEXT NULL,
      ssid TEXT NULL,
      ap_name TEXT NULL,
      base_grant_url TEXT NULL,
      continue_url TEXT NULL,
      full_name TEXT NULL,
      user_agent TEXT NULL,
      accept_language TEXT NULL,
      public_ip TEXT NULL,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  // daily chains table
  await qExec(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day TEXT PRIMARY KEY,
      tz TEXT NOT NULL,
      record_count INT NOT NULL,
      day_hash TEXT NOT NULL,
      prev_day_hash TEXT NULL,
      chain_hash TEXT NOT NULL,
      signature TEXT NULL,
      signature_alg TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  console.log("DATABASE: table ready");
}

// -------------------- Redis (optional) + in-memory fallback --------------------
let redis = null;
const mem = {
  otp: new Map(),        // key => {otp, exp, marker, phone, first_name,last_name, kvkk_accepted, kvkk_version, base, cont, client_mac, client_ip, ua, lang, public_ip, wrong, locked_until}
  rateMac: new Map(),    // mac => exp
  ratePhone: new Map(),  // phone => exp
};

function memGet(map, key) {
  const it = map.get(key);
  if (!it) return null;
  if (it.exp && Date.now() > it.exp) {
    map.delete(key);
    return null;
  }
  return it;
}
function memSet(map, key, val, ttlSec) {
  map.set(key, { ...val, exp: Date.now() + ttlSec * 1000 });
}

async function ensureRedis() {
  if (!ENV.REDIS_URL || !Redis) {
    console.log("REDIS: not configured or ioredis missing (fallback to memory)");
    return;
  }
  redis = new Redis(ENV.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await redis.connect();
  console.log("REDIS: connected");
}

async function storeOtp(key, obj) {
  if (redis) {
    await redis.set(`otp:${key}`, JSON.stringify(obj), "EX", ENV.OTP_TTL_SECONDS);
    return;
  }
  memSet(mem.otp, key, obj, ENV.OTP_TTL_SECONDS);
}
async function loadOtp(key) {
  if (redis) {
    const v = await redis.get(`otp:${key}`);
    return v ? JSON.parse(v) : null;
  }
  return memGet(mem.otp, key);
}
async function deleteOtp(key) {
  if (redis) {
    await redis.del(`otp:${key}`);
    return;
  }
  mem.otp.delete(key);
}
async function rateLimit(mapName, key, seconds) {
  if (!key) return false;
  const now = Date.now();
  if (redis) {
    const rk = `rl:${mapName}:${key}`;
    const ok = await redis.set(rk, "1", "NX", "EX", seconds);
    return ok !== "OK";
  }
  const map = mapName === "mac" ? mem.rateMac : mem.ratePhone;
  const it = memGet(map, key);
  if (it) return true;
  memSet(map, key, { v: 1 }, seconds);
  return false;
}

// -------------------- Logging --------------------
async function logEvent(evt) {
  // evt fields: event, first_name,last_name, phone, kvkk_accepted, kvkk_version, marker, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, full_name, user_agent, accept_language, public_ip, meta
  const e = {
    event: evt.event,
    first_name: evt.first_name ?? null,
    last_name: evt.last_name ?? null,
    phone: evt.phone ?? null,
    kvkk_accepted: evt.kvkk_accepted ?? null,
    kvkk_version: evt.kvkk_version ?? null,
    marker: evt.marker ?? null,
    client_mac: evt.client_mac ?? null,
    client_ip: evt.client_ip ?? null,
    ssid: evt.ssid ?? null,
    ap_name: evt.ap_name ?? null,
    base_grant_url: evt.base_grant_url ?? null,
    continue_url: evt.continue_url ?? null,
    full_name: evt.full_name ?? null,
    user_agent: evt.user_agent ?? null,
    accept_language: evt.accept_language ?? null,
    public_ip: evt.public_ip ?? null,
    meta: evt.meta ?? {},
  };

  try {
    await qExec(
      `INSERT INTO access_logs(
        event, first_name, last_name, phone, kvkk_accepted, kvkk_version, marker,
        client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, full_name,
        user_agent, accept_language, public_ip, meta
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,$12,$13,$14,
        $15,$16,$17,$18::jsonb
      )`,
      [
        e.event, e.first_name, e.last_name, e.phone, e.kvkk_accepted, e.kvkk_version, e.marker,
        e.client_mac, e.client_ip, e.ssid, e.ap_name, e.base_grant_url, e.continue_url, e.full_name,
        e.user_agent, e.accept_language, e.public_ip, JSON.stringify(e.meta),
      ]
    );
  } catch (err) {
    console.error("DB LOG ERROR:", err?.message || err);
  }
}

// -------------------- Admin Basic Auth --------------------
function requireBasicAuth(req, res, next) {
  const user = ENV.ADMIN_USER;
  const pass = ENV.ADMIN_PASS;
  if (!user || !pass) return res.status(503).send("Admin auth is not configured (ADMIN_USER/ADMIN_PASS).");

  const h = req.headers.authorization || "";
  if (!h.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin"');
    return res.status(401).send("Auth required");
  }
  const [u, p] = Buffer.from(h.slice(6), "base64").toString("utf8").split(":");
  if (u !== user || p !== pass) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin"');
    return res.status(401).send("Invalid credentials");
  }
  next();
}

// -------------------- Meraki query parsing --------------------
function parseMerakiParams(req) {
  // Meraki passes a bunch of params. Keep everything in meta.rawQuery too.
  const q = req.query || {};
  const base_grant_url = safeStr(q.base_grant_url || q.base_grant || "");
  const continue_url = safeStr(q.continue_url || q.user_continue_url || q.continue || "");
  const client_mac = safeStr(q.client_mac || q.clientMac || "");
  const client_ip = safeStr(q.client_ip || q.clientIp || "");
  const gateway_id = safeStr(q.gateway_id || "");
  const node_id = safeStr(q.node_id || "");
  const node_mac = safeStr(q.node_mac || "");
  const ssid = safeStr(q.ssid || "");
  const ap_name = safeStr(q.ap_name || q.apName || "");
  return {
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    gateway_id,
    node_id,
    node_mac,
    ssid,
    ap_name,
    raw: q,
  };
}

function buildGrantClientRedirect(baseGrantUrl, originalQuery, continueUrl) {
  // If base_grant_url already includes /grant?..., keep it.
  // Else if it's a base URL, append /grant
  let url = baseGrantUrl || "";
  if (!url) return "";

  // If base_grant_url is like ".../grant" or ".../grant?..."
  const hasGrant = /\/grant(\?|$)/.test(url);
  if (!hasGrant) {
    url = url.replace(/\/$/, "") + "/grant";
  }

  // Rebuild query string using original query keys (gateway_id,node_id,client_ip,client_mac,node_mac,...)
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(originalQuery || {})) {
    if (v === undefined || v === null) continue;
    if (k === "base_grant_url") continue;
    params.set(k, safeStr(v));
  }
  if (continueUrl) params.set("continue_url", continueUrl);

  return `${url}?${params.toString()}`;
}

// -------------------- UI pages --------------------
function renderSplashPage(ctx) {
  // ctx: { base_grant_url, continue_url, client_mac, client_ip, marker, otp, kvkk_version }
  const showOtp = ENV.OTP_MODE === "screen" ? `<div class="otpbox">
      <div class="muted">OTP (screen mode):</div>
      <div class="otp">${escHtml(ctx.otp || "—")}</div>
    </div>` : "";

  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Guest WiFi</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b1020;color:#e8e8e8}
  .card{width:min(560px,92vw);background:#111a33;border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
  h1{margin:0 0 6px 0;font-size:22px}
  .muted{opacity:.7;font-size:13px}
  label{display:block;margin-top:12px;font-size:13px;opacity:.9}
  input{width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:#0f1730;color:#fff;outline:none}
  input:focus{border-color:rgba(99,102,241,.8)}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .btn{margin-top:14px;width:100%;padding:11px 14px;border-radius:12px;border:0;background:#4f46e5;color:#fff;font-weight:700;cursor:pointer}
  .btn:disabled{opacity:.5;cursor:not-allowed}
  .kvkk{display:flex;gap:10px;align-items:flex-start;margin-top:12px}
  .kvkk input{width:auto;margin-top:3px}
  .otpbox{margin-top:14px;padding:12px;border-radius:12px;background:#0f1730;border:1px solid rgba(255,255,255,.08)}
  .otp{font-size:28px;font-weight:900;letter-spacing:3px;margin-top:4px}
  .tiny{font-size:12px;opacity:.75;margin-top:8px}
  .err{margin-top:10px;color:#fca5a5}
</style>
</head>
<body>
  <div class="card">
    <h1>Misafir Wi-Fi</h1>
    <div class="muted">Bağlantı için bilgileri girip onaylayın.</div>

    <form method="POST" action="/otp/request">
      <input type="hidden" name="base_grant_url" value="${escHtml(ctx.base_grant_url)}"/>
      <input type="hidden" name="continue_url" value="${escHtml(ctx.continue_url)}"/>
      <input type="hidden" name="client_mac" value="${escHtml(ctx.client_mac)}"/>
      <input type="hidden" name="client_ip" value="${escHtml(ctx.client_ip)}"/>

      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" placeholder="Ad" required />
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" placeholder="Soyad" required />
        </div>
      </div>

      <label>Cep Telefonu</label>
      <input name="phone" placeholder="+905XXXXXXXXX" required />

      <div class="kvkk">
        <input id="kvkk" type="checkbox" name="kvkk_accepted" value="true" required />
        <label for="kvkk">
          <div><b>KVKK Aydınlatma Metni</b>’ni okudum ve kabul ediyorum.</div>
          <div class="tiny">Versiyon: ${escHtml(ctx.kvkk_version)}</div>
        </label>
      </div>

      <button class="btn" type="submit">OTP Oluştur</button>
      <div class="tiny">Not: OTP ekran modunda ise kod bu sayfada görüntülenir.</div>
    </form>

    ${showOtp}

    <hr style="border:0;border-top:1px solid rgba(255,255,255,.08);margin:16px 0"/>

    <form method="POST" action="/otp/verify">
      <input type="hidden" name="marker" value="${escHtml(ctx.marker || "")}"/>
      <label>OTP Kodu</label>
      <input name="otp" placeholder="6 haneli" required />

      <button class="btn" type="submit" ${ctx.marker ? "" : "disabled"}>Bağlan</button>
      ${ctx.marker ? `<div class="tiny">Marker: ${escHtml(ctx.marker)}</div>` : `<div class="err">Önce OTP Oluştur’a basın.</div>`}
    </form>
  </div>
</body>
</html>`;
}

// -------------------- Routes --------------------
app.get("/health", (req, res) => res.json({ ok: true, time: nowIso() }));

// Splash entry
app.get("/", async (req, res) => {
  const m = parseMerakiParams(req);
  const ua = safeStr(req.headers["user-agent"] || "");
  const lang = safeStr(req.headers["accept-language"] || "");
  const public_ip = getClientPublicIP(req);

  console.log("SPLASH_OPEN", {
    hasBaseGrant: !!m.base_grant_url,
    hasContinue: !!m.continue_url,
    hasClientMac: !!m.client_mac,
    mode: ENV.OTP_MODE,
  });

  await logEvent({
    event: "SPLASH_OPEN",
    client_mac: m.client_mac,
    client_ip: m.client_ip,
    ssid: m.ssid,
    ap_name: m.ap_name,
    base_grant_url: m.base_grant_url,
    continue_url: m.continue_url,
    user_agent: ua,
    accept_language: lang,
    public_ip,
    kvkk_version: ENV.KVKK_VERSION,
    meta: { rawQuery: m.raw },
  });

  // Render base page (no marker yet)
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(
    renderSplashPage({
      base_grant_url: m.base_grant_url,
      continue_url: m.continue_url,
      client_mac: m.client_mac,
      client_ip: m.client_ip,
      marker: "",
      otp: "",
      kvkk_version: ENV.KVKK_VERSION,
    })
  );
});

// Request OTP
app.post("/otp/request", async (req, res) => {
  const base_grant_url = safeStr(req.body.base_grant_url || "");
  const continue_url = safeStr(req.body.continue_url || "");
  const client_mac = safeStr(req.body.client_mac || "");
  const client_ip = safeStr(req.body.client_ip || "");
  const first_name = safeStr(req.body.first_name || "").trim();
  const last_name = safeStr(req.body.last_name || "").trim();
  const phone = normalizePhone(req.body.phone || "");
  const kvkk_accepted = safeStr(req.body.kvkk_accepted) === "true" || safeStr(req.body.kvkk_accepted) === "on";
  const ua = safeStr(req.headers["user-agent"] || "");
  const lang = safeStr(req.headers["accept-language"] || "");
  const public_ip = getClientPublicIP(req);

  // Rate limits
  if (await rateLimit("mac", client_mac, ENV.RL_MAC_SECONDS)) {
    return res.status(429).send("Çok sık deneme (MAC). Lütfen bekleyin.");
  }
  if (await rateLimit("phone", phone, ENV.RL_PHONE_SECONDS)) {
    return res.status(429).send("Çok sık deneme (Telefon). Lütfen bekleyin.");
  }

  const marker = randomDigits(6);
  const otp = randomDigits(6);
  const key = marker; // simplest: marker is lookup key

  const obj = {
    marker,
    otp,
    first_name,
    last_name,
    phone,
    kvkk_accepted,
    kvkk_version: ENV.KVKK_VERSION,
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    ua,
    lang,
    public_ip,
    wrong: 0,
    locked_until: 0,
    created_at: nowIso(),
  };
  await storeOtp(key, obj);

  console.log("OTP_CREATED", { marker, last4: last4(phone), client_mac });
  await logEvent({
    event: "OTP_CREATED",
    first_name,
    last_name,
    phone,
    kvkk_accepted,
    kvkk_version: ENV.KVKK_VERSION,
    marker,
    client_mac,
    client_ip,
    base_grant_url,
    continue_url,
    full_name: [first_name, last_name].filter(Boolean).join(" "),
    user_agent: ua,
    accept_language: lang,
    public_ip,
    meta: { otp_mode: ENV.OTP_MODE },
  });

  if (ENV.OTP_MODE === "screen") {
    console.log("OTP_SCREEN_CODE", { marker, otp });
    await logEvent({
      event: "OTP_SCREEN_CODE",
      marker,
      client_mac,
      client_ip,
      phone,
      kvkk_version: ENV.KVKK_VERSION,
      meta: { otp },
    });
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(
    renderSplashPage({
      base_grant_url,
      continue_url,
      client_mac,
      client_ip,
      marker,
      otp: ENV.OTP_MODE === "screen" ? otp : "",
      kvkk_version: ENV.KVKK_VERSION,
    })
  );
});

// Verify OTP and grant
app.post("/otp/verify", async (req, res) => {
  const marker = safeStr(req.body.marker || "").trim();
  const otpIn = safeStr(req.body.otp || "").trim();
  if (!marker) return res.status(400).send("marker missing");

  const obj = await loadOtp(marker);
  if (!obj) return res.status(400).send("OTP süresi doldu / bulunamadı.");

  // Lock check
  if (obj.locked_until && Date.now() < obj.locked_until) {
    return res.status(429).send("Çok fazla yanlış deneme. Bir süre bekleyin.");
  }

  if (otpIn !== obj.otp) {
    obj.wrong = (obj.wrong || 0) + 1;
    if (obj.wrong >= ENV.MAX_WRONG_ATTEMPTS) {
      obj.locked_until = Date.now() + ENV.LOCK_SECONDS * 1000;
    }
    await storeOtp(marker, obj);

    await logEvent({
      event: "OTP_WRONG",
      marker,
      client_mac: obj.client_mac,
      client_ip: obj.client_ip,
      phone: obj.phone,
      kvkk_version: obj.kvkk_version,
      meta: { wrong: obj.wrong, locked_until: obj.locked_until ? new Date(obj.locked_until).toISOString() : null },
    });

    return res.status(401).send("OTP hatalı.");
  }

  console.log("OTP_VERIFY_OK", { marker, client_mac: obj.client_mac });
  await logEvent({
    event: "OTP_VERIFIED",
    marker,
    client_mac: obj.client_mac,
    client_ip: obj.client_ip,
    phone: obj.phone,
    first_name: obj.first_name,
    last_name: obj.last_name,
    kvkk_accepted: obj.kvkk_accepted,
    kvkk_version: obj.kvkk_version,
    full_name: [obj.first_name, obj.last_name].filter(Boolean).join(" "),
    user_agent: obj.ua,
    accept_language: obj.lang,
    public_ip: obj.public_ip,
    meta: {},
  });

  // Build grant redirect
  // We do client-side redirect to Meraki /grant with original params + continue_url
  const originalQuery = {}; // we don't have original query keys now; but we can reconstruct minimal:
  // If base_grant_url is provided by Meraki, it usually already has required tokens embedded in its path.
  // However, some deployments require gateway_id/node_id/client_mac/client_ip/node_mac in query.
  // We preserved them inside continue_url sometimes; but safest: keep base_grant_url as received (can include tokens).
  // Here we append common parameters if present in stored meta.rawQuery? Not stored. We'll pass only continue_url.
  // Many Meraki splash flows accept that because base_grant_url is already bound to session.
  // If you need exact params, keep them in hidden fields and store; you can extend obj.meta.
  const grantUrl = buildGrantClientRedirect(obj.base_grant_url, originalQuery, obj.continue_url);

  if (!grantUrl) {
    // fallback: just show success
    await deleteOtp(marker);
    return res.status(200).send("OTP OK ama base_grant_url yok. Meraki parametrelerini kontrol edin.");
  }

  await logEvent({
    event: "GRANT_CLIENT_REDIRECT",
    marker,
    client_mac: obj.client_mac,
    client_ip: obj.client_ip,
    phone: obj.phone,
    kvkk_version: obj.kvkk_version,
    meta: { grant_url: grantUrl },
  });

  console.log("GRANT_CLIENT_REDIRECT:", grantUrl);

  await deleteOtp(marker);

  // Redirect user to Meraki grant
  res.redirect(302, grantUrl);
});

// -------------------- Admin: logs (HTML by default; JSON with ?format=json) --------------------
app.get("/admin/logs", requireBasicAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 2000);
  const format = safeStr(req.query.format || "").toLowerCase();

  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     ORDER BY id DESC
     LIMIT $1`,
    [limit]
  );

  if (format === "json") return res.json(rows);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>/admin/logs</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:16px;background:#0b1020;color:#e8e8e8}
  .top{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:12px}
  .btn{background:#4f46e5;border:0;padding:8px 12px;border-radius:10px;cursor:pointer;color:#fff;font-weight:700}
  .card{background:#111a33;border:1px solid rgba(255,255,255,.08);border-radius:14px;overflow:hidden}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
  th{position:sticky;top:0;background:#0f1730;text-align:left}
  tr:hover td{background:rgba(255,255,255,.03)}
  .muted{opacity:.7}
  .nowrap{white-space:nowrap}
  a{color:#fff}
</style>
</head>
<body>
  <div class="top">
    <div>
      <div style="font-size:20px;font-weight:800">/admin/logs</div>
      <div class="muted">limit=${limit} • tz=${escHtml(ENV.TZ)} • <a href="/admin/logs?limit=${limit}&format=json">JSON</a></div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn" onclick="location.reload()">Refresh</button>
      <button class="btn" onclick="location.href='/admin/daily/build?day=' + new Date().toISOString().slice(0,10)">Daily</button>
    </div>
  </div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th class="nowrap">id</th>
          <th class="nowrap">time</th>
          <th>event</th>
          <th>name</th>
          <th>phone</th>
          <th class="nowrap">mac</th>
          <th class="nowrap">ip</th>
          <th class="nowrap">marker</th>
          <th class="nowrap">kvkk</th>
        </tr>
      </thead>
      <tbody>
        ${rows
          .map((r) => {
            const name = [r.first_name, r.last_name].filter(Boolean).join(" ");
            return `<tr>
              <td class="nowrap">${escHtml(r.id)}</td>
              <td class="nowrap">${escHtml(fmtTimeTR(r.created_at, ENV.TZ))}</td>
              <td>${escHtml(r.event)}</td>
              <td>${escHtml(name)}</td>
              <td class="nowrap">${escHtml(r.phone)}</td>
              <td class="nowrap">${escHtml(r.client_mac)}</td>
              <td class="nowrap">${escHtml(r.client_ip)}</td>
              <td class="nowrap">${escHtml(r.marker)}</td>
              <td class="nowrap">${escHtml(r.kvkk_version)}</td>
            </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  </div>
</body>
</html>`);
});

// -------------------- Daily chain build/export/verify --------------------
function canonicalRecordForChain(r) {
  // IMPORTANT: stable key order
  // Only include “log integrity” fields (change carefully)
  return {
    id: r.id,
    created_at: new Date(r.created_at).toISOString(),
    event: r.event,
    first_name: r.first_name,
    last_name: r.last_name,
    phone: r.phone,
    client_mac: r.client_mac,
    client_ip: r.client_ip,
    marker: r.marker,
    kvkk_version: r.kvkk_version,
  };
}

async function buildDaily(day) {
  const tz = ENV.TZ;
  const dayStart = `${day}T00:00:00.000Z`;
  const dayEnd = `${day}T23:59:59.999Z`;

  // We store created_at in UTC; daily bucket by day string (UTC day).
  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     WHERE created_at >= $1::timestamptz AND created_at <= $2::timestamptz
     ORDER BY id ASC`,
    [dayStart, dayEnd]
  );

  // canonical JSON-lines
  const lines = rows.map((r) => JSON.stringify(canonicalRecordForChain(r)));
  const payload = lines.join("\n") + "\n"; // newline-terminated
  const day_hash = sha256Hex(payload);

  // prev day row
  const prevDay = new Date(new Date(day + "T00:00:00Z").getTime() - 86400000);
  const prevDayStr = toDayStr(prevDay);
  const prev = await qRows(`SELECT day_hash, chain_hash FROM daily_chains WHERE day=$1`, [prevDayStr]);
  const prev_day_hash = prev[0]?.day_hash || null;
  const prev_chain_hash = prev[0]?.chain_hash || "";

  const chain_hash = sha256Hex(`${prev_chain_hash}\n${day_hash}`);

  let signature = null;
  let signature_alg = null;
  if (ENV.DAILY_HMAC_SECRET) {
    signature = hmacSha256Hex(ENV.DAILY_HMAC_SECRET, chain_hash);
    signature_alg = "HMAC-SHA256(chain_hash)";
  } else {
    signature = null;
    signature_alg = "PLACEHOLDER";
  }

  // upsert daily
  await qExec(
    `INSERT INTO daily_chains(day, tz, record_count, day_hash, prev_day_hash, chain_hash, signature, signature_alg)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT(day) DO UPDATE SET
       tz=EXCLUDED.tz,
       record_count=EXCLUDED.record_count,
       day_hash=EXCLUDED.day_hash,
       prev_day_hash=EXCLUDED.prev_day_hash,
       chain_hash=EXCLUDED.chain_hash,
       signature=EXCLUDED.signature,
       signature_alg=EXCLUDED.signature_alg`,
    [day, tz, rows.length, day_hash, prev_day_hash, chain_hash, signature, signature_alg]
  );

  return {
    day,
    tz,
    record_count: rows.length,
    day_hash,
    prev_day_hash,
    chain_hash,
    signature,
    signature_alg,
  };
}

app.get("/admin/daily/build", requireBasicAuth, async (req, res) => {
  const day = safeStr(req.query.day || "").trim() || toDayStr();
  const out = await buildDaily(day);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(out, null, 2) + `\n\n<a href="/admin/logs">Back</a>`);
});

app.get("/admin/daily/export", requireBasicAuth, async (req, res) => {
  const day = safeStr(req.query.day || "").trim() || toDayStr();
  const format = safeStr(req.query.format || "csv").toLowerCase();

  const dayStart = `${day}T00:00:00.000Z`;
  const dayEnd = `${day}T23:59:59.999Z`;

  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     WHERE created_at >= $1::timestamptz AND created_at <= $2::timestamptz
     ORDER BY id ASC`,
    [dayStart, dayEnd]
  );

  if (format === "json") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.end(JSON.stringify(rows, null, 2));
  }

  // CSV
  const header = [
    "id",
    "created_at",
    "event",
    "first_name",
    "last_name",
    "phone",
    "client_mac",
    "client_ip",
    "marker",
    "kvkk_version",
  ];
  const csvEsc = (v) => {
    const s = safeStr(v);
    if (/[,"\n]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
    return s;
  };

  const out = [header.join(",")].concat(
    rows.map((r) =>
      [
        r.id,
        new Date(r.created_at).toISOString(),
        r.event,
        r.first_name,
        r.last_name,
        r.phone,
        r.client_mac,
        r.client_ip,
        r.marker,
        r.kvkk_version,
      ].map(csvEsc).join(",")
    )
  );

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `inline; filename="logs_${day}.csv"`);
  res.end(out.join("\n") + "\n");
});

app.get("/admin/daily/verify", requireBasicAuth, async (req, res) => {
  const day = safeStr(req.query.day || "").trim() || toDayStr();

  const row = await qRows(`SELECT * FROM daily_chains WHERE day=$1`, [day]);
  if (!row[0]) return res.status(404).json({ ok: false, error: "daily_chains not built for day. Run /admin/daily/build" });

  const expected = await buildDaily(day); // rebuild recalculates and upserts same values
  const current = await qRows(`SELECT * FROM daily_chains WHERE day=$1`, [day]);

  const ok =
    current[0].day_hash === expected.day_hash &&
    current[0].chain_hash === expected.chain_hash &&
    safeStr(current[0].signature) === safeStr(expected.signature);

  res.json({
    ok,
    day,
    expected,
    stored: {
      day_hash: current[0].day_hash,
      chain_hash: current[0].chain_hash,
      signature: current[0].signature,
      signature_alg: current[0].signature_alg,
      record_count: current[0].record_count,
      tz: current[0].tz,
    },
    note:
      ENV.DAILY_HMAC_SECRET
        ? "Signature is active (HMAC). For stronger legal posture, later replace with qualified e-sign / HSM workflow."
        : "Signature is PLACEHOLDER (set DAILY_HMAC_SECRET to enable HMAC signing).",
  });
});

// -------------------- Boot --------------------
(async () => {
  try {
    await ensureDb();
    await ensureRedis();

    app.listen(ENV.PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${ENV.PORT}`);
    });
  } catch (err) {
    console.error("BOOT ERROR:", err?.stack || err);
    process.exit(1);
  }
})();
