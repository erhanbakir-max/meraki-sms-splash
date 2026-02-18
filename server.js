/* eslint-disable no-console */
"use strict";

/**
 * meraki-sms-splash - single-file server.js
 * - Marker UI yok (kullanıcı görmez)
 * - OTP only flow
 * - Admin logs UI (Basic Auth, external paket yok)
 * - 5651 daily hash + chain + package + HMAC signature placeholder
 * - Postgres schema: add missing columns safely (ALTER IF NOT EXISTS)
 * - Redis opsiyonel (ioredis varsa kullanır, yoksa memory store)
 */

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const express = require("express");
const { Pool } = require("pg");

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || "8080", 10);
const TZ = process.env.TZ || "Europe/Istanbul";

const DATABASE_URL = process.env.DATABASE_URL || "";
const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ""; // 5651 imza placeholder (HMAC)
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen|sms (sms opsiyon)
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);
const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_TLS_URL || "";

// Debug env snapshot
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
  DAILY_HMAC_SET: !!DAILY_HMAC_SECRET,
});

// -------------------- Utilities --------------------
function sha256Hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

function hmacSha256Hex(secret, str) {
  return crypto.createHmac("sha256", secret).update(str, "utf8").digest("hex");
}

function randDigits(n) {
  const max = 10 ** n;
  const x = crypto.randomInt(0, max);
  return String(x).padStart(n, "0");
}

function safeStr(x) {
  return (x === undefined || x === null) ? "" : String(x);
}

function nowISO() {
  return new Date().toISOString();
}

function parseBasicAuth(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Basic ")) return null;
  const b64 = h.slice(6).trim();
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
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send("ADMIN_USER / ADMIN_PASS not set.");
  }
  const creds = parseBasicAuth(req);
  if (!creds || creds.user !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Unauthorized");
  }
  next();
}

// cookie helper (no external lib)
function getCookie(req, name) {
  const cookie = req.headers.cookie || "";
  const parts = cookie.split(";").map(s => s.trim());
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq > 0) {
      const k = p.slice(0, eq);
      const v = p.slice(eq + 1);
      if (k === name) return decodeURIComponent(v);
    }
  }
  return "";
}
function setCookie(res, name, value, { maxAgeSeconds = 86400, httpOnly = true } = {}) {
  const attrs = [];
  attrs.push(`${name}=${encodeURIComponent(value)}`);
  attrs.push(`Path=/`);
  attrs.push(`Max-Age=${maxAgeSeconds}`);
  // Captive portal bazen third-party gibi davranabiliyor; SameSite=Lax genelde iyi.
  attrs.push(`SameSite=Lax`);
  // Railway HTTPS -> Secure iyi ama captive portal bazen http->https; yine de Railway zaten https.
  attrs.push(`Secure`);
  if (httpOnly) attrs.push(`HttpOnly`);
  res.setHeader("Set-Cookie", attrs.join("; "));
}

// IP & headers snapshot for meta
function requestMeta(req) {
  const xf = safeStr(req.headers["x-forwarded-for"]);
  const clientIp = xf ? xf.split(",")[0].trim() : safeStr(req.socket?.remoteAddress);
  return {
    public_ip: clientIp,
    user_agent: safeStr(req.headers["user-agent"]),
    accept_language: safeStr(req.headers["accept-language"]),
    referer: safeStr(req.headers.referer),
  };
}

// -------------------- Storage (Redis optional) --------------------
class MemoryStore {
  constructor() {
    this.map = new Map(); // key -> {value, expMs}
    setInterval(() => this.sweep(), 10_000).unref();
  }
  sweep() {
    const now = Date.now();
    for (const [k, v] of this.map.entries()) {
      if (v.expMs && v.expMs <= now) this.map.delete(k);
    }
  }
  async get(key) {
    const v = this.map.get(key);
    if (!v) return null;
    if (v.expMs && v.expMs <= Date.now()) {
      this.map.delete(key);
      return null;
    }
    return v.value;
  }
  async set(key, value, ttlSeconds) {
    const expMs = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
    this.map.set(key, { value, expMs });
  }
  async del(key) {
    this.map.delete(key);
  }
  async incr(key, ttlSeconds) {
    const cur = await this.get(key);
    const n = parseInt(cur || "0", 10) + 1;
    await this.set(key, String(n), ttlSeconds);
    return n;
  }
}

async function initStore() {
  if (!REDIS_URL) return { kind: "memory", store: new MemoryStore() };

  // ioredis opsiyonel require (kurulu değilse memory'e düş)
  let Redis;
  try {
    // eslint-disable-next-line import/no-extraneous-dependencies
    Redis = require("ioredis");
  } catch (e) {
    console.warn("REDIS_URL var ama ioredis yok -> memory store kullanılacak");
    return { kind: "memory", store: new MemoryStore() };
  }

  const redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
    lazyConnect: true,
  });

  try {
    await redis.connect();
    await redis.ping();
    console.log("REDIS: connected");
  } catch (e) {
    console.warn("REDIS connect failed -> memory store kullanılacak", e?.message);
    return { kind: "memory", store: new MemoryStore() };
  }

  const api = {
    async get(key) {
      return await redis.get(key);
    },
    async set(key, value, ttlSeconds) {
      if (ttlSeconds) {
        await redis.set(key, value, "EX", ttlSeconds);
      } else {
        await redis.set(key, value);
      }
    },
    async del(key) {
      await redis.del(key);
    },
    async incr(key, ttlSeconds) {
      const n = await redis.incr(key);
      if (ttlSeconds) await redis.expire(key, ttlSeconds);
      return n;
    },
  };

  return { kind: "redis", store: api };
}

// -------------------- Database --------------------
if (!DATABASE_URL) {
  console.error("DATABASE_URL not set!");
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function qRows(sql, params) {
  const r = await pool.query(sql, params);
  return r.rows;
}

async function ensureSchema() {
  // access_logs: esnek, meta jsonb içine her şeyi koy
  await qRows(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      event TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      client_mac TEXT,
      client_ip TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      marker TEXT,
      kvkk_version TEXT,
      kvkk_accepted BOOLEAN,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `, []);

  // eski tablo farklıysa eksikleri ekle (güvenli)
  const colsToAdd = [
    ["first_name", "TEXT"],
    ["last_name", "TEXT"],
    ["phone", "TEXT"],
    ["client_mac", "TEXT"],
    ["client_ip", "TEXT"],
    ["ssid", "TEXT"],
    ["ap_name", "TEXT"],
    ["base_grant_url", "TEXT"],
    ["continue_url", "TEXT"],
    ["marker", "TEXT"],
    ["kvkk_version", "TEXT"],
    ["kvkk_accepted", "BOOLEAN"],
    ["meta", "JSONB NOT NULL DEFAULT '{}'::jsonb"],
  ];
  for (const [c, t] of colsToAdd) {
    await qRows(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ${c} ${t};`, []);
  }

  // 5651 daily hashes/chains/packages
  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      record_count INTEGER NOT NULL,
      day_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `, []);
  await qRows(`ALTER TABLE daily_hashes ADD COLUMN IF NOT EXISTS tz TEXT;`, []);

  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      prev_day DATE,
      prev_day_hash TEXT,
      chain_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `, []);
  await qRows(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS tz TEXT;`, []);
  await qRows(`ALTER TABLE daily_chains ADD COLUMN IF NOT EXISTS prev_day_hash TEXT;`, []);

  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      package JSONB NOT NULL,
      algo TEXT NOT NULL DEFAULT 'HMAC-SHA256',
      signature TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `, []);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS tz TEXT;`, []);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS package JSONB;`, []);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS signature TEXT;`, []);
  await qRows(`ALTER TABLE daily_packages ADD COLUMN IF NOT EXISTS algo TEXT;`, []);

  console.log("DATABASE: table ready");
}

async function logEvent(event, fields = {}) {
  try {
    const {
      first_name, last_name, phone, client_mac, client_ip, ssid, ap_name,
      base_grant_url, continue_url, marker, kvkk_version, kvkk_accepted, meta
    } = fields;

    await qRows(
      `INSERT INTO access_logs(
        event, first_name, last_name, phone, client_mac, client_ip, ssid, ap_name,
        base_grant_url, continue_url, marker, kvkk_version, kvkk_accepted, meta
      ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)`,
      [
        event,
        safeStr(first_name) || null,
        safeStr(last_name) || null,
        safeStr(phone) || null,
        safeStr(client_mac) || null,
        safeStr(client_ip) || null,
        safeStr(ssid) || null,
        safeStr(ap_name) || null,
        safeStr(base_grant_url) || null,
        safeStr(continue_url) || null,
        safeStr(marker) || null,
        safeStr(kvkk_version) || null,
        (kvkk_accepted === undefined ? null : !!kvkk_accepted),
        JSON.stringify(meta || {}),
      ]
    );
  } catch (e) {
    console.error("DB LOG ERROR:", e?.message || e);
  }
}

// -------------------- Express app --------------------
const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "256kb" }));

// serve /public (logo here)
app.use("/public", express.static(path.join(__dirname, "public"), {
  fallthrough: true,
  maxAge: "1h",
}));

// Healthcheck
app.get("/health", (req, res) => res.status(200).send("ok"));

// -------------------- UI Theme (Odeon-like) --------------------
// Logo: put file at ./public/logo.png (your provided image)
function pageShell({ title, body, extraHead = "" }) {
  // Sade koyu arka plan + mavi aksan (Odeon hissi)
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${title}</title>
  ${extraHead}
  <style>
    :root{
      --bg:#0B1220;
      --card:#111A2E;
      --card2:#0F172A;
      --text:#E6EAF2;
      --muted:#98A2B3;
      --line:rgba(255,255,255,.08);
      --accent:#2563EB;
      --accent2:#60A5FA;
      --ok:#16A34A;
      --bad:#EF4444;
      --shadow: 0 20px 60px rgba(0,0,0,.45);
      --radius:16px;
      --font: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background: radial-gradient(1200px 700px at 25% 10%, rgba(37,99,235,.25), transparent 55%),
                  radial-gradient(900px 600px at 80% 30%, rgba(96,165,250,.18), transparent 60%),
                  var(--bg);
      color:var(--text);
      font-family:var(--font);
    }
    a{color:var(--accent2); text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{
      max-width: 920px;
      margin: 0 auto;
      padding: 28px 16px 56px;
    }
    .topbar{
      display:flex; align-items:center; gap:12px;
      margin-bottom:18px;
    }
    .logo{
      width: 170px;
      height: auto;
      display:block;
      filter: drop-shadow(0 10px 20px rgba(0,0,0,.35));
    }
    .title{
      margin:0;
      font-size: 18px;
      color: var(--muted);
      font-weight: 600;
    }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .cardin{ padding: 18px; }
    .h1{
      margin: 0 0 6px;
      font-size: 22px;
      letter-spacing: .2px;
    }
    .p{ margin: 0 0 14px; color: var(--muted); line-height:1.55 }
    .row{ display:flex; gap:12px; flex-wrap:wrap }
    .col{ flex: 1 1 260px }
    label{ display:block; font-size:12px; color: var(--muted); margin: 10px 0 6px }
    input{
      width:100%;
      padding: 12px 12px;
      background: rgba(15,23,42,.7);
      border: 1px solid rgba(255,255,255,.10);
      border-radius: 12px;
      color: var(--text);
      outline:none;
    }
    input:focus{
      border-color: rgba(96,165,250,.55);
      box-shadow: 0 0 0 4px rgba(37,99,235,.18);
    }
    .btn{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      gap:10px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.10);
      background: linear-gradient(180deg, rgba(37,99,235,.95), rgba(29,78,216,.95));
      color: white;
      font-weight: 700;
      cursor:pointer;
      width: 100%;
      margin-top: 12px;
    }
    .btn:hover{ filter: brightness(1.03); }
    .pill{
      display:inline-flex; gap:8px; align-items:center;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(15,23,42,.55);
      color: var(--muted);
      font-size: 12px;
    }
    .kvkk{
      display:flex; gap:10px; align-items:flex-start;
      padding: 12px;
      border: 1px solid rgba(255,255,255,.10);
      border-radius: 12px;
      background: rgba(15,23,42,.5);
      margin-top: 8px;
    }
    .kvkk input{ width:auto; margin-top: 3px }
    .hint{ font-size: 12px; color: var(--muted); margin-top: 10px }
    .otpbox{
      margin-top: 14px;
      padding: 14px;
      border-radius: 14px;
      border: 1px dashed rgba(96,165,250,.55);
      background: rgba(37,99,235,.10);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 22px;
      font-weight: 800;
      letter-spacing: 2px;
      text-align:center;
    }
    .err{
      margin-top: 12px;
      padding: 12px;
      border-radius: 12px;
      border: 1px solid rgba(239,68,68,.35);
      background: rgba(239,68,68,.10);
      color: #ffd3d3;
    }
    .ok{
      margin-top: 12px;
      padding: 12px;
      border-radius: 12px;
      border: 1px solid rgba(22,163,74,.35);
      background: rgba(22,163,74,.10);
      color: #d6ffe4;
    }
    .footer{
      margin-top: 14px;
      color: rgba(152,162,179,.8);
      font-size: 12px;
      text-align: center;
    }
    .table{
      width:100%;
      border-collapse: collapse;
      overflow:hidden;
      border-radius: 14px;
    }
    .table th, .table td{
      padding: 10px 10px;
      border-bottom: 1px solid rgba(255,255,255,.08);
      font-size: 13px;
      vertical-align: top;
      word-break: break-word;
    }
    .table th{
      text-align:left;
      color: rgba(230,234,242,.9);
      font-size: 12px;
      letter-spacing: .3px;
      background: rgba(15,23,42,.45);
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .toolbar{
      display:flex; gap:10px; align-items:center; justify-content:space-between;
      flex-wrap: wrap;
      margin: 10px 0 14px;
    }
    .smallbtn{
      padding: 8px 10px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(15,23,42,.55);
      color: var(--text);
      cursor:pointer;
      font-weight: 700;
      font-size: 12px;
    }
    .smallbtn:hover{ filter: brightness(1.05); }
    .stack{ display:flex; gap:10px; align-items:center; flex-wrap: wrap;}
    .muted{ color: var(--muted); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <img class="logo" alt="Odeon" src="/public/logo.png" onerror="this.style.display='none'"/>
      <div>
        <div class="title">Odeon Teknoloji • Misafir Wi-Fi Erişim</div>
      </div>
    </div>
    <div class="card"><div class="cardin">
      ${body}
    </div></div>
    <div class="footer">© ${new Date().getFullYear()} Odeon Teknoloji</div>
  </div>
</body>
</html>`;
}

// -------------------- Session & OTP helpers --------------------
let STORE; // {kind, store}
function sessionKey(sid) { return `sess:${sid}`; }
function otpKey(sid) { return `otp:${sid}`; }
function rlKeyPhone(phone) { return `rl:phone:${phone}`; }
function rlKeyMac(mac) { return `rl:mac:${mac}`; }
function lockKey(sid) { return `lock:${sid}`; }
function wrongKey(sid) { return `wrong:${sid}`; }

// Captive portal: query paramlar her sayfada gelmeyebiliyor.
// Bu yüzden base_grant_url/continue_url/mac/ip vb’yi HTML form hidden alanıyla taşıyoruz.
// Cookie yine var ama “tek noktaya bağımlı” olmayacağız.

function normalizePhone(raw) {
  let p = safeStr(raw).trim();
  // Çok basit normalize: boşluk/()- sil
  p = p.replace(/[^\d+]/g, "");
  // 0 ile başlayan TR -> +90’a çevirme (opsiyon)
  if (p.startsWith("0") && p.length === 11) p = "+9" + p; // "0xxxxxxxxxx" -> "+90xxxxxxxxxx"
  if (p.startsWith("90") && !p.startsWith("+")) p = "+" + p;
  return p;
}

function buildGrantRedirect(base_grant_url, continue_url) {
  // Meraki base_grant_url genelde zaten query içerir.
  // continue_url varsa ekle.
  if (!base_grant_url) return "";
  try {
    const u = new URL(base_grant_url);
    if (continue_url) u.searchParams.set("continue_url", continue_url);
    return u.toString();
  } catch {
    // base_grant_url URL değilse (nadir) string concat
    if (!continue_url) return base_grant_url;
    const sep = base_grant_url.includes("?") ? "&" : "?";
    return `${base_grant_url}${sep}continue_url=${encodeURIComponent(continue_url)}`;
  }
}

// -------------------- Routes: Splash --------------------
app.get("/", async (req, res) => {
  // Meraki params
  const base_grant_url = safeStr(req.query.base_grant_url);
  const continue_url = safeStr(req.query.continue_url);
  const client_mac = safeStr(req.query.client_mac);
  const client_ip = safeStr(req.query.client_ip);
  const ssid = safeStr(req.query.ssid);
  const ap_name = safeStr(req.query.ap_name);

  console.log("SPLASH_OPEN", {
    hasBaseGrant: !!base_grant_url,
    hasContinue: !!continue_url,
    hasClientMac: !!client_mac,
    mode: OTP_MODE,
  });

  const sid = getCookie(req, "sid") || crypto.randomUUID();
  setCookie(res, "sid", sid, { maxAgeSeconds: 7 * 86400, httpOnly: true });

  // store session snapshot (opsiyonel; ama asıl taşıma hidden input ile)
  const sess = {
    sid,
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    ssid,
    ap_name,
    created_at: nowISO(),
  };
  await STORE.store.set(sessionKey(sid), JSON.stringify(sess), 7 * 86400);

  await logEvent("SPLASH_OPEN", {
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url,
    kvkk_version: KVKK_VERSION,
    meta: requestMeta(req),
  });

  const body = `
    <div class="pill">KVKK versiyon: <b>${KVKK_VERSION}</b> • Zaman dilimi: <b>${TZ}</b></div>
    <h1 class="h1">İnternete bağlan</h1>
    <p class="p">Telefon numaranı gir, doğrulama kodunu al ve bağlan.</p>

    <form method="POST" action="/otp/start" autocomplete="on">
      <div class="row">
        <div class="col">
          <label>Ad</label>
          <input name="first_name" placeholder="Ad" maxlength="64"/>
        </div>
        <div class="col">
          <label>Soyad</label>
          <input name="last_name" placeholder="Soyad" maxlength="64"/>
        </div>
      </div>

      <label>Telefon</label>
      <input name="phone" inputmode="tel" placeholder="+905xxxxxxxxx" required/>

      <div class="kvkk">
        <input id="kvkk" type="checkbox" name="kvkk_accepted" value="true" required/>
        <div>
          <div style="font-weight:800;margin-bottom:4px">KVKK Aydınlatma Metni</div>
          <div class="muted" style="font-size:12px;line-height:1.45">
            İnternete erişim için gerekli loglama (5651 kapsamında) yapılacaktır. Devam etmek için onay veriniz.
          </div>
        </div>
      </div>

      <!-- Meraki paramlarını HIDDEN taşıyoruz: marker YOK -->
      <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}"/>
      <input type="hidden" name="continue_url" value="${escapeHtml(continue_url)}"/>
      <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}"/>
      <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}"/>
      <input type="hidden" name="ssid" value="${escapeHtml(ssid)}"/>
      <input type="hidden" name="ap_name" value="${escapeHtml(ap_name)}"/>

      <button class="btn" type="submit">Doğrulama Kodu Al</button>

      <div class="hint">Sorun yaşarsan: Wi-Fi ağına bağlı olduğundan emin ol.</div>
    </form>
  `;

  res.status(200).send(pageShell({ title: "Odeon • Wi-Fi", body }));
});

function escapeHtml(s) {
  return safeStr(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

app.post("/otp/start", async (req, res) => {
  const sid = getCookie(req, "sid") || crypto.randomUUID();
  setCookie(res, "sid", sid, { maxAgeSeconds: 7 * 86400, httpOnly: true });

  const first_name = safeStr(req.body.first_name).trim();
  const last_name = safeStr(req.body.last_name).trim();
  const phone = normalizePhone(req.body.phone);

  const kvkk_accepted = req.body.kvkk_accepted === "true" || req.body.kvkk_accepted === "on";

  // Meraki params: hidden ile geliyor
  const base_grant_url = safeStr(req.body.base_grant_url);
  const continue_url = safeStr(req.body.continue_url);
  const client_mac = safeStr(req.body.client_mac);
  const client_ip = safeStr(req.body.client_ip);
  const ssid = safeStr(req.body.ssid);
  const ap_name = safeStr(req.body.ap_name);

  // Rate limit: phone/mac
  const rlPhone = await STORE.store.get(rlKeyPhone(phone));
  if (rlPhone) {
    return res.status(429).send(pageShell({
      title: "Çok hızlı",
      body: `<div class="err">Çok sık denedin. Lütfen ${RL_PHONE_SECONDS} saniye sonra tekrar dene.</div>`
    }));
  }
  if (client_mac) {
    const rlMac = await STORE.store.get(rlKeyMac(client_mac));
    if (rlMac) {
      return res.status(429).send(pageShell({
        title: "Çok hızlı",
        body: `<div class="err">Çok sık denedin. Lütfen ${RL_MAC_SECONDS} saniye sonra tekrar dene.</div>`
      }));
    }
  }

  // Lock check (çok yanlış giriş)
  const locked = await STORE.store.get(lockKey(sid));
  if (locked) {
    return res.status(423).send(pageShell({
      title: "Kilitli",
      body: `<div class="err">Çok fazla hatalı deneme. Lütfen ${LOCK_SECONDS} saniye sonra tekrar dene.</div>`
    }));
  }

  const otp = randDigits(6);
  const otpHash = sha256Hex(`${sid}:${otp}`);

  const otpPayload = {
    otpHash,
    phone,
    first_name,
    last_name,
    kvkk_accepted,
    kvkk_version: KVKK_VERSION,
    created_at: nowISO(),
    // Meraki paramlarını burada da tutalım
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    ssid,
    ap_name,
  };

  await STORE.store.set(otpKey(sid), JSON.stringify(otpPayload), OTP_TTL_SECONDS);
  await STORE.store.set(rlKeyPhone(phone), "1", RL_PHONE_SECONDS);
  if (client_mac) await STORE.store.set(rlKeyMac(client_mac), "1", RL_MAC_SECONDS);

  console.log("OTP_CREATED", { sid, last4: phone.slice(-4), client_mac: client_mac || "" });
  if (OTP_MODE === "screen") {
    console.log("OTP_SCREEN_CODE", { sid, otp });
  }

  await logEvent("OTP_CREATED", {
    first_name, last_name, phone,
    client_mac, client_ip, ssid, ap_name,
    base_grant_url, continue_url,
    kvkk_version: KVKK_VERSION,
    kvkk_accepted,
    marker: null,
    meta: { ...requestMeta(req), mode: OTP_MODE },
  });

  const otpBox = (OTP_MODE === "screen")
    ? `<div class="otpbox">${otp}</div><div class="hint">Bu kod yalnızca ${OTP_TTL_SECONDS} saniye geçerlidir.</div>`
    : `<div class="hint">Kod SMS ile gönderildi.</div>`;

  const body = `
    <div class="pill">Telefon: <b>${escapeHtml(phone)}</b></div>
    <h1 class="h1">Doğrulama Kodu</h1>
    <p class="p">Kodunu girerek bağlantıyı tamamla.</p>

    ${otpBox}

    <form method="POST" action="/otp/verify" autocomplete="one-time-code">
      <label>OTP Kodu</label>
      <input name="otp" inputmode="numeric" pattern="[0-9]{6}" placeholder="6 haneli kod" maxlength="6" required/>

      <!-- Meraki paramlarını tekrar hidden taşıyoruz (cookie kaybolsa bile çalışsın) -->
      <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}"/>
      <input type="hidden" name="continue_url" value="${escapeHtml(continue_url)}"/>
      <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}"/>
      <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}"/>
      <input type="hidden" name="ssid" value="${escapeHtml(ssid)}"/>
      <input type="hidden" name="ap_name" value="${escapeHtml(ap_name)}"/>

      <button class="btn" type="submit">Doğrula ve Bağlan</button>
      <div class="hint"><a href="/">Geri dön</a></div>
    </form>
  `;

  res.status(200).send(pageShell({ title: "OTP Doğrula", body }));
});

app.post("/otp/verify", async (req, res) => {
  const sid = getCookie(req, "sid");
  const otp = safeStr(req.body.otp).trim();

  // Hidden’den tekrar al
  const base_grant_url = safeStr(req.body.base_grant_url);
  const continue_url = safeStr(req.body.continue_url);
  const client_mac = safeStr(req.body.client_mac);
  const client_ip = safeStr(req.body.client_ip);
  const ssid = safeStr(req.body.ssid);
  const ap_name = safeStr(req.body.ap_name);

  if (!sid) {
    return res.status(400).send(pageShell({
      title: "Hata",
      body: `<div class="err">Oturum bulunamadı. Lütfen baştan deneyin.</div><div class="hint"><a href="/">Başa dön</a></div>`
    }));
  }

  // lock check
  const locked = await STORE.store.get(lockKey(sid));
  if (locked) {
    return res.status(423).send(pageShell({
      title: "Kilitli",
      body: `<div class="err">Çok fazla hatalı deneme. Lütfen daha sonra tekrar dene.</div>`
    }));
  }

  const raw = await STORE.store.get(otpKey(sid));
  if (!raw) {
    return res.status(400).send(pageShell({
      title: "Süre doldu",
      body: `<div class="err">OTP süresi dolmuş olabilir. Lütfen yeniden kod al.</div><div class="hint"><a href="/">Başa dön</a></div>`
    }));
  }

  const payload = JSON.parse(raw);
  const expectedHash = payload.otpHash;
  const gotHash = sha256Hex(`${sid}:${otp}`);

  if (gotHash !== expectedHash) {
    const wrong = await STORE.store.incr(wrongKey(sid), OTP_TTL_SECONDS);
    if (wrong >= MAX_WRONG_ATTEMPTS) {
      await STORE.store.set(lockKey(sid), "1", LOCK_SECONDS);
    }
    await logEvent("OTP_VERIFY_FAIL", {
      phone: payload.phone,
      first_name: payload.first_name,
      last_name: payload.last_name,
      client_mac: client_mac || payload.client_mac,
      client_ip: client_ip || payload.client_ip,
      ssid: ssid || payload.ssid,
      ap_name: ap_name || payload.ap_name,
      base_grant_url: base_grant_url || payload.base_grant_url,
      continue_url: continue_url || payload.continue_url,
      kvkk_version: payload.kvkk_version,
      kvkk_accepted: payload.kvkk_accepted,
      meta: { ...requestMeta(req), wrong_attempt: wrong },
    });

    return res.status(401).send(pageShell({
      title: "Hatalı kod",
      body: `<div class="err">OTP hatalı. Lütfen tekrar deneyin.</div><div class="hint"><a href="/">Başa dön</a></div>`
    }));
  }

  // Verified OK
  await STORE.store.del(otpKey(sid));
  await STORE.store.del(wrongKey(sid));

  const finalBase = base_grant_url || payload.base_grant_url;
  const finalContinue = continue_url || payload.continue_url;

  if (!finalBase) {
    // Asıl senin gördüğün hata buydu. Cookie/param kaybolsa bile artık hidden ile geldiği için normalde düşmemeli.
    return res.status(400).send(pageShell({
      title: "Eksik parametre",
      body: `<div class="err">OTP verified but base_grant_url missing.</div><div class="hint"><a href="/">Başa dön</a></div>`
    }));
  }

  await logEvent("OTP_VERIFIED", {
    phone: payload.phone,
    first_name: payload.first_name,
    last_name: payload.last_name,
    client_mac: client_mac || payload.client_mac,
    client_ip: client_ip || payload.client_ip,
    ssid: ssid || payload.ssid,
    ap_name: ap_name || payload.ap_name,
    base_grant_url: finalBase,
    continue_url: finalContinue,
    kvkk_version: payload.kvkk_version,
    kvkk_accepted: payload.kvkk_accepted,
    meta: requestMeta(req),
  });

  const redirectUrl = buildGrantRedirect(finalBase, finalContinue);

  await logEvent("GRANT_REDIRECT", {
    phone: payload.phone,
    client_mac: client_mac || payload.client_mac,
    client_ip: client_ip || payload.client_ip,
    base_grant_url: finalBase,
    continue_url: finalContinue,
    kvkk_version: payload.kvkk_version,
    kvkk_accepted: payload.kvkk_accepted,
    meta: { ...requestMeta(req), redirect_to: redirectUrl },
  });

  // Captive portal davranışı: bazen redirecti engelleyebiliyor. Hem meta refresh hem link veriyoruz.
  const body = `
    <div class="ok"><b>OK</b> • İnternet erişimi açılıyor…</div>
    <p class="p">Yönlendirme olmazsa aşağıdaki bağlantıya tıkla.</p>
    <a class="smallbtn" href="${escapeHtml(redirectUrl)}">Devam et</a>
    <meta http-equiv="refresh" content="0;url=${escapeHtml(redirectUrl)}">
  `;
  return res.status(200).send(pageShell({ title: "OK", body }));
});

// -------------------- Admin: Logs UI --------------------
app.get("/admin/logs", requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10), 1000);
  const tz = safeStr(req.query.tz || TZ);

  // JSON istenirse
  if (req.query.format === "json" || req.query.json === "1") {
    const rows = await qRows(
      `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, ssid, ap_name, marker, kvkk_version
       FROM access_logs
       ORDER BY id DESC
       LIMIT $1`,
      [limit]
    );
    return res.json(rows);
  }

  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     ORDER BY id DESC
     LIMIT $1`,
    [limit]
  );

  const fmt = (iso) => {
    try {
      // server-side basit format (TZ)
      const d = new Date(iso);
      // İstanbul saatine kaba yaklaşım: UI zaten TZ paramı gösteriyor
      return d.toLocaleString("tr-TR", { timeZone: tz });
    } catch {
      return iso;
    }
  };

  const trs = rows.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${escapeHtml(fmt(r.created_at))}</td>
      <td>${escapeHtml(r.event)}</td>
      <td>${escapeHtml([r.first_name, r.last_name].filter(Boolean).join(" "))}</td>
      <td>${escapeHtml(r.phone || "")}</td>
      <td>${escapeHtml(r.client_mac || "")}</td>
      <td>${escapeHtml(r.client_ip || "")}</td>
      <td>${escapeHtml(r.marker || "")}</td>
      <td>${escapeHtml(r.kvkk_version || "")}</td>
    </tr>
  `).join("");

  const body = `
    <h1 class="h1">/admin/logs</h1>
    <div class="toolbar">
      <div class="stack">
        <span class="pill">limit=${limit}</span>
        <span class="pill">tz=${escapeHtml(tz)}</span>
        <a class="pill" href="/admin/logs?limit=${limit}&tz=${encodeURIComponent(tz)}&format=json">JSON</a>
      </div>
      <div class="stack">
        <form method="GET" action="/admin/logs" class="stack" style="margin:0">
          <input name="limit" value="${limit}" style="width:120px" />
          <input name="tz" value="${escapeHtml(tz)}" style="width:200px" />
          <button class="smallbtn" type="submit">Refresh</button>
        </form>
        <a class="smallbtn" href="/admin/daily">Daily</a>
      </div>
    </div>

    <div style="max-height:70vh; overflow:auto; border-radius:14px; border:1px solid rgba(255,255,255,.08)">
      <table class="table">
        <thead>
          <tr>
            <th style="width:70px">id</th>
            <th style="width:200px">time</th>
            <th style="width:180px">event</th>
            <th>name</th>
            <th style="width:160px">phone</th>
            <th style="width:210px">mac</th>
            <th style="width:160px">ip</th>
            <th style="width:110px">marker</th>
            <th style="width:150px">kvkk</th>
          </tr>
        </thead>
        <tbody>${trs}</tbody>
      </table>
    </div>
  `;
  res.status(200).send(pageShell({ title: "Admin Logs", body }));
});

// -------------------- 5651 Daily --------------------
function parseDayParam(s) {
  // yyyy-mm-dd
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || "");
  if (!m) return null;
  const d = new Date(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return null;
  return `${m[1]}-${m[2]}-${m[3]}`; // normalized
}

async function dailyLogsForDay(dayStr, tz) {
  // (created_at AT TIME ZONE tz)::date = day::date  --> avoids text=date
  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, kvkk_version, kvkk_accepted, meta
     FROM access_logs
     WHERE ((created_at AT TIME ZONE $1)::date = $2::date)
     ORDER BY id ASC`,
    [tz, dayStr]
  );
  return rows;
}

function canonicalizeLogs(rows) {
  // deterministic canonical string
  // meta json: stable stringify
  const stable = (obj) => {
    try {
      if (!obj || typeof obj !== "object") return String(obj || "");
      const keys = Object.keys(obj).sort();
      const out = {};
      for (const k of keys) out[k] = obj[k];
      return JSON.stringify(out);
    } catch {
      return "";
    }
  };

  return rows.map(r => [
    r.id,
    new Date(r.created_at).toISOString(),
    safeStr(r.event),
    safeStr(r.first_name),
    safeStr(r.last_name),
    safeStr(r.phone),
    safeStr(r.client_mac),
    safeStr(r.client_ip),
    safeStr(r.ssid),
    safeStr(r.ap_name),
    safeStr(r.base_grant_url),
    safeStr(r.continue_url),
    safeStr(r.kvkk_version),
    r.kvkk_accepted === null || r.kvkk_accepted === undefined ? "" : (r.kvkk_accepted ? "1" : "0"),
    stable(r.meta),
  ].join("|")).join("\n");
}

async function buildDaily(dayStr, tz) {
  const rows = await dailyLogsForDay(dayStr, tz);
  const canon = canonicalizeLogs(rows);
  const day_hash = sha256Hex(canon);
  const record_count = rows.length;

  // prev day chain
  const prev = await qRows(
    `SELECT day, day_hash FROM daily_hashes WHERE day < $1::date ORDER BY day DESC LIMIT 1`,
    [dayStr]
  );
  const prev_day = prev[0]?.day ? String(prev[0].day).slice(0,10) : null;
  const prev_day_hash = prev[0]?.day_hash || null;

  // chain: H(day_hash + prev_day_hash)
  const chain_payload = `${dayStr}|${tz}|${day_hash}|${prev_day || ""}|${prev_day_hash || ""}`;
  const chain_hash = sha256Hex(chain_payload);

  // package: JSON
  const pkg = {
    day: dayStr,
    tz,
    record_count,
    day_hash,
    prev_day,
    prev_day_hash,
    chain_hash,
    created_at: nowISO(),
  };

  const signature = DAILY_HMAC_SECRET ? hmacSha256Hex(DAILY_HMAC_SECRET, JSON.stringify(pkg)) : null;

  // upsert
  await qRows(
    `INSERT INTO daily_hashes(day, tz, record_count, day_hash)
     VALUES($1::date, $2, $3, $4)
     ON CONFLICT(day) DO UPDATE SET tz=EXCLUDED.tz, record_count=EXCLUDED.record_count, day_hash=EXCLUDED.day_hash`,
    [dayStr, tz, record_count, day_hash]
  );

  await qRows(
    `INSERT INTO daily_chains(day, tz, prev_day, prev_day_hash, chain_hash)
     VALUES($1::date, $2, $3::date, $4, $5)
     ON CONFLICT(day) DO UPDATE SET tz=EXCLUDED.tz, prev_day=EXCLUDED.prev_day, prev_day_hash=EXCLUDED.prev_day_hash, chain_hash=EXCLUDED.chain_hash`,
    [dayStr, tz, prev_day, prev_day_hash, chain_hash]
  );

  await qRows(
    `INSERT INTO daily_packages(day, tz, package, algo, signature)
     VALUES($1::date, $2, $3::jsonb, $4, $5)
     ON CONFLICT(day) DO UPDATE SET tz=EXCLUDED.tz, package=EXCLUDED.package, algo=EXCLUDED.algo, signature=EXCLUDED.signature`,
    [dayStr, tz, JSON.stringify(pkg), "HMAC-SHA256", signature]
  );

  return { ...pkg, signature };
}

async function verifyDaily(dayStr) {
  const got = await qRows(
    `SELECT p.day, p.tz, p.package, p.signature, p.algo
     FROM daily_packages p
     WHERE p.day = $1::date`,
    [dayStr]
  );
  if (!got.length) return { ok: false, reason: "daily_packages not found for day" };
  const row = got[0];
  const pkg = row.package;

  // recompute signature (if secret set)
  let expectedSig = null;
  if (DAILY_HMAC_SECRET) {
    expectedSig = hmacSha256Hex(DAILY_HMAC_SECRET, JSON.stringify(pkg));
  }

  // also recompute day_hash/chain from logs to validate integrity
  const tz = pkg.tz || TZ;
  const rows = await dailyLogsForDay(dayStr, tz);
  const canon = canonicalizeLogs(rows);
  const day_hash = sha256Hex(canon);
  const chain_payload = `${dayStr}|${tz}|${day_hash}|${pkg.prev_day || ""}|${pkg.prev_day_hash || ""}`;
  const chain_hash = sha256Hex(chain_payload);

  const okHash = (day_hash === pkg.day_hash) && (chain_hash === pkg.chain_hash);
  const okSig = DAILY_HMAC_SECRET ? (expectedSig === row.signature) : true;

  return {
    ok: okHash && okSig,
    ok_hash: okHash,
    ok_signature: okSig,
    expected: { day_hash, chain_hash, signature: expectedSig },
    stored: { day_hash: pkg.day_hash, chain_hash: pkg.chain_hash, signature: row.signature },
    algo: row.algo,
    tz,
    record_count_db: rows.length,
  };
}

app.get("/admin/daily", requireAdmin, async (req, res) => {
  const tz = safeStr(req.query.tz || TZ);

  // last 14 days list
  const days = await qRows(
    `SELECT h.day, h.tz, h.record_count, h.day_hash, c.chain_hash
     FROM daily_hashes h
     LEFT JOIN daily_chains c ON c.day=h.day
     ORDER BY h.day DESC
     LIMIT 14`,
    []
  );

  const rowsHtml = days.map(d => {
    const dayStr = String(d.day).slice(0,10);
    return `
      <tr>
        <td>${escapeHtml(dayStr)}</td>
        <td>${escapeHtml(d.tz || "")}</td>
        <td>${d.record_count}</td>
        <td style="font-family:ui-monospace,monospace;font-size:12px">${escapeHtml(d.day_hash || "")}</td>
        <td style="font-family:ui-monospace,monospace;font-size:12px">${escapeHtml(d.chain_hash || "")}</td>
        <td class="stack">
          <a class="smallbtn" href="/admin/daily/build?day=${dayStr}&tz=${encodeURIComponent(tz)}">Build</a>
          <a class="smallbtn" href="/admin/daily/verify?day=${dayStr}">Verify</a>
        </td>
      </tr>
    `;
  }).join("");

  const today = new Date().toISOString().slice(0,10);

  const body = `
    <h1 class="h1">/admin/daily</h1>
    <p class="p">5651 için günlük paket oluşturma ve doğrulama ekranı.</p>

    <div class="toolbar">
      <div class="stack">
        <span class="pill">tz=${escapeHtml(tz)}</span>
      </div>
      <div class="stack">
        <a class="smallbtn" href="/admin/daily/build?day=${today}&tz=${encodeURIComponent(tz)}">Bugün Build</a>
        <a class="smallbtn" href="/admin/logs">Logs</a>
      </div>
    </div>

    <div style="overflow:auto; border-radius:14px; border:1px solid rgba(255,255,255,.08)">
      <table class="table">
        <thead>
          <tr>
            <th>day</th>
            <th>tz</th>
            <th>count</th>
            <th>day_hash</th>
            <th>chain_hash</th>
            <th>actions</th>
          </tr>
        </thead>
        <tbody>${rowsHtml || ""}</tbody>
      </table>
    </div>
  `;
  res.status(200).send(pageShell({ title: "Admin Daily", body }));
});

app.get("/admin/daily/build", requireAdmin, async (req, res) => {
  const dayStr = parseDayParam(req.query.day);
  const tz = safeStr(req.query.tz || TZ);
  if (!dayStr) return res.status(400).send("invalid day. use yyyy-mm-dd");

  try {
    const out = await buildDaily(dayStr, tz);
    // JSON döndür
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(200).send(JSON.stringify(out, null, 2) + "\n");
  } catch (e) {
    console.error("daily build error", e);
    return res.status(500).send(`daily build error: ${e?.message || e}`);
  }
});

app.get("/admin/daily/verify", requireAdmin, async (req, res) => {
  const dayStr = parseDayParam(req.query.day);
  if (!dayStr) return res.status(400).send("invalid day. use yyyy-mm-dd");

  try {
    const out = await verifyDaily(dayStr);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.status(200).send(JSON.stringify(out, null, 2) + "\n");
  } catch (e) {
    console.error("daily verify error", e);
    return res.status(500).send(`daily verify error: ${e?.message || e}`);
  }
});

// -------------------- Boot --------------------
(async () => {
  try {
    // DB ping
    await pool.query("SELECT 1");
    console.log("DATABASE: connected");
    await ensureSchema();

    STORE = await initStore();
    if (STORE.kind === "memory") console.log("REDIS: not used (memory store)");

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (e) {
    console.error("FATAL:", e);
    process.exit(1);
  }
})();
