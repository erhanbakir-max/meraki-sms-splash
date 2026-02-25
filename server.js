/**
 * Odeon Meraki Splash + OTP (Screen/SMS) + 5651 Logging + Admin UI + Daily HMAC pack
 * - CommonJS (require) to avoid ESM issues.
 * - Works on Node 20/22.
 *
 * ENV (Railway Variables)
 *   PORT=8080
 *   TZ=Europe/Istanbul
 *   OTP_MODE=screen|sms          (sms = send OTP via İleti Merkezi)
 *   OTP_TTL_SECONDS=180
 *   RL_MAC_SECONDS=30
 *   RL_PHONE_SECONDS=60
 *   MAX_WRONG_ATTEMPTS=5
 *   LOCK_SECONDS=600
 *   KVKK_VERSION=2026-02-12-placeholder
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   DAILY_HMAC_SECRET=...        (required for /cron/daily + daily packages)
 *   DATABASE_URL=...             (Railway Postgres)
 *   REDIS_URL=... or REDIS_PUBLIC_URL=...  (Railway Redis)
 *
 * İleti Merkezi (OTP_MODE=sms) - API Key/Hash auth (JSON)
 *   IM_API_URL=https://api.iletimerkezi.com/v1/send-sms/json
 *   IM_API_KEY=...   (API Key)
 *   IM_API_HASH=...  (API Hash)  <-- panelde hash/secret üretilmiş olmalı
 *   IM_SENDER=...    (approved sender/header)
 *   SMS_TEST_MODE=true|false     (true => no SMS sent; logs only)
 */

const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const { Pool } = require("pg");

let Redis;
try { Redis = require("ioredis"); } catch (_) { Redis = null; }

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ----------------------- Utils -----------------------
const TZ = process.env.TZ || "Europe/Istanbul";
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen|sms
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);
const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";
const DEBUG = String(process.env.DEBUG || "false").toLowerCase() === "true";

function nowIso() { return new Date().toISOString(); }
function safeLog(...args) { if (DEBUG) console.log(...args); }

function randDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += Math.floor(Math.random() * 10).toString();
  return out;
}

function maskPhone(p) {
  const s = String(p || "");
  if (s.length < 4) return "XXXX";
  return "XXXX" + s.slice(-4);
}

function normalizeTRPhoneForOtp(input) {
  // Accept +90xxxxxxxxxx / 05xxxxxxxxx / 5xxxxxxxxx, return 5xxxxxxxxx (10 digits)
  let p = String(input || "").trim().replace(/\s+/g, "").replace(/-/g, "");
  if (p.startsWith("00")) p = "+" + p.slice(2);
  if (p.startsWith("+90")) p = p.slice(3);
  if (p.startsWith("90")) p = p.slice(2);
  if (p.startsWith("0")) p = p.slice(1);
  if (!/^5\d{9}$/.test(p)) return null;
  return p;
}

function basicAuth(req) {
  const h = req.headers.authorization || "";
  const m = /^Basic\s+(.+)$/i.exec(h);
  if (!m) return null;
  const raw = Buffer.from(m[1], "base64").toString("utf8");
  const idx = raw.indexOf(":");
  if (idx < 0) return null;
  return { user: raw.slice(0, idx), pass: raw.slice(idx + 1) };
}

function requireAdmin(req, res, next) {
  const u = process.env.ADMIN_USER || "";
  const p = process.env.ADMIN_PASS || "";
  if (!u || !p) return res.status(503).send("Admin not configured");
  const got = basicAuth(req);
  if (!got || got.user !== u || got.pass !== p) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  next();
}

function clientMeta(req) {
  return {
    ua: req.headers["user-agent"] || "",
    accept_language: req.headers["accept-language"] || "",
    referer: req.headers["referer"] || "",
  };
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ----------------------- Redis (optional) -----------------------
const inMem = { otpByMarker: new Map(), rlByKey: new Map() };
function memGet(map, key) { return map.get(key); }
function memSet(map, key, val) { map.set(key, val); }
function memDel(map, key) { map.delete(key); }

let redis = null;
function redisConfigured() {
  const u = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL;
  return !!u && !!Redis;
}

async function redisInit() {
  if (!redisConfigured()) {
    console.log("REDIS: not configured. Running WITHOUT persistent store.");
    return;
  }
  const url = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL;
  redis = new Redis(url, { maxRetriesPerRequest: 1, enableReadyCheck: true });
  await redis.ping();
  console.log("REDIS: connected");
}

async function kvGet(key) {
  if (!redis) return memGet(inMem.otpByMarker, key);
  const s = await redis.get(key);
  return s ? JSON.parse(s) : null;
}
async function kvSet(key, val, ttlSeconds) {
  if (!redis) return memSet(inMem.otpByMarker, key, val);
  await redis.set(key, JSON.stringify(val), "EX", ttlSeconds);
}
async function kvDel(key) {
  if (!redis) return memDel(inMem.otpByMarker, key);
  await redis.del(key);
}
async function rlHit(key, windowSec) {
  const ts = Date.now();
  if (!redis) {
    const last = memGet(inMem.rlByKey, key) || 0;
    if (ts - last < windowSec * 1000) return false;
    memSet(inMem.rlByKey, key, ts);
    return true;
  }
  const ok = await redis.set(key, String(ts), "EX", windowSec, "NX");
  return !!ok;
}

// ----------------------- Postgres -----------------------
let pool = null;
function dbConfigured() { return !!process.env.DATABASE_URL; }

async function dbInit() {
  if (!dbConfigured()) {
    console.log("DATABASE: not configured. 5651 logs will NOT be stored.");
    return;
  }
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await pool.query("SELECT 1");
  console.log("DATABASE: connected");
  await ensureSchema();
  console.log("DATABASE: table ready");
}

async function q(text, params) { return pool.query(text, params); }

async function ensureCol(table, col, typeSql) {
  await q(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${col} ${typeSql}`);
}

async function ensureSchema() {
  await q(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      event TEXT NOT NULL,
      client_mac TEXT,
      client_ip TEXT,
      phone TEXT,
      full_name TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      kvkk_version TEXT,
      tz TEXT,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb
    )
  `);

  await ensureCol("access_logs", "continue_url", "TEXT");
  await ensureCol("access_logs", "tz", "TEXT");
  await ensureCol("access_logs", "meta", "JSONB NOT NULL DEFAULT '{}'::jsonb");

  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone)`);

  await q(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      tz TEXT NOT NULL,
      record_count INT NOT NULL,
      hmac_hex TEXT NOT NULL
    )
  `);
  await ensureCol("daily_packages", "tz", "TEXT");
  await ensureCol("daily_packages", "record_count", "INT");
  await ensureCol("daily_packages", "hmac_hex", "TEXT");
}

async function dbLog(event, ctx) {
  if (!pool) return;
  try {
    await q(
      `INSERT INTO access_logs(event, client_mac, client_ip, phone, full_name, ssid, ap_name, base_grant_url, continue_url, kvkk_version, tz, meta)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
      [
        event,
        ctx.client_mac || null,
        ctx.client_ip || null,
        ctx.phone || null,
        ctx.full_name || null,
        ctx.ssid || null,
        ctx.ap_name || null,
        ctx.base_grant_url || null,
        ctx.continue_url || null,
        KVKK_VERSION,
        TZ,
        JSON.stringify(ctx.meta || {}),
      ]
    );
  } catch (e) {
    console.log("DB LOG ERROR:", e.message);
  }
}

// ----------------------- SMS (İleti Merkezi) -----------------------
function normalizeTRPhoneForSms(input) {
  const p10 = normalizeTRPhoneForOtp(input);
  if (!p10) return null;
  return "90" + p10;
}

async function sendOtpSms(phoneRaw, otp) {
  const testMode = String(process.env.SMS_TEST_MODE || "false").toLowerCase() === "true";

  const url = (process.env.IM_API_URL || "").trim() || "https://api.iletimerkezi.com/v1/send-sms/json";
  const key = String(process.env.IM_API_KEY || "").trim();
  const hash = String(process.env.IM_API_HASH || "").trim();
  const sender = String(process.env.IM_SENDER || "").trim();

  const to = normalizeTRPhoneForSms(phoneRaw);
  if (!to) throw new Error("MSISDN invalid");
  if (!key || !hash || !sender) {
    throw new Error("İleti Merkezi env missing (IM_API_KEY/IM_API_HASH/IM_SENDER)");
  }

  const messageText = `Odeon WiFi doğrulama kodunuz: ${otp}`;

  const payload = {
    request: {
      authentication: { key, hash },
      order: {
        sender,
        sendDateTime: [],
        iys: "1",
        iysList: "BIREYSEL",
        message: {
          text: messageText,
          receipents: { number: [to] }
        }
      }
    }
  };

  if (testMode) {
    console.log("SMS_TEST_MODE=TRUE. Would send:", { to, sender, messageText, url });
    return { ok: true, test: true };
  }

  const res = await axios.post(url, payload, {
    timeout: 15000,
    headers: { "Content-Type": "application/json" },
  });
  return res.data;
}

// ----------------------- Meraki helpers -----------------------
function pickGrantParams(query) {
  const out = {};
  for (const [k, v] of Object.entries(query || {})) {
    if (k === "base_grant_url") continue;
    out[k] = v;
  }
  return out;
}

function buildGrantUrl(baseGrantUrl, paramsObj) {
  const u = String(baseGrantUrl || "").trim();
  if (!u) return null;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(paramsObj || {})) {
    if (v === undefined || v === null) continue;
    qs.append(k, String(v));
  }
  const tail = qs.toString();
  if (!tail) return u;
  return u + (u.includes("?") ? "&" : "?") + tail;
}

// ----------------------- Routes -----------------------
app.get("/health", (_req, res) => res.json({ ok: true, at: nowIso() }));

// Meraki bazen parametreleri "/?base_grant_url=..." olarak gönderir.
// Query düşmesin diye "/" isteğini "/splash"e query ile yönlendiriyoruz.
app.get("/", (req, res) => {
  const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  return res.redirect(302, "/splash" + qs);
});

app.get("/splash", async (req, res) => {
  console.log("SPLASH_URL", req.originalUrl);

  const base_grant_url = req.query.base_grant_url ? String(req.query.base_grant_url) : "";
  const hasBaseGrant = !!String(base_grant_url).trim();

  const client_mac = req.query.client_mac ? String(req.query.client_mac) : "";
  const client_ip = req.query.client_ip ? String(req.query.client_ip) : "";
  const ssid = req.query.ssid ? String(req.query.ssid) : "";
  const ap_name = req.query.ap_name ? String(req.query.ap_name) : "";
  const continue_url = req.query.continue_url
    ? String(req.query.continue_url)
    : (req.query.user_continue_url ? String(req.query.user_continue_url) : "");

  console.log("SPLASH_OPEN", {
    hasBaseGrant,
    hasContinue: !!String(continue_url || "").trim(),
    hasClientMac: !!client_mac,
    mode: OTP_MODE,
  });

  await dbLog("splash_open", {
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url: continue_url || null,
    meta: { ...clientMeta(req), raw_query: req.query },
  });

  res.type("html").send(`<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Odeon Guest WiFi</title>
  <style>
    :root{--bg:#0b1220;--card:#0f1a2f;--muted:#9fb2d1;--text:#e9f1ff;--accent:#00a3ff;--accent2:#00d18f;--border:rgba(255,255,255,.08)}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui;background:linear-gradient(180deg,#070b14,#0b1220);color:var(--text)}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{width:100%;max-width:460px;background:rgba(15,26,47,.92);border:1px solid var(--border);border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.45);overflow:hidden}
    .top{padding:22px 22px 10px;display:flex;align-items:center;gap:14px}
    .logo{width:44px;height:44px;border-radius:10px;background:#fff;display:flex;align-items:center;justify-content:center;overflow:hidden}
    .logo img{width:100%;height:100%;object-fit:contain}
    h1{font-size:18px;margin:0}
    .sub{color:var(--muted);font-size:13px;margin-top:4px}
    .body{padding:18px 22px 22px}
    label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px}
    input{width:100%;padding:12px;border-radius:12px;border:1px solid var(--border);background:rgba(0,0,0,.18);color:var(--text)}
    .kvkk{margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:12px;background:rgba(0,0,0,.12);color:var(--muted);font-size:12px;max-height:120px;overflow:auto}
    .chk{display:flex;gap:10px;align-items:flex-start;margin-top:12px}
    .chk input{width:18px;height:18px;margin-top:2px}
    .btn{margin-top:14px;width:100%;padding:12px;border:none;border-radius:12px;background:linear-gradient(90deg,var(--accent),var(--accent2));color:#001018;font-weight:700;cursor:pointer}
    .foot{padding:12px 22px;color:var(--muted);font-size:12px;border-top:1px solid var(--border)}
    .warn{color:#ffd38a;font-size:12px;margin-top:10px}
    .tiny{font-size:11px;color:var(--muted);margin-top:10px}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="top">
      <div class="logo"><img src="/logo.png" alt="Odeon"/></div>
      <div>
        <h1>Odeon Guest WiFi</h1>
        <div class="sub">Telefon doğrulaması ile internete bağlanın</div>
      </div>
    </div>
    <div class="body">
      ${!hasBaseGrant ? `<div class="warn">Uyarı: Meraki parametreleri eksik. Bu sayfaya Meraki Splash üzerinden gelmelisiniz.</div>` : ""}

      <form method="POST" action="/otp/start">
        <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}"/>
        <input type="hidden" name="grant_params_json" value="${escapeHtml(JSON.stringify(pickGrantParams(req.query)))}"/>
        <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}"/>
        <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}"/>
        <input type="hidden" name="ssid" value="${escapeHtml(ssid)}"/>
        <input type="hidden" name="ap_name" value="${escapeHtml(ap_name)}"/>

        <label>Ad Soyad</label>
        <input name="full_name" maxlength="80" placeholder="Ad Soyad" required/>

        <label>Cep Telefonu</label>
        <input name="phone" inputmode="tel" placeholder="5XXXXXXXXX" required/>

        <div class="kvkk">
          <b>KVKK Aydınlatma Metni (Placeholder)</b><br/>
          Bu metin daha sonra şirket metni ile değiştirilecektir.
        </div>

        <div class="chk">
          <input type="checkbox" name="kvkk_ok" value="1" required/>
          <div>KVKK metnini okudum ve kabul ediyorum.</div>
        </div>

        <button class="btn" type="submit" ${!hasBaseGrant ? "disabled style=\"opacity:.6;cursor:not-allowed\" " : ""}>Kodu Gönder</button>
        <div class="tiny">Numara formatı: <b>5XXXXXXXXX</b> (başında 0 olmadan)</div>
      </form>
    </div>
    <div class="foot">© ${new Date().getFullYear()} Odeon Technology</div>
  </div>
</div>
</body>
</html>`);
});

app.post("/otp/start", async (req, res) => {
  const phoneRaw = String(req.body.phone || "");
  const phone10 = normalizeTRPhoneForOtp(phoneRaw);
  const full_name = String(req.body.full_name || "").trim().slice(0, 80);

  const client_mac = String(req.body.client_mac || "");
  const client_ip = String(req.body.client_ip || "");
  const ssid = String(req.body.ssid || "");
  const ap_name = String(req.body.ap_name || "");

  const base_grant_url = String(req.body.base_grant_url || "").trim();
  console.log("OTP_START_BASE_GRANT", JSON.stringify(req.body.base_grant_url));

  const grant_params_json = String(req.body.grant_params_json || "{}");
  const kvkk_ok = req.body.kvkk_ok === "1";

  if (!kvkk_ok) return res.status(400).send("KVKK consent required");
  if (!phone10) return res.status(400).send("MSISDN format invalid. Expected 5XXXXXXXXX (10 digits).");
  if (!base_grant_url || !/^https?:\/\//i.test(base_grant_url)) {
    return res.status(400).send("base_grant_url missing/invalid");
  }

  const okMac = await rlHit(`rl:mac:${client_mac || "nomac"}`, RL_MAC_SECONDS);
  const okPhone = await rlHit(`rl:phone:${phone10}`, RL_PHONE_SECONDS);
  if (!okMac || !okPhone) return res.status(429).send("Too many requests. Please wait.");

  const otp = randDigits(6);
  const marker = randDigits(6);

  let grantParams = {};
  try { grantParams = JSON.parse(grant_params_json); } catch (_) { grantParams = {}; }

  const payload = {
    otp,
    phone: phone10,
    full_name,
    expiresAt: Date.now() + OTP_TTL_SECONDS * 1000,
    wrong: 0,
    lockedUntil: 0,
    grant: { base_grant_url, grantParams, client_mac, client_ip, ssid, ap_name }
  };

  await kvSet(`otp:${marker}`, payload, OTP_TTL_SECONDS);

  console.log("OTP_CREATED", { marker, last4: phone10.slice(-4), client_mac: client_mac || "" });
  await dbLog("otp_created", { client_mac, client_ip, phone: phone10, full_name, ssid, ap_name, base_grant_url, continue_url: (grantParams.continue_url || grantParams.user_continue_url) || null, meta: { marker, ...clientMeta(req) } });

  try {
    if (OTP_MODE === "sms") {
      await sendOtpSms(phone10, otp);
      console.log("OTP_SMS_SENT", { marker, last4: phone10.slice(-4) });
      await dbLog("otp_sms_sent", { client_mac, client_ip, phone: phone10, full_name, ssid, ap_name, base_grant_url, meta: { marker } });
    } else {
      console.log("OTP_SCREEN_CODE", { marker, otp });
    }
  } catch (e) {
    console.log("OTP_SMS_FAILED", { marker, err: e.message });
    await dbLog("otp_sms_failed", { client_mac, client_ip, phone: phone10, full_name, ssid, ap_name, base_grant_url, meta: { marker, err: e.message } });
    console.log("OTP_SCREEN_CODE", { marker, otp });
  }

  res.type("html").send(`<!doctype html><html lang="tr"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Kod Doğrulama</title>
<style>
  body{margin:0;font-family:system-ui;background:#0b1220;color:#e9f1ff;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
  .card{width:100%;max-width:420px;background:#0f1a2f;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:22px;box-shadow:0 16px 48px rgba(0,0,0,.45)}
  h1{font-size:18px;margin:0 0 8px}
  p{margin:0 0 14px;color:#9fb2d1;font-size:13px}
  label{display:block;font-size:12px;color:#9fb2d1;margin:12px 0 6px}
  input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.18);color:#e9f1ff}
  .btn{margin-top:14px;width:100%;padding:12px;border:none;border-radius:12px;background:linear-gradient(90deg,#00a3ff,#00d18f);font-weight:700;color:#001018;cursor:pointer}
</style></head><body>
<div class="card">
  <h1>Kodu Girin</h1>
  <p>${OTP_MODE === "sms" ? "Kod SMS ile gönderildi." : "Kod ekranda/loglarda görünebilir (screen mode)."} Telefon: <b>${maskPhone(phone10)}</b></p>
  <form method="POST" action="/otp/verify">
    <input type="hidden" name="marker" value="${escapeHtml(marker)}"/>
    <label>Doğrulama Kodu</label>
    <input name="otp" inputmode="numeric" maxlength="6" placeholder="6 haneli kod" required/>
    <button class="btn" type="submit">Bağlan</button>
  </form>
</div>
</body></html>`);
});

app.post("/otp/verify", async (req, res) => {
  const marker = String(req.body.marker || "").trim();
  const otpIn = String(req.body.otp || "").trim();

  const key = `otp:${marker}`;
  const st = await kvGet(key);
  if (!st) return res.status(400).send("OTP expired or invalid");
  if (Date.now() > (st.expiresAt || 0)) { await kvDel(key); return res.status(400).send("OTP expired"); }
  if (Date.now() < (st.lockedUntil || 0)) return res.status(429).send("Locked. Try later.");

  if (otpIn !== st.otp) {
    st.wrong = (st.wrong || 0) + 1;
    if (st.wrong >= MAX_WRONG_ATTEMPTS) st.lockedUntil = Date.now() + LOCK_SECONDS * 1000;
    await kvSet(key, st, Math.max(5, Math.floor((st.expiresAt - Date.now()) / 1000)));
    await dbLog("otp_wrong", { client_mac: st.grant?.client_mac, client_ip: st.grant?.client_ip, phone: st.phone, full_name: st.full_name, ssid: st.grant?.ssid, ap_name: st.grant?.ap_name, base_grant_url: st.grant?.base_grant_url, continue_url: (st.grant?.grantParams?.continue_url || st.grant?.grantParams?.user_continue_url) || null, meta: { marker, wrong: st.wrong } });
    return res.status(400).send("Wrong code");
  }

  console.log("OTP_VERIFY_OK", { marker, client_mac: st.grant?.client_mac || "" });
  await dbLog("otp_verify_ok", { client_mac: st.grant?.client_mac, client_ip: st.grant?.client_ip, phone: st.phone, full_name: st.full_name, ssid: st.grant?.ssid, ap_name: st.grant?.ap_name, base_grant_url: st.grant?.base_grant_url, continue_url: (st.grant?.grantParams?.continue_url || st.grant?.grantParams?.user_continue_url) || null, meta: { marker } });

  console.log("VERIFY_BASE_GRANT", JSON.stringify(st.grant?.base_grant_url));
  const grantUrl = buildGrantUrl(st.grant?.base_grant_url, st.grant?.grantParams || {});
  if (!grantUrl) return res.status(400).send("OTP verified but base_grant_url missing");

  await kvDel(key);
  console.log("GRANT_CLIENT_REDIRECT:", grantUrl);
  return res.redirect(grantUrl);
});

// Admin
app.get("/admin", requireAdmin, (_req, res) => res.redirect("/admin/logs"));

app.get("/admin/logs", requireAdmin, async (req, res) => {
  if (!pool) return res.status(503).send("DB not configured");
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || "50", 10)));
  const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
  const rows = (await q(
    `SELECT id, created_at, event, client_mac, client_ip, phone, full_name, ssid, ap_name, kvkk_version, tz
     FROM access_logs
     ORDER BY created_at DESC
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  )).rows;

  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Logs</title>
<style>
  body{font-family:system-ui;margin:0;background:#0b1220;color:#e9f1ff}
  .top{padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.08);display:flex;gap:12px;align-items:center}
  a{color:#7dd3ff;text-decoration:none}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top}
  th{color:#9fb2d1;font-weight:600}
  .wrap{padding:16px}
  .muted{color:#9fb2d1}
  .pill{display:inline-block;padding:2px 8px;border:1px solid rgba(255,255,255,.10);border-radius:999px;font-size:12px;color:#9fb2d1}
</style></head><body>
<div class="top">
  <b>Admin</b>
  <a href="/admin/logs">Logs</a>
  <a href="/admin/daily">Daily</a>
  <span class="muted">limit=${limit} offset=${offset}</span>
</div>
<div class="wrap">
<table><thead><tr>
  <th>Time</th><th>Event</th><th>MAC</th><th>IP</th><th>Phone</th><th>Name</th><th>SSID/AP</th><th>KVKK</th>
</tr></thead><tbody>
${rows.map(r => {
  const t = new Date(r.created_at).toISOString();
  return `<tr>
    <td class="muted">${escapeHtml(t)}</td>
    <td><span class="pill">${escapeHtml(r.event)}</span></td>
    <td class="muted">${escapeHtml(r.client_mac || "")}</td>
    <td class="muted">${escapeHtml(r.client_ip || "")}</td>
    <td class="muted">${escapeHtml(r.phone ? maskPhone(r.phone) : "")}</td>
    <td>${escapeHtml(r.full_name || "")}</td>
    <td class="muted">${escapeHtml((r.ssid||"") + (r.ap_name ? " / " + r.ap_name : ""))}</td>
    <td class="muted">${escapeHtml(r.kvkk_version || "")}</td>
  </tr>`;
}).join("")}
</tbody></table>
<div style="margin-top:14px;display:flex;gap:10px">
  <a href="/admin/logs?limit=${limit}&offset=${Math.max(0, offset-limit)}">Prev</a>
  <a href="/admin/logs?limit=${limit}&offset=${offset+limit}">Next</a>
</div>
</div></body></html>`);
});

// Daily packages UI + endpoints
function dayStrTR(d = new Date()) {
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" });
  return fmt.format(d);
}

async function rowsForDay(day) {
  const start = new Date(`${day}T00:00:00.000Z`);
  const end = new Date(`${day}T23:59:59.999Z`);
  return (await q(
    `SELECT id, created_at, event, client_mac, client_ip, phone, full_name, ssid, ap_name, base_grant_url, continue_url, kvkk_version, tz, meta
     FROM access_logs
     WHERE created_at >= $1 AND created_at <= $2
     ORDER BY created_at ASC, id ASC`,
    [start.toISOString(), end.toISOString()]
  )).rows;
}

function canonicalLine(r) {
  const obj = {
    id: r.id,
    created_at: new Date(r.created_at).toISOString(),
    event: r.event || "",
    client_mac: r.client_mac || "",
    client_ip: r.client_ip || "",
    phone: r.phone || "",
    full_name: r.full_name || "",
    ssid: r.ssid || "",
    ap_name: r.ap_name || "",
    base_grant_url: r.base_grant_url || "",
    continue_url: r.continue_url || "",
    kvkk_version: r.kvkk_version || "",
    tz: r.tz || "",
    meta: r.meta || {},
  };
  const keys = Object.keys(obj).sort();
  const sorted = {};
  for (const k of keys) sorted[k] = obj[k];
  return JSON.stringify(sorted);
}

function hmacHex(secret, lines) {
  const h = crypto.createHmac("sha256", secret);
  for (const line of lines) { h.update(line); h.update("\n"); }
  return h.digest("hex");
}

async function buildDaily(day) {
  const secret = process.env.DAILY_HMAC_SECRET || "";
  if (!secret) throw new Error("DAILY_HMAC_SECRET missing");
  const rs = await rowsForDay(day);
  const lines = rs.map(canonicalLine);
  const hex = hmacHex(secret, lines);
  await q(
    `INSERT INTO daily_packages(day, tz, record_count, hmac_hex)
     VALUES($1,$2,$3,$4)
     ON CONFLICT(day) DO UPDATE SET tz=EXCLUDED.tz, record_count=EXCLUDED.record_count, hmac_hex=EXCLUDED.hmac_hex, created_at=NOW()`,
    [day, TZ, rs.length, hex]
  );
  return { day, tz: TZ, record_count: rs.length, hmac_hex: hex };
}

async function verifyDaily(day) {
  const secret = process.env.DAILY_HMAC_SECRET || "";
  if (!secret) throw new Error("DAILY_HMAC_SECRET missing");
  const pack = (await q(`SELECT day, tz, record_count, hmac_hex FROM daily_packages WHERE day=$1`, [day])).rows[0];
  if (!pack) return { ok: false, reason: "not_built" };
  const rs = await rowsForDay(day);
  const hex = hmacHex(secret, rs.map(canonicalLine));
  return { ok: hex === pack.hmac_hex, expected: pack.hmac_hex, computed: hex, count_db: pack.record_count, count_now: rs.length, tz: pack.tz };
}

app.get("/admin/daily", requireAdmin, async (_req, res) => {
  if (!pool) return res.status(503).send("DB not configured");
  const rows = (await q(`SELECT day, created_at, tz, record_count, hmac_hex FROM daily_packages ORDER BY day DESC LIMIT 30`)).rows;
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Daily Packages</title>
<style>
  body{font-family:system-ui;margin:0;background:#0b1220;color:#e9f1ff}
  .top{padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.08);display:flex;gap:12px;align-items:center}
  a{color:#7dd3ff;text-decoration:none}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top}
  th{color:#9fb2d1;font-weight:600}
  .wrap{padding:16px}
  code{color:#9fe3ff}
</style></head><body>
<div class="top"><b>Admin</b><a href="/admin/logs">Logs</a><a href="/admin/daily">Daily</a></div>
<div class="wrap">
  <div style="margin-bottom:10px;color:#9fb2d1">Build: <code>/admin/daily/build?day=YYYY-MM-DD</code> &nbsp; Verify: <code>/admin/daily/verify?day=YYYY-MM-DD</code></div>
  <table><thead><tr><th>Day</th><th>Created</th><th>TZ</th><th>Count</th><th>HMAC</th></tr></thead><tbody>
  ${rows.map(r => `<tr>
    <td>${escapeHtml(r.day)}</td>
    <td style="color:#9fb2d1">${escapeHtml(new Date(r.created_at).toISOString())}</td>
    <td style="color:#9fb2d1">${escapeHtml(r.tz)}</td>
    <td style="color:#9fb2d1">${escapeHtml(String(r.record_count))}</td>
    <td><code>${escapeHtml(r.hmac_hex.slice(0, 40))}…</code></td>
  </tr>`).join("")}
  </tbody></table>
</div></body></html>`);
});

app.get("/admin/daily/build", requireAdmin, async (req, res) => {
  try { res.json({ ok: true, ...(await buildDaily(String(req.query.day || dayStrTR()))) }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});
app.get("/admin/daily/verify", requireAdmin, async (req, res) => {
  try { res.json(await verifyDaily(String(req.query.day || dayStrTR()))); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Cron endpoint (GET/POST)
app.all("/cron/daily", async (req, res) => {
  try {
    const secret = process.env.DAILY_HMAC_SECRET || "";
    if (!secret) return res.status(503).send("DAILY_HMAC_SECRET missing");
    const key = process.env.CRON_KEY;
    if (key) {
      const got = req.get("x-cron-key") || req.query.key;
      if (got !== key) return res.status(403).send("Forbidden");
    }
    const day = String(req.query.day || dayStrTR());
    const built = await buildDaily(day);
    const ver = await verifyDaily(day);
    res.json({ ok: true, built, verify: ver });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ----------------------- Start -----------------------
async function main() {
  console.log("ENV:", {
    OTP_MODE,
    OTP_TTL_SECONDS,
    RL_MAC_SECONDS,
    RL_PHONE_SECONDS,
    MAX_WRONG_ATTEMPTS,
    LOCK_SECONDS,
    KVKK_VERSION,
    TZ,
    DB_SET: !!process.env.DATABASE_URL,
    REDIS_SET: !!(process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL),
    ADMIN_USER_SET: !!process.env.ADMIN_USER,
    ADMIN_PASS_SET: !!process.env.ADMIN_PASS,
    DAILY_HMAC_SET: !!process.env.DAILY_HMAC_SECRET,
  });

  await Promise.allSettled([redisInit(), dbInit()]);

  const port = parseInt(process.env.PORT || "8080", 10);
  app.listen(port, () => console.log(`Server running on port ${port}`));
}

main().catch((e) => { console.error("Fatal start error:", e); process.exit(1); });
