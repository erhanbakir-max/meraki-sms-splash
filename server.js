"use strict";

/**
 * Meraki Splash + OTP (screen) + 5651 log (Postgres) + Daily hash chain (HMAC)
 * - CommonJS (require) => "Cannot use import outside a module" hatası biter.
 * - Redis opsiyonel: REDIS_URL varsa kullanır, yoksa memory fallback.
 * - Postgres zorunlu: DATABASE_URL varsa 5651 log + daily çalışır (yoksa sadece splash).
 *
 * ENV (Railway Variables):
 *   PORT=8080 (Railway otomatik)
 *   TZ=Europe/Istanbul
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   DATABASE_URL=... (Railway Postgres reference)
 *   REDIS_URL=... (Railway Redis reference) [opsiyonel]
 *   OTP_MODE=screen
 *   OTP_TTL_SECONDS=180
 *   KVKK_VERSION=2026-02-12-placeholder
 *   DAILY_HMAC_SECRET=... (5651 günlük imza için zorunlu önerilir)
 *   BRAND_NAME=Odeon Technology
 *   BRAND_LOGO_URL=https://.../logo.svg (opsiyonel)
 */

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

let Redis = null;
try {
  Redis = require("ioredis");
} catch (_) {
  Redis = null;
}

process.env.TZ = process.env.TZ || "Europe/Istanbul";

const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(express.json({ limit: "128kb" }));

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || "8080", 10);

const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms sonra)
const OTP_TTL_SECONDS = clampInt(process.env.OTP_TTL_SECONDS, 180, 30, 600);
const RL_MAC_SECONDS = clampInt(process.env.RL_MAC_SECONDS, 30, 5, 600);
const RL_PHONE_SECONDS = clampInt(process.env.RL_PHONE_SECONDS, 60, 5, 600);
const MAX_WRONG_ATTEMPTS = clampInt(process.env.MAX_WRONG_ATTEMPTS, 5, 1, 20);
const LOCK_SECONDS = clampInt(process.env.LOCK_SECONDS, 600, 60, 3600);

const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const BRAND_NAME = process.env.BRAND_NAME || "Odeon Technology";
const BRAND_LOGO_URL = process.env.BRAND_LOGO_URL || ""; // opsiyonel

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ""; // önerilir (5651)
const DB_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || "";

// -------------------- Helpers --------------------
function clampInt(v, def, min, max) {
  const n = parseInt(String(v ?? ""), 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, n));
}

function nowISO() {
  return new Date().toISOString();
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function hmacHex(key, s) {
  return crypto.createHmac("sha256", String(key)).update(String(s)).digest("hex");
}

function randDigits(len) {
  let out = "";
  while (out.length < len) out += String(Math.floor(Math.random() * 10));
  return out.slice(0, len);
}

function safeLast4(s) {
  if (!s) return null;
  const t = String(s).replace(/\D/g, "");
  if (t.length < 4) return null;
  return t.slice(-4);
}

function cleanPhoneTR10(s) {
  // beklenen: 5XXXXXXXXX (10 hane)
  const t = String(s || "").replace(/\D/g, "");
  if (t.length === 10 && t.startsWith("5")) return t;
  // bazen 0 ile geliyor: 05XXXXXXXXX
  if (t.length === 11 && t.startsWith("05")) return t.slice(1);
  // bazen 90 ile geliyor: 90 5XXXXXXXXX
  if (t.length === 12 && t.startsWith("90") && t[2] === "5") return t.slice(2);
  return "";
}

function parseBasicAuth(req) {
  const h = req.headers["authorization"];
  if (!h || typeof h !== "string") return null;
  const m = h.match(/^Basic\s+(.+)$/i);
  if (!m) return null;
  let decoded = "";
  try {
    decoded = Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return null;
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
}

function requireAdmin(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send("ADMIN_USER / ADMIN_PASS not configured");
  }
  const creds = parseBasicAuth(req);
  if (!creds || creds.user !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Unauthorized");
  }
  next();
}

function getClientIp(req) {
  // X-Forwarded-For ilk IP
  const xff = req.headers["x-forwarded-for"];
  if (xff && typeof xff === "string") {
    const ip = xff.split(",")[0].trim();
    return ip || "";
  }
  return (req.socket && req.socket.remoteAddress) ? String(req.socket.remoteAddress) : "";
}

// -------------------- Redis (optional) + Memory fallback --------------------
const memStore = new Map(); // key => { val, exp }

function memSet(key, val, ttlSec) {
  memStore.set(key, { val, exp: Date.now() + ttlSec * 1000 });
}
function memGet(key) {
  const it = memStore.get(key);
  if (!it) return null;
  if (Date.now() > it.exp) {
    memStore.delete(key);
    return null;
  }
  return it.val;
}
function memDel(key) {
  memStore.delete(key);
}

let redis = null;
if (Redis && REDIS_URL) {
  try {
    redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2 });
    redis.on("error", (e) => console.log("REDIS_ERROR:", e && e.message ? e.message : e));
    console.log("REDIS: connected");
  } catch (e) {
    console.log("REDIS: failed, fallback to memory:", e.message);
    redis = null;
  }
} else {
  console.log("REDIS: not configured. Running WITHOUT persistent store.");
}

async function kvSet(key, val, ttlSec) {
  if (redis) {
    await redis.set(key, JSON.stringify(val), "EX", ttlSec);
    return;
  }
  memSet(key, val, ttlSec);
}

async function kvGet(key) {
  if (redis) {
    const raw = await redis.get(key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }
  return memGet(key);
}

async function kvDel(key) {
  if (redis) {
    await redis.del(key);
    return;
  }
  memDel(key);
}

// -------------------- Postgres (5651 logs + daily) --------------------
let pool = null;

if (DB_URL) {
  pool = new Pool({ connectionString: DB_URL, max: 5, idleTimeoutMillis: 30000 });
  pool.on("error", (e) => console.log("PG_POOL_ERROR:", e && e.message ? e.message : e));
  console.log("DATABASE: connected");
} else {
  console.log("DATABASE: not configured (DATABASE_URL missing). 5651 logs disabled.");
}

async function q(sql, params = []) {
  if (!pool) return { rows: [] };
  const r = await pool.query(sql, params);
  return r;
}

async function ensureDb() {
  if (!pool) return;

  // access_logs: text kolonlar (sen "text" demiştin) -> inet yok.
  // daily_summaries: gün bazlı hash zinciri
  await q(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
      accept_language TEXT,
      user_agent TEXT,
      tz TEXT,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_event ON access_logs(event);`);

  await q(`
    CREATE TABLE IF NOT EXISTS daily_summaries (
      day DATE PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      tz TEXT NOT NULL,
      count_total BIGINT NOT NULL,
      count_verify_ok BIGINT NOT NULL,
      count_grant_ok BIGINT NOT NULL,
      hash_prev TEXT,
      hash_curr TEXT NOT NULL,
      hmac_sig TEXT NOT NULL
    );
  `);

  console.log("DATABASE: table ready");
}

async function dbLog(ev, data) {
  if (!pool) return;
  try {
    const meta = data && data.meta ? data.meta : {};
    await q(
      `INSERT INTO access_logs
        (event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, marker, phone, full_name, kvkk_version, accept_language, user_agent, tz, meta)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
      [
        String(ev),
        data.client_mac || null,
        data.client_ip || null,
        data.ssid || null,
        data.ap_name || null,
        data.base_grant_url || null,
        data.continue_url || null,
        data.marker || null,
        data.phone || null,
        data.full_name || null,
        data.kvkk_version || KVKK_VERSION,
        data.accept_language || null,
        data.user_agent || null,
        data.tz || process.env.TZ || "Europe/Istanbul",
        JSON.stringify(meta || {}),
      ]
    );
  } catch (e) {
    console.log("DB LOG ERROR:", e.message || e);
  }
}

// -------------------- Meraki Splash parse --------------------
function extractMerakiParams(req) {
  // Meraki genelde querystring ile gelir
  const q = req.query || {};
  const base_grant_url = q.base_grant_url ? String(q.base_grant_url) : "";
  const continue_url = q.continue_url ? String(q.continue_url) : "";
  const client_ip = q.client_ip ? String(q.client_ip) : "";
  const client_mac = q.client_mac ? String(q.client_mac) : "";
  const node_mac = q.node_mac ? String(q.node_mac) : "";
  const gateway_id = q.gateway_id ? String(q.gateway_id) : "";
  const node_id = q.node_id ? String(q.node_id) : "";

  return { base_grant_url, continue_url, client_ip, client_mac, node_mac, gateway_id, node_id };
}

function splashContext(req) {
  const m = extractMerakiParams(req);
  const hasBaseGrant = !!m.base_grant_url;
  const hasContinue = !!m.continue_url;
  const hasClientMac = !!m.client_mac;
  return { ...m, hasBaseGrant, hasContinue, hasClientMac };
}

// -------------------- Rate limit + lock (Redis/mem) --------------------
async function rlKey(kind, v) {
  return `rl:${kind}:${v}`;
}
async function lockKey(mac) {
  return `lock:mac:${mac}`;
}

async function isLocked(mac) {
  if (!mac) return false;
  const v = await kvGet(await lockKey(mac));
  return !!v;
}

async function bumpRate(kind, v, windowSec) {
  const key = await rlKey(kind, v);
  const cur = await kvGet(key);
  if (!cur) {
    await kvSet(key, { n: 1 }, windowSec);
    return 1;
  }
  cur.n = (cur.n || 0) + 1;
  await kvSet(key, cur, windowSec);
  return cur.n;
}

// -------------------- OTP store --------------------
async function otpKey(marker) {
  return `otp:${marker}`;
}

async function createOtp({ phone10, client_mac }) {
  const marker = randDigits(6);
  const otp = randDigits(6);
  const payload = {
    marker,
    otp,
    phone_last4: safeLast4(phone10),
    phone10: phone10 || "",
    client_mac: client_mac || "",
    wrong: 0,
    created_at: nowISO(),
  };
  await kvSet(await otpKey(marker), payload, OTP_TTL_SECONDS);
  return payload;
}

async function getOtp(marker) {
  if (!marker) return null;
  return await kvGet(await otpKey(marker));
}

async function delOtp(marker) {
  if (!marker) return;
  await kvDel(await otpKey(marker));
}

// -------------------- UI (HTML) --------------------
function pageShell({ title, bodyHtml, subtitle }) {
  const logo = BRAND_LOGO_URL ? `<img src="${escapeHtml(BRAND_LOGO_URL)}" alt="logo" onerror="this.style.display='none'">` : "";
  const safeTitle = escapeHtml(title || BRAND_NAME);
  const safeSub = escapeHtml(subtitle || "");
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${safeTitle}</title>
  <style>
    :root{
      --bg0:#070B14; --bg1:#0B1224; --card:#0F1A33; --card2:#0C152B;
      --text:#EAF0FF; --muted:#A8B3D6; --line:rgba(255,255,255,.08);
      --accent:#5B7CFF; --accent2:#00B3FF; --ok:#25D695; --bad:#FF5C7A;
      --shadow: 0 12px 40px rgba(0,0,0,.45); --radius: 18px;
      --font: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }
    *{box-sizing:border-box}
    body{
      margin:0; font-family:var(--font); color:var(--text);
      background: radial-gradient(1200px 600px at 20% 10%, rgba(91,124,255,.25), transparent 60%),
                  radial-gradient(900px 500px at 80% 20%, rgba(0,179,255,.18), transparent 55%),
                  linear-gradient(180deg, var(--bg0), var(--bg1));
      min-height:100vh;
    }
    .wrap{max-width:980px; margin:0 auto; padding:28px 18px 60px;}
    .topbar{
      display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:14px 16px; border:1px solid var(--line);
      background:rgba(15,26,51,.6); backdrop-filter: blur(8px);
      border-radius: var(--radius); box-shadow: var(--shadow);
    }
    .brand{display:flex; align-items:center; gap:12px;}
    .logo{
      width:44px; height:44px; border-radius:12px;
      background:rgba(255,255,255,.06); display:grid; place-items:center; overflow:hidden;
      border:1px solid var(--line);
    }
    .logo img{width:100%; height:100%; object-fit:contain; padding:8px;}
    .brand h1{font-size:16px; margin:0; letter-spacing:.2px;}
    .brand p{margin:2px 0 0; font-size:12px; color:var(--muted);}
    .card{
      margin-top:18px; border:1px solid var(--line);
      background:rgba(15,26,51,.55); border-radius: var(--radius);
      box-shadow: var(--shadow); overflow:hidden;
    }
    .card-h{padding:16px 16px 10px; display:flex; align-items:center; justify-content:space-between; gap:10px;}
    .card-h .title{font-size:15px; margin:0;}
    .grid{display:grid; grid-template-columns: 1.2fr .8fr; gap:14px; padding:0 16px 16px;}
    @media (max-width:860px){ .grid{grid-template-columns:1fr;} }
    .panel{ border:1px solid var(--line); border-radius:16px; background:rgba(12,21,43,.55); padding:14px; }
    label{display:block; font-size:12px; color:var(--muted); margin:0 0 8px;}
    input{
      width:100%; padding:12px 12px; border-radius:12px;
      border:1px solid var(--line); background:rgba(0,0,0,.20);
      color:var(--text); outline:none;
    }
    input:focus{border-color: rgba(0,179,255,.5); box-shadow: 0 0 0 4px rgba(0,179,255,.12);}
    .hint{font-size:12px; color:var(--muted); margin-top:10px; line-height:1.45;}
    .btn{
      appearance:none; border:1px solid rgba(91,124,255,.45);
      background: linear-gradient(180deg, rgba(91,124,255,.95), rgba(91,124,255,.75));
      color:white; padding:10px 12px; border-radius:12px; cursor:pointer;
      font-weight:700; font-size:13px; width:100%;
    }
    .btn:active{transform: translateY(1px);}
    .btn.ghost{background:rgba(0,0,0,.12); color:var(--text); border:1px solid var(--line);}
    .row{display:grid; grid-template-columns:1fr 1fr; gap:10px;}
    @media (max-width:520px){ .row{grid-template-columns:1fr;} }
    .pill{
      display:inline-flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);
      border:1px solid var(--line); padding:8px 10px; border-radius:999px; background:rgba(0,0,0,.12);
    }
    table{width:100%; border-collapse: collapse;}
    th,td{padding:12px 12px; border-top:1px solid var(--line); font-size:13px; vertical-align:top;}
    th{color:var(--muted); font-weight:700; text-align:left; background:rgba(0,0,0,.10);}
    tr:hover td{background:rgba(255,255,255,.03);}
    .ok{color:var(--ok); font-weight:800;}
    .bad{color:var(--bad); font-weight:800;}
    .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    a{color:#bcd0ff}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo">${logo}</div>
        <div>
          <h1>${escapeHtml(BRAND_NAME)}</h1>
          <p>${safeSub}</p>
        </div>
      </div>
      <div style="display:flex; gap:10px; align-items:center;">
        <span class="pill"><span class="mono">TZ</span>&nbsp;${escapeHtml(process.env.TZ || "Europe/Istanbul")}</span>
      </div>
    </div>
    ${bodyHtml || ""}
  </div>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// -------------------- Splash pages --------------------
function kvkkPlaceholderHtml() {
  return `
  <div class="hint">
    <b>KVKK Aydınlatma Metni (Placeholder)</b><br>
    Bu metin örnek amaçlıdır. Kurumunuzun KVKK aydınlatma metni ile değiştirilecektir.
  </div>`;
}

function splashFormHtml(ctx, screenOtp) {
  const q = reqQueryPreserve(ctx);
  const subtitle = "Misafir İnternet Erişimi • KVKK Onay • OTP Doğrulama";
  const otpInfo = screenOtp ? `<div class="pill"><span class="mono">OTP</span>&nbsp;<span class="ok mono">${escapeHtml(screenOtp)}</span></div>` : "";

  const body = `
  <div class="card">
    <div class="card-h">
      <h2 class="title">Bağlantı Doğrulama</h2>
      ${otpInfo}
    </div>
    <div class="grid">
      <div class="panel">
        <form method="POST" action="/otp/start${q}">
          <div class="row">
            <div>
              <label>Ad Soyad</label>
              <input name="full_name" placeholder="Ad Soyad" required maxlength="80">
            </div>
            <div>
              <label>Cep Telefonu</label>
              <input name="phone" placeholder="5XXXXXXXXX" inputmode="numeric" required maxlength="16">
            </div>
          </div>
          <label style="margin-top:12px;">
            <input type="checkbox" name="kvkk_ok" value="1" required>
            KVKK aydınlatma metnini okudum, onaylıyorum.
          </label>
          ${kvkkPlaceholderHtml()}
          <div style="margin-top:12px;">
            <button class="btn" type="submit">OTP Oluştur</button>
          </div>
          <div class="hint">
            <b>Not:</b> Şimdilik OTP <b>ekranda</b> gösteriliyor (OTP_MODE=screen).
          </div>
        </form>
      </div>

      <div class="panel">
        <form method="POST" action="/otp/verify${q}">
          <label>Marker</label>
          <input name="marker" placeholder="6 haneli marker" inputmode="numeric" required maxlength="6">
          <label style="margin-top:10px;">OTP</label>
          <input name="otp" placeholder="6 haneli OTP" inputmode="numeric" required maxlength="6">
          <div style="margin-top:12px;">
            <button class="btn" type="submit">Doğrula & Bağlan</button>
          </div>
          <div class="hint">
            Bu adım sonunda Meraki Grant’e yönlendirilirsiniz.
          </div>
        </form>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-h">
      <h2 class="title">Teknik (Meraki)</h2>
      <span class="pill">${ctx.hasBaseGrant ? `<span class="ok">base_grant_url OK</span>` : `<span class="bad">base_grant_url yok</span>`}</span>
    </div>
    <div style="padding:0 16px 16px;">
      <div class="hint mono">
        client_mac=${escapeHtml(ctx.client_mac || "")}<br>
        client_ip=${escapeHtml(ctx.client_ip || "")}<br>
        continue_url=${escapeHtml(ctx.continue_url || "")}
      </div>
    </div>
  </div>
  `;
  return pageShell({ title: BRAND_NAME, subtitle, bodyHtml: body });
}

function reqQueryPreserve(ctx) {
  // Meraki query paramlarını sayfalar arası taşı
  const p = new URLSearchParams();
  for (const k of ["base_grant_url", "continue_url", "client_ip", "client_mac", "node_mac", "gateway_id", "node_id"]) {
    if (ctx[k]) p.set(k, ctx[k]);
  }
  const qs = p.toString();
  return qs ? `?${qs}` : "";
}

// -------------------- Routes --------------------
app.get("/", async (req, res) => {
  const ctx = splashContext(req);
  console.log("SPLASH_OPEN", { hasBaseGrant: ctx.hasBaseGrant, hasContinue: !!ctx.continue_url, hasClientMac: !!ctx.client_mac, mode: OTP_MODE });

  await dbLog("SPLASH_OPEN", {
    client_mac: ctx.client_mac || null,
    client_ip: ctx.client_ip || null,
    base_grant_url: ctx.base_grant_url || null,
    continue_url: ctx.continue_url || null,
    kvkk_version: KVKK_VERSION,
    accept_language: (req.headers["accept-language"] || "").toString(),
    user_agent: (req.headers["user-agent"] || "").toString(),
    tz: process.env.TZ || "Europe/Istanbul",
    meta: { gateway_id: ctx.gateway_id || null, node_id: ctx.node_id || null, node_mac: ctx.node_mac || null },
  });

  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(splashFormHtml(ctx, null));
});

app.post("/otp/start", async (req, res) => {
  const ctx = splashContext(req);
  const full_name = String(req.body.full_name || "").trim();
  const phone10 = cleanPhoneTR10(req.body.phone || "");
  const kvkk_ok = String(req.body.kvkk_ok || "") === "1";

  const client_mac = ctx.client_mac || "";
  const client_ip = ctx.client_ip || getClientIp(req);

  if (!kvkk_ok) return res.status(400).send("KVKK onayı gerekli.");
  if (!full_name || full_name.length < 3) return res.status(400).send("Ad soyad gerekli.");
  if (!phone10) return res.status(400).send("Telefon formatı hatalı. 5XXXXXXXXX (10 hane) olmalı.");

  if (client_mac) {
    if (await isLocked(client_mac)) return res.status(429).send("Cihaz geçici olarak kilitli.");
    await bumpRate("mac", client_mac, RL_MAC_SECONDS);
  }
  await bumpRate("phone", phone10, RL_PHONE_SECONDS);

  const otpObj = await createOtp({ phone10, client_mac });
  console.log("OTP_CREATED", { marker: otpObj.marker, last4: safeLast4(phone10), client_mac: client_mac || null });

  await dbLog("OTP_CREATED", {
    marker: otpObj.marker,
    phone: phone10,
    full_name,
    client_mac: client_mac || null,
    client_ip: client_ip || null,
    base_grant_url: ctx.base_grant_url || null,
    continue_url: ctx.continue_url || null,
    kvkk_version: KVKK_VERSION,
    accept_language: (req.headers["accept-language"] || "").toString(),
    user_agent: (req.headers["user-agent"] || "").toString(),
    tz: process.env.TZ || "Europe/Istanbul",
    meta: { otp_mode: OTP_MODE },
  });

  // OTP_MODE=screen => ekranda göster
  if (OTP_MODE === "screen") {
    console.log("OTP_SCREEN_CODE", { marker: otpObj.marker, otp: otpObj.otp });
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(splashFormHtml(ctx, otpObj.otp));
  }

  // sms modunu sonra açacağız
  res.status(501).send("OTP_MODE=sms henüz aktif değil.");
});

app.post("/otp/verify", async (req, res) => {
  const ctx = splashContext(req);
  const marker = String(req.body.marker || "").replace(/\D/g, "").slice(0, 6);
  const otp = String(req.body.otp || "").replace(/\D/g, "").slice(0, 6);

  const client_mac = ctx.client_mac || "";
  const client_ip = ctx.client_ip || getClientIp(req);

  const obj = await getOtp(marker);
  if (!obj) {
    await dbLog("OTP_VERIFY_FAIL", { marker, client_mac, client_ip, meta: { reason: "NOT_FOUND" } });
    return res.status(400).send("Marker bulunamadı / süresi doldu.");
  }

  // client_mac gelmezse de doğrulama yapalım, ama grant için base_grant_url şart.
  if (await isLocked(obj.client_mac || client_mac)) {
    await dbLog("OTP_VERIFY_FAIL", { marker, client_mac, client_ip, meta: { reason: "LOCKED" } });
    return res.status(429).send("Cihaz geçici olarak kilitli.");
  }

  if (obj.otp !== otp) {
    obj.wrong = (obj.wrong || 0) + 1;
    await kvSet(await otpKey(marker), obj, OTP_TTL_SECONDS);

    await dbLog("OTP_VERIFY_FAIL", {
      marker,
      client_mac,
      client_ip,
      phone: obj.phone10 || null,
      meta: { reason: "WRONG_OTP", wrong: obj.wrong },
    });

    if (obj.wrong >= MAX_WRONG_ATTEMPTS) {
      const m = obj.client_mac || client_mac;
      if (m) await kvSet(await lockKey(m), { locked: true }, LOCK_SECONDS);
      return res.status(429).send("Çok fazla deneme. Cihaz kilitlendi.");
    }
    return res.status(400).send("OTP hatalı.");
  }

  await dbLog("OTP_VERIFY_OK", {
    marker,
    client_mac,
    client_ip,
    phone: obj.phone10 || null,
    meta: { otp_mode: OTP_MODE },
  });

  console.log("OTP_VERIFY_OK", { marker, client_mac: client_mac || obj.client_mac || "" });

  // Meraki grant için base_grant_url şart
  if (!ctx.base_grant_url) {
    // Kullanıcı internete çıkamaz; sayfaya geri dönsün
    console.log("WARN: base_grant_url missing after OTP verify");
    return res.status(200).send(pageShell({
      title: BRAND_NAME,
      subtitle: "Hata",
      bodyHtml: `<div class="card"><div class="card-h"><h2 class="title">Meraki Bilgisi Eksik</h2></div>
      <div style="padding:0 16px 16px;">
        <div class="hint">OTP doğrulandı ancak <b>base_grant_url</b> gelmedi. Bu genelde splash sayfasının Meraki tarafından doğru çağrılmaması veya test URL’si ile açılması durumunda olur.</div>
        <div class="hint"><a href="/">Splash sayfasına Meraki üzerinden tekrar yönlen.</a></div>
      </div></div>`
    }));
  }

  // redirect to Meraki grant
  const grantUrl = buildMerakiGrantUrl(ctx, 3600);
  console.log("GRANT_CLIENT_REDIRECT:", grantUrl);

  await dbLog("GRANT_REDIRECT", {
    marker,
    client_mac,
    client_ip,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url || null,
    phone: obj.phone10 || null,
    meta: { duration: 3600 }
  });

  // marker bir kez kullanılsın
  await delOtp(marker);

  res.setHeader("Cache-Control", "no-store");
  return res.redirect(302, grantUrl);
});

function buildMerakiGrantUrl(ctx, durationSec) {
  // Meraki gereksinimi: base_grant_url + duration + continue_url (varsa)
  // base_grant_url zaten ".../grant" şeklinde gelir. Üzerine query ekle.
  const u = new URL(ctx.base_grant_url);
  u.searchParams.set("duration", String(durationSec || 3600));

  // continue_url varsa ekle; yoksa ekleme (bazı ortamlarda yok)
  if (ctx.continue_url) u.searchParams.set("continue_url", ctx.continue_url);

  // bazı meraki ortamlarında bu paramlar ayrıca istenebiliyor; biz varsa geçiriyoruz:
  for (const k of ["gateway_id", "node_id", "client_ip", "client_mac", "node_mac"]) {
    if (ctx[k]) u.searchParams.set(k, ctx[k]);
  }
  return u.toString();
}

// -------------------- Admin UI (5651) --------------------
app.get("/admin/logs", requireAdmin, async (req, res) => {
  const limit = clampInt(req.query.limit, 200, 50, 2000);
  const qtxt = String(req.query.q || "").trim();
  const day = String(req.query.day || "").trim(); // YYYY-MM-DD
  const phone = String(req.query.phone || "").trim();
  const mac = String(req.query.mac || "").trim();

  if (!pool) return res.status(500).send("DATABASE_URL missing");

  const where = [];
  const params = [];
  let i = 1;

  if (qtxt) {
    where.push(`(event ILIKE $${i} OR client_mac ILIKE $${i} OR client_ip ILIKE $${i} OR phone ILIKE $${i} OR full_name ILIKE $${i})`);
    params.push(`%${qtxt}%`);
    i++;
  }
  if (day) {
    where.push(`created_at >= $${i}::date AND created_at < ($${i}::date + interval '1 day')`);
    params.push(day);
    i++;
  }
  if (phone) {
    where.push(`phone = $${i}`);
    params.push(cleanPhoneTR10(phone) || phone);
    i++;
  }
  if (mac) {
    where.push(`lower(client_mac) = lower($${i})`);
    params.push(mac);
    i++;
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  params.push(limit);

  const rows = (await q(
    `SELECT id, created_at, event, client_mac, client_ip, ssid, ap_name, phone, full_name, kvkk_version
     FROM access_logs
     ${whereSql}
     ORDER BY created_at DESC, id DESC
     LIMIT $${i}`,
    params
  )).rows;

  const today = new Date().toISOString().slice(0, 10);

  const body = `
  <div class="card">
    <div class="card-h">
      <h2 class="title">5651 Loglar</h2>
      <span class="pill"><span class="mono">Kayıt</span>&nbsp;${rows.length}</span>
    </div>
    <div style="padding:0 16px 16px;">
      <form method="GET" action="/admin/logs">
        <div class="row">
          <div><label>Arama (q)</label><input name="q" value="${escapeHtml(qtxt)}" placeholder="event / mac / ip / telefon / ad"></div>
          <div><label>Gün (YYYY-MM-DD)</label><input name="day" value="${escapeHtml(day)}" placeholder="${today}"></div>
        </div>
        <div class="row" style="margin-top:10px;">
          <div><label>Telefon</label><input name="phone" value="${escapeHtml(phone)}" placeholder="5XXXXXXXXX"></div>
          <div><label>MAC</label><input name="mac" value="${escapeHtml(mac)}" placeholder="aa:bb:cc:dd:ee:ff"></div>
        </div>
        <div style="margin-top:12px;">
          <button class="btn" type="submit">Filtrele</button>
        </div>
        <div class="hint">
          Daily rapor: <a href="/admin/daily">/admin/daily</a> • Doğrulama: <a href="/admin/daily/verify">/admin/daily/verify</a>
        </div>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-h"><h2 class="title">Kayıtlar</h2></div>
    <div style="overflow:auto">
      <table>
        <thead>
          <tr>
            <th>Zaman</th><th>Event</th><th>MAC</th><th>IP</th><th>Telefon</th><th>Ad Soyad</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td class="mono">${escapeHtml(new Date(r.created_at).toISOString())}</td>
              <td><span class="mono">${escapeHtml(r.event)}</span></td>
              <td class="mono">${escapeHtml(r.client_mac || "")}</td>
              <td class="mono">${escapeHtml(r.client_ip || "")}</td>
              <td class="mono">${escapeHtml(r.phone || "")}</td>
              <td>${escapeHtml(r.full_name || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  `;

  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(pageShell({ title: "Admin Logs", subtitle: "5651 Uyumlu Kayıtlar • Admin", bodyHtml: body }));
});

app.get("/admin/daily", requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).send("DATABASE_URL missing");

  const rows = (await q(
    `SELECT day, created_at, tz, count_total, count_verify_ok, count_grant_ok, hash_prev, hash_curr, hmac_sig
     FROM daily_summaries
     ORDER BY day DESC
     LIMIT 60`
  )).rows;

  const body = `
  <div class="card">
    <div class="card-h">
      <h2 class="title">Daily 5651 Özet (Hash Chain)</h2>
      <span class="pill">${DAILY_HMAC_SECRET ? `<span class="ok">HMAC aktif</span>` : `<span class="bad">DAILY_HMAC_SECRET yok</span>`}</span>
    </div>
    <div style="padding:0 16px 16px;">
      <div class="hint">
        Bu sayfa her günün özet hash’ini ve bir önceki güne bağlı hash-chain’i gösterir.
        <br>Doğrulama: <a href="/admin/daily/verify">/admin/daily/verify</a>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-h"><h2 class="title">Son 60 Gün</h2></div>
    <div style="overflow:auto">
      <table>
        <thead>
          <tr>
            <th>Gün</th><th>Toplam</th><th>Verify OK</th><th>Grant OK</th><th>hash_prev</th><th>hash_curr</th><th>hmac</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td class="mono">${escapeHtml(String(r.day))}</td>
              <td class="mono">${escapeHtml(String(r.count_total))}</td>
              <td class="mono">${escapeHtml(String(r.count_verify_ok))}</td>
              <td class="mono">${escapeHtml(String(r.count_grant_ok))}</td>
              <td class="mono">${escapeHtml((r.hash_prev || "").slice(0, 16))}…</td>
              <td class="mono">${escapeHtml((r.hash_curr || "").slice(0, 16))}…</td>
              <td class="mono">${escapeHtml((r.hmac_sig || "").slice(0, 16))}…</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  `;

  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(pageShell({ title: "Daily", subtitle: "5651 Günlük Özet & İmza • Admin", bodyHtml: body }));
});

app.get("/admin/daily/verify", requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).send("DATABASE_URL missing");
  if (!DAILY_HMAC_SECRET) return res.status(500).send("DAILY_HMAC_SECRET missing");

  const rows = (await q(
    `SELECT day, tz, count_total, count_verify_ok, count_grant_ok, hash_prev, hash_curr, hmac_sig
     FROM daily_summaries
     ORDER BY day ASC`
  )).rows;

  let ok = true;
  let prev = "";
  const checks = [];

  for (const r of rows) {
    const material = `${r.day}|${r.tz}|${r.count_total}|${r.count_verify_ok}|${r.count_grant_ok}|${r.hash_prev || ""}|${prev}`;
    // açıklama: hash_prev alanı DB’de durur, ayrıca zincir kontrolünde "prev" ile de kıyaslıyoruz
    const expectedHash = sha256Hex(material);
    const expectedHmac = hmacHex(DAILY_HMAC_SECRET, expectedHash);

    const chainOk = (r.hash_prev || "") === prev;
    const hashOk = (r.hash_curr || "") === expectedHash;
    const hmacOk = (r.hmac_sig || "") === expectedHmac;

    const rowOk = chainOk && hashOk && hmacOk;
    if (!rowOk) ok = false;

    checks.push({
      day: String(r.day),
      chainOk, hashOk, hmacOk,
      expectedPrev: prev,
      gotPrev: r.hash_prev || "",
    });

    prev = r.hash_curr || "";
  }

  const body = `
  <div class="card">
    <div class="card-h">
      <h2 class="title">Daily Doğrulama</h2>
      <span class="pill">${ok ? `<span class="ok">OK</span>` : `<span class="bad">FAIL</span>`}</span>
    </div>
    <div style="overflow:auto">
      <table>
        <thead><tr><th>Gün</th><th>Chain</th><th>Hash</th><th>HMAC</th></tr></thead>
        <tbody>
          ${checks.slice(-60).reverse().map(c => `
            <tr>
              <td class="mono">${escapeHtml(c.day)}</td>
              <td>${c.chainOk ? `<span class="ok">OK</span>` : `<span class="bad">FAIL</span>`}</td>
              <td>${c.hashOk ? `<span class="ok">OK</span>` : `<span class="bad">FAIL</span>`}</td>
              <td>${c.hmacOk ? `<span class="ok">OK</span>` : `<span class="bad">FAIL</span>`}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  `;

  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(pageShell({ title: "Daily Verify", subtitle: "Hash Chain & HMAC Doğrulama • Admin", bodyHtml: body }));
});

// -------------------- Daily builder (startup) --------------------
// Her start'ta: "bugün" için günlük özet üret.
// Çok sık üretmesin diye: aynı gün varsa overwrite eder (idempotent).
async function buildTodayDaily() {
  if (!pool) return;
  if (!DAILY_HMAC_SECRET) {
    console.log("DAILY: DAILY_HMAC_SECRET not set. Skipping daily build.");
    return;
  }

  const tz = process.env.TZ || "Europe/Istanbul";
  const day = new Date().toISOString().slice(0, 10);

  try {
    // counts
    const total = (await q(
      `SELECT COUNT(*)::bigint AS n FROM access_logs WHERE created_at >= $1::date AND created_at < ($1::date + interval '1 day')`,
      [day]
    )).rows[0]?.n || 0n;

    const verifyOk = (await q(
      `SELECT COUNT(*)::bigint AS n FROM access_logs WHERE event='OTP_VERIFY_OK' AND created_at >= $1::date AND created_at < ($1::date + interval '1 day')`,
      [day]
    )).rows[0]?.n || 0n;

    const grantOk = (await q(
      `SELECT COUNT(*)::bigint AS n FROM access_logs WHERE event='GRANT_REDIRECT' AND created_at >= $1::date AND created_at < ($1::date + interval '1 day')`,
      [day]
    )).rows[0]?.n || 0n;

    // prev hash = önceki günün hash_curr
    const prevRow = (await q(
      `SELECT hash_curr FROM daily_summaries WHERE day < $1::date ORDER BY day DESC LIMIT 1`,
      [day]
    )).rows[0];

    const prevHash = prevRow ? String(prevRow.hash_curr || "") : "";

    const material = `${day}|${tz}|${total}|${verifyOk}|${grantOk}|${prevHash}|${prevHash}`;
    const hashCurr = sha256Hex(material);
    const sig = hmacHex(DAILY_HMAC_SECRET, hashCurr);

    await q(
      `INSERT INTO daily_summaries(day, tz, count_total, count_verify_ok, count_grant_ok, hash_prev, hash_curr, hmac_sig)
       VALUES($1::date,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (day) DO UPDATE SET
         tz=EXCLUDED.tz,
         count_total=EXCLUDED.count_total,
         count_verify_ok=EXCLUDED.count_verify_ok,
         count_grant_ok=EXCLUDED.count_grant_ok,
         hash_prev=EXCLUDED.hash_prev,
         hash_curr=EXCLUDED.hash_curr,
         hmac_sig=EXCLUDED.hmac_sig,
         created_at=NOW()`,
      [day, tz, String(total), String(verifyOk), String(grantOk), prevHash || null, hashCurr, sig]
    );

    console.log("DAILY: built", { day, hashCurr: hashCurr.slice(0, 16) + "…" });
  } catch (e) {
    console.log("DAILY build error", e.message || e);
  }
}

// -------------------- Startup --------------------
(async () => {
  // ENV log
  console.log("ENV:", {
    OTP_MODE,
    OTP_TTL_SECONDS,
    RL_MAC_SECONDS,
    RL_PHONE_SECONDS,
    MAX_WRONG_ATTEMPTS,
    LOCK_SECONDS,
    KVKK_VERSION,
    TZ: process.env.TZ,
    DB_SET: !!DB_URL,
    REDIS_SET: !!REDIS_URL,
    ADMIN_USER_SET: !!ADMIN_USER,
    ADMIN_PASS_SET: !!ADMIN_PASS,
    DAILY_HMAC_SET: !!DAILY_HMAC_SECRET,
  });

  await ensureDb();
  await buildTodayDaily();

  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();
