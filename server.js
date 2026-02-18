/* eslint-disable no-console */
const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
let Redis = null;
try {
  Redis = require("ioredis");
} catch (_) {
  // ioredis yoksa bile uygulama çalışsın diye fallback var
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---------- ENV ----------
const PORT = parseInt(process.env.PORT || "8080", 10);
const TZ = process.env.TZ || "Europe/Istanbul";

const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms daha sonra)
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);

const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);

const KVKK_VERSION = process.env.KVKK_VERSION || "placeholder";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || "";
const CRON_SECRET = process.env.CRON_SECRET || "";

const DATABASE_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "";

const GRANT_DURATION_SECONDS = parseInt(process.env.GRANT_DURATION_SECONDS || "3600", 10);

// ---------- Helpers ----------
function nowIso() {
  return new Date().toISOString();
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function hmacSha256Hex(key, s) {
  return crypto.createHmac("sha256", key).update(s).digest("hex");
}

function safeStr(v, max = 500) {
  if (v === undefined || v === null) return "";
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function normalizePhoneTR(raw) {
  // Beklenen: 5XXXXXXXXX (10 hane) — başında 0 yok
  const s = (raw || "").replace(/\D/g, "");
  if (!s) return "";
  if (s.length === 10 && s.startsWith("5")) return s;            // 533...
  if (s.length === 11 && s.startsWith("0") && s[1] === "5") return s.slice(1); // 0533 -> 533
  if (s.length === 12 && s.startsWith("90") && s[2] === "5") return s.slice(2); // 90533 -> 533
  return s; // yine de döndür (validasyon ayrı)
}

function isValidMsisdn(s) {
  return /^\d{10}$/.test(s) && s.startsWith("5");
}

function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function genMarker() {
  // marker: teknik korelasyon anahtarı (kullanıcı görmez)
  return String(Math.floor(100000 + Math.random() * 900000));
}

function pickHeader(req, name) {
  const v = req.headers[name.toLowerCase()];
  return v ? String(v) : "";
}

function basicAuthOk(req) {
  if (!ADMIN_USER || !ADMIN_PASS) return false;
  const h = pickHeader(req, "authorization");
  if (!h || !h.startsWith("Basic ")) return false;
  const decoded = Buffer.from(h.slice(6), "base64").toString("utf8");
  const i = decoded.indexOf(":");
  if (i < 0) return false;
  const u = decoded.slice(0, i);
  const p = decoded.slice(i + 1);

  // timing-safe compare
  const ub = Buffer.from(u);
  const pb = Buffer.from(p);
  const u0 = Buffer.from(ADMIN_USER);
  const p0 = Buffer.from(ADMIN_PASS);
  const uOk = ub.length === u0.length && crypto.timingSafeEqual(ub, u0);
  const pOk = pb.length === p0.length && crypto.timingSafeEqual(pb, p0);
  return uOk && pOk;
}

function requireAdmin(req, res) {
  if (basicAuthOk(req)) return true;
  res.setHeader("WWW-Authenticate", 'Basic realm="Admin"');
  res.status(401).send("Auth required");
  return false;
}

function requireBearer(req, res, token) {
  const h = pickHeader(req, "authorization");
  if (!h || !h.startsWith("Bearer ")) {
    res.status(401).send("Bearer token required");
    return false;
  }
  const got = h.slice("Bearer ".length);
  const a = Buffer.from(got);
  const b = Buffer.from(token || "");
  if (!token || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.status(403).send("Forbidden");
    return false;
  }
  return true;
}

// ---------- Redis (optional) ----------
const memoryStore = new Map(); // fallback
function memSet(key, val, ttlSec) {
  memoryStore.set(key, { val, exp: Date.now() + ttlSec * 1000 });
}
function memGet(key) {
  const o = memoryStore.get(key);
  if (!o) return null;
  if (Date.now() > o.exp) {
    memoryStore.delete(key);
    return null;
  }
  return o.val;
}
function memDel(key) {
  memoryStore.delete(key);
}

let redis = null;
if (REDIS_URL && Redis) {
  redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 1,
    enableReadyCheck: true,
    lazyConnect: false,
  });
  redis.on("error", (e) => console.error("REDIS error:", e?.message || e));
}

// unified KV ops
async function kvSetJson(key, obj, ttlSec) {
  const s = JSON.stringify(obj);
  if (redis) {
    await redis.set(key, s, "EX", ttlSec);
    return;
  }
  memSet(key, obj, ttlSec);
}
async function kvGetJson(key) {
  if (redis) {
    const s = await redis.get(key);
    return s ? JSON.parse(s) : null;
  }
  return memGet(key);
}
async function kvDel(key) {
  if (redis) return redis.del(key);
  memDel(key);
}
async function kvIncrWithTTL(key, ttlSec) {
  if (redis) {
    const n = await redis.incr(key);
    if (n === 1) await redis.expire(key, ttlSec);
    return n;
  }
  const cur = memGet(key) || 0;
  const next = cur + 1;
  memSet(key, next, ttlSec);
  return next;
}

// ---------- Postgres ----------
let pool = null;

async function q(text, params = []) {
  const r = await pool.query(text, params);
  return r;
}

async function ensureDb() {
  if (!DATABASE_URL) {
    console.log("DATABASE: not configured (DATABASE_URL missing).");
    return;
  }
  pool = new Pool({
    connectionString: DATABASE_URL,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });
  await q("SELECT 1");
  console.log("DATABASE: connected");

  // Create base tables
  await q(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      day DATE NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')::date,
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
      user_agent TEXT,
      accept_language TEXT,
      tz TEXT,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE PRIMARY KEY,
      record_count INT NOT NULL,
      day_hash TEXT NOT NULL,
      chain_hash TEXT NOT NULL,
      signature_hmac TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      manifest JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  // Auto-migrate missing columns if older table exists
  // (hataları “column does not exist” görmeyelim)
  const cols = [
    ["continue_url", "TEXT"],
    ["user_agent", "TEXT"],
    ["accept_language", "TEXT"],
    ["tz", "TEXT"],
    ["day", "DATE NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')::date"],
    ["meta", "JSONB NOT NULL DEFAULT '{}'::jsonb"],
  ];
  for (const [name, type] of cols) {
    await q(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ${name} ${type};`);
  }

  console.log("DATABASE: table ready");
}

async function logEvent(event, ctx, extra = {}) {
  if (!pool) return;

  const ua = safeStr(extra.user_agent || "");
  const al = safeStr(extra.accept_language || "");
  const tz = safeStr(extra.tz || TZ);

  const meta = extra.meta || {};

  const row = {
    event: safeStr(event, 50),
    client_mac: safeStr(ctx.client_mac || "", 50),
    client_ip: safeStr(ctx.client_ip || "", 60),
    ssid: safeStr(ctx.ssid || "", 200),
    ap_name: safeStr(ctx.ap_name || "", 200),
    base_grant_url: safeStr(ctx.base_grant_url || "", 800),
    continue_url: safeStr(ctx.continue_url || "", 800),
    marker: safeStr(ctx.marker || "", 20),
    phone: safeStr(ctx.phone || "", 20),
    full_name: safeStr(ctx.full_name || "", 200),
    kvkk_version: safeStr(ctx.kvkk_version || KVKK_VERSION, 100),
    user_agent: ua,
    accept_language: al,
    tz,
    meta,
  };

  try {
    await q(
      `INSERT INTO access_logs(event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url,
                               marker, phone, full_name, kvkk_version, user_agent, accept_language, tz, meta)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
      [
        row.event,
        row.client_mac || null,
        row.client_ip || null,
        row.ssid || null,
        row.ap_name || null,
        row.base_grant_url || null,
        row.continue_url || null,
        row.marker || null,
        row.phone || null,
        row.full_name || null,
        row.kvkk_version || null,
        row.user_agent || null,
        row.accept_language || null,
        row.tz || null,
        JSON.stringify(row.meta || {}),
      ]
    );
  } catch (e) {
    console.error("DB LOG ERROR:", e?.message || e);
  }
}

// ---------- Meraki Splash context ----------
function extractSplashCtx(req) {
  // Meraki query param isimleri farklı gelebiliyor; hepsini yakala
  const qy = req.query || {};
  const ctx = {
    // Meraki
    base_grant_url: safeStr(qy.base_grant_url || qy.baseGrantUrl || "", 800),
    continue_url: safeStr(qy.continue_url || qy.continueUrl || "", 800),
    gateway_id: safeStr(qy.gateway_id || qy.gatewayId || "", 64),
    node_id: safeStr(qy.node_id || qy.nodeId || "", 64),
    node_mac: safeStr(qy.node_mac || qy.nodeMac || "", 64),
    client_ip: safeStr(qy.client_ip || qy.clientIp || "", 64),
    client_mac: safeStr(qy.client_mac || qy.clientMac || "", 64),
    ssid: safeStr(qy.ssid || "", 200),
    ap_name: safeStr(qy.ap_name || qy.apName || "", 200),
  };
  return ctx;
}

function makeGrantRedirectUrl(ctx) {
  if (!ctx.base_grant_url) return "";

  const u = new URL(ctx.base_grant_url);

  // Meraki grant endpoint genelde bu paramları istiyor
  if (ctx.gateway_id) u.searchParams.set("gateway_id", ctx.gateway_id);
  if (ctx.node_id) u.searchParams.set("node_id", ctx.node_id);
  if (ctx.client_ip) u.searchParams.set("client_ip", ctx.client_ip);
  if (ctx.client_mac) u.searchParams.set("client_mac", ctx.client_mac);
  if (ctx.node_mac) u.searchParams.set("node_mac", ctx.node_mac);
  if (ctx.continue_url) u.searchParams.set("continue_url", ctx.continue_url);

  u.searchParams.set("duration", String(GRANT_DURATION_SECONDS));
  return u.toString();
}

// ---------- OTP storage keys ----------
const kOtp = (marker) => `otp:${marker}`;
const kCtx = (marker) => `ctx:${marker}`;
const kMacRL = (mac) => `rl:mac:${mac}`;
const kPhoneRL = (phone) => `rl:phone:${phone}`;
const kWrong = (marker) => `wrong:${marker}`;
const kLock = (marker) => `lock:${marker}`;

// ---------- UI (very simple, Odeon-like minimal) ----------
function pageHtml({ title, body, otp = "", showOtp = false }) {
  const odeonBlue = "#0B2D5B";
  const odeonCyan = "#00A6D6";
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    :root{
      --bg:#F5F7FB;
      --card:#FFFFFF;
      --text:#0E1726;
      --muted:#5B6B80;
      --primary:${odeonBlue};
      --accent:${odeonCyan};
      --border:#E6ECF5;
      --shadow: 0 10px 30px rgba(14,23,38,.08);
      --radius:14px;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }
    body{ margin:0; background:var(--bg); color:var(--text); }
    .wrap{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
    .card{ width:100%; max-width:420px; background:var(--card); border:1px solid var(--border);
           border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; }
    .top{ padding:18px 20px; border-bottom:1px solid var(--border);
          background:linear-gradient(135deg, rgba(11,45,91,.08), rgba(0,166,214,.10)); }
    .brand{ display:flex; align-items:center; gap:12px; }
    .brand img{ height:28px; width:auto; display:block; }
    .brand .t{ font-weight:700; letter-spacing:.2px; }
    .content{ padding:18px 20px 20px; }
    label{ display:block; font-size:13px; color:var(--muted); margin:10px 0 6px; }
    input[type="text"], input[type="tel"]{
      width:100%; padding:12px 12px; border-radius:12px; border:1px solid var(--border);
      outline:none; font-size:14px; background:#fff;
    }
    input:focus{ border-color: rgba(0,166,214,.55); box-shadow:0 0 0 4px rgba(0,166,214,.12); }
    .row{ display:flex; gap:10px; }
    .row > *{ flex:1; }
    .kvkk{ display:flex; gap:10px; align-items:flex-start; margin-top:12px; font-size:13px; color:var(--muted); }
    .kvkk input{ margin-top:3px; }
    .btn{
      margin-top:14px; width:100%; border:0; cursor:pointer;
      padding:12px 14px; border-radius:12px; background:var(--primary); color:#fff; font-weight:700;
    }
    .btn:hover{ filter:brightness(1.03); }
    .otpBox{
      margin-top:12px; padding:12px; border-radius:12px; border:1px dashed rgba(0,166,214,.55);
      background: rgba(0,166,214,.06);
    }
    .otpCode{ font-size:22px; letter-spacing:6px; font-weight:800; color:var(--primary); text-align:center; }
    .small{ font-size:12px; color:var(--muted); margin-top:8px; line-height:1.35; }
    .err{ margin-top:10px; padding:10px 12px; border-radius:12px; background:#FFF2F2; border:1px solid #FFD6D6; color:#8A1F1F; font-size:13px; }
    .ok{ margin-top:10px; padding:10px 12px; border-radius:12px; background:#F0FFF5; border:1px solid #C9F2D4; color:#1C6B35; font-size:13px; }
    a{ color:var(--accent); text-decoration:none; }
    a:hover{ text-decoration:underline; }
    .footer{ padding:14px 20px; border-top:1px solid var(--border); font-size:12px; color:var(--muted); }
    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="top">
        <div class="brand">
          <img src="/public/logo.png" alt="Odeon Technology" onerror="this.style.display='none'"/>
          <div class="t">Misafir İnternet</div>
        </div>
      </div>
      <div class="content">
        ${body}
        ${
          showOtp
            ? `<div class="otpBox">
                 <div class="small">Tek kullanımlık doğrulama kodu:</div>
                 <div class="otpCode mono">${otp}</div>
                 <div class="small">Bu kod <b>${OTP_TTL_SECONDS}</b> saniye geçerlidir.</div>
               </div>`
            : ""
        }
      </div>
      <div class="footer">
        KVKK v: <span class="mono">${KVKK_VERSION}</span> • Saat dilimi: <span class="mono">${TZ}</span>
      </div>
    </div>
  </div>
</body>
</html>`;
}

function kvkkPlaceholderHtml() {
  return `<div class="small">
  <b>KVKK Aydınlatma Metni (Placeholder)</b><br/>
  Bu alan daha sonra şirketinizin resmi KVKK metni ile değiştirilecektir.
</div>`;
}

// ---------- Routes ----------
app.use("/public", express.static("public"));

app.get("/health", async (_req, res) => {
  res.json({
    ok: true,
    ts: nowIso(),
    otp_mode: OTP_MODE,
    redis: !!redis,
    db: !!pool,
  });
});

app.get("/", async (req, res) => {
  const ctx = extractSplashCtx(req);

  // marker: kullanıcıya gösterilmiyor, sadece korelasyon
  const marker = genMarker();

  const user_agent = pickHeader(req, "user-agent");
  const accept_language = pickHeader(req, "accept-language");

  ctx.marker = marker;

  console.log("SPLASH_OPEN", {
    hasBaseGrant: !!ctx.base_grant_url,
    hasContinue: !!ctx.continue_url,
    hasClientMac: !!ctx.client_mac,
    mode: OTP_MODE,
  });

  await kvSetJson(kCtx(marker), ctx, 15 * 60);

  await logEvent("SPLASH_OPEN", ctx, {
    user_agent,
    accept_language,
    tz: TZ,
    meta: { query: req.query || {} },
  });

  const body = `
    <form method="POST" action="/start">
      <input type="hidden" name="marker" value="${marker}"/>
      <label>Ad Soyad</label>
      <input name="full_name" type="text" autocomplete="name" required placeholder="Ad Soyad"/>
      <label>Cep Telefonu</label>
      <input name="phone" type="tel" autocomplete="tel" required placeholder="5XXXXXXXXX"/>
      <div class="kvkk">
        <input id="kvkk" type="checkbox" name="kvkk" value="1" required/>
        <label for="kvkk" style="margin:0">
          KVKK Aydınlatma Metni’ni okudum ve onaylıyorum.
          <div style="margin-top:6px">${kvkkPlaceholderHtml()}</div>
        </label>
      </div>
      <button class="btn" type="submit">Kodu Oluştur</button>
      <div class="small">
        Telefon formatı: <b>5XXXXXXXXX</b> (başında 0 yazma).
      </div>
    </form>
  `;

  res.send(pageHtml({ title: "Misafir İnternet", body }));
});

app.post("/start", async (req, res) => {
  const marker = safeStr(req.body.marker || "", 20);
  const full_name = safeStr(req.body.full_name || "", 200).trim();
  const phoneRaw = safeStr(req.body.phone || "", 30);
  const phone = normalizePhoneTR(phoneRaw);

  const user_agent = pickHeader(req, "user-agent");
  const accept_language = pickHeader(req, "accept-language");

  const ctx = (await kvGetJson(kCtx(marker))) || { marker };
  ctx.marker = marker;
  ctx.full_name = full_name;
  ctx.phone = phone;
  ctx.kvkk_version = KVKK_VERSION;

  // Rate-limit (MAC + phone)
  const mac = safeStr(ctx.client_mac || "", 50);
  if (mac) {
    const macN = await kvIncrWithTTL(kMacRL(mac), RL_MAC_SECONDS);
    if (macN > 10) {
      await logEvent("OTP_RL_MAC", ctx, { user_agent, accept_language, tz: TZ, meta: { macN } });
      return res.status(429).send(pageHtml({
        title: "Limit",
        body: `<div class="err">Çok sık denendi. Lütfen ${RL_MAC_SECONDS} sn sonra tekrar deneyin.</div>`,
      }));
    }
  }
  if (phone) {
    const phN = await kvIncrWithTTL(kPhoneRL(phone), RL_PHONE_SECONDS);
    if (phN > 10) {
      await logEvent("OTP_RL_PHONE", ctx, { user_agent, accept_language, tz: TZ, meta: { phN } });
      return res.status(429).send(pageHtml({
        title: "Limit",
        body: `<div class="err">Çok sık denendi. Lütfen ${RL_PHONE_SECONDS} sn sonra tekrar deneyin.</div>`,
      }));
    }
  }

  // Validate phone (only if provided)
  if (!isValidMsisdn(phone)) {
    await logEvent("OTP_PHONE_INVALID", ctx, { user_agent, accept_language, tz: TZ, meta: { raw: phoneRaw, norm: phone } });
    return res.status(400).send(pageHtml({
      title: "Hata",
      body: `<div class="err">Telefon formatı hatalı. Örnek: 5XXXXXXXXX</div>`,
    }));
  }

  // Lock check
  const locked = await kvGetJson(kLock(marker));
  if (locked) {
    return res.status(429).send(pageHtml({
      title: "Kilitli",
      body: `<div class="err">Çok fazla hatalı deneme. Lütfen daha sonra tekrar deneyin.</div>`,
    }));
  }

  const otp = genOtp();

  await kvSetJson(kOtp(marker), { otp, created_at: nowIso() }, OTP_TTL_SECONDS);
  await kvSetJson(kWrong(marker), { n: 0 }, OTP_TTL_SECONDS);

  await kvSetJson(kCtx(marker), ctx, 15 * 60);

  console.log("OTP_CREATED", { marker, last4: phone.slice(-4), client_mac: ctx.client_mac || "" });

  await logEvent("OTP_CREATED", ctx, {
    user_agent,
    accept_language,
    tz: TZ,
    meta: { otp_mode: OTP_MODE }
  });

  if (OTP_MODE === "screen") {
    console.log("OTP_SCREEN_CODE", { marker, otp });

    const body = `
      <form method="POST" action="/verify">
        <input type="hidden" name="marker" value="${marker}"/>
        <label>Doğrulama Kodu</label>
        <input name="otp" type="text" inputmode="numeric" maxlength="6" required placeholder="6 haneli kod"/>
        <button class="btn" type="submit">Bağlan</button>
        <div class="small">Kod ekranda görünüyor. (SMS daha sonra devreye alınacak)</div>
      </form>
    `;
    return res.send(pageHtml({ title: "Kod", body, otp, showOtp: true }));
  }

  // SMS mode placeholder
  return res.send(pageHtml({
    title: "SMS",
    body: `<div class="ok">SMS modu daha sonra devreye alınacak. Şimdilik OTP_MODE=screen kullanın.</div>`,
  }));
});

app.post("/verify", async (req, res) => {
  const marker = safeStr(req.body.marker || "", 20);
  const otpIn = safeStr(req.body.otp || "", 20).replace(/\D/g, "");

  const user_agent = pickHeader(req, "user-agent");
  const accept_language = pickHeader(req, "accept-language");

  const ctx = (await kvGetJson(kCtx(marker))) || { marker };
  ctx.marker = marker;

  const locked = await kvGetJson(kLock(marker));
  if (locked) {
    await logEvent("OTP_LOCKED", ctx, { user_agent, accept_language, tz: TZ });
    return res.status(429).send(pageHtml({
      title: "Kilitli",
      body: `<div class="err">Çok fazla hatalı deneme. Lütfen daha sonra tekrar deneyin.</div>`,
    }));
  }

  const otpObj = await kvGetJson(kOtp(marker));
  if (!otpObj || !otpObj.otp) {
    await logEvent("OTP_EXPIRED", ctx, { user_agent, accept_language, tz: TZ });
    return res.status(400).send(pageHtml({
      title: "Süre doldu",
      body: `<div class="err">Kod süresi doldu. Lütfen yeniden kod oluşturun.</div><div class="small"><a href="/">Başa dön</a></div>`,
    }));
  }

  const ok =
    otpIn.length === 6 &&
    Buffer.from(otpIn).length === Buffer.from(otpObj.otp).length &&
    crypto.timingSafeEqual(Buffer.from(otpIn), Buffer.from(otpObj.otp));

  if (!ok) {
    const w = (await kvGetJson(kWrong(marker))) || { n: 0 };
    w.n = (w.n || 0) + 1;
    await kvSetJson(kWrong(marker), w, OTP_TTL_SECONDS);

    await logEvent("OTP_VERIFY_BAD", ctx, { user_agent, accept_language, tz: TZ, meta: { wrong: w.n } });

    if (w.n >= MAX_WRONG_ATTEMPTS) {
      await kvSetJson(kLock(marker), { locked: true }, LOCK_SECONDS);
      await logEvent("OTP_LOCK_SET", ctx, { user_agent, accept_language, tz: TZ });
      return res.status(429).send(pageHtml({
        title: "Kilitlendi",
        body: `<div class="err">Çok fazla hatalı deneme. ${LOCK_SECONDS} sn kilitlendi.</div>`,
      }));
    }

    return res.status(400).send(pageHtml({
      title: "Hatalı",
      body: `<div class="err">Kod hatalı. Tekrar deneyin.</div>
             <form method="POST" action="/verify">
               <input type="hidden" name="marker" value="${marker}"/>
               <label>Doğrulama Kodu</label>
               <input name="otp" type="text" inputmode="numeric" maxlength="6" required placeholder="6 haneli kod"/>
               <button class="btn" type="submit">Bağlan</button>
             </form>`,
    }));
  }

  console.log("OTP_VERIFY_OK", { marker, client_mac: ctx.client_mac || "" });

  await logEvent("OTP_VERIFY_OK", ctx, { user_agent, accept_language, tz: TZ });

  // one-time OTP cleanup
  await kvDel(kOtp(marker));
  await kvDel(kWrong(marker));

  // Grant redirect
  const grantUrl = makeGrantRedirectUrl(ctx);

  if (!grantUrl) {
    await logEvent("GRANT_MISSING_BASE", ctx, { user_agent, accept_language, tz: TZ });
    return res.send(pageHtml({
      title: "OK",
      body: `<div class="ok">OK</div><div class="small">Base grant bilgisi gelmediği için yönlendirme yapılamadı.</div>`,
    }));
  }

  console.log("GRANT_CLIENT_REDIRECT:", grantUrl);
  await logEvent("GRANT_REDIRECT", ctx, { user_agent, accept_language, tz: TZ, meta: { grantUrl } });

  // Meraki için en sağlıklısı: 302 redirect
  return res.redirect(302, grantUrl);
});

// ---------- Admin UI ----------
app.get("/admin", (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.redirect("/admin/logs");
});

app.get("/admin/logs", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  if (!pool) return res.status(500).send("DB not configured");

  const mac = safeStr(req.query.mac || "", 64);
  const phone = safeStr(req.query.phone || "", 32);
  const last24 = String(req.query.last24 || "1") === "1";
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);

  const where = [];
  const params = [];
  let i = 1;

  if (last24) {
    where.push(`ts >= now() - interval '24 hours'`);
  }
  if (mac) {
    where.push(`client_mac = $${i++}`);
    params.push(mac);
  }
  if (phone) {
    where.push(`phone = $${i++}`);
    params.push(phone);
  }

  const sql = `
    SELECT ts, event, client_mac, client_ip, ssid, ap_name, phone, full_name, kvkk_version
    FROM access_logs
    ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY ts DESC
    LIMIT ${limit};
  `;

  const rows = (await q(sql, params)).rows;

  const trs = rows
    .map((r) => {
      return `<tr>
        <td class="mono">${safeStr(r.ts)}</td>
        <td>${safeStr(r.event)}</td>
        <td class="mono">${safeStr(r.client_mac || "")}</td>
        <td class="mono">${safeStr(r.client_ip || "")}</td>
        <td>${safeStr(r.ssid || "")}</td>
        <td>${safeStr(r.ap_name || "")}</td>
        <td class="mono">${safeStr(r.phone || "")}</td>
        <td>${safeStr(r.full_name || "")}</td>
        <td class="mono">${safeStr(r.kvkk_version || "")}</td>
      </tr>`;
    })
    .join("");

  const html = `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Logs</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;background:#F5F7FB;color:#0E1726}
  .wrap{padding:18px}
  .top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
  .card{background:#fff;border:1px solid #E6ECF5;border-radius:12px;box-shadow:0 10px 30px rgba(14,23,38,.08);overflow:hidden}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px;border-bottom:1px solid #EEF2F8;vertical-align:top}
  th{background:#FBFCFE;text-align:left;color:#5B6B80;font-weight:700}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .filters{display:flex;gap:8px;flex-wrap:wrap}
  input{padding:10px;border:1px solid #E6ECF5;border-radius:10px}
  button{padding:10px 12px;border:0;background:#0B2D5B;color:#fff;border-radius:10px;font-weight:700;cursor:pointer}
  a{color:#00A6D6;text-decoration:none}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div style="display:flex;align-items:center;gap:10px">
      <img src="/public/logo.png" style="height:22px" onerror="this.style.display='none'"/>
      <div><b>5651 Logs</b> <span style="color:#5B6B80">(son ${limit} kayıt)</span></div>
    </div>
    <div><a href="/admin/daily">Günlük İmzalar</a></div>
  </div>

  <form class="filters" method="GET" action="/admin/logs">
    <input name="mac" placeholder="mac" value="${mac}"/>
    <input name="phone" placeholder="phone (5XXXXXXXXX)" value="${phone}"/>
    <input name="limit" placeholder="limit" value="${limit}"/>
    <label style="display:flex;align-items:center;gap:6px;color:#5B6B80;font-size:13px">
      <input type="checkbox" name="last24" value="1" ${last24 ? "checked" : ""}/> son 24 saat
    </label>
    <button type="submit">Filtrele</button>
  </form>

  <div style="height:12px"></div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th>ts</th><th>event</th><th>mac</th><th>ip</th><th>ssid</th><th>ap</th><th>phone</th><th>name</th><th>kvkk</th>
        </tr>
      </thead>
      <tbody>
        ${trs || `<tr><td colspan="9" style="color:#5B6B80">Kayıt yok</td></tr>`}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>`;
  res.send(html);
});

// ---------- Daily signing (5651) ----------
async function buildDaily(dayStr /* YYYY-MM-DD optional */) {
  if (!pool) throw new Error("DB not configured");
  if (!DAILY_HMAC_SECRET) throw new Error("DAILY_HMAC_SECRET missing");

  const day = dayStr || new Date().toISOString().slice(0, 10); // UTC day
  // Logs for that day by UTC day column or ts range
  // (day kolonu var; yoksa da ensureDb ekliyor)
  const logs = (await q(
    `SELECT id, ts, event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, marker, phone, full_name, kvkk_version, user_agent, accept_language, tz, meta
     FROM access_logs
     WHERE day = $1::date
     ORDER BY ts ASC, id ASC`,
    [day]
  )).rows;

  const record_count = logs.length;
  const canonicalLines = [];
  const rowHashes = [];

  for (const r of logs) {
    const obj = {
      ts: new Date(r.ts).toISOString(),
      event: r.event || "",
      client_mac: r.client_mac || "",
      client_ip: r.client_ip || "",
      ssid: r.ssid || "",
      ap_name: r.ap_name || "",
      base_grant_url: r.base_grant_url || "",
      continue_url: r.continue_url || "",
      marker: r.marker || "",
      phone: r.phone || "",
      full_name: r.full_name || "",
      kvkk_version: r.kvkk_version || "",
      user_agent: r.user_agent || "",
      accept_language: r.accept_language || "",
      tz: r.tz || "",
      meta: r.meta || {},
    };
    const line = JSON.stringify(obj);
    canonicalLines.push(line);
    rowHashes.push(sha256Hex(line));
  }

  const day_hash = sha256Hex(rowHashes.join("\n"));

  // chain hash: previous day chain + today day_hash
  const prev = (await q(`SELECT chain_hash FROM daily_packages WHERE day < $1::date ORDER BY day DESC LIMIT 1`, [day])).rows[0];
  const prevChain = prev ? prev.chain_hash : "0";
  const chain_hash = sha256Hex(prevChain + "\n" + day + "\n" + day_hash);

  // signature (HMAC placeholder). İstersen sonra “e-imza/KamuSM” ile gerçek imza entegrasyonu yaparız.
  const signature_hmac = hmacSha256Hex(DAILY_HMAC_SECRET, chain_hash);

  const manifest = {
    day,
    tz: TZ,
    record_count,
    day_hash,
    chain_hash,
    signature_hmac,
    algorithm: "SHA256 + HMAC-SHA256(DAILY_HMAC_SECRET)",
    note: "Bu HMAC bir 'imza placeholder'ıdır. Üretim için nitelikli e-imza/kayıt zinciri tasarımı ayrıca yapılmalıdır.",
  };

  await q(
    `INSERT INTO daily_packages(day, record_count, day_hash, chain_hash, signature_hmac, manifest)
     VALUES($1::date,$2,$3,$4,$5,$6::jsonb)
     ON CONFLICT(day) DO UPDATE SET
       record_count=EXCLUDED.record_count,
       day_hash=EXCLUDED.day_hash,
       chain_hash=EXCLUDED.chain_hash,
       signature_hmac=EXCLUDED.signature_hmac,
       manifest=EXCLUDED.manifest,
       created_at=now()`,
    [day, record_count, day_hash, chain_hash, signature_hmac, JSON.stringify(manifest)]
  );

  return { manifest, lines: canonicalLines };
}

app.get("/admin/daily", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  if (!pool) return res.status(500).send("DB not configured");

  const rows = (await q(
    `SELECT day, record_count, day_hash, chain_hash, signature_hmac, created_at
     FROM daily_packages
     ORDER BY day DESC
     LIMIT 60`
  )).rows;

  const trs = rows.map(r => `
    <tr>
      <td class="mono">${r.day}</td>
      <td>${r.record_count}</td>
      <td class="mono">${safeStr(r.day_hash, 16)}…</td>
      <td class="mono">${safeStr(r.chain_hash, 16)}…</td>
      <td class="mono">${safeStr(r.signature_hmac, 16)}…</td>
      <td class="mono">${safeStr(r.created_at)}</td>
      <td><a href="/admin/daily/${r.day}">indir</a></td>
    </tr>
  `).join("");

  res.send(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Daily</title>
  <style>
    body{font-family:system-ui;margin:0;background:#F5F7FB;color:#0E1726}
    .wrap{padding:18px}
    .card{background:#fff;border:1px solid #E6ECF5;border-radius:12px;box-shadow:0 10px 30px rgba(14,23,38,.08);overflow:hidden}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:10px;border-bottom:1px solid #EEF2F8}
    th{background:#FBFCFE;text-align:left;color:#5B6B80}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    button{padding:10px 12px;border:0;background:#0B2D5B;color:#fff;border-radius:10px;font-weight:700;cursor:pointer}
    a{color:#00A6D6;text-decoration:none}
  </style></head><body>
  <div class="wrap">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:10px">
        <img src="/public/logo.png" style="height:22px" onerror="this.style.display='none'"/>
        <b>Günlük İmzalar</b>
      </div>
      <div><a href="/admin/logs">Logs</a></div>
    </div>

    <form method="POST" action="/admin/daily/build" style="margin-bottom:12px">
      <button type="submit">Bugünü Oluştur/Update Et</button>
    </form>

    <div class="card">
      <table>
        <thead><tr>
          <th>day</th><th>count</th><th>day_hash</th><th>chain_hash</th><th>hmac</th><th>created</th><th></th>
        </tr></thead>
        <tbody>${trs || `<tr><td colspan="7" style="color:#5B6B80">Henüz yok</td></tr>`}</tbody>
      </table>
    </div>
  </div>
  </body></html>`);
});

app.post("/admin/daily/build", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await buildDaily();
    res.redirect("/admin/daily");
  } catch (e) {
    res.status(500).send(String(e?.message || e));
  }
});

app.get("/admin/daily/:day", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const day = safeStr(req.params.day || "", 20);
  try {
    const { manifest, lines } = await buildDaily(day); // idempotent
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.send(JSON.stringify({ manifest, jsonl_preview_first_50: lines.slice(0, 50) }, null, 2));
  } catch (e) {
    res.status(500).send(String(e?.message || e));
  }
});

// ---------- Plan B Cron endpoint ----------
app.post("/cron/daily", async (req, res) => {
  // Cron job burayı çağıracak: Authorization: Bearer CRON_SECRET
  if (!requireBearer(req, res, CRON_SECRET)) return;
  try {
    const day = safeStr(req.query.day || "", 20) || undefined;
    const out = await buildDaily(day);
    res.json({ ok: true, manifest: out.manifest });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ---------- Startup / CLI daily mode ----------
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
    DB_SET: !!DATABASE_URL,
    REDIS_SET: !!REDIS_URL,
    ADMIN_USER_SET: !!ADMIN_USER,
    ADMIN_PASS_SET: !!ADMIN_PASS,
    DAILY_HMAC_SET: !!DAILY_HMAC_SECRET,
  });

  if (redis) {
    try {
      await redis.ping();
      console.log("REDIS: connected");
    } catch (e) {
      console.log("REDIS: not reachable, fallback memory store");
      redis = null;
    }
  } else {
    console.log("REDIS: not configured. Running WITHOUT persistent store.");
  }

  if (DATABASE_URL) {
    await ensureDb();
  } else {
    console.log("DATABASE: not configured. 5651 logs disabled.");
  }

  const args = process.argv.slice(2);
  if (args.includes("--daily")) {
    // Railway Cron Jobs "service runs and exits" modeline uygun
    // Not: Cron’u ayrı service olarak kurarsan bunu kullanırsın.
    if (!pool) throw new Error("DATABASE_URL missing for --daily");
    const out = await buildDaily();
    console.log("DAILY BUILT:", out.manifest);
    process.exit(0);
  }

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
