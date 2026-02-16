/**
 * server.js — Meraki Splash + OTP(screen) + KVKK + 5651 log + Admin UI + “imzalama”(hash-chain placeholder)
 *
 * ✅ DB kolon tipleri: TEXT olacak şekilde tasarlandı (client_ip TEXT)
 * ✅ Admin: /admin/logs  (Basic Auth: ADMIN_USER / ADMIN_PASS)
 * ✅ 5651 için: kayıtlar Postgres’te, zincir hash ile “değiştirilemezlik” kanıtı (placeholder)
 *
 * Railway env (öneri):
 * - PORT=8080 (Railway otomatik)
 * - DATABASE_URL = ${{MerakiPostgres.DATABASE_URL}}
 * - REDIS_URL / REDIS_PUBLIC_URL (opsiyonel)
 * - OTP_MODE=screen
 * - OTP_TTL_SECONDS=180
 * - KVKK_VERSION=2026-02-12-placeholder
 * - ADMIN_USER=...
 * - ADMIN_PASS=...
 * - SIGNING_SECRET=... (uzun random)
 */

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

let Redis = null;
let redis = null;
try {
  Redis = require("ioredis");
} catch (_) {
  // ignore
}

// -------------------- ENV --------------------
const PORT = Number(process.env.PORT || 8080);
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms'i sonra)
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180);

const KVKK_VERSION = process.env.KVKK_VERSION || "placeholder";
const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const SIGNING_SECRET = process.env.SIGNING_SECRET || "CHANGE_ME_SIGNING_SECRET";

const RL_MAC_SECONDS = Number(process.env.RL_MAC_SECONDS || 30);
const RL_PHONE_SECONDS = Number(process.env.RL_PHONE_SECONDS || 60);
const MAX_WRONG_ATTEMPTS = Number(process.env.MAX_WRONG_ATTEMPTS || 5);
const LOCK_SECONDS = Number(process.env.LOCK_SECONDS || 600);

// DB
const DATABASE_URL = process.env.DATABASE_URL || "";
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

// Redis
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "";
if (Redis && REDIS_URL) {
  redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, enableReadyCheck: true });
}

function log(...args) {
  console.log(...args);
}

// -------------------- APP --------------------
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// -------------------- HELPERS --------------------
function nowIso() {
  return new Date().toISOString();
}

function safeText(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
}

function normalizePhone(raw) {
  const s = (raw || "").toString().trim();
  if (!s) return null;
  // sadece rakam ve + kalsın
  let t = s.replace(/[^\d+]/g, "");
  // 0xxxxxxxxxx => +90xxxxxxxxxx
  if (/^0\d{10}$/.test(t)) t = "+9" + t; // 0 -> +90 (0xxxxxxxxxx => +90xxxxxxxxxx)
  if (/^\+?90\d{10}$/.test(t) && !t.startsWith("+")) t = "+" + t;
  return t;
}

function getPublicIp(req) {
  // Railway/Proxy arkasında: x-forwarded-for
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return req.socket?.remoteAddress || null;
}

function basicAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send("Admin credentials are not set (ADMIN_USER/ADMIN_PASS).");
  }
  const h = req.headers.authorization || "";
  if (!h.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(h.slice(6), "base64").toString("utf8");
  const [u, p] = decoded.split(":");
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set("WWW-Authenticate", 'Basic realm="admin"');
  return res.status(401).send("Invalid credentials");
}

function hmacHex(secret, data) {
  return crypto.createHmac("sha256", secret).update(data, "utf8").digest("hex");
}

function canonicalRowForHash(row) {
  // Stabil, sıralı, JSONB de stabil stringify
  const stableMeta = row.meta ? JSON.stringify(row.meta) : "";
  return [
    row.created_at || "",
    row.event || "",
    row.first_name || "",
    row.last_name || "",
    row.phone || "",
    String(row.kvkk_accepted ?? ""),
    row.kvkk_version || "",
    row.client_mac || "",
    row.client_ip || "",
    row.ssid || "",
    row.ap_name || "",
    row.base_grant_url || "",
    row.continue_url || "",
    row.node_mac || "",
    row.node_id || "",
    row.gateway_id || "",
    row.public_ip || "",
    row.user_agent || "",
    stableMeta,
    row.prev_hash || "",
  ].join("|");
}

// -------------------- DB INIT --------------------
async function dbInit() {
  if (!pool) {
    log("DATABASE: not configured (DATABASE_URL missing).");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

      event TEXT NOT NULL,

      first_name TEXT,
      last_name TEXT,
      phone TEXT,

      kvkk_accepted BOOLEAN NOT NULL DEFAULT false,
      kvkk_version TEXT,

      client_mac TEXT,
      client_ip TEXT,

      ssid TEXT,
      ap_name TEXT,

      base_grant_url TEXT,
      continue_url TEXT,

      node_mac TEXT,
      node_id TEXT,
      gateway_id TEXT,

      public_ip TEXT,
      user_agent TEXT,

      meta JSONB NOT NULL DEFAULT '{}'::jsonb,

      prev_hash TEXT,
      row_hash TEXT
    );
  `);

  // indexler (rapor/sorgu)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs(client_ip);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_event ON access_logs(event);`);

  log("DATABASE: connected");
  log("DATABASE: table ready");
}

// -------------------- OTP STORE (Redis or Memory fallback) --------------------
const memOtp = new Map(); // key -> {otp, exp, wrong, lockedUntil, payload}
const memRate = new Map(); // key -> {count, resetAt}

function rateKeyMac(mac) { return `rl:mac:${mac || "unknown"}`; }
function rateKeyPhone(phone) { return `rl:ph:${phone || "unknown"}`; }

function rateAllow(key, windowSeconds) {
  const now = Date.now();
  const item = memRate.get(key);
  if (!item || item.resetAt <= now) {
    memRate.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
    return true;
  }
  if (item.count >= 20) return false; // basit limit
  item.count += 1;
  return true;
}

async function otpSet(marker, obj) {
  const key = `otp:${marker}`;
  const payload = JSON.stringify(obj);
  if (redis) {
    await redis.set(key, payload, "EX", OTP_TTL_SECONDS);
    return;
  }
  memOtp.set(key, obj);
  setTimeout(() => memOtp.delete(key), OTP_TTL_SECONDS * 1000).unref?.();
}

async function otpGet(marker) {
  const key = `otp:${marker}`;
  if (redis) {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  return memOtp.get(key) || null;
}

async function otpDel(marker) {
  const key = `otp:${marker}`;
  if (redis) {
    await redis.del(key);
    return;
  }
  memOtp.delete(key);
}

// -------------------- LOG INSERT (hash-chain) --------------------
async function getLastRowHash() {
  if (!pool) return null;
  const r = await pool.query(`SELECT row_hash FROM access_logs ORDER BY id DESC LIMIT 1;`);
  return r.rows?.[0]?.row_hash || null;
}

async function insertLog(row) {
  if (!pool) return;

  // prev_hash zinciri
  const prev_hash = await getLastRowHash();
  row.prev_hash = prev_hash || null;

  // created_at DB default: now(), ama hash için “yakın” zaman sabitleyelim
  row.created_at = nowIso();

  // row_hash üret
  const canon = canonicalRowForHash(row);
  row.row_hash = hmacHex(SIGNING_SECRET, canon);

  const q = `
    INSERT INTO access_logs(
      created_at, event,
      first_name, last_name, phone,
      kvkk_accepted, kvkk_version,
      client_mac, client_ip,
      ssid, ap_name,
      base_grant_url, continue_url,
      node_mac, node_id, gateway_id,
      public_ip, user_agent,
      meta,
      prev_hash, row_hash
    )
    VALUES(
      $1::timestamptz, $2,
      $3, $4, $5,
      $6::boolean, $7,
      $8, $9,
      $10, $11,
      $12, $13,
      $14, $15, $16,
      $17, $18,
      $19::jsonb,
      $20, $21
    )
  `;

  const vals = [
    row.created_at,
    row.event,

    row.first_name,
    row.last_name,
    row.phone,

    !!row.kvkk_accepted,
    row.kvkk_version,

    row.client_mac,
    row.client_ip,

    row.ssid,
    row.ap_name,

    row.base_grant_url,
    row.continue_url,

    row.node_mac,
    row.node_id,
    row.gateway_id,

    row.public_ip,
    row.user_agent,

    JSON.stringify(row.meta || {}),

    row.prev_hash,
    row.row_hash,
  ];

  await pool.query(q, vals);
}

// -------------------- MERAKI PARAMS --------------------
function extractMerakiParams(req) {
  // Meraki query param isimleri farklı gelebilir; bu set iş görüyor
  const q = req.query || {};
  const base_grant_url = safeText(q.base_grant_url || q.baseGrantUrl || q.grant_url);
  const continue_url = safeText(q.continue_url || q.user_continue_url || q.continue || q.redirect);

  const client_mac = safeText(q.client_mac || q.clientMac);
  const client_ip = safeText(q.client_ip || q.clientIp);
  const node_mac = safeText(q.node_mac || q.nodeMac);
  const node_id = safeText(q.node_id || q.nodeId);
  const gateway_id = safeText(q.gateway_id || q.gatewayId);
  const ssid = safeText(q.ssid);
  const ap_name = safeText(q.ap_name || q.apName);

  return {
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    node_mac,
    node_id,
    gateway_id,
    ssid,
    ap_name,
  };
}

function buildGrantRedirectUrl(params) {
  // En sağlıklısı: base_grant_url’yi redirect etmek, gerekli query'leri (continue_url/duration) eklemek
  // base_grant_url örnek: https://eu.network-auth.com/splash/XXXXX/grant
  if (!params.base_grant_url) return null;

  const u = new URL(params.base_grant_url);
  // Meraki bazen gerekli alanları base_grant_url içinde taşır; biz ek olarak güvenli şekilde ekleyelim
  if (params.gateway_id) u.searchParams.set("gateway_id", params.gateway_id);
  if (params.node_id) u.searchParams.set("node_id", params.node_id);
  if (params.client_ip) u.searchParams.set("client_ip", params.client_ip);
  if (params.client_mac) u.searchParams.set("client_mac", params.client_mac);
  if (params.node_mac) u.searchParams.set("node_mac", params.node_mac);
  if (params.continue_url) u.searchParams.set("continue_url", params.continue_url);

  // süre (opsiyonel)
  u.searchParams.set("duration", "3600");
  return u.toString();
}

// -------------------- UI (SPLASH) --------------------
function splashHtml(ctx) {
  // KVKK placeholder
  const kvkkText = `
    <div class="kvkk-box">
      <h3>KVKK Aydınlatma Metni (Placeholder)</h3>
      <p>Buraya firmanızın KVKK aydınlatma metni HTML olarak eklenecek.</p>
      <p><b>Versiyon:</b> ${ctx.kvkkVersion}</p>
    </div>
  `;

  // Hidden fields: meraki params + marker
  const hidden = Object.entries(ctx.hidden || {})
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${String(v || "").replace(/"/g, "&quot;")}" />`)
    .join("\n");

  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Misafir Wi-Fi Giriş</title>
  <style>
    :root{--bg:#0b0f1a;--card:#121a2a;--text:#eaf0ff;--muted:#a7b3d6;--accent:#6e5cff;--danger:#ff4d4d;}
    body{margin:0;background:radial-gradient(1200px 800px at 70% 10%, #1a2450 0%, var(--bg) 55%);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
    .card{width:min(520px,100%);background:rgba(18,26,42,.92);border:1px solid rgba(255,255,255,.08);border-radius:18px;box-shadow:0 12px 40px rgba(0,0,0,.35);overflow:hidden}
    .head{padding:22px 22px 10px;display:flex;gap:14px;align-items:center}
    .logo{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#20e3b2);display:flex;align-items:center;justify-content:center;font-weight:800;color:#0b0f1a}
    .title{font-size:18px;font-weight:800;line-height:1.2}
    .sub{color:var(--muted);font-size:13px;margin-top:3px}
    .content{padding:0 22px 22px}
    label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px}
    input[type="text"], input[type="tel"]{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.04);color:var(--text);outline:none}
    input:focus{border-color:rgba(110,92,255,.65);box-shadow:0 0 0 4px rgba(110,92,255,.18)}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .kvkk{margin-top:12px;display:flex;gap:10px;align-items:flex-start}
    .kvkk input{margin-top:4px}
    .kvkk small{color:var(--muted);display:block;margin-top:6px}
    .kvkk-box{margin-top:10px;padding:12px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08)}
    .kvkk-box h3{margin:0 0 6px;font-size:13px}
    .kvkk-box p{margin:6px 0;color:var(--muted);font-size:12px;line-height:1.35}
    .actions{margin-top:16px;display:flex;gap:10px}
    button{flex:1;padding:12px;border-radius:12px;border:none;background:linear-gradient(135deg,var(--accent),#20e3b2);color:#0b0f1a;font-weight:900;cursor:pointer}
    .ghost{background:transparent;border:1px solid rgba(255,255,255,.14);color:var(--text)}
    .err{margin-top:12px;color:var(--danger);font-size:13px}
    .meta{margin-top:12px;color:rgba(167,179,214,.8);font-size:11px}
    .chip{display:inline-block;padding:3px 8px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);margin-right:6px}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="head">
      <div class="logo">Wi</div>
      <div>
        <div class="title">Misafir İnternet Girişi</div>
        <div class="sub">Ad-Soyad, telefon ve KVKK onayı ile giriş.</div>
      </div>
    </div>
    <div class="content">
      ${ctx.error ? `<div class="err">${ctx.error}</div>` : ""}
      <form method="POST" action="/otp/create">
        ${hidden}
        <div class="row">
          <div>
            <label>Ad</label>
            <input name="first_name" type="text" required maxlength="80" placeholder="Ad" />
          </div>
          <div>
            <label>Soyad</label>
            <input name="last_name" type="text" required maxlength="80" placeholder="Soyad" />
          </div>
        </div>

        <label>Cep Telefonu</label>
        <input name="phone" type="tel" required maxlength="20" placeholder="0 5xx xxx xx xx" />

        <div class="kvkk">
          <input type="checkbox" name="kvkk_accepted" value="true" required />
          <div>
            <div><b>KVKK Aydınlatma Metni</b> ve <b>Açık Rıza</b> koşullarını okudum, kabul ediyorum.</div>
            <small>Bu metin daha sonra gerçek içerikle değiştirilecek.</small>
          </div>
        </div>

        ${kvkkText}

        <div class="actions">
          <button type="submit">Devam Et</button>
          <button type="button" class="ghost" onclick="location.reload()">Yenile</button>
        </div>

        <div class="meta">
          <span class="chip">OTP: ${OTP_MODE}</span>
          <span class="chip">KVKK: ${ctx.kvkkVersion}</span>
        </div>
      </form>
    </div>
  </div>
</div>
</body>
</html>`;
}

function otpHtml(ctx) {
  const hidden = Object.entries(ctx.hidden || {})
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${String(v || "").replace(/"/g, "&quot;")}" />`)
    .join("\n");

  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>OTP Doğrulama</title>
  <style>
    :root{--bg:#0b0f1a;--card:#121a2a;--text:#eaf0ff;--muted:#a7b3d6;--accent:#6e5cff;--danger:#ff4d4d;}
    body{margin:0;background:radial-gradient(1200px 800px at 70% 10%, #1a2450 0%, var(--bg) 55%);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
    .card{width:min(520px,100%);background:rgba(18,26,42,.92);border:1px solid rgba(255,255,255,.08);border-radius:18px;box-shadow:0 12px 40px rgba(0,0,0,.35);overflow:hidden}
    .head{padding:22px 22px 10px}
    .title{font-size:18px;font-weight:900}
    .sub{color:var(--muted);font-size:13px;margin-top:4px}
    .content{padding:0 22px 22px}
    label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px}
    input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.04);color:var(--text);outline:none}
    input:focus{border-color:rgba(110,92,255,.65);box-shadow:0 0 0 4px rgba(110,92,255,.18)}
    .actions{margin-top:16px;display:flex;gap:10px}
    button{flex:1;padding:12px;border-radius:12px;border:none;background:linear-gradient(135deg,var(--accent),#20e3b2);color:#0b0f1a;font-weight:900;cursor:pointer}
    .ghost{background:transparent;border:1px solid rgba(255,255,255,.14);color:var(--text)}
    .err{margin-top:12px;color:var(--danger);font-size:13px}
    .codebox{margin-top:10px;padding:12px;border-radius:12px;background:rgba(255,255,255,.03);border:1px dashed rgba(255,255,255,.2);color:var(--muted);font-size:12px}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="head">
      <div class="title">Doğrulama Kodu</div>
      <div class="sub">Telefonuna gelen kodu gir (şimdilik ekranda gösteriyoruz).</div>
    </div>
    <div class="content">
      ${ctx.error ? `<div class="err">${ctx.error}</div>` : ""}
      ${ctx.debugCode ? `<div class="codebox"><b>DEBUG (screen mode):</b> Kod = <b>${ctx.debugCode}</b></div>` : ""}
      <form method="POST" action="/otp/verify">
        ${hidden}
        <label>OTP</label>
        <input name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required placeholder="6 haneli kod" />
        <div class="actions">
          <button type="submit">Bağlan</button>
          <button type="button" class="ghost" onclick="history.back()">Geri</button>
        </div>
      </form>
    </div>
  </div>
</div>
</body>
</html>`;
}

// -------------------- ROUTES --------------------

// health
app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    ts: nowIso(),
    redis: !!redis,
    db: !!pool,
    otp_mode: OTP_MODE,
    kvkk_version: KVKK_VERSION,
    admin_user_set: !!ADMIN_USER,
  });
});

// Splash entry
app.get(["/", "/splash"], async (req, res) => {
  const p = extractMerakiParams(req);

  log("SPLASH_OPEN", {
    hasBaseGrant: !!p.base_grant_url,
    hasContinue: !!p.continue_url,
    hasClientMac: !!p.client_mac,
    mode: OTP_MODE,
  });

  if (!p.base_grant_url) {
    // bazen Meraki paramları yokken direkt açılabilir; yine de UI gösterelim
  }

  // UI’da hidden olarak taşıyalım
  const hidden = {
    base_grant_url: p.base_grant_url || "",
    continue_url: p.continue_url || "",
    client_mac: p.client_mac || "",
    client_ip: p.client_ip || "",
    node_mac: p.node_mac || "",
    node_id: p.node_id || "",
    gateway_id: p.gateway_id || "",
    ssid: p.ssid || "",
    ap_name: p.ap_name || "",
  };

  res.status(200).send(
    splashHtml({
      kvkkVersion: KVKK_VERSION,
      hidden,
      error: null,
    })
  );
});

// Create OTP
app.post("/otp/create", async (req, res) => {
  try {
    const first_name = safeText(req.body.first_name);
    const last_name = safeText(req.body.last_name);
    const phone = normalizePhone(req.body.phone);
    const kvkk_accepted = req.body.kvkk_accepted === "true" || req.body.kvkk_accepted === true;

    const p = {
      base_grant_url: safeText(req.body.base_grant_url),
      continue_url: safeText(req.body.continue_url),
      client_mac: safeText(req.body.client_mac),
      client_ip: safeText(req.body.client_ip),
      node_mac: safeText(req.body.node_mac),
      node_id: safeText(req.body.node_id),
      gateway_id: safeText(req.body.gateway_id),
      ssid: safeText(req.body.ssid),
      ap_name: safeText(req.body.ap_name),
    };

    // Rate limit (basit)
    if (p.client_mac && !rateAllow(rateKeyMac(p.client_mac), RL_MAC_SECONDS)) {
      return res.status(429).send(otpHtml({ error: "Çok fazla deneme. Lütfen biraz sonra tekrar deneyin.", hidden: {} }));
    }
    if (phone && !rateAllow(rateKeyPhone(phone), RL_PHONE_SECONDS)) {
      return res.status(429).send(otpHtml({ error: "Çok fazla deneme. Lütfen biraz sonra tekrar deneyin.", hidden: {} }));
    }

    if (!first_name || !last_name || !phone || !kvkk_accepted) {
      return res.status(400).send(
        splashHtml({
          kvkkVersion: KVKK_VERSION,
          hidden: { ...p },
          error: "Lütfen ad/soyad/telefon ve KVKK onayını doldurun.",
        })
      );
    }

    // OTP üret
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const marker = String(Math.floor(100000 + Math.random() * 900000));

    const payload = {
      marker,
      otp,
      created_at: nowIso(),
      wrong: 0,
      locked_until: 0,
      first_name,
      last_name,
      phone,
      kvkk_accepted: true,
      kvkk_version: KVKK_VERSION,
      meraki: p,
    };

    await otpSet(marker, payload);

    log("OTP_CREATED", { marker, last4: phone.slice(-4), client_mac: p.client_mac });

    // 5651 log: OTP_CREATED
    await insertLog({
      event: "OTP_CREATED",
      first_name,
      last_name,
      phone,
      kvkk_accepted: true,
      kvkk_version: KVKK_VERSION,
      client_mac: p.client_mac,
      client_ip: p.client_ip,
      ssid: p.ssid,
      ap_name: p.ap_name,
      base_grant_url: p.base_grant_url,
      continue_url: p.continue_url,
      node_mac: p.node_mac,
      node_id: p.node_id,
      gateway_id: p.gateway_id,
      public_ip: getPublicIp(req),
      user_agent: safeText(req.headers["user-agent"]),
      meta: { otp_mode: OTP_MODE },
    }).catch((e) => log("DB LOG ERROR:", e?.message || e));

    // screen mode: kodu ekranda göster (sms sonra)
    const hidden = { marker };
    res.status(200).send(
      otpHtml({
        hidden,
        debugCode: OTP_MODE === "screen" ? otp : null,
        error: null,
      })
    );
  } catch (e) {
    log("OTP_CREATE_ERR", e);
    res.status(500).send("Server error");
  }
});

// Verify OTP and grant
app.post("/otp/verify", async (req, res) => {
  try {
    const marker = safeText(req.body.marker);
    const otp = safeText(req.body.otp);

    if (!marker || !otp) return res.status(400).send("Missing marker/otp");

    const obj = await otpGet(marker);
    if (!obj) return res.status(400).send(otpHtml({ hidden: { marker }, error: "Kod süresi doldu. Baştan deneyin." }));

    // lock / wrong attempts
    const now = Date.now();
    if (obj.locked_until && obj.locked_until > now) {
      return res.status(429).send(otpHtml({ hidden: { marker }, error: "Çok fazla yanlış deneme. Biraz bekleyin." }));
    }

    if (String(obj.otp) !== String(otp)) {
      obj.wrong = (obj.wrong || 0) + 1;
      if (obj.wrong >= MAX_WRONG_ATTEMPTS) {
        obj.locked_until = now + LOCK_SECONDS * 1000;
      }
      await otpSet(marker, obj);
      return res.status(400).send(otpHtml({ hidden: { marker }, error: "Kod hatalı. Tekrar deneyin." }));
    }

    // OK
    log("OTP_VERIFY_OK", { marker, client_mac: obj.meraki?.client_mac });

    await insertLog({
      event: "OTP_VERIFIED",
      first_name: obj.first_name,
      last_name: obj.last_name,
      phone: obj.phone,
      kvkk_accepted: true,
      kvkk_version: obj.kvkk_version,
      client_mac: obj.meraki?.client_mac,
      client_ip: obj.meraki?.client_ip,
      ssid: obj.meraki?.ssid,
      ap_name: obj.meraki?.ap_name,
      base_grant_url: obj.meraki?.base_grant_url,
      continue_url: obj.meraki?.continue_url,
      node_mac: obj.meraki?.node_mac,
      node_id: obj.meraki?.node_id,
      gateway_id: obj.meraki?.gateway_id,
      public_ip: getPublicIp(req),
      user_agent: safeText(req.headers["user-agent"]),
      meta: { marker },
    }).catch((e) => log("DB LOG ERROR:", e?.message || e));

    const redirectUrl = buildGrantRedirectUrl(obj.meraki || {});
    if (!redirectUrl) {
      await otpDel(marker);
      return res.status(200).send("OTP OK but base_grant_url missing.");
    }

    log("GRANT_CLIENT_REDIRECT:", redirectUrl);

    await otpDel(marker);
    return res.redirect(302, redirectUrl);
  } catch (e) {
    log("OTP_VERIFY_ERR", e);
    res.status(500).send("Server error");
  }
});

// -------------------- ADMIN UI --------------------
function adminLayout(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    :root{--bg:#0b0f1a;--card:#121a2a;--text:#eaf0ff;--muted:#a7b3d6;--accent:#6e5cff;--danger:#ff4d4d;}
    body{margin:0;background:radial-gradient(1200px 800px at 70% 10%, #1a2450 0%, var(--bg) 55%);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;}
    .wrap{max-width:1200px;margin:0 auto;padding:22px}
    .card{background:rgba(18,26,42,.92);border:1px solid rgba(255,255,255,.08);border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.35);padding:16px}
    h1{margin:0 0 12px;font-size:18px}
    .muted{color:var(--muted)}
    table{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}
    th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
    th{color:rgba(167,179,214,.9);text-align:left;font-weight:800}
    .toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
    label{display:block;color:var(--muted);font-size:11px;margin-bottom:6px}
    input,select{padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.04);color:var(--text);outline:none}
    a.btn, button.btn{display:inline-block;padding:10px 12px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#20e3b2);color:#0b0f1a;font-weight:900;border:none;text-decoration:none;cursor:pointer}
    a.ghost{background:transparent;border:1px solid rgba(255,255,255,.14);color:var(--text)}
    .chip{display:inline-block;padding:3px 8px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);margin-right:6px}
    .ok{color:#20e3b2;font-weight:900}
    .bad{color:var(--danger);font-weight:900}
    pre{white-space:pre-wrap;word-break:break-word;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);padding:10px;border-radius:12px}
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
    <div class="muted" style="margin-top:14px;font-size:11px">
      <span class="chip">KVKK_VERSION: ${KVKK_VERSION}</span>
      <span class="chip">OTP_MODE: ${OTP_MODE}</span>
      <span class="chip">DB: ${pool ? "on" : "off"}</span>
      <span class="chip">REDIS: ${redis ? "on" : "off"}</span>
    </div>
  </div>
</body>
</html>`;
}

// Query builder for admin logs
async function fetchLogs(filters) {
  if (!pool) return { rows: [], total: 0 };

  const where = [];
  const vals = [];
  let i = 1;

  if (filters.sinceHours) {
    where.push(`created_at >= now() - ($${i}::int || ' hours')::interval`);
    vals.push(filters.sinceHours);
    i++;
  }
  if (filters.phone) {
    where.push(`phone ILIKE $${i}`);
    vals.push(`%${filters.phone}%`);
    i++;
  }
  if (filters.mac) {
    where.push(`client_mac ILIKE $${i}`);
    vals.push(`%${filters.mac}%`);
    i++;
  }
  if (filters.ip) {
    where.push(`client_ip ILIKE $${i}`);
    vals.push(`%${filters.ip}%`);
    i++;
  }
  if (filters.event) {
    where.push(`event = $${i}`);
    vals.push(filters.event);
    i++;
  }

  const w = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const limit = Math.min(Number(filters.limit || 200), 2000);
  const offset = Math.max(Number(filters.offset || 0), 0);

  const totalQ = await pool.query(`SELECT COUNT(*)::bigint AS c FROM access_logs ${w};`, vals);
  const q = await pool.query(
    `SELECT * FROM access_logs ${w} ORDER BY id DESC LIMIT ${limit} OFFSET ${offset};`,
    vals
  );
  return { rows: q.rows || [], total: Number(totalQ.rows?.[0]?.c || 0) };
}

// Admin logs UI
app.get("/admin/logs", basicAuth, async (req, res) => {
  try {
    const sinceHours = safeText(req.query.h || "24");
    const phone = safeText(req.query.phone);
    const mac = safeText(req.query.mac);
    const ip = safeText(req.query.ip);
    const event = safeText(req.query.event);
    const limit = safeText(req.query.limit || "200");
    const offset = safeText(req.query.offset || "0");

    const { rows, total } = await fetchLogs({ sinceHours, phone, mac, ip, event, limit, offset });

    const events = ["OTP_CREATED", "OTP_VERIFIED"];
    const rowsHtml = rows
      .map((r) => {
        const ok = r.row_hash && (r.prev_hash !== undefined);
        return `<tr>
          <td>${r.id}</td>
          <td>${new Date(r.created_at).toLocaleString("tr-TR")}</td>
          <td><b>${r.event}</b></td>
          <td>${(r.first_name || "")} ${(r.last_name || "")}<div class="muted">${r.phone || ""}</div></td>
          <td>${r.client_mac || ""}<div class="muted">${r.client_ip || ""}</div></td>
          <td>${r.ssid || ""}<div class="muted">${r.ap_name || ""}</div></td>
          <td>${r.kvkk_accepted ? `<span class="ok">true</span>` : `<span class="bad">false</span>`}<div class="muted">${r.kvkk_version || ""}</div></td>
          <td>${ok ? `<span class="ok">hash</span>` : `<span class="bad">-</span>`}</td>
        </tr>`;
      })
      .join("");

    const body = `
      <div class="card">
        <h1>5651 Logları</h1>
        <div class="muted">Filtrele, görüntüle, dışa aktar (CSV/JSON) ve hash-zincir doğrulama.</div>

        <form class="toolbar" method="GET" action="/admin/logs">
          <div>
            <label>Son kaç saat</label>
            <input name="h" value="${sinceHours || ""}" style="width:110px"/>
          </div>
          <div>
            <label>Telefon</label>
            <input name="phone" value="${phone || ""}" placeholder="0533..."/>
          </div>
          <div>
            <label>MAC</label>
            <input name="mac" value="${mac || ""}" placeholder="96:47:..."/>
          </div>
          <div>
            <label>IP</label>
            <input name="ip" value="${ip || ""}" placeholder="10.120..."/>
          </div>
          <div>
            <label>Event</label>
            <select name="event">
              <option value="">(hepsi)</option>
              ${events.map((e) => `<option value="${e}" ${event === e ? "selected" : ""}>${e}</option>`).join("")}
            </select>
          </div>
          <div>
            <label>Limit</label>
            <input name="limit" value="${limit || ""}" style="width:90px"/>
          </div>
          <div>
            <input type="hidden" name="offset" value="0"/>
            <button class="btn" type="submit">Uygula</button>
          </div>
          <div>
            <label>&nbsp;</label>
            <a class="btn ghost" href="/admin/export.csv?h=${encodeURIComponent(sinceHours || "")}&phone=${encodeURIComponent(phone || "")}&mac=${encodeURIComponent(mac || "")}&ip=${encodeURIComponent(ip || "")}&event=${encodeURIComponent(event || "")}">CSV</a>
          </div>
          <div>
            <label>&nbsp;</label>
            <a class="btn ghost" href="/admin/export.json?h=${encodeURIComponent(sinceHours || "")}&phone=${encodeURIComponent(phone || "")}&mac=${encodeURIComponent(mac || "")}&ip=${encodeURIComponent(ip || "")}&event=${encodeURIComponent(event || "")}">JSON</a>
          </div>
          <div>
            <label>&nbsp;</label>
            <a class="btn ghost" href="/admin/verify-chain?h=${encodeURIComponent(sinceHours || "")}">Hash Doğrula</a>
          </div>
        </form>

        <div style="margin-top:10px" class="muted">
          Toplam: <b>${total}</b> | Gösterilen: <b>${rows.length}</b>
        </div>

        <table>
          <thead>
            <tr>
              <th>ID</th><th>Zaman</th><th>Event</th><th>Kullanıcı</th><th>Cihaz</th><th>SSID/AP</th><th>KVKK</th><th>İmza</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml || `<tr><td colspan="8" class="muted">Kayıt yok</td></tr>`}
          </tbody>
        </table>

        <div style="margin-top:12px" class="muted">
          Not: “İmzalama” şu an <b>HMAC hash-zinciri</b> (placeholder). Gerçek e-imza/HSM entegrasyonu istersen bir sonraki adımda “gün sonu imzalı paket” formatına geçeriz.
        </div>
      </div>
    `;

    res.status(200).send(adminLayout("Admin Logs", body));
  } catch (e) {
    log("ADMIN_LOGS_ERR", e);
    res.status(500).send(adminLayout("Admin Logs", `<div class="card"><h1>Hata</h1><pre>${String(e?.stack || e)}</pre></div>`));
  }
});

// Export CSV
app.get("/admin/export.csv", basicAuth, async (req, res) => {
  try {
    const sinceHours = safeText(req.query.h || "24");
    const phone = safeText(req.query.phone);
    const mac = safeText(req.query.mac);
    const ip = safeText(req.query.ip);
    const event = safeText(req.query.event);

    const { rows } = await fetchLogs({ sinceHours, phone, mac, ip, event, limit: 2000, offset: 0 });

    const headers = [
      "id","created_at","event","first_name","last_name","phone","kvkk_accepted","kvkk_version",
      "client_mac","client_ip","ssid","ap_name","base_grant_url","continue_url",
      "node_mac","node_id","gateway_id","public_ip","user_agent","prev_hash","row_hash","meta"
    ];

    const csvEscape = (v) => {
      if (v === null || v === undefined) return "";
      const s = typeof v === "string" ? v : JSON.stringify(v);
      if (/[,"\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    };

    let out = headers.join(",") + "\n";
    for (const r of rows) {
      const line = headers.map((h) => csvEscape(r[h])).join(",");
      out += line + "\n";
    }

    // “paket imzası” placeholder: tüm dosyayı hashle
    const packSig = hmacHex(SIGNING_SECRET, out);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("X-Package-Signature", packSig);
    res.status(200).send(out);
  } catch (e) {
    log("EXPORT_CSV_ERR", e);
    res.status(500).send("export error");
  }
});

// Export JSON
app.get("/admin/export.json", basicAuth, async (req, res) => {
  try {
    const sinceHours = safeText(req.query.h || "24");
    const phone = safeText(req.query.phone);
    const mac = safeText(req.query.mac);
    const ip = safeText(req.query.ip);
    const event = safeText(req.query.event);

    const { rows } = await fetchLogs({ sinceHours, phone, mac, ip, event, limit: 2000, offset: 0 });

    const payload = { exported_at: nowIso(), rows };
    const raw = JSON.stringify(payload);
    const packSig = hmacHex(SIGNING_SECRET, raw);

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("X-Package-Signature", packSig);
    res.status(200).send(raw);
  } catch (e) {
    log("EXPORT_JSON_ERR", e);
    res.status(500).send("export error");
  }
});

// Verify hash-chain
app.get("/admin/verify-chain", basicAuth, async (req, res) => {
  try {
    const sinceHours = safeText(req.query.h || "24");

    if (!pool) return res.status(500).send("DB not configured");

    const q = await pool.query(
      `SELECT * FROM access_logs WHERE created_at >= now() - ($1::int || ' hours')::interval ORDER BY id ASC;`,
      [sinceHours]
    );

    let ok = 0;
    let bad = 0;
    let lastHash = null;
    const badSamples = [];

    for (const r of q.rows) {
      const row = {
        created_at: new Date(r.created_at).toISOString(),
        event: r.event,
        first_name: r.first_name,
        last_name: r.last_name,
        phone: r.phone,
        kvkk_accepted: r.kvkk_accepted,
        kvkk_version: r.kvkk_version,
        client_mac: r.client_mac,
        client_ip: r.client_ip,
        ssid: r.ssid,
        ap_name: r.ap_name,
        base_grant_url: r.base_grant_url,
        continue_url: r.continue_url,
        node_mac: r.node_mac,
        node_id: r.node_id,
        gateway_id: r.gateway_id,
        public_ip: r.public_ip,
        user_agent: r.user_agent,
        meta: r.meta,
        prev_hash: r.prev_hash,
      };

      const canon = canonicalRowForHash(row);
      const expected = hmacHex(SIGNING_SECRET, canon);

      const chainOk = (r.prev_hash || null) === (lastHash || null);
      const hashOk = expected === r.row_hash;

      if (chainOk && hashOk) ok++;
      else {
        bad++;
        if (badSamples.length < 10) {
          badSamples.push({ id: r.id, chainOk, hashOk, prev_db: r.prev_hash, prev_calc: lastHash, row_hash_db: r.row_hash, row_hash_calc: expected });
        }
      }
      lastHash = r.row_hash || lastHash;
    }

    const body = `
      <div class="card">
        <h1>Hash Zinciri Doğrulama</h1>
        <div class="muted">Son ${sinceHours} saatlik kayıtlar için kontrol.</div>
        <div style="margin-top:10px">
          <span class="chip">OK: <b class="ok">${ok}</b></span>
          <span class="chip">BAD: <b class="bad">${bad}</b></span>
        </div>
        ${bad ? `<h3 style="margin-top:14px">Örnek Hatalar</h3><pre>${JSON.stringify(badSamples, null, 2)}</pre>` : `<div style="margin-top:12px" class="ok">Zincir sağlam ✅</div>`}
        <div style="margin-top:12px" class="muted">
          Not: Bu yöntem “değiştirilemezlik kanıtı” sağlar. 5651 için gerçek dünyada ayrıca <b>zaman damgası</b> ve/veya <b>e-imza</b> ile “gün sonu” paket imzalama yapılır.
        </div>
        <div style="margin-top:12px">
          <a class="btn ghost" href="/admin/logs">Geri</a>
        </div>
      </div>
    `;
    res.status(200).send(adminLayout("Verify Chain", body));
  } catch (e) {
    log("VERIFY_CHAIN_ERR", e);
    res.status(500).send(adminLayout("Verify Chain", `<div class="card"><h1>Hata</h1><pre>${String(e?.stack || e)}</pre></div>`));
  }
});

// -------------------- STARTUP --------------------
(async () => {
  try {
    log("ENV:", {
      OTP_MODE,
      OTP_TTL_SECONDS,
      RL_MAC_SECONDS,
      RL_PHONE_SECONDS,
      MAX_WRONG_ATTEMPTS,
      LOCK_SECONDS,
      KVKK_VERSION,
      ADMIN_USER_SET: !!ADMIN_USER,
      ADMIN_PASS_SET: !!ADMIN_PASS,
      REDIS: !!redis,
      DB: !!pool,
    });

    if (redis) log("REDIS: connected");
    else log("REDIS: not configured");

    if (pool) await dbInit();

    app.listen(PORT, () => {
      log(`Server running on port ${PORT}`);
    });
  } catch (e) {
    log("BOOT_ERR", e);
    process.exit(1);
  }
})();
