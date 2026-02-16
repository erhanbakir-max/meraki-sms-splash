/**
 * server.js - Meraki captive portal helper
 * - OTP_MODE=screen (SMS yok)
 * - Redis: OTP store (persist)
 * - Postgres: 5651 access_logs + daily_packages (hash/zincir)
 * - Admin UI: /admin/logs, /admin/daily (Basic Auth)
 *
 * ENV required:
 *  - PORT (Railway)
 *  - REDIS_URL or REDIS_PUBLIC_URL
 *  - DATABASE_URL (Postgres)
 *  - OTP_MODE=screen
 *  - ADMIN_USER, ADMIN_PASS   (admin endpoints)
 *
 * Optional:
 *  - OTP_TTL_SECONDS (default 180)
 *  - RL_MAC_SECONDS (default 30)
 *  - RL_PHONE_SECONDS (default 60)
 *  - MAX_WRONG_ATTEMPTS (default 5)
 *  - LOCK_SECONDS (default 600)
 *  - KVKK_VERSION (default 'placeholder')
 *  - TZ (default 'Europe/Istanbul')
 */

"use strict";

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const { createClient } = require("redis");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || "8080", 10);

const OTP_MODE = (process.env.OTP_MODE || "screen").trim();
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);

const KVKK_VERSION = (process.env.KVKK_VERSION || "placeholder").trim();
const TZ = (process.env.TZ || "Europe/Istanbul").trim();

const ADMIN_USER = (process.env.ADMIN_USER || "").trim();
const ADMIN_PASS = (process.env.ADMIN_PASS || "").trim();

const REDIS_URL = (process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "").trim();
const DATABASE_URL = (process.env.DATABASE_URL || "").trim();

console.log("ENV:", {
  OTP_MODE,
  OTP_TTL_SECONDS,
  RL_MAC_SECONDS,
  RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS,
  KVKK_VERSION,
  TZ,
  ADMIN_USER_SET: !!ADMIN_USER,
  ADMIN_PASS_SET: !!ADMIN_PASS,
});

// -------------------- Helpers --------------------
function nowIso() {
  return new Date().toISOString();
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

// JSON canonicalize (stable)
function stableStringify(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(stableStringify).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

function isYmd(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function safeText(x, max = 2000) {
  if (x === undefined || x === null) return null;
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function normalizePhone(input) {
  if (!input) return "";
  let s = String(input).trim();
  // keep + and digits
  s = s.replace(/[^\d+]/g, "");
  // allow starting 0 or +90...
  return s;
}

function normalizeMac(input) {
  if (!input) return "";
  return String(input).trim().toLowerCase();
}

function getReqPublicIp(req) {
  // Prefer x-forwarded-for (Railway uses proxies)
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  const xr = req.headers["x-real-ip"];
  if (xr) return String(xr).trim();
  return (req.socket && req.socket.remoteAddress) ? String(req.socket.remoteAddress) : "";
}

function basicAuthHeader(user, pass) {
  const token = Buffer.from(`${user}:${pass}`).toString("base64");
  return `Basic ${token}`;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(503).send("admin credentials not configured");
  }
  const hdr = req.headers["authorization"] || "";
  if (!hdr.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("auth required");
  }
  try {
    const raw = Buffer.from(hdr.slice(6), "base64").toString("utf8");
    const [u, p] = raw.split(":");
    if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  } catch (_) {}
  res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
  return res.status(401).send("invalid credentials");
}

// -------------------- Redis --------------------
let redis = null;
let redisEnabled = false;

async function initRedis() {
  if (!REDIS_URL) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing).");
    return;
  }
  redis = createClient({ url: REDIS_URL });
  redis.on("error", (err) => console.error("REDIS_ERROR", err));
  await redis.connect();
  redisEnabled = true;
  console.log("REDIS: connected");
}

function rKeyOtp(marker) { return `otp:${marker}`; }
function rKeyRlMac(mac) { return `rl:mac:${mac}`; }
function rKeyRlPhone(phone) { return `rl:phone:${phone}`; }
function rKeyLockMac(mac) { return `lock:mac:${mac}`; }

// -------------------- Postgres --------------------
let pool = null;
let dbEnabled = false;

async function initDb() {
  if (!DATABASE_URL) {
    console.log("DATABASE: not configured (DATABASE_URL missing).");
    return;
  }
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
  });
  await pool.query("SELECT 1");
  dbEnabled = true;
  console.log("DATABASE: connected");

  // access_logs table (client_ip TEXT per your note)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      event text NOT NULL,

      first_name text,
      last_name text,
      phone text,

      client_mac text,
      client_ip text,

      ssid text,
      ap_name text,

      base_grant_url text,
      continue_url text,

      marker text,

      kvkk_accepted boolean,
      kvkk_version text,

      meta jsonb
    );
  `);

  // daily_packages table (5651 daily chain)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day date PRIMARY KEY,
      tz text NOT NULL DEFAULT 'Europe/Istanbul',
      record_count integer NOT NULL,
      body_json jsonb NOT NULL,
      day_hash text NOT NULL,
      prev_day_hash text,
      chain_hash text NOT NULL,
      signature_type text,
      signature text,
      signed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("DATABASE: table ready");
}

async function qRows(sql, params = []) {
  if (!dbEnabled) return [];
  const r = await pool.query(sql, params);
  return r.rows || [];
}

async function logDb(event, payload) {
  if (!dbEnabled) return;

  // columns expected in payload:
  // first_name,last_name,phone,client_mac,client_ip,ssid,ap_name,base_grant_url,continue_url,marker,kvkk_accepted,kvkk_version,meta
  const p = payload || {};
  const client_ip = p.client_ip ? String(p.client_ip) : null; // TEXT
  const sql = `
    INSERT INTO access_logs(
      event, client_mac, client_ip, ssid, ap_name,
      base_grant_url, continue_url, marker,
      phone, first_name, last_name,
      kvkk_accepted, kvkk_version, meta
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
  `;
  const vals = [
    event,
    p.client_mac ? safeText(p.client_mac, 128) : null,
    client_ip ? safeText(client_ip, 128) : null,
    p.ssid ? safeText(p.ssid, 128) : null,
    p.ap_name ? safeText(p.ap_name, 128) : null,
    p.base_grant_url ? safeText(p.base_grant_url, 2000) : null,
    p.continue_url ? safeText(p.continue_url, 2000) : null,
    p.marker ? safeText(p.marker, 64) : null,
    p.phone ? safeText(p.phone, 64) : null,
    p.first_name ? safeText(p.first_name, 128) : null,
    p.last_name ? safeText(p.last_name, 128) : null,
    (p.kvkk_accepted === undefined ? null : !!p.kvkk_accepted),
    p.kvkk_version ? safeText(p.kvkk_version, 64) : null,
    JSON.stringify(p.meta || null),
  ];

  try {
    await pool.query(sql, vals);
  } catch (e) {
    console.error("DB LOG ERROR:", e.message);
  }
}

// -------------------- Meraki param parsing --------------------
function parseMerakiParams(req) {
  // Meraki sends gateway_id, node_id, client_ip, client_mac, node_mac, continue_url, etc.
  // In some flows, base_grant_url is present.
  const q = req.query || {};

  const base_grant_url = q.base_grant_url ? String(q.base_grant_url) : "";
  const continue_url = q.continue_url ? String(q.continue_url) : "";

  const gateway_id = q.gateway_id ? String(q.gateway_id) : "";
  const node_id = q.node_id ? String(q.node_id) : "";
  const client_ip = q.client_ip ? String(q.client_ip) : "";
  const client_mac = q.client_mac ? String(q.client_mac) : "";
  const node_mac = q.node_mac ? String(q.node_mac) : "";

  // optional
  const ssid = q.ssid ? String(q.ssid) : "";
  const ap_name = q.ap_name ? String(q.ap_name) : "";

  const hasBaseGrant = !!base_grant_url;
  const hasContinue = !!continue_url;
  const hasClientMac = !!client_mac;

  return {
    base_grant_url,
    continue_url,
    gateway_id,
    node_id,
    client_ip,
    client_mac,
    node_mac,
    ssid,
    ap_name,
    hasBaseGrant,
    hasContinue,
    hasClientMac,
  };
}

// Build grant URL for client redirect (Meraki expects browser redirect)
function buildGrantClientRedirect(params) {
  // Best practice: redirect client to base_grant_url with required params.
  // If base_grant_url already includes '?' keep it simple; else add query.
  // We'll attach required fields if present.
  const base = params.base_grant_url;
  if (!base) return "";

  const url = new URL(base);
  // Meraki required fields often: gateway_id, node_id, client_ip, client_mac, node_mac, continue_url
  if (params.gateway_id) url.searchParams.set("gateway_id", params.gateway_id);
  if (params.node_id) url.searchParams.set("node_id", params.node_id);
  if (params.client_ip) url.searchParams.set("client_ip", params.client_ip);
  if (params.client_mac) url.searchParams.set("client_mac", params.client_mac);
  if (params.node_mac) url.searchParams.set("node_mac", params.node_mac);

  // include continue_url to keep flow smooth
  if (params.continue_url) url.searchParams.set("continue_url", params.continue_url);

  return url.toString();
}

// -------------------- OTP & Rate-limit --------------------
function makeMarker() {
  // 6-digit marker
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function isLocked(mac) {
  if (!redisEnabled) return false;
  const v = await redis.get(rKeyLockMac(mac));
  return !!v;
}

async function lockMac(mac, reason = "too_many_wrong") {
  if (!redisEnabled) return;
  await redis.set(rKeyLockMac(mac), reason, { EX: LOCK_SECONDS });
}

async function rateLimitByMac(mac) {
  if (!redisEnabled) return true;
  const key = rKeyRlMac(mac);
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, RL_MAC_SECONDS);
  return n <= 5; // basic burst
}

async function rateLimitByPhone(phone) {
  if (!redisEnabled) return true;
  const key = rKeyRlPhone(phone);
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, RL_PHONE_SECONDS);
  return n <= 5;
}

async function otpCreate({ phone, client_mac, meta }) {
  const marker = makeMarker();
  const otp = makeMarker(); // 6-digit OTP
  const data = {
    marker,
    otp,
    created_at: nowIso(),
    phone,
    client_mac,
    wrong: 0,
    meta: meta || null,
  };
  if (redisEnabled) {
    await redis.set(rKeyOtp(marker), JSON.stringify(data), { EX: OTP_TTL_SECONDS });
  }
  return { marker, otp };
}

async function otpGet(marker) {
  if (!redisEnabled) return null;
  const v = await redis.get(rKeyOtp(marker));
  if (!v) return null;
  try { return JSON.parse(v); } catch { return null; }
}

async function otpBumpWrong(marker) {
  if (!redisEnabled) return null;
  const d = await otpGet(marker);
  if (!d) return null;
  d.wrong = (d.wrong || 0) + 1;
  // Keep remaining TTL: easiest set again with full TTL is OK for now (or you can keep TTL via TTL command)
  await redis.set(rKeyOtp(marker), JSON.stringify(d), { EX: OTP_TTL_SECONDS });
  return d;
}

async function otpConsume(marker) {
  if (!redisEnabled) return;
  await redis.del(rKeyOtp(marker));
}

// -------------------- Daily packages (5651) --------------------
async function fetchAccessLogsForDay(dayYmd, tz = TZ) {
  const sql = `
    SELECT
      id,
      created_at,
      event,
      first_name,
      last_name,
      phone,
      client_mac,
      client_ip,
      ssid,
      ap_name,
      base_grant_url,
      continue_url,
      marker,
      kvkk_accepted,
      kvkk_version,
      meta
    FROM access_logs
    WHERE created_at >= ((($1::date)::timestamp) AT TIME ZONE $2)
      AND created_at <  (((($1::date + 1))::timestamp) AT TIME ZONE $2)
    ORDER BY created_at ASC, id ASC
  `;
  return await qRows(sql, [dayYmd, tz]);
}

async function buildDailyPackage(dayYmd, tz = TZ) {
  if (!dbEnabled) throw new Error("db disabled");
  if (!isYmd(dayYmd)) throw new Error("bad day format");

  const rows = await fetchAccessLogsForDay(dayYmd, tz);

  const body = {
    day: dayYmd,
    tz,
    generated_at: nowIso(),
    record_count: rows.length,
    records: rows.map(x => ({
      id: x.id,
      created_at: x.created_at,
      event: x.event,
      first_name: x.first_name,
      last_name: x.last_name,
      phone: x.phone,
      client_mac: x.client_mac,
      client_ip: x.client_ip,
      ssid: x.ssid,
      ap_name: x.ap_name,
      base_grant_url: x.base_grant_url,
      continue_url: x.continue_url,
      marker: x.marker,
      kvkk_accepted: x.kvkk_accepted,
      kvkk_version: x.kvkk_version,
      meta: x.meta || null,
    })),
  };

  const canonical = stableStringify(body);
  const day_hash = sha256Hex(canonical);

  const prev = await qRows(
    `SELECT day, day_hash, chain_hash FROM daily_packages WHERE day < $1::date ORDER BY day DESC LIMIT 1`,
    [dayYmd]
  );
  const prev_day_hash = prev.length ? prev[0].day_hash : null;
  const prev_chain_hash = prev.length ? prev[0].chain_hash : "GENESIS";
  const chain_hash = sha256Hex(prev_chain_hash + "\n" + day_hash);

  await pool.query(
    `
    INSERT INTO daily_packages(day, tz, record_count, body_json, day_hash, prev_day_hash, chain_hash, updated_at)
    VALUES ($1::date, $2, $3, $4::jsonb, $5, $6, $7, now())
    ON CONFLICT (day)
    DO UPDATE SET
      tz = EXCLUDED.tz,
      record_count = EXCLUDED.record_count,
      body_json = EXCLUDED.body_json,
      day_hash = EXCLUDED.day_hash,
      prev_day_hash = EXCLUDED.prev_day_hash,
      chain_hash = EXCLUDED.chain_hash,
      updated_at = now()
    `,
    [dayYmd, tz, rows.length, JSON.stringify(body), day_hash, prev_day_hash, chain_hash]
  );

  return { day: dayYmd, tz, record_count: rows.length, day_hash, prev_day_hash, chain_hash };
}

async function verifyDailyPackage(dayYmd) {
  if (!dbEnabled) throw new Error("db disabled");
  if (!isYmd(dayYmd)) throw new Error("bad day format");

  const r = await qRows(`SELECT * FROM daily_packages WHERE day = $1::date`, [dayYmd]);
  if (!r.length) return { ok: false, reason: "not_found" };

  const pkg = r[0];
  const canonical = stableStringify(pkg.body_json);
  const computed_day_hash = sha256Hex(canonical);

  const prev = await qRows(`SELECT chain_hash FROM daily_packages WHERE day < $1::date ORDER BY day DESC LIMIT 1`, [dayYmd]);
  const prev_chain_hash = prev.length ? prev[0].chain_hash : "GENESIS";
  const computed_chain_hash = sha256Hex(prev_chain_hash + "\n" + computed_day_hash);

  const ok = (computed_day_hash === pkg.day_hash) && (computed_chain_hash === pkg.chain_hash);
  return {
    ok,
    stored: { day_hash: pkg.day_hash, chain_hash: pkg.chain_hash },
    computed: { day_hash: computed_day_hash, chain_hash: computed_chain_hash },
  };
}

// -------------------- UI (KVKK placeholder + OTP screen) --------------------
function renderSplashForm(params, opts = {}) {
  const { error = "", marker = "", phone = "", first_name = "", last_name = "", kvkkAccepted = false } = opts;

  // simple modern UI
  const logo = `
    <div style="display:flex;justify-content:center;margin-bottom:14px;">
      <div style="width:56px;height:56px;border-radius:16px;background:#1a1a2e;display:flex;align-items:center;justify-content:center;border:1px solid #2b2b4a;">
        <div style="width:26px;height:26px;border-radius:50%;background:#9dd1ff;opacity:.9"></div>
      </div>
    </div>
  `;

  const kvkkHtml = `
    <div style="max-height:140px;overflow:auto;border:1px solid #2b2b4a;border-radius:10px;padding:10px;background:#0f0f1f;font-size:12px;opacity:.9">
      <b>KVKK Aydınlatma Metni (Placeholder)</b><br/>
      Bu metin daha sonra gerçek KVKK metni ile değiştirilecektir. Kullanıcıdan açık rıza/onay alınır.
    </div>
  `;

  // keep original meraki query string
  const qs = new URLSearchParams(params.rawQuery || {}).toString();

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Guest WiFi</title>
  <style>
    body{margin:0;background:#070711;color:#eaeaf2;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:22px;}
    .card{width:420px;max-width:100%;background:#0c0c18;border:1px solid #23233a;border-radius:18px;padding:18px 16px;box-shadow:0 14px 50px rgba(0,0,0,.45)}
    h1{font-size:18px;margin:0 0 10px 0;text-align:center}
    .sub{font-size:12px;opacity:.75;text-align:center;margin-bottom:14px}
    label{display:block;font-size:12px;opacity:.85;margin:10px 0 6px}
    input{width:100%;box-sizing:border-box;background:#0f0f1f;border:1px solid #2b2b4a;border-radius:10px;padding:10px;color:#eaeaf2;outline:none}
    input:focus{border-color:#6aa8ff}
    .row{display:flex;gap:10px}
    .row > div{flex:1}
    .err{background:#2a1020;border:1px solid #5a2340;color:#ffb7d0;padding:10px;border-radius:10px;font-size:12px;margin:10px 0}
    .btn{width:100%;margin-top:12px;background:#6aa8ff;border:none;border-radius:12px;padding:12px;color:#06101f;font-weight:700;cursor:pointer}
    .btn:hover{filter:brightness(1.05)}
    .muted{font-size:11px;opacity:.7;margin-top:10px;text-align:center}
    .chk{display:flex;gap:8px;align-items:flex-start;margin-top:10px}
    .chk input{width:auto;margin-top:2px}
    .codebox{display:flex;gap:8px;align-items:center}
    .codebox input{flex:1}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      ${logo}
      <h1>Misafir Wi-Fi Girişi</h1>
      <div class="sub">Devam etmek için bilgilerinizi girin ve doğrulayın.</div>

      ${error ? `<div class="err">${error}</div>` : ""}

      <form method="POST" action="/otp/start?${qs}">
        <div class="row">
          <div>
            <label>Ad</label>
            <input name="first_name" value="${escapeHtml(first_name)}" required />
          </div>
          <div>
            <label>Soyad</label>
            <input name="last_name" value="${escapeHtml(last_name)}" required />
          </div>
        </div>

        <label>Cep Telefonu</label>
        <input name="phone" placeholder="05xx..." value="${escapeHtml(phone)}" required />

        ${kvkkHtml}
        <div class="chk">
          <input type="checkbox" name="kvkk_accepted" value="true" ${kvkkAccepted ? "checked" : ""} required />
          <div style="font-size:12px;opacity:.9">KVKK metnini okudum, anladım ve onaylıyorum.</div>
        </div>

        <button class="btn" type="submit">Kod Göster</button>
        <div class="muted">OTP ekran üzerinde gösterilir (SMS kapalı).</div>
      </form>

      ${marker ? `
        <hr style="border:0;border-top:1px solid #23233a;margin:14px 0"/>
        <form method="POST" action="/otp/verify?${qs}">
          <input type="hidden" name="marker" value="${escapeHtml(marker)}"/>
          <div class="codebox">
            <div style="flex:1">
              <label>Kod</label>
              <input name="otp" placeholder="6 haneli kod" inputmode="numeric" required />
            </div>
          </div>
          <button class="btn" type="submit">Bağlan</button>
        </form>
      ` : ""}
      <div class="muted">KVKK Version: ${escapeHtml(KVKK_VERSION)}</div>
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// -------------------- Routes --------------------

// Health
app.get("/health", (req, res) => res.status(200).send("ok"));

// Splash landing
app.get("/", async (req, res) => {
  const params = parseMerakiParams(req);
  params.rawQuery = req.query || {};

  console.log("SPLASH_OPEN", {
    hasBaseGrant: params.hasBaseGrant,
    hasContinue: params.hasContinue,
    hasClientMac: params.hasClientMac,
    mode: OTP_MODE,
  });

  await logDb("SPLASH_OPEN", {
    client_mac: params.client_mac,
    client_ip: params.client_ip || getReqPublicIp(req),
    ssid: params.ssid,
    ap_name: params.ap_name,
    base_grant_url: params.base_grant_url,
    continue_url: params.continue_url,
    kvkk_version: KVKK_VERSION,
    meta: { query: params.rawQuery, ua: req.headers["user-agent"] || null },
  });

  return res.status(200).send(renderSplashForm(params, { kvkkAccepted: false }));
});

// Start OTP (screen mode shows OTP in server log only; UI asks user to enter it)
app.post("/otp/start", async (req, res) => {
  const params = parseMerakiParams(req);
  params.rawQuery = req.query || {};

  const first_name = safeText(req.body.first_name, 64);
  const last_name = safeText(req.body.last_name, 64);
  const phone = normalizePhone(req.body.phone);
  const kvkk_accepted = (req.body.kvkk_accepted === "true" || req.body.kvkk_accepted === true);

  if (!params.client_mac) {
    return res.status(400).send(renderSplashForm(params, { error: "client_mac eksik (Meraki parametresi).", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }

  if (!kvkk_accepted) {
    return res.status(400).send(renderSplashForm(params, { error: "KVKK onayı gerekli.", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }

  if (!redisEnabled) {
    return res.status(503).send(renderSplashForm(params, { error: "Redis bağlı değil (OTP store yok).", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }

  const mac = normalizeMac(params.client_mac);
  if (await isLocked(mac)) {
    await logDb("LOCKED", { client_mac: mac, phone, first_name, last_name, kvkk_accepted, kvkk_version: KVKK_VERSION, meta: { reason: "lock" } });
    return res.status(429).send(renderSplashForm(params, { error: "Çok fazla hatalı deneme. Bir süre sonra tekrar deneyin.", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }

  if (!(await rateLimitByMac(mac))) {
    return res.status(429).send(renderSplashForm(params, { error: "Çok hızlı deneme (MAC rate limit).", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }
  if (!(await rateLimitByPhone(phone))) {
    return res.status(429).send(renderSplashForm(params, { error: "Çok hızlı deneme (Telefon rate limit).", first_name, last_name, phone, kvkkAccepted: kvkk_accepted }));
  }

  const { marker, otp } = await otpCreate({
    phone,
    client_mac: mac,
    meta: {
      first_name,
      last_name,
      client_ip: params.client_ip || getReqPublicIp(req),
      base_grant_url: params.base_grant_url,
      continue_url: params.continue_url,
      gateway_id: params.gateway_id,
      node_id: params.node_id,
      node_mac: params.node_mac,
      ssid: params.ssid,
      ap_name: params.ap_name,
      kvkk_accepted: true,
      kvkk_version: KVKK_VERSION,
    },
  });

  console.log("OTP_CREATED", { marker, last4: phone.slice(-4), client_mac: mac });

  await logDb("OTP_CREATED", {
    first_name, last_name, phone,
    client_mac: mac,
    client_ip: params.client_ip || getReqPublicIp(req),
    ssid: params.ssid,
    ap_name: params.ap_name,
    base_grant_url: params.base_grant_url,
    continue_url: params.continue_url,
    marker,
    kvkk_accepted: true,
    kvkk_version: KVKK_VERSION,
    meta: { mode: OTP_MODE },
  });

  // Screen mode: show OTP in server logs only (you can choose to show on UI; currently NOT showing for security)
  console.log("OTP_SCREEN_CODE", { marker, otp });

  // Render verify form (marker included)
  return res.status(200).send(renderSplashForm(params, {
    marker,
    phone,
    first_name,
    last_name,
    kvkkAccepted: true,
  }));
});

// Verify OTP
app.post("/otp/verify", async (req, res) => {
  const params = parseMerakiParams(req);
  params.rawQuery = req.query || {};

  const marker = safeText(req.body.marker, 64);
  const otp = safeText(req.body.otp, 16);

  if (!redisEnabled) {
    return res.status(503).send("redis not ready");
  }
  if (!marker || !otp) {
    return res.status(400).send("missing marker/otp");
  }

  const d = await otpGet(marker);
  if (!d) {
    await logDb("OTP_EXPIRED", {
      marker,
      client_mac: params.client_mac || null,
      client_ip: params.client_ip || getReqPublicIp(req),
      kvkk_version: KVKK_VERSION,
      meta: { reason: "not_found" },
    });
    return res.status(400).send(renderSplashForm(params, { error: "Kod süresi dolmuş. Tekrar deneyin." }));
  }

  const mac = normalizeMac(d.client_mac || params.client_mac || "");
  if (await isLocked(mac)) {
    return res.status(429).send(renderSplashForm(params, { error: "Hesap kilitli. Bir süre sonra tekrar deneyin." }));
  }

  if (String(d.otp) !== String(otp)) {
    const bumped = await otpBumpWrong(marker);
    const wrong = bumped ? (bumped.wrong || 0) : 1;

    await logDb("OTP_WRONG", {
      marker,
      phone: d.phone,
      client_mac: mac,
      client_ip: (d.meta && d.meta.client_ip) ? d.meta.client_ip : (params.client_ip || getReqPublicIp(req)),
      kvkk_version: KVKK_VERSION,
      meta: { wrong },
    });

    if (wrong >= MAX_WRONG_ATTEMPTS) {
      await lockMac(mac, "too_many_wrong");
      await logDb("LOCK_SET", { client_mac: mac, phone: d.phone, marker, kvkk_version: KVKK_VERSION, meta: { wrong } });
      return res.status(429).send(renderSplashForm(params, { error: "Çok fazla hatalı deneme. Kilitlendi." }));
    }

    return res.status(400).send(renderSplashForm(params, { error: "Kod yanlış.", marker }));
  }

  await otpConsume(marker);

  console.log("OTP_VERIFY_OK", { marker, client_mac: mac });

  await logDb("OTP_VERIFIED", {
    marker,
    first_name: d.meta?.first_name || null,
    last_name: d.meta?.last_name || null,
    phone: d.phone,
    client_mac: mac,
    client_ip: d.meta?.client_ip || params.client_ip || getReqPublicIp(req),
    ssid: d.meta?.ssid || params.ssid,
    ap_name: d.meta?.ap_name || params.ap_name,
    base_grant_url: d.meta?.base_grant_url || params.base_grant_url,
    continue_url: d.meta?.continue_url || params.continue_url,
    kvkk_accepted: true,
    kvkk_version: d.meta?.kvkk_version || KVKK_VERSION,
    meta: { mode: OTP_MODE },
  });

  // Build grant redirect URL
  const merakiParams = {
    ...params,
    base_grant_url: d.meta?.base_grant_url || params.base_grant_url,
    continue_url: d.meta?.continue_url || params.continue_url,
    gateway_id: d.meta?.gateway_id || params.gateway_id,
    node_id: d.meta?.node_id || params.node_id,
    client_ip: d.meta?.client_ip || params.client_ip,
    client_mac: d.meta?.client_mac || params.client_mac,
    node_mac: d.meta?.node_mac || params.node_mac,
  };

  const redirectUrl = buildGrantClientRedirect(merakiParams);

  console.log("GRANT_CLIENT_REDIRECT:", redirectUrl);

  await logDb("GRANT_REDIRECT", {
    marker,
    phone: d.phone,
    client_mac: mac,
    client_ip: d.meta?.client_ip || params.client_ip || getReqPublicIp(req),
    base_grant_url: merakiParams.base_grant_url,
    continue_url: merakiParams.continue_url,
    kvkk_version: d.meta?.kvkk_version || KVKK_VERSION,
    meta: { redirect: redirectUrl },
  });

  if (!redirectUrl) {
    return res.status(400).send("missing base_grant_url");
  }

  // Redirect client browser to Meraki grant endpoint
  return res.redirect(302, redirectUrl);
});

// -------------------- Admin: Logs --------------------
app.get("/admin/logs", requireAdmin, async (req, res) => {
  try {
    if (!dbEnabled) return res.status(503).send("db not configured");

    const limit = Math.min(parseInt(req.query.limit || "200", 10), 1000);
    const rows = await qRows(`
      SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
      FROM access_logs
      ORDER BY id DESC
      LIMIT $1
    `, [limit]);

    const html = `<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Logs</title>
<style>
body{font-family:system-ui;background:#0b0b12;color:#eaeaf2;margin:24px}
a{color:#9dd1ff}
table{width:100%;border-collapse:collapse;background:#111124;border:1px solid #23233a;border-radius:12px;overflow:hidden}
th,td{padding:9px 10px;border-bottom:1px solid #23233a;font-size:13px}
th{background:#15152c;text-align:left}
tr:hover td{background:#141428}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.btn{display:inline-block;padding:6px 10px;border:1px solid #2b2b4a;border-radius:8px;text-decoration:none}
</style>
</head>
<body>
<div class="top">
  <h2 style="margin:0">/admin/logs</h2>
  <div style="display:flex;gap:8px">
    <a class="btn" href="/admin/daily">Daily</a>
    <a class="btn" href="/admin/logs?limit=${limit}">Refresh</a>
  </div>
</div>
<table>
<thead><tr>
<th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>marker</th><th>kvkk</th>
</tr></thead>
<tbody>
${rows.map(r => `
<tr>
<td>${r.id}</td>
<td>${escapeHtml(String(r.created_at))}</td>
<td>${escapeHtml(r.event)}</td>
<td>${escapeHtml((r.first_name||"") + " " + (r.last_name||""))}</td>
<td>${escapeHtml(r.phone||"")}</td>
<td>${escapeHtml(r.client_mac||"")}</td>
<td>${escapeHtml(r.client_ip||"")}</td>
<td>${escapeHtml(r.marker||"")}</td>
<td>${escapeHtml(r.kvkk_version||"")}</td>
</tr>
`).join("")}
</tbody>
</table>
</body></html>`;
    return res.status(200).send(html);
  } catch (e) {
    console.error("ADMIN_LOGS_ERR", e);
    return res.status(500).send("admin logs error");
  }
});

// -------------------- Admin: Daily (5651) --------------------
app.get("/admin/daily", requireAdmin, async (req, res) => {
  try {
    if (!dbEnabled) return res.status(503).send("db not configured");

    const rows = await qRows(`
      SELECT day, tz, record_count, day_hash, chain_hash, prev_day_hash, created_at, updated_at, signed_at
      FROM daily_packages
      ORDER BY day DESC
      LIMIT 60
    `);

    const html = `<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>5651 Daily Packages</title>
<style>
body{font-family:system-ui;background:#0b0b12;color:#eaeaf2;margin:24px}
a{color:#9dd1ff}
table{width:100%;border-collapse:collapse;background:#111124;border:1px solid #23233a;border-radius:12px;overflow:hidden}
th,td{padding:9px 10px;border-bottom:1px solid #23233a;font-size:13px}
th{background:#15152c;text-align:left}
tr:hover td{background:#141428}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;gap:12px}
.btn{display:inline-block;padding:6px 10px;border:1px solid #2b2b4a;border-radius:8px;text-decoration:none;background:transparent;color:#eaeaf2}
input{padding:8px 10px;border-radius:8px;border:1px solid #2b2b4a;background:#0f0f1f;color:#eaeaf2}
.card{background:#111124;border:1px solid #23233a;border-radius:12px;padding:10px}
.small{font-size:12px;opacity:.75}
</style></head>
<body>
<div class="top">
  <div>
    <h2 style="margin:0 0 4px 0;">/admin/daily</h2>
    <div class="small">Günlük paket: canonical JSON → day_hash → chain_hash (GENESIS zinciri). İmzalama placeholder.</div>
  </div>
  <div class="card">
    <form method="GET" action="/admin/daily/build" style="display:flex;gap:8px;align-items:center;margin:0">
      <input name="day" placeholder="YYYY-MM-DD" />
      <button class="btn" type="submit">Build/Update</button>
      <a class="btn" href="/admin/logs">Logs</a>
    </form>
  </div>
</div>

<table>
<thead><tr>
<th>day</th><th>count</th><th>day_hash</th><th>chain_hash</th><th>signed</th><th>actions</th>
</tr></thead>
<tbody>
${rows.map(x => `
<tr>
<td>${String(x.day).slice(0,10)}</td>
<td>${x.record_count}</td>
<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(x.day_hash)}</td>
<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(x.chain_hash)}</td>
<td>${x.signed_at ? "yes" : "no"}</td>
<td>
  <a class="btn" href="/admin/daily/${String(x.day).slice(0,10)}/export.json">export</a>
  <a class="btn" href="/admin/daily/${String(x.day).slice(0,10)}/verify">verify</a>
</td>
</tr>
`).join("")}
</tbody>
</table>
</body></html>`;

    return res.status(200).send(html);
  } catch (e) {
    console.error("ADMIN_DAILY_ERR", e);
    return res.status(500).send("admin daily error");
  }
});

app.get("/admin/daily/build", requireAdmin, async (req, res) => {
  try {
    if (!dbEnabled) return res.status(503).send("db not configured");
    const day = String(req.query.day || "").trim();
    if (!isYmd(day)) return res.status(400).send("day must be YYYY-MM-DD");
    const out = await buildDailyPackage(day, TZ);
    return res.status(200).send(`<pre>${escapeHtml(JSON.stringify(out, null, 2))}</pre><p><a href="/admin/daily">Back</a></p>`);
  } catch (e) {
    console.error("ADMIN_DAILY_BUILD_ERR", e);
    return res.status(500).send("daily build error");
  }
});

app.get("/admin/daily/:day/export.json", requireAdmin, async (req, res) => {
  try {
    if (!dbEnabled) return res.status(503).send("db not configured");
    const day = String(req.params.day || "").trim();
    if (!isYmd(day)) return res.status(400).send("bad day");

    const r = await qRows(`SELECT body_json, day_hash, chain_hash, created_at, updated_at, signed_at, signature_type, signature FROM daily_packages WHERE day=$1::date`, [day]);
    if (!r.length) return res.status(404).send("not found");

    const row = r[0];
    const payload = {
      day,
      meta: {
        day_hash: row.day_hash,
        chain_hash: row.chain_hash,
        created_at: row.created_at,
        updated_at: row.updated_at,
        signed_at: row.signed_at,
        signature_type: row.signature_type,
        signature: row.signature,
      },
      body: row.body_json,
    };

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="5651_${day}.json"`);
    return res.status(200).send(JSON.stringify(payload, null, 2));
  } catch (e) {
    console.error("ADMIN_DAILY_EXPORT_ERR", e);
    return res.status(500).send("export error");
  }
});

app.get("/admin/daily/:day/verify", requireAdmin, async (req, res) => {
  try {
    if (!dbEnabled) return res.status(503).send("db not configured");
    const day = String(req.params.day || "").trim();
    if (!isYmd(day)) return res.status(400).send("bad day");

    const out = await verifyDailyPackage(day);
    return res.status(200).send(`<h3>Verify ${escapeHtml(day)}</h3><pre>${escapeHtml(JSON.stringify(out, null, 2))}</pre><p><a href="/admin/daily">Back</a></p>`);
  } catch (e) {
    console.error("ADMIN_DAILY_VERIFY_ERR", e);
    return res.status(500).send("verify error");
  }
});

// -------------------- Start --------------------
async function main() {
  try {
    await initRedis();
    await initDb();
  } catch (e) {
    console.error("INIT_ERROR", e);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

main();
