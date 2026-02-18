"use strict";

/**
 * server.js
 * - CommonJS
 * - No basic-auth dependency
 * - Redis optional
 * - Postgres required
 * - Meraki splash OTP (screen/sms)
 * - Admin logs + Daily 5651 (hash/chain/HMAC) + ZIP export
 */

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const archiver = require("archiver");

let Redis = null;
try {
  Redis = require("ioredis");
} catch (_) {
  // ok
}

let smsService = null;
try {
  smsService = require("./smsService");
} catch (_) {
  // optional
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: true, limit: "200kb" }));
app.use(express.json({ limit: "200kb" }));

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || "8080", 10);
const TZ = process.env.TZ || "Europe/Istanbul";

const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || "180", 10);

const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || "30", 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || "60", 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || "600", 10);

const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const DATABASE_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || "";

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || "";
const DAILY_HMAC_SET = !!DAILY_HMAC_SECRET;

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
  DAILY_HMAC_SET
});

// -------------------- Utils --------------------
function nowIso() {
  return new Date().toISOString();
}
function safeText(x) {
  if (x === null || x === undefined) return "";
  return String(x);
}
function escapeHtml(s) {
  return safeText(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function randDigits(n) {
  let out = "";
  while (out.length < n) out += Math.floor(Math.random() * 10);
  return out.slice(0, n);
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}
function hmacHex(secret, msg) {
  return crypto.createHmac("sha256").update(String(msg), "utf8").digest("hex");
}
function constantTimeEq(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}
function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    ""
  );
}
function requestId(req) {
  return (
    safeText(req.headers["x-request-id"]) ||
    safeText(req.headers["cf-ray"]) ||
    sha256Hex(nowIso() + "|" + Math.random())
  );
}
function normalizePhone(raw) {
  let s = safeText(raw).trim();
  if (!s) return "";
  s = s.replace(/[^\d+]/g, "");
  if (s.startsWith("0") && s.length === 11) s = "+9" + s; // +90...
  if (s.startsWith("90") && !s.startsWith("+")) s = "+" + s;
  if (s.startsWith("5") && s.length === 10) s = "+90" + s;
  return s;
}
function merakiParam(req, key) {
  return safeText(req.query[key] ?? req.body?.[key] ?? "");
}
function pickBaseGrantUrl(req) {
  let u =
    merakiParam(req, "base_grant_url") ||
    merakiParam(req, "baseGrantUrl") ||
    merakiParam(req, "grant_url") ||
    "";
  if (!u) return "";
  try {
    if (u.includes("%3A") || u.includes("%2F")) u = decodeURIComponent(u);
  } catch (_) {}
  return u;
}
function pickContinueUrl(req) {
  let u = merakiParam(req, "continue_url") || merakiParam(req, "continueUrl") || "";
  if (!u) return "";
  try {
    if (u.includes("%3A") || u.includes("%2F")) u = decodeURIComponent(u);
  } catch (_) {}
  return u;
}
function pickClientMac(req) {
  let m = merakiParam(req, "client_mac") || merakiParam(req, "clientMac") || "";
  return m.trim().toLowerCase();
}
function pickNodeMac(req) {
  let m = merakiParam(req, "node_mac") || merakiParam(req, "nodeMac") || "";
  return m.trim().toLowerCase();
}
function pickClientIpMeraki(req) {
  let ip = merakiParam(req, "client_ip") || "";
  return ip.trim();
}

// -------------------- KV (Redis optional) --------------------
const mem = {
  kv: new Map(),
  get(key) {
    const it = this.kv.get(key);
    if (!it) return null;
    if (it.exp && Date.now() > it.exp) {
      this.kv.delete(key);
      return null;
    }
    return it.value;
  },
  set(key, value, ttlSec) {
    const exp = ttlSec ? Date.now() + ttlSec * 1000 : null;
    this.kv.set(key, { value, exp });
  },
  del(key) {
    this.kv.delete(key);
  },
  incr(key, ttlSec) {
    const v = parseInt(this.get(key) || "0", 10) + 1;
    this.set(key, String(v), ttlSec);
    return v;
  }
};

let redis = null;
if (REDIS_URL && Redis) {
  try {
    redis = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  } catch (e) {
    console.log("REDIS init fail -> memory fallback:", e.message);
    redis = null;
  }
}
async function kvGet(key) {
  if (!redis) return mem.get(key);
  try {
    return await redis.get(key);
  } catch (_) {
    return mem.get(key);
  }
}
async function kvSet(key, val, ttlSec) {
  if (!redis) return mem.set(key, val, ttlSec);
  try {
    if (ttlSec) await redis.set(key, val, "EX", ttlSec);
    else await redis.set(key, val);
  } catch (_) {
    mem.set(key, val, ttlSec);
  }
}
async function kvDel(key) {
  if (!redis) return mem.del(key);
  try {
    await redis.del(key);
  } catch (_) {
    mem.del(key);
  }
}
async function kvIncr(key, ttlSec) {
  if (!redis) return mem.incr(key, ttlSec);
  try {
    const v = await redis.incr(key);
    if (ttlSec) await redis.expire(key, ttlSec);
    return v;
  } catch (_) {
    return mem.incr(key, ttlSec);
  }
}

// -------------------- DB --------------------
if (!DATABASE_URL) console.error("DATABASE_URL missing!");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("sslmode=require") ? { rejectUnauthorized: false } : undefined
});

async function q(sql, params) {
  return pool.query(sql, params);
}

async function ensureSchema() {
  await q(`SELECT 1`, []);
  console.log("DATABASE: connected");

  await q(
    `
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      kvkk_accepted BOOLEAN,
      kvkk_version TEXT,
      client_mac TEXT,
      client_ip TEXT,
      ssid TEXT,
      ap_name TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      public_ip TEXT,
      user_agent TEXT,
      accept_language TEXT,
      request_id TEXT,
      meta JSONB
    );
    `,
    []
  );

  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`, []);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`, []);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`, []);

  await q(
    `
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE NOT NULL,
      tz TEXT NOT NULL,
      record_count INT NOT NULL DEFAULT 0,
      package_json JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(day, tz)
    );
    `,
    []
  );

  await q(
    `
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day DATE NOT NULL,
      tz TEXT NOT NULL,
      record_count INT NOT NULL DEFAULT 0,
      day_hash TEXT,
      algo TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(day, tz)
    );
    `,
    []
  );

  await q(
    `
    CREATE TABLE IF NOT EXISTS daily_chains (
      day DATE NOT NULL,
      tz TEXT NOT NULL,
      prev_chain_hash TEXT,
      chain_hash TEXT,
      signature_hmac TEXT,
      signer TEXT,
      algo TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(day, tz)
    );
    `,
    []
  );

  console.log("DATABASE: table ready");
}

async function dbLog(event, fields) {
  const f = fields || {};
  try {
    await q(
      `
      INSERT INTO access_logs(
        event, first_name, last_name, phone, kvkk_accepted, kvkk_version,
        client_mac, client_ip, ssid, ap_name,
        base_grant_url, continue_url, public_ip,
        user_agent, accept_language, request_id, meta
      )
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      `,
      [
        event,
        f.first_name || null,
        f.last_name || null,
        f.phone || null,
        f.kvkk_accepted === undefined ? null : !!f.kvkk_accepted,
        f.kvkk_version || KVKK_VERSION,
        f.client_mac || null,
        f.client_ip || null,
        f.ssid || null,
        f.ap_name || null,
        f.base_grant_url || null,
        f.continue_url || null,
        f.public_ip || null,
        f.user_agent || null,
        f.accept_language || null,
        f.request_id || null,
        f.meta ? JSON.stringify(f.meta) : null
      ]
    );
  } catch (e) {
    console.log("DB LOG ERROR:", e.message);
  }
}

function rowCanonical(r) {
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
    meta: r.meta || null
  };
  return JSON.stringify(obj);
}

async function getRowsForDay(day, tz) {
  const sql = `
    SELECT *
    FROM access_logs
    WHERE ((created_at AT TIME ZONE $2)::date) = ($1::date)
    ORDER BY id ASC
  `;
  const r = await q(sql, [day, tz]);
  return r.rows || [];
}

function csvEscape(v) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildDailyCsv(rows) {
  const cols = [
    "id","created_at_iso","event","first_name","last_name","phone",
    "client_mac","client_ip","ssid","ap_name","kvkk_version",
    "base_grant_url","continue_url","public_ip","user_agent",
    "accept_language","request_id","meta_json"
  ];
  const lines = [cols.join(",")];
  for (const r of rows) {
    const created_at_iso = new Date(r.created_at).toISOString();
    const meta_json = r.meta ? JSON.stringify(r.meta) : "";
    const values = [
      r.id,
      created_at_iso,
      r.event || "",
      r.first_name || "",
      r.last_name || "",
      r.phone || "",
      r.client_mac || "",
      r.client_ip || "",
      r.ssid || "",
      r.ap_name || "",
      r.kvkk_version || "",
      r.base_grant_url || "",
      r.continue_url || "",
      r.public_ip || "",
      r.user_agent || "",
      r.accept_language || "",
      r.request_id || "",
      meta_json
    ].map(csvEscape);
    lines.push(values.join(","));
  }
  return { csv: lines.join("\n") + "\n", cols };
}

async function exportDailyArtifacts(day, tz) {
  const rows = await getRowsForDay(day, tz);

  const { csv, cols } = buildDailyCsv(rows);
  const row_hashes = rows.map((r) => sha256Hex(rowCanonical(r)));
  const day_hash = sha256Hex(row_hashes.join("\n"));

  const prev = await q(
    `SELECT chain_hash FROM daily_chains WHERE day = ($1::date - interval '1 day')::date AND tz = $2 LIMIT 1`,
    [day, tz]
  );
  const prev_chain_hash = prev.rows[0] ? prev.rows[0].chain_hash : null;
  const chain_hash = sha256Hex((prev_chain_hash || "") + "|" + day_hash);
  const signature_hmac = DAILY_HMAC_SET ? hmacHex(DAILY_HMAC_SECRET, chain_hash) : null;

  const first_id = rows[0]?.id ?? null;
  const last_id = rows.length ? rows[rows.length - 1].id : null;
  const first_ts = rows[0]?.created_at ? new Date(rows[0].created_at).toISOString() : null;
  const last_ts = rows.length ? new Date(rows[rows.length - 1].created_at).toISOString() : null;

  const manifest = {
    spec: "odeon-5651-v1",
    generated_at: nowIso(),
    day,
    tz,
    record_count: rows.length,
    id_range: { first_id, last_id },
    time_range_utc: { first_ts, last_ts },
    hashing: {
      algo: "sha256",
      row_hashes: "sha256(canonical_row_json)",
      day_hash,
      prev_chain_hash,
      chain_hash
    },
    signing: {
      method: DAILY_HMAC_SET ? "HMAC-SHA256" : "none",
      signature_hmac
    },
    csv: {
      filename: `daily-${day}-${tz}.csv`,
      columns: cols,
      sha256: sha256Hex(csv)
    }
  };

  await q(
    `
    INSERT INTO daily_packages(day, tz, record_count, package_json)
    VALUES ($1::date, $2, $3, $4::jsonb)
    ON CONFLICT(day, tz)
    DO UPDATE SET record_count=EXCLUDED.record_count, package_json=EXCLUDED.package_json, created_at=now()
    `,
    [day, tz, rows.length, JSON.stringify({ manifest, row_hashes_count: row_hashes.length })]
  );

  await q(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash, algo)
    VALUES ($1::date, $2, $3, $4, 'sha256')
    ON CONFLICT(day, tz)
    DO UPDATE SET record_count=EXCLUDED.record_count, day_hash=EXCLUDED.day_hash, created_at=now(), algo='sha256'
    `,
    [day, tz, rows.length, day_hash]
  );

  await q(
    `
    INSERT INTO daily_chains(day, tz, prev_chain_hash, chain_hash, signature_hmac, signer, algo)
    VALUES ($1::date, $2, $3, $4, $5, $6, 'sha256')
    ON CONFLICT(day, tz)
    DO UPDATE SET prev_chain_hash=EXCLUDED.prev_chain_hash, chain_hash=EXCLUDED.chain_hash,
                  signature_hmac=EXCLUDED.signature_hmac, signer=EXCLUDED.signer,
                  created_at=now(), algo='sha256'
    `,
    [day, tz, prev_chain_hash, chain_hash, signature_hmac, DAILY_HMAC_SET ? "HMAC-SHA256" : null]
  );

  return { rows, csv, row_hashes, manifest, signature_hmac, day_hash, chain_hash, prev_chain_hash };
}

// -------------------- Rate limit / lockout / OTP store --------------------
function macKey(mac) {
  return "mac:" + sha256Hex(mac || "");
}
function phoneKey(p) {
  return "ph:" + sha256Hex(p || "");
}
async function rateLimitOrThrow({ client_mac, phone }) {
  const m = client_mac || "nomac";
  const p = phone || "nophone";
  const mc = await kvIncr("rl:" + macKey(m), RL_MAC_SECONDS);
  const pc = await kvIncr("rl:" + phoneKey(p), RL_PHONE_SECONDS);
  if (mc > 20 || pc > 20) throw new Error("rate_limit");
}
function lockedKey(mac) {
  return "lock:" + macKey(mac || "");
}
async function isLocked(mac) {
  const v = await kvGet(lockedKey(mac));
  return v === "1";
}
async function lock(mac) {
  await kvSet(lockedKey(mac), "1", LOCK_SECONDS);
}
function wrongKey(mac) {
  return "wrong:" + macKey(mac || "");
}
async function incrWrong(mac) {
  const n = await kvIncr(wrongKey(mac), LOCK_SECONDS);
  if (n >= MAX_WRONG_ATTEMPTS) await lock(mac);
  return n;
}
async function clearWrong(mac) {
  await kvDel(wrongKey(mac));
}
function otpKey(mac) {
  return "otp:" + macKey(mac || "");
}
async function setOtp(mac, otp) {
  await kvSet(otpKey(mac), otp, OTP_TTL_SECONDS);
}
async function getOtp(mac) {
  return await kvGet(otpKey(mac));
}
async function clearOtp(mac) {
  await kvDel(otpKey(mac));
}

// -------------------- Admin auth (no dependency) --------------------
function requireAdminAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return res.status(503).send("Admin credentials not set");

  const h = safeText(req.headers.authorization || "");
  if (!h.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const b64 = h.slice(6).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8");
  } catch (_) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Bad auth");
  }
  const idx = decoded.indexOf(":");
  const user = idx >= 0 ? decoded.slice(0, idx) : decoded;
  const pass = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (!constantTimeEq(user, ADMIN_USER) || !constantTimeEq(pass, ADMIN_PASS)) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Bad auth");
  }
  next();
}

// -------------------- Static logo --------------------
app.get("/logo.png", (req, res) => {
  const p = path.join(__dirname, "logo.png");
  if (fs.existsSync(p)) return res.sendFile(p);
  return res.status(404).send("logo not found");
});

// -------------------- UI shell (sade) --------------------
function pageShell(title, bodyHtml) {
  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${escapeHtml(title)}</title>
<style>
:root{
  --bg:#071022;
  --card:#0c1a35;
  --line:rgba(255,255,255,.10);
  --text:#eaf0ff;
  --muted:#b7c3e6;
  --brand:#2b6cff;
  --brand2:#0f4ad8;
  --shadow: 0 12px 30px rgba(0,0,0,.35);
  --r:16px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
}
*{box-sizing:border-box}
body{
  margin:0; font-family:var(--sans); color:var(--text);
  background:
    radial-gradient(900px 600px at 20% 10%, rgba(43,108,255,.25), transparent 55%),
    radial-gradient(900px 600px at 90% 20%, rgba(34,197,94,.10), transparent 55%),
    var(--bg);
  min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
}
.wrap{width:100%; max-width:720px;}
.card{border:1px solid var(--line); border-radius:var(--r); box-shadow:var(--shadow); overflow:hidden;
  background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
}
.head{display:flex; gap:14px; align-items:center; padding:18px 20px; border-bottom:1px solid var(--line); background:rgba(0,0,0,.14);}
.logo{width:44px; height:44px; border-radius:12px; background:rgba(255,255,255,.06); overflow:hidden; display:flex; align-items:center; justify-content:center;}
.logo img{width:100%; height:100%; object-fit:contain; padding:6px;}
h1{margin:0; font-size:16px}
.sub{margin:3px 0 0; color:var(--muted); font-size:13px}
.content{padding:18px 20px}
label{display:block; font-size:12px; color:var(--muted); margin:10px 0 6px}
input{
  width:100%; padding:12px 12px; border-radius:12px;
  border:1px solid var(--line); background:rgba(0,0,0,.25); color:var(--text); outline:none;
}
input:focus{border-color: rgba(43,108,255,.55); box-shadow:0 0 0 4px rgba(43,108,255,.15)}
.row{display:grid; grid-template-columns:1fr 1fr; gap:12px}
@media (max-width:640px){ .row{grid-template-columns:1fr} }
.btn{
  width:100%; margin-top:14px; padding:12px 14px; border-radius:12px;
  border:1px solid rgba(43,108,255,.55);
  background:linear-gradient(180deg,var(--brand),var(--brand2));
  color:white; font-weight:800; cursor:pointer;
}
.hr{height:1px; background:var(--line); margin:16px 0}
.muted{color:var(--muted); font-size:13px; line-height:1.4}
.tiny{color:var(--muted); font-size:12px}
.error{border:1px solid rgba(255,77,109,.35); background:rgba(255,77,109,.10); color:#ffd0d7; padding:10px 12px; border-radius:12px; margin:10px 0;}
.ok{border:1px solid rgba(34,197,94,.35); background:rgba(34,197,94,.10); color:#c9ffe0; padding:10px 12px; border-radius:12px; margin:10px 0;}
.otpBox{
  font-family:var(--mono); padding:10px 12px; border-radius:12px;
  border:1px dashed rgba(255,255,255,.18); background:rgba(0,0,0,.25);
  display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:10px;
}
.otpBox b{font-size:18px; letter-spacing:2px}
.pill{font-size:12px; color:var(--muted); border:1px solid var(--line); padding:6px 10px; border-radius:999px; background:rgba(0,0,0,.2)}
a{color:#9fb7ff}
table{width:100%; border-collapse:collapse; border:1px solid var(--line); border-radius:14px; overflow:hidden; background:rgba(0,0,0,.18)}
th,td{padding:10px; border-bottom:1px solid var(--line); font-size:13px; vertical-align:top}
th{color:var(--muted); font-weight:700; text-align:left; background:rgba(0,0,0,.22)}
tr:last-child td{border-bottom:none}
.topActions{display:flex; gap:10px; justify-content:flex-end; margin-bottom:12px; flex-wrap:wrap}
.btn2{display:inline-block; padding:9px 12px; border-radius:12px; text-decoration:none; border:1px solid var(--line); background:rgba(0,0,0,.20); color:var(--text)}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="head">
        <div class="logo"><img src="/logo.png" alt="logo" onerror="this.style.display='none'"/></div>
        <div>
          <h1>${escapeHtml(title)}</h1>
          <div class="sub">Odeon Technology • Güvenli misafir erişimi</div>
        </div>
      </div>
      <div class="content">${bodyHtml}</div>
    </div>
  </div>
</body>
</html>`;
}

function splashFormHtml({ base_grant_url, continue_url, client_mac, client_ip, error, otpScreen }) {
  const hidden = `
    <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}">
    <input type="hidden" name="continue_url" value="${escapeHtml(continue_url)}">
    <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}">
    <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}">
  `;
  const err = error ? `<div class="error">${escapeHtml(error)}</div>` : "";
  const otpBlock =
    otpScreen && OTP_MODE === "screen"
      ? `<div class="hr"></div>
         <div class="muted">OTP (Test modu):</div>
         <div class="otpBox"><b>${escapeHtml(otpScreen)}</b><span class="pill">3 dk geçerli</span></div>
         <div class="tiny" style="margin-top:8px;">Prod için <b>OTP_MODE=sms</b> kullanın.</div>`
      : "";

  return pageShell(
    "GUEST erişimi",
    `
    <div class="muted">Lütfen bilgilerinizi girin. OTP doğrulaması sonrası internete yönlendirilirsiniz.</div>
    ${err}
    <form method="POST" action="/otp/request">
      ${hidden}
      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" autocomplete="given-name" required />
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" autocomplete="family-name" required />
        </div>
      </div>

      <label>Telefon</label>
      <input name="phone" inputmode="tel" autocomplete="tel" placeholder="05xxxxxxxxx" required />

      <label>
        <input type="checkbox" name="kvkk_accepted" value="1" required />
        KVKK aydınlatma metnini okudum ve kabul ediyorum.
      </label>

      <button class="btn" type="submit">OTP Gönder</button>
      ${otpBlock}
    </form>

    <div class="hr"></div>
    <div class="tiny">KVKK versiyon: <b>${escapeHtml(KVKK_VERSION)}</b></div>
    `
  );
}

function otpVerifyHtml({ base_grant_url, continue_url, client_mac, client_ip, error }) {
  const err = error ? `<div class="error">${escapeHtml(error)}</div>` : "";
  return pageShell(
    "OTP doğrulama",
    `
    <div class="muted">Telefonunuza gelen OTP kodunu girin.</div>
    ${err}
    <form method="POST" action="/otp/verify">
      <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}">
      <input type="hidden" name="continue_url" value="${escapeHtml(continue_url)}">
      <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}">
      <input type="hidden" name="client_ip" value="${escapeHtml(client_ip)}">
      <label>OTP</label>
      <input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="6 haneli" required />
      <button class="btn" type="submit">Doğrula ve Bağlan</button>
    </form>
    `
  );
}

// -------------------- Splash entry --------------------
app.get("/", async (req, res) => {
  const base_grant_url = pickBaseGrantUrl(req);
  const continue_url = pickContinueUrl(req);
  const client_mac = pickClientMac(req);
  const client_ip = pickClientIpMeraki(req) || getClientIp(req);

  console.log("SPLASH_OPEN", {
    hasBaseGrant: !!base_grant_url,
    hasContinue: !!continue_url,
    hasClientMac: !!client_mac,
    mode: OTP_MODE
  });

  await dbLog("SPLASH_OPEN", {
    client_mac,
    client_ip,
    base_grant_url,
    continue_url,
    public_ip: getClientIp(req),
    user_agent: safeText(req.headers["user-agent"] || ""),
    accept_language: safeText(req.headers["accept-language"] || ""),
    request_id: requestId(req),
    kvkk_version: KVKK_VERSION,
    meta: {
      node_mac: pickNodeMac(req) || null,
      gateway_id: merakiParam(req, "gateway_id") || null,
      referrer: safeText(req.headers.referer || ""),
      rawQuery: req.originalUrl || req.url
    }
  });

  if (!base_grant_url) {
    return res.send(
      splashFormHtml({
        base_grant_url: "",
        continue_url,
        client_mac,
        client_ip,
        error: "Meraki base_grant_url bulunamadı. Captive Portal splash URL isteği parametreli gelmeli.",
        otpScreen: null
      })
    );
  }

  return res.send(
    splashFormHtml({
      base_grant_url,
      continue_url,
      client_mac,
      client_ip,
      error: null,
      otpScreen: null
    })
  );
});

// -------------------- OTP request --------------------
app.post("/otp/request", async (req, res) => {
  const base_grant_url = safeText(req.body.base_grant_url || "");
  const continue_url = safeText(req.body.continue_url || "");
  const client_mac = safeText(req.body.client_mac || "").toLowerCase();
  const client_ip = safeText(req.body.client_ip || "") || getClientIp(req);

  const first_name = safeText(req.body.first_name || "").trim();
  const last_name = safeText(req.body.last_name || "").trim();
  const phone = normalizePhone(req.body.phone || "");
  const kvkk_accepted = !!req.body.kvkk_accepted;

  try {
    if (!kvkk_accepted) throw new Error("KVKK onayı gerekli.");
    if (!first_name || !last_name) throw new Error("Ad/Soyad gerekli.");
    if (!phone) throw new Error("Telefon gerekli.");
    if (!client_mac) throw new Error("client_mac bulunamadı.");
    if (await isLocked(client_mac)) throw new Error("Çok fazla deneme. Lütfen sonra tekrar deneyin.");

    await rateLimitOrThrow({ client_mac, phone });

    const otp = randDigits(6);
    await setOtp(client_mac, otp);

    await dbLog("OTP_CREATED", {
      first_name,
      last_name,
      phone,
      kvkk_accepted: true,
      kvkk_version: KVKK_VERSION,
      client_mac,
      client_ip,
      base_grant_url,
      continue_url,
      public_ip: getClientIp(req),
      user_agent: safeText(req.headers["user-agent"] || ""),
      accept_language: safeText(req.headers["accept-language"] || ""),
      request_id: requestId(req),
      meta: { otp_mode: OTP_MODE, otp_ttl: OTP_TTL_SECONDS }
    });

    console.log("OTP_CREATED", { last4: phone.slice(-4), client_mac });

    if (OTP_MODE === "sms") {
      if (!smsService || typeof smsService.sendSms !== "function") {
        throw new Error("smsService.sendSms yok. smsService.js ekli olmalı.");
      }
      await smsService.sendSms(phone, `Odeon WiFi OTP: ${otp}`);
      return res.send(
        otpVerifyHtml({ base_grant_url, continue_url, client_mac, client_ip, error: null })
      );
    }

    console.log("OTP_SCREEN_CODE", { otp });
    return res.send(
      splashFormHtml({
        base_grant_url,
        continue_url,
        client_mac,
        client_ip,
        error: null,
        otpScreen: otp
      }) +
        otpVerifyHtml({
          base_grant_url,
          continue_url,
          client_mac,
          client_ip,
          error: null
        })
    );
  } catch (e) {
    return res.send(
      splashFormHtml({
        base_grant_url,
        continue_url,
        client_mac,
        client_ip,
        error: e.message || "Hata",
        otpScreen: null
      })
    );
  }
});

// -------------------- OTP verify --------------------
app.post("/otp/verify", async (req, res) => {
  const base_grant_url = safeText(req.body.base_grant_url || "");
  const continue_url = safeText(req.body.continue_url || "");
  const client_mac = safeText(req.body.client_mac || "").toLowerCase();
  const client_ip = safeText(req.body.client_ip || "") || getClientIp(req);

  const otp = safeText(req.body.otp || "").trim();

  try {
    if (!client_mac) throw new Error("client_mac bulunamadı.");
    if (await isLocked(client_mac)) throw new Error("Çok fazla deneme. Lütfen sonra tekrar deneyin.");

    const exp = await getOtp(client_mac);
    if (!exp) throw new Error("OTP süresi dolmuş. Lütfen tekrar OTP isteyin.");

    if (otp !== exp) {
      const n = await incrWrong(client_mac);
      await dbLog("OTP_WRONG", {
        client_mac,
        client_ip,
        base_grant_url,
        continue_url,
        public_ip: getClientIp(req),
        user_agent: safeText(req.headers["user-agent"] || ""),
        accept_language: safeText(req.headers["accept-language"] || ""),
        request_id: requestId(req),
        kvkk_version: KVKK_VERSION,
        meta: { wrong_count: n }
      });
      throw new Error("OTP hatalı.");
    }

    await clearWrong(client_mac);
    await clearOtp(client_mac);

    await dbLog("OTP_VERIFIED", {
      client_mac,
      client_ip,
      base_grant_url,
      continue_url,
      public_ip: getClientIp(req),
      user_agent: safeText(req.headers["user-agent"] || ""),
      accept_language: safeText(req.headers["accept-language"] || ""),
      request_id: requestId(req),
      kvkk_version: KVKK_VERSION,
      meta: { ok: true }
    });

    console.log("OTP_VERIFY_OK", { client_mac });

    if (!base_grant_url) {
      return res
        .status(400)
        .send("OTP verified but base_grant_url missing. Meraki captive portal isteği parametreli gelmeli.");
    }

    // Meraki grant redirect
    let grantUrl = base_grant_url;
    const sep = grantUrl.includes("?") ? "&" : "?";
    const cont = continue_url
      ? encodeURIComponent(continue_url)
      : encodeURIComponent("http://connectivitycheck.gstatic.com/generate_204");
    grantUrl = `${grantUrl}${sep}continue_url=${cont}`;

    await dbLog("GRANT_REDIRECT", {
      client_mac,
      client_ip,
      base_grant_url,
      continue_url,
      public_ip: getClientIp(req),
      user_agent: safeText(req.headers["user-agent"] || ""),
      accept_language: safeText(req.headers["accept-language"] || ""),
      request_id: requestId(req),
      kvkk_version: KVKK_VERSION,
      meta: { grantUrl }
    });

    return res.redirect(302, grantUrl);
  } catch (e) {
    return res.send(
      otpVerifyHtml({ base_grant_url, continue_url, client_mac, client_ip, error: e.message || "Hata" })
    );
  }
});

// -------------------- Admin: logs --------------------
app.get("/admin/logs", requireAdminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(500, parseInt(req.query.limit || "200", 10)));
  const asJson = safeText(req.query.json || "") === "1";
  const tz = safeText(req.query.tz || TZ) || TZ;

  try {
    const r = await q(
      `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, kvkk_version
       FROM access_logs
       ORDER BY id DESC
       LIMIT $1`,
      [limit]
    );

    if (asJson) return res.json(r.rows);

    const rows = r.rows || [];
    const tr = rows
      .map((x) => {
        const t = new Date(x.created_at).toLocaleString("tr-TR", { timeZone: tz });
        const name = [x.first_name, x.last_name].filter(Boolean).join(" ");
        return `<tr>
          <td>${escapeHtml(x.id)}</td>
          <td>${escapeHtml(t)}</td>
          <td>${escapeHtml(x.event)}</td>
          <td>${escapeHtml(name)}</td>
          <td>${escapeHtml(x.phone || "")}</td>
          <td>${escapeHtml(x.client_mac || "")}</td>
          <td>${escapeHtml(x.client_ip || "")}</td>
          <td>${escapeHtml(x.kvkk_version || "")}</td>
        </tr>`;
      })
      .join("");

    const body = `
      <div class="topActions">
        <a class="btn2" href="/admin/logs?limit=${limit}&tz=${encodeURIComponent(tz)}">Refresh</a>
        <a class="btn2" href="/admin/daily">Daily</a>
        <a class="btn2" href="/admin/logs?limit=${limit}&tz=${encodeURIComponent(tz)}&json=1">JSON</a>
      </div>
      <div class="tiny">limit=${limit} • tz=${escapeHtml(tz)}</div>
      <div class="hr"></div>
      <table>
        <thead>
          <tr>
            <th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>kvkk</th>
          </tr>
        </thead>
        <tbody>${tr}</tbody>
      </table>
    `;
    return res.send(pageShell("/admin/logs", body));
  } catch (e) {
    return res.status(500).send("admin logs error: " + e.message);
  }
});

// -------------------- Admin: daily --------------------
app.get("/admin/daily", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || new Date().toLocaleDateString("en-CA", { timeZone: tz }));

  const body = `
    <div class="topActions">
      <a class="btn2" href="/admin/logs">Logs</a>
      <a class="btn2" href="/admin/daily?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Refresh</a>
      <a class="btn2" href="/admin/daily/build?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Build</a>
      <a class="btn2" href="/admin/daily/verify?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Verify</a>
      <a class="btn2" href="/admin/daily/export.zip?day=${encodeURIComponent(day)}&tz=${encodeURIComponent(tz)}">Export ZIP</a>
    </div>

    <form method="GET" action="/admin/daily">
      <div class="row">
        <div>
          <label>Day (YYYY-MM-DD)</label>
          <input name="day" value="${escapeHtml(day)}"/>
        </div>
        <div>
          <label>Time Zone</label>
          <input name="tz" value="${escapeHtml(tz)}"/>
        </div>
      </div>
      <button class="btn" type="submit">Open</button>
    </form>

    <div class="hr"></div>
    <div class="muted">5651 paketi: CSV + manifest + chain hash + (opsiyonel) HMAC imza.</div>
    <div class="tiny">HMAC: <b>${DAILY_HMAC_SET ? "enabled" : "disabled (DAILY_HMAC_SECRET set et)"}</b></div>
  `;

  return res.send(pageShell("/admin/daily", body));
});

app.get("/admin/daily/build", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required");

  try {
    const { manifest } = await exportDailyArtifacts(day, tz);
    return res.json({
      ok: true,
      day,
      tz,
      record_count: manifest.record_count,
      day_hash: manifest.hashing.day_hash,
      prev_chain_hash: manifest.hashing.prev_chain_hash,
      chain_hash: manifest.hashing.chain_hash,
      signature_hmac: manifest.signing.signature_hmac
    });
  } catch (e) {
    console.log("daily build error", e);
    return res.status(500).send("daily build error: " + e.message);
  }
});

app.get("/admin/daily/verify", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required");

  try {
    const rows = await getRowsForDay(day, tz);
    const row_hashes = rows.map((r) => sha256Hex(rowCanonical(r)));
    const recomputed_day_hash = sha256Hex(row_hashes.join("\n"));

    const chainRow = await q(
      `SELECT prev_chain_hash, chain_hash, signature_hmac FROM daily_chains WHERE day=$1::date AND tz=$2 LIMIT 1`,
      [day, tz]
    );
    const prev_chain_hash = chainRow.rows[0]?.prev_chain_hash || null;
    const stored_chain = chainRow.rows[0]?.chain_hash || null;
    const stored_sig = chainRow.rows[0]?.signature_hmac || null;

    const recomputed_chain = sha256Hex((prev_chain_hash || "") + "|" + recomputed_day_hash);
    const recomputed_sig = DAILY_HMAC_SET ? hmacHex(DAILY_HMAC_SECRET, recomputed_chain) : null;

    const hashRow = await q(
      `SELECT day_hash FROM daily_hashes WHERE day=$1::date AND tz=$2 LIMIT 1`,
      [day, tz]
    );
    const stored_day_hash = hashRow.rows[0]?.day_hash || null;

    return res.json({
      ok: true,
      day,
      tz,
      record_count: rows.length,
      stored: { day_hash: stored_day_hash, chain_hash: stored_chain, signature_hmac: stored_sig },
      recomputed: { day_hash: recomputed_day_hash, chain_hash: recomputed_chain, signature_hmac: recomputed_sig },
      match: {
        day_hash: stored_day_hash ? stored_day_hash === recomputed_day_hash : null,
        chain_hash: stored_chain ? stored_chain === recomputed_chain : null,
        signature_hmac: stored_sig && recomputed_sig ? stored_sig === recomputed_sig : null
      }
    });
  } catch (e) {
    console.log("daily verify error", e);
    return res.status(500).send("daily verify error: " + e.message);
  }
});

// ✅ ZIP EXPORT (tek dosyada gerçek zip)
app.get("/admin/daily/export.zip", requireAdminAuth, async (req, res) => {
  const tz = safeText(req.query.tz || TZ) || TZ;
  const day = safeText(req.query.day || "");
  if (!day) return res.status(400).send("day required");

  try {
    const { csv, row_hashes, manifest, signature_hmac } = await exportDailyArtifacts(day, tz);

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="odeon-5651-${day}-${tz}.zip"`);

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", (err) => {
      console.error("zip error", err);
      try { res.status(500).end("zip error"); } catch (_) {}
    });

    archive.pipe(res);

    archive.append(csv, { name: `daily-${day}-${tz}.csv` });
    archive.append(JSON.stringify(manifest, null, 2) + "\n", { name: `manifest-${day}-${tz}.json` });
    archive.append((signature_hmac || "HMAC_NOT_SET") + "\n", { name: `signature-${day}-${tz}.hmac.txt` });

    // satır hash listesi (isteyen denetçi için)
    archive.append(row_hashes.join("\n") + "\n", { name: `row-hashes-${day}-${tz}.sha256.txt` });

    await archive.finalize();
  } catch (e) {
    console.log("daily export zip error", e);
    return res.status(500).send("daily export zip error: " + e.message);
  }
});

// -------------------- Health --------------------
app.get("/healthz", (req, res) => res.json({ ok: true, time: nowIso() }));

// -------------------- Start --------------------
(async () => {
  try {
    if (redis) {
      try {
        await redis.connect();
        console.log("REDIS: connected");
      } catch (e) {
        console.log("REDIS: connect fail -> memory fallback:", e.message);
        redis = null;
      }
    }
    await ensureSchema();
    app.listen(PORT, () => console.log("Server running on port", PORT));
  } catch (e) {
    console.error("Fatal startup error:", e);
    process.exit(1);
  }
})();
