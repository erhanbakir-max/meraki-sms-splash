import express from "express";
import crypto from "crypto";
import { Pool } from "pg";
import Redis from "ioredis";

// =========================
// ENV
// =========================
const PORT = Number(process.env.PORT || 8080);
const TZ = process.env.TZ || "Europe/Istanbul";

const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms daha sonra)
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180);

const RL_MAC_SECONDS = Number(process.env.RL_MAC_SECONDS || 30);
const RL_PHONE_SECONDS = Number(process.env.RL_PHONE_SECONDS || 60);

const MAX_WRONG_ATTEMPTS = Number(process.env.MAX_WRONG_ATTEMPTS || 5);
const LOCK_SECONDS = Number(process.env.LOCK_SECONDS || 600);

const KVKK_VERSION = process.env.KVKK_VERSION || "2026-02-12-placeholder";

const ADMIN_USER = process.env.ADMIN_USER || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";

const DAILY_HMAC_KEY = process.env.DAILY_HMAC_KEY || ""; // 5651 imza için önerilir (zorunlu değil ama önerilir)

// Railway Postgres genelde DATABASE_URL verir
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.PG_URL || "";

// Redis
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "";

// =========================
// Helpers
// =========================
function nowIso() {
  return new Date().toISOString();
}

function safeStr(v) {
  if (v === undefined || v === null) return "";
  return String(v);
}

function sanitizePhoneTR(raw) {
  // Beklenen: 5XXXXXXXXX (10 hane, 0 yok, +90 yok)
  const digits = safeStr(raw).replace(/\D/g, "");
  if (digits.length === 10 && digits.startsWith("5")) return digits;
  // 0 ile geldiyse 0'ı at (05xxxxxxxxx)
  if (digits.length === 11 && digits.startsWith("05")) return digits.slice(1);
  // +90 ile geldiyse
  if (digits.length === 12 && digits.startsWith("90") && digits.slice(2).startsWith("5")) return digits.slice(2);
  return ""; // invalid
}

function maskLast4(s) {
  const v = safeStr(s);
  if (!v) return null;
  return v.length >= 4 ? v.slice(-4) : v;
}

function randMarker() {
  // 6 haneli marker (log takip)
  return String(Math.floor(100000 + Math.random() * 900000));
}

function randOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function hmacHex(key, s) {
  return crypto.createHmac("sha256", key).update(s).digest("hex");
}

function basicAuthMiddleware(req, res, next) {
  // Eğer admin creds yoksa admin ekranını kapat
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(403).send("Admin disabled (ADMIN_USER / ADMIN_PASS not set).");
  }

  const hdr = req.headers["authorization"] || "";
  if (!hdr.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const b64 = hdr.slice(6).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  const idx = decoded.indexOf(":");
  const u = idx >= 0 ? decoded.slice(0, idx) : decoded;
  const p = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (u !== ADMIN_USER || p !== ADMIN_PASS) {
    res.setHeader("WWW-Authenticate", 'Basic realm="admin"');
    return res.status(401).send("Auth required");
  }
  next();
}

// =========================
// Redis
// =========================
let redis = null;

async function initRedis() {
  if (!REDIS_URL) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing). Running WITHOUT persistent store.");
    return null;
  }
  try {
    const r = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      lazyConnect: true
    });
    await r.connect();
    console.log("REDIS: connected");
    return r;
  } catch (e) {
    console.log("REDIS: failed to connect, running WITHOUT store. err=", e?.message || e);
    return null;
  }
}

async function rGet(key) {
  if (!redis) return null;
  return await redis.get(key);
}
async function rSet(key, val, ttlSec) {
  if (!redis) return;
  if (ttlSec) await redis.set(key, val, "EX", ttlSec);
  else await redis.set(key, val);
}
async function rDel(key) {
  if (!redis) return;
  await redis.del(key);
}
async function rIncrWithTTL(key, ttlSec) {
  if (!redis) return 1;
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, ttlSec);
  return n;
}

// =========================
// Postgres
// =========================
let pool = null;

async function initDb() {
  if (!DATABASE_URL) {
    console.log("DATABASE: not configured (DATABASE_URL missing). Running WITHOUT DB logs.");
    return null;
  }
  const p = new Pool({
    connectionString: DATABASE_URL,
    max: 5,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 10_000,
  });
  // test
  await p.query("SELECT 1;");
  console.log("DATABASE: connected");
  return p;
}

async function q(sql, params = []) {
  if (!pool) return { rows: [] };
  return await pool.query(sql, params);
}

async function ensureSchema() {
  if (!pool) return;

  // access_logs (5651)
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
      grant_url TEXT,
      marker TEXT,
      phone TEXT,
      full_name TEXT,
      kvkk_version TEXT,
      user_agent TEXT,
      accept_language TEXT,
      tz TEXT,
      meta JSONB
    );
  `);

  // Bazı ortamda eski tabloyla gelmiş olabilir -> missing kolonları ekle
  const addCols = [
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS continue_url TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS grant_url TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS user_agent TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS accept_language TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS tz TEXT;`,
  ];
  for (const s of addCols) {
    try { await q(s); } catch {}
  }

  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs(client_ip);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_logs_event ON access_logs(event);`);

  // daily chain (hash + hmac + zincir)
  await q(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day DATE PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      record_count INT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      prev_sha256 TEXT,
      hmac_sha256 TEXT,
      payload_json JSONB,
      payload_text TEXT
    );
  `);

  console.log("DATABASE: table ready");
}

async function dbLog(event, ctx = {}) {
  if (!pool) return;

  const {
    client_mac = "",
    client_ip = "",
    ssid = "",
    ap_name = "",
    base_grant_url = "",
    continue_url = "",
    grant_url = "",
    marker = "",
    phone = "",
    full_name = "",
    kvkk_version = KVKK_VERSION,
    user_agent = "",
    accept_language = "",
    tz = TZ,
    meta = {},
  } = ctx;

  try {
    await q(
      `INSERT INTO access_logs(event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, grant_url, marker, phone, full_name, kvkk_version, user_agent, accept_language, tz, meta)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)`,
      [
        event,
        safeStr(client_mac) || null,
        safeStr(client_ip) || null,
        safeStr(ssid) || null,
        safeStr(ap_name) || null,
        safeStr(base_grant_url) || null,
        safeStr(continue_url) || null,
        safeStr(grant_url) || null,
        safeStr(marker) || null,
        safeStr(phone) || null,
        safeStr(full_name) || null,
        safeStr(kvkk_version) || null,
        safeStr(user_agent) || null,
        safeStr(accept_language) || null,
        safeStr(tz) || null,
        JSON.stringify(meta || {}),
      ]
    );
  } catch (e) {
    console.log("DB LOG ERROR:", e?.message || e);
  }
}

// =========================
// OTP Store
// =========================
function otpKey(marker) { return `otp:${marker}`; }
function lockMacKey(mac) { return `lock:mac:${mac}`; }
function lockPhoneKey(ph) { return `lock:ph:${ph}`; }
function rlMacKey(mac) { return `rl:mac:${mac}`; }
function rlPhoneKey(ph) { return `rl:ph:${ph}`; }
function wrongKey(marker) { return `wrong:${marker}`; }

async function isLocked(mac, phone) {
  const m = mac ? await rGet(lockMacKey(mac)) : null;
  const p = phone ? await rGet(lockPhoneKey(phone)) : null;
  return Boolean(m || p);
}

async function bumpWrong(marker, mac, phone) {
  const n = await rIncrWithTTL(wrongKey(marker), LOCK_SECONDS);
  if (n >= MAX_WRONG_ATTEMPTS) {
    if (mac) await rSet(lockMacKey(mac), "1", LOCK_SECONDS);
    if (phone) await rSet(lockPhoneKey(phone), "1", LOCK_SECONDS);
  }
  return n;
}

// =========================
// UI (minimal, hızlı)
// =========================
function pageHtml(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1220; color:#e7eefc; margin:0}
  .wrap{max-width:560px;margin:0 auto;padding:22px}
  .card{background:#121a2b;border:1px solid rgba(255,255,255,.08); border-radius:16px; padding:18px; box-shadow:0 10px 30px rgba(0,0,0,.35)}
  h1{font-size:18px;margin:0 0 10px 0}
  .muted{opacity:.75;font-size:12px}
  label{display:block;font-size:12px;opacity:.9;margin:12px 0 6px}
  input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.10);background:#0b1220;color:#e7eefc;outline:none}
  input:focus{border-color:rgba(120,170,255,.55)}
  button{width:100%;margin-top:14px;padding:12px 14px;border:0;border-radius:12px;background:#3b82f6;color:white;font-weight:700;cursor:pointer}
  button:hover{filter:brightness(1.05)}
  .row{display:flex;gap:12px}
  .row>div{flex:1}
  .ok{padding:12px;border-radius:12px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35)}
  .warn{padding:12px;border-radius:12px;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35)}
  .err{padding:12px;border-radius:12px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35)}
  a{color:#93c5fd}
  code{background:rgba(255,255,255,.06); padding:2px 6px; border-radius:8px}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{border-bottom:1px solid rgba(255,255,255,.08);padding:8px 6px;text-align:left;font-size:12px}
  th{opacity:.8}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    ${body}
  </div>
  <div class="muted" style="margin-top:10px">TZ: ${TZ} • KVKK: ${KVKK_VERSION}</div>
</div>
</body>
</html>`;
}

function kvkkPlaceholderHtml() {
  return `<div class="muted" style="margin-top:8px">
    <strong>KVKK Aydınlatma Metni (placeholder)</strong><br/>
    Bu alan daha sonra gerçek KVKK metni ile değiştirilecektir.
  </div>`;
}

// =========================
// Meraki param parse
// =========================
function getMerakiCtx(req) {
  const q = req.query || {};
  // Meraki standart paramları:
  // base_grant_url, continue_url, user_continue_url, client_mac, client_ip, gateway_id, node_id, node_mac, ssid_name
  const base_grant_url = safeStr(q.base_grant_url || q.baseGrantUrl || "");
  const continue_url = safeStr(q.continue_url || q.user_continue_url || q.userContinueUrl || "");
  const client_mac = safeStr(q.client_mac || q.clientMac || "");
  const client_ip = safeStr(q.client_ip || q.clientIp || "");
  const gateway_id = safeStr(q.gateway_id || "");
  const node_id = safeStr(q.node_id || "");
  const node_mac = safeStr(q.node_mac || "");
  const ssid = safeStr(q.ssid_name || q.ssid || "");
  const ap_name = safeStr(q.ap_name || q.ap || "");

  const user_agent = safeStr(req.headers["user-agent"] || "");
  const accept_language = safeStr(req.headers["accept-language"] || "");

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
    user_agent,
    accept_language,
  };
}

// =========================
// Daily canonical export (5651 bütünlük)
// =========================
function canonicalizeDaily(records, dayISO, prevSha) {
  // records: rows from access_logs ordered
  // Canonical TEXT: stable, deterministic
  // Format:
  // DAY=YYYY-MM-DD
  // PREV_SHA=...
  // COUNT=n
  // then each line:
  // ts|event|client_mac|client_ip|phone|full_name|ssid|ap_name|base_grant_url|continue_url|grant_url|kvkk_version|ua|lang|tz|marker|meta_sha
  const lines = [];
  lines.push(`DAY=${dayISO}`);
  lines.push(`PREV_SHA=${prevSha || ""}`);
  lines.push(`COUNT=${records.length}`);

  for (const r of records) {
    const metaStr = r.meta ? JSON.stringify(r.meta) : "";
    const metaSha = sha256Hex(metaStr);
    const line = [
      new Date(r.created_at).toISOString(),
      safeStr(r.event),
      safeStr(r.client_mac),
      safeStr(r.client_ip),
      safeStr(r.phone),
      safeStr(r.full_name),
      safeStr(r.ssid),
      safeStr(r.ap_name),
      safeStr(r.base_grant_url),
      safeStr(r.continue_url),
      safeStr(r.grant_url),
      safeStr(r.kvkk_version),
      safeStr(r.user_agent),
      safeStr(r.accept_language),
      safeStr(r.tz),
      safeStr(r.marker),
      metaSha
    ].join("|");
    lines.push(line);
  }

  const payloadText = lines.join("\n");
  const payloadSha = sha256Hex(payloadText);

  return { payloadText, payloadSha };
}

async function getPrevDailySha(dayISO) {
  // prev day
  const d = new Date(dayISO + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() - 1);
  const prevISO = d.toISOString().slice(0, 10);
  const prev = await q(`SELECT payload_sha256 FROM daily_chains WHERE day = $1`, [prevISO]);
  return prev.rows?.[0]?.payload_sha256 || "";
}

async function buildDaily(dayISO) {
  if (!pool) throw new Error("DB not configured");

  const prevSha = await getPrevDailySha(dayISO);
  const rows = await q(
    `SELECT created_at, event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, grant_url, marker, phone, full_name, kvkk_version, user_agent, accept_language, tz, meta
     FROM access_logs
     WHERE (created_at AT TIME ZONE 'UTC')::date = $1::date
     ORDER BY created_at ASC, id ASC`,
    [dayISO]
  );

  const records = rows.rows || [];
  const { payloadText, payloadSha } = canonicalizeDaily(records, dayISO, prevSha);
  const sig = DAILY_HMAC_KEY ? hmacHex(DAILY_HMAC_KEY, payloadText) : null;

  const payloadJson = {
    day: dayISO,
    prev_sha256: prevSha || null,
    record_count: records.length,
    payload_sha256: payloadSha,
    hmac_sha256: sig,
  };

  await q(
    `INSERT INTO daily_chains(day, record_count, payload_sha256, prev_sha256, hmac_sha256, payload_json, payload_text)
     VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)
     ON CONFLICT(day) DO UPDATE SET
       record_count=EXCLUDED.record_count,
       payload_sha256=EXCLUDED.payload_sha256,
       prev_sha256=EXCLUDED.prev_sha256,
       hmac_sha256=EXCLUDED.hmac_sha256,
       payload_json=EXCLUDED.payload_json,
       payload_text=EXCLUDED.payload_text`,
    [dayISO, records.length, payloadSha, prevSha || null, sig, JSON.stringify(payloadJson), payloadText]
  );

  return payloadJson;
}

async function verifyDaily(dayISO) {
  if (!pool) throw new Error("DB not configured");

  const d = await q(`SELECT day, record_count, payload_sha256, prev_sha256, hmac_sha256, payload_text FROM daily_chains WHERE day=$1`, [dayISO]);
  if (!d.rows.length) {
    return { ok: false, reason: "No daily record for that day. Build first." };
  }
  const row = d.rows[0];

  const prevSha = await getPrevDailySha(dayISO);
  const rows = await q(
    `SELECT created_at, event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, grant_url, marker, phone, full_name, kvkk_version, user_agent, accept_language, tz, meta
     FROM access_logs
     WHERE (created_at AT TIME ZONE 'UTC')::date = $1::date
     ORDER BY created_at ASC, id ASC`,
    [dayISO]
  );
  const records = rows.rows || [];
  const { payloadText, payloadSha } = canonicalizeDaily(records, dayISO, prevSha);

  const okSha = payloadSha === row.payload_sha256;
  let okHmac = true;
  if (DAILY_HMAC_KEY && row.hmac_sha256) {
    const sig = hmacHex(DAILY_HMAC_KEY, payloadText);
    okHmac = sig === row.hmac_sha256;
  }

  return {
    ok: okSha && okHmac,
    ok_sha256: okSha,
    ok_hmac: okHmac,
    expected_sha256: row.payload_sha256,
    computed_sha256: payloadSha,
    expected_prev_sha256: row.prev_sha256 || "",
    computed_prev_sha256: prevSha || "",
    record_count_db: row.record_count,
    record_count_now: records.length,
  };
}

// =========================
// App
// =========================
const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "256kb" }));

// Health
app.get("/health", (req, res) => res.json({ ok: true, ts: nowIso() }));

// Splash GET
app.get("/", async (req, res) => {
  const meraki = getMerakiCtx(req);
  const mode = safeStr(req.query.mode || OTP_MODE || "screen");

  console.log("SPLASH_OPEN", {
    hasBaseGrant: Boolean(meraki.base_grant_url),
    hasContinue: Boolean(meraki.continue_url),
    hasClientMac: Boolean(meraki.client_mac),
    mode
  });

  await dbLog("SPLASH_OPEN", {
    ...meraki,
    tz: TZ,
    meta: {
      gateway_id: meraki.gateway_id,
      node_id: meraki.node_id,
      node_mac: meraki.node_mac,
      mode
    }
  });

  const body = `
    <h1>Misafir İnternet Erişimi</h1>
    <div class="muted">Lütfen bilgilerinizi girin ve KVKK onayını verin.</div>

    ${kvkkPlaceholderHtml()}

    <form method="POST" action="/otp/start">
      <label>Ad Soyad</label>
      <input name="full_name" autocomplete="name" required placeholder="Ad Soyad"/>

      <label>Cep Telefonu (5XXXXXXXXX)</label>
      <input name="phone" inputmode="numeric" autocomplete="tel" required placeholder="5XXXXXXXXX"/>

      <label style="display:flex;gap:8px;align-items:flex-start;margin-top:14px">
        <input type="checkbox" name="kvkk_ok" value="1" required style="width:18px;height:18px;margin-top:2px"/>
        <span style="font-size:12px;opacity:.9">KVKK metnini okudum, anladım ve onaylıyorum.</span>
      </label>

      <input type="hidden" name="base_grant_url" value="${encodeURIComponent(meraki.base_grant_url)}"/>
      <input type="hidden" name="continue_url" value="${encodeURIComponent(meraki.continue_url)}"/>
      <input type="hidden" name="client_mac" value="${encodeURIComponent(meraki.client_mac)}"/>
      <input type="hidden" name="client_ip" value="${encodeURIComponent(meraki.client_ip)}"/>
      <input type="hidden" name="ssid" value="${encodeURIComponent(meraki.ssid)}"/>
      <input type="hidden" name="ap_name" value="${encodeURIComponent(meraki.ap_name)}"/>
      <input type="hidden" name="gateway_id" value="${encodeURIComponent(meraki.gateway_id)}"/>
      <input type="hidden" name="node_id" value="${encodeURIComponent(meraki.node_id)}"/>
      <input type="hidden" name="node_mac" value="${encodeURIComponent(meraki.node_mac)}"/>
      <input type="hidden" name="mode" value="${encodeURIComponent(mode)}"/>

      <button type="submit">Devam Et</button>
    </form>
  `;

  res.status(200).send(pageHtml("Guest WiFi", body));
});

// OTP Start
app.post("/otp/start", async (req, res) => {
  const full_name = safeStr(req.body.full_name).trim();
  const phone = sanitizePhoneTR(req.body.phone);
  const kvkk_ok = safeStr(req.body.kvkk_ok) === "1";

  const meraki = {
    base_grant_url: decodeURIComponent(safeStr(req.body.base_grant_url || "")),
    continue_url: decodeURIComponent(safeStr(req.body.continue_url || "")),
    client_mac: decodeURIComponent(safeStr(req.body.client_mac || "")),
    client_ip: decodeURIComponent(safeStr(req.body.client_ip || "")),
    ssid: decodeURIComponent(safeStr(req.body.ssid || "")),
    ap_name: decodeURIComponent(safeStr(req.body.ap_name || "")),
    gateway_id: decodeURIComponent(safeStr(req.body.gateway_id || "")),
    node_id: decodeURIComponent(safeStr(req.body.node_id || "")),
    node_mac: decodeURIComponent(safeStr(req.body.node_mac || "")),
  };

  const mode = safeStr(req.body.mode || OTP_MODE || "screen").toLowerCase();

  if (!full_name || !phone || !kvkk_ok) {
    await dbLog("OTP_START_REJECTED", {
      ...meraki,
      phone,
      full_name,
      meta: { reason: "missing_fields_or_invalid_phone", kvkk_ok, mode }
    });
    return res.status(400).send(pageHtml("Hata", `<div class="err">Bilgiler eksik veya telefon formatı hatalı. Telefon <code>5XXXXXXXXX</code> olmalı.</div>`));
  }

  // lock/rate
  if (await isLocked(meraki.client_mac, phone)) {
    await dbLog("OTP_LOCKED", { ...meraki, phone, full_name, meta: { mode } });
    return res.status(429).send(pageHtml("Kilit", `<div class="err">Çok fazla deneme yapıldı. Lütfen daha sonra tekrar deneyin.</div>`));
  }

  if (redis) {
    const macCount = meraki.client_mac ? await rIncrWithTTL(rlMacKey(meraki.client_mac), RL_MAC_SECONDS) : 0;
    const phCount = await rIncrWithTTL(rlPhoneKey(phone), RL_PHONE_SECONDS);

    if ((meraki.client_mac && macCount > 3) || phCount > 3) {
      await dbLog("OTP_RATE_LIMIT", { ...meraki, phone, full_name, meta: { macCount, phCount, mode } });
      return res.status(429).send(pageHtml("Yavaş", `<div class="warn">Çok hızlı deneme yapıyorsun. Lütfen ${RL_PHONE_SECONDS} sn sonra tekrar dene.</div>`));
    }
  }

  const marker = randMarker();
  const otp = randOtp();

  const store = {
    marker,
    otp,
    created_at: nowIso(),
    phone,
    full_name,
    kvkk_version: KVKK_VERSION,
    tz: TZ,
    meraki,
    ua: safeStr(req.headers["user-agent"] || ""),
    lang: safeStr(req.headers["accept-language"] || "")
  };

  await rSet(otpKey(marker), JSON.stringify(store), OTP_TTL_SECONDS);

  console.log("OTP_CREATED", { marker, last4: maskLast4(phone), client_mac: meraki.client_mac });

  await dbLog("OTP_CREATED", {
    ...meraki,
    marker,
    phone,
    full_name,
    user_agent: store.ua,
    accept_language: store.lang,
    tz: TZ,
    meta: { mode }
  });

  // screen mode: OTP'yi ekranda göster
  if (mode === "screen") {
    console.log("OTP_SCREEN_CODE", { marker, otp });

    await dbLog("OTP_SCREEN_SHOWN", {
      ...meraki,
      marker,
      phone,
      full_name,
      meta: { mode }
    });

    const body = `
      <h1>Doğrulama Kodu</h1>
      <div class="ok">Kodunuz: <code style="font-size:18px">${otp}</code></div>
      <div class="muted" style="margin-top:10px">Kod ${OTP_TTL_SECONDS} saniye geçerlidir.</div>

      <form method="POST" action="/otp/verify">
        <label>OTP Kodu</label>
        <input name="otp" inputmode="numeric" required placeholder="6 haneli kod"/>
        <input type="hidden" name="marker" value="${marker}"/>
        <button type="submit">Bağlan</button>
      </form>
    `;
    return res.status(200).send(pageHtml("OTP", body));
  }

  // sms mode (şimdilik kapalı/placeholder)
  await dbLog("OTP_SMS_SKIPPED", {
    ...meraki,
    marker,
    phone,
    full_name,
    meta: { reason: "OTP_MODE=sms not implemented yet" }
  });
  return res.status(501).send(pageHtml("SMS", `<div class="warn">SMS modu henüz devrede değil. <code>OTP_MODE=screen</code> kullan.</div>`));
});

// OTP Verify
app.post("/otp/verify", async (req, res) => {
  const marker = safeStr(req.body.marker).trim();
  const otpIn = safeStr(req.body.otp).replace(/\D/g, "");

  const raw = await rGet(otpKey(marker));
  if (!raw) {
    await dbLog("OTP_VERIFY_FAIL", { marker, meta: { reason: "expired_or_missing" } });
    return res.status(400).send(pageHtml("Hata", `<div class="err">Kod süresi dolmuş olabilir. Lütfen tekrar deneyin.</div><a href="/">Başa dön</a>`));
  }

  let st = null;
  try { st = JSON.parse(raw); } catch { st = null; }
  if (!st || !st.otp) {
    await dbLog("OTP_VERIFY_FAIL", { marker, meta: { reason: "store_corrupt" } });
    return res.status(400).send(pageHtml("Hata", `<div class="err">Doğrulama verisi bozuk. Lütfen tekrar deneyin.</div><a href="/">Başa dön</a>`));
  }

  const meraki = st.meraki || {};
  const phone = st.phone || "";
  const full_name = st.full_name || "";

  if (await isLocked(meraki.client_mac, phone)) {
    await dbLog("OTP_LOCKED", { ...meraki, marker, phone, full_name });
    return res.status(429).send(pageHtml("Kilit", `<div class="err">Çok fazla deneme yapıldı. Lütfen daha sonra tekrar deneyin.</div>`));
  }

  if (otpIn !== st.otp) {
    const wrong = await bumpWrong(marker, meraki.client_mac, phone);

    await dbLog("OTP_VERIFY_FAIL", {
      ...meraki,
      marker,
      phone,
      full_name,
      meta: { reason: "wrong_otp", wrong_attempts: wrong }
    });

    return res.status(401).send(pageHtml("Hata", `<div class="err">Kod yanlış. Tekrar deneyin.</div>`));
  }

  // OK
  await rDel(otpKey(marker));

  console.log("OTP_VERIFY_OK", { marker, client_mac: meraki.client_mac });

  await dbLog("OTP_VERIFY_OK", {
    ...meraki,
    marker,
    phone,
    full_name,
    user_agent: st.ua || "",
    accept_language: st.lang || "",
    tz: TZ,
    meta: {}
  });

  // Grant redirect: Meraki’ye “izin ver”
  // base_grant_url yoksa grant yapamayız -> kullanıcı OK görür ama internet açılmaz
  if (!meraki.base_grant_url) {
    await dbLog("GRANT_MISSING_BASE_URL", { ...meraki, marker, phone, full_name, meta: { reason: "base_grant_url_missing" } });
    return res.status(200).send(pageHtml("OK", `
      <h1>OK</h1>
      <div class="warn">Doğrulama başarılı fakat Meraki parametreleri eksik: <code>base_grant_url</code> yok. (Genelde PC’nin captive portal’ı doğru açmamasından olur.)</div>
    `));
  }

  // continue_url yoksa default ver (Android/Windows connectivity check vs.)
  const cont = meraki.continue_url || "http://connectivitycheck.gstatic.com/generate_204";

  // Meraki grant linki
  // Not: bazı ortamlarda base_grant_url zaten query taşır; biz append güvenli yapalım
  const u = new URL(meraki.base_grant_url);
  u.searchParams.set("continue_url", cont);
  // duration: 3600 (1 saat) istersen env’den yapılır
  u.searchParams.set("duration", "3600");

  const grantUrl = u.toString();
  console.log("GRANT_CLIENT_REDIRECT:", grantUrl);

  await dbLog("GRANT_CLIENT_REDIRECT", {
    ...meraki,
    grant_url: grantUrl,
    marker,
    phone,
    full_name,
    user_agent: st.ua || "",
    accept_language: st.lang || "",
    tz: TZ,
    meta: { duration: 3600 }
  });

  return res.redirect(302, grantUrl);
});

// =========================
// ADMIN UI (5651)
// =========================
app.get("/admin", basicAuthMiddleware, async (req, res) => {
  const body = `
    <h1>Admin</h1>
    <div class="muted">5651 log ve günlük imza/zincir</div>
    <ul>
      <li><a href="/admin/5651">5651 Log Ekranı</a></li>
      <li><a href="/admin/daily">Günlük İmza/Zincir</a></li>
    </ul>
  `;
  res.send(pageHtml("Admin", body));
});

app.get("/admin/5651", basicAuthMiddleware, async (req, res) => {
  const hours = Number(req.query.hours || 24);
  const phone = sanitizePhoneTR(req.query.phone || "");
  const mac = safeStr(req.query.mac || "").toLowerCase();
  const ip = safeStr(req.query.ip || "");
  const event = safeStr(req.query.event || "");

  let where = `WHERE created_at >= NOW() - ($1::int || ' hours')::interval`;
  const params = [hours];

  if (phone) { params.push(phone); where += ` AND phone = $${params.length}`; }
  if (mac) { params.push(mac); where += ` AND lower(client_mac) = $${params.length}`; }
  if (ip) { params.push(ip); where += ` AND client_ip = $${params.length}`; }
  if (event) { params.push(event); where += ` AND event = $${params.length}`; }

  const rows = await q(
    `SELECT created_at, event, client_mac, client_ip, phone, full_name, ssid, ap_name, marker
     FROM access_logs
     ${where}
     ORDER BY created_at DESC
     LIMIT 200`,
    params
  );

  const tr = (rows.rows || []).map(r => `
    <tr>
      <td>${new Date(r.created_at).toISOString()}</td>
      <td>${safeStr(r.event)}</td>
      <td>${safeStr(r.phone)}</td>
      <td>${safeStr(r.full_name)}</td>
      <td>${safeStr(r.client_mac)}</td>
      <td>${safeStr(r.client_ip)}</td>
      <td>${safeStr(r.ssid)}</td>
      <td>${safeStr(r.ap_name)}</td>
      <td>${safeStr(r.marker)}</td>
    </tr>
  `).join("");

  const body = `
    <h1>5651 Loglar</h1>
    <div class="muted">Son kayıtlar (max 200). Filtreleyebilirsin.</div>

    <form method="GET" action="/admin/5651">
      <div class="row">
        <div>
          <label>Son kaç saat?</label>
          <input name="hours" value="${hours}" placeholder="24"/>
        </div>
        <div>
          <label>Telefon (5XXXXXXXXX)</label>
          <input name="phone" value="${phone || ""}" placeholder="5XXXXXXXXX"/>
        </div>
      </div>

      <div class="row">
        <div>
          <label>MAC</label>
          <input name="mac" value="${mac}" placeholder="aa:bb:cc:dd:ee:ff"/>
        </div>
        <div>
          <label>IP</label>
          <input name="ip" value="${ip}" placeholder="10.x.x.x"/>
        </div>
      </div>

      <label>Event</label>
      <input name="event" value="${event}" placeholder="GRANT_CLIENT_REDIRECT"/>

      <button type="submit">Filtrele</button>
    </form>

    <div style="margin-top:14px" class="muted">
      Export: <a href="/admin/daily/export?day=${new Date().toISOString().slice(0,10)}">Bugün TXT</a> •
      <a href="/admin/daily/export.json?day=${new Date().toISOString().slice(0,10)}">Bugün JSON</a>
    </div>

    <table>
      <thead>
        <tr>
          <th>Zaman</th><th>Event</th><th>Telefon</th><th>Ad Soyad</th><th>MAC</th><th>IP</th><th>SSID</th><th>AP</th><th>Marker</th>
        </tr>
      </thead>
      <tbody>${tr || `<tr><td colspan="9" class="muted">Kayıt yok</td></tr>`}</tbody>
    </table>
  `;
  res.send(pageHtml("5651", body));
});

// Daily UI
app.get("/admin/daily", basicAuthMiddleware, async (req, res) => {
  const day = safeStr(req.query.day || new Date().toISOString().slice(0, 10));

  const existing = await q(`SELECT day, record_count, payload_sha256, prev_sha256, hmac_sha256, created_at FROM daily_chains WHERE day=$1`, [day]);
  const row = existing.rows[0];

  const body = `
    <h1>Günlük İmza/Zincir</h1>
    <div class="muted">5651 için günlük paket hash + (opsiyonel) HMAC imza</div>

    <form method="GET" action="/admin/daily">
      <label>Gün (YYYY-MM-DD)</label>
      <input name="day" value="${day}" />
      <button type="submit">Göster</button>
    </form>

    <div class="row" style="margin-top:10px">
      <div><a href="/admin/daily/build?day=${day}">Build</a></div>
      <div><a href="/admin/daily/verify?day=${day}">Verify</a></div>
      <div><a href="/admin/daily/export?day=${day}">Export TXT</a></div>
      <div><a href="/admin/daily/export.json?day=${day}">Export JSON</a></div>
    </div>

    <div style="margin-top:12px">
      ${row ? `
        <div class="ok">
          <div><strong>Day:</strong> ${row.day}</div>
          <div><strong>Records:</strong> ${row.record_count}</div>
          <div><strong>SHA256:</strong> <code>${row.payload_sha256}</code></div>
          <div><strong>Prev:</strong> <code>${row.prev_sha256 || ""}</code></div>
          <div><strong>HMAC:</strong> <code>${row.hmac_sha256 || ""}</code></div>
          <div class="muted">Created: ${new Date(row.created_at).toISOString()}</div>
        </div>
      ` : `<div class="warn">Bu gün için günlük paket yok. Build yap.</div>`}
    </div>
  `;
  res.send(pageHtml("Daily", body));
});

app.get("/admin/daily/build", basicAuthMiddleware, async (req, res) => {
  const day = safeStr(req.query.day || new Date().toISOString().slice(0, 10));
  try {
    const out = await buildDaily(day);
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get("/admin/daily/verify", basicAuthMiddleware, async (req, res) => {
  const day = safeStr(req.query.day || new Date().toISOString().slice(0, 10));
  try {
    const out = await verifyDaily(day);
    res.json(out);
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get("/admin/daily/export", basicAuthMiddleware, async (req, res) => {
  const day = safeStr(req.query.day || new Date().toISOString().slice(0, 10));
  const d = await q(`SELECT payload_text FROM daily_chains WHERE day=$1`, [day]);
  if (!d.rows.length || !d.rows[0].payload_text) {
    return res.status(404).send("No payload_text. Build first: /admin/daily/build?day=YYYY-MM-DD");
  }
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="5651-${day}.txt"`);
  res.send(d.rows[0].payload_text);
});

app.get("/admin/daily/export.json", basicAuthMiddleware, async (req, res) => {
  const day = safeStr(req.query.day || new Date().toISOString().slice(0, 10));
  const d = await q(`SELECT payload_json FROM daily_chains WHERE day=$1`, [day]);
  if (!d.rows.length || !d.rows[0].payload_json) {
    return res.status(404).json({ ok: false, error: "No payload_json. Build first." });
  }
  res.json(d.rows[0].payload_json);
});

// =========================
// Boot
// =========================
(async () => {
  console.log("ENV:", {
    OTP_MODE,
    OTP_TTL_SECONDS,
    RL_MAC_SECONDS,
    RL_PHONE_SECONDS,
    MAX_WRONG_ATTEMPTS,
    LOCK_SECONDS,
    KVKK_VERSION,
    TZ,
    DB_SET: Boolean(DATABASE_URL),
    REDIS_SET: Boolean(REDIS_URL),
    ADMIN_USER_SET: Boolean(ADMIN_USER),
    ADMIN_PASS_SET: Boolean(ADMIN_PASS),
    DAILY_HMAC_SET: Boolean(DAILY_HMAC_KEY),
  });

  // init
  redis = await initRedis();
  pool = await initDb();
  if (pool) await ensureSchema();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
