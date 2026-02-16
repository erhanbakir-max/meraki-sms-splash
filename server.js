/**
 * meraki-sms-splash - server.js (single file)
 * - Splash OTP flow (screen mode supported)
 * - PostgreSQL logging
 * - Admin UI (/admin/logs)
 * - 5651 daily packaging + hash chain + HMAC signature
 *
 * ENV:
 *   PORT=8080
 *   DATABASE_URL=postgres://...
 *   REDIS_URL=redis://... (optional)
 *   TZ=Europe/Istanbul
 *   OTP_MODE=screen|sms   (default: screen)
 *   OTP_TTL_SECONDS=180
 *   RL_MAC_SECONDS=30
 *   RL_PHONE_SECONDS=60
 *   MAX_WRONG_ATTEMPTS=5
 *   LOCK_SECONDS=600
 *   KVKK_VERSION=YYYY-MM-DD-placeholder
 *   ADMIN_USER=...
 *   ADMIN_PASS=...
 *   DAILY_HMAC_SECRET=... (for signature)
 */

'use strict';

const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

let Redis = null;
try { Redis = require('ioredis'); } catch (_) { /* optional */ }

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '256kb' }));

// -------------------- ENV --------------------
const PORT = parseInt(process.env.PORT || '8080', 10);
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_CONNECTION_STRING;
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_CONNECTION_STRING;

const TZ = process.env.TZ || 'Europe/Istanbul';
const OTP_MODE = (process.env.OTP_MODE || 'screen').toLowerCase(); // screen|sms
const OTP_TTL_SECONDS = parseInt(process.env.OTP_TTL_SECONDS || '180', 10);
const RL_MAC_SECONDS = parseInt(process.env.RL_MAC_SECONDS || '30', 10);
const RL_PHONE_SECONDS = parseInt(process.env.RL_PHONE_SECONDS || process.env.RL_MSISDN_SECONDS || '60', 10);
const MAX_WRONG_ATTEMPTS = parseInt(process.env.MAX_WRONG_ATTEMPTS || '5', 10);
const LOCK_SECONDS = parseInt(process.env.LOCK_SECONDS || '600', 10);
const KVKK_VERSION = process.env.KVKK_VERSION || '2026-02-12-placeholder';

const ADMIN_USER = process.env.ADMIN_USER || '';
const ADMIN_PASS = process.env.ADMIN_PASS || '';

const DAILY_HMAC_SECRET = process.env.DAILY_HMAC_SECRET || ''; // if empty, signature will be null

console.log('ENV:', {
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

// -------------------- DB --------------------
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set. Exiting.');
  process.exit(1);
}
const pool = new Pool({ connectionString: DATABASE_URL });

async function q(text, params) {
  return pool.query(text, params);
}
async function qRows(text, params) {
  const r = await q(text, params);
  return r.rows;
}

async function ensureSchema() {
  // access_logs basic + optional columns we evolved during debug
  await q(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id bigserial PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      event text NOT NULL,
      first_name text,
      last_name text,
      phone text,
      kvkk_accepted bool,
      kvkk_version text,
      marker text,
      client_mac text,
      client_ip text,        -- TEXT (as you confirmed)
      ssid text,
      ap_name text,
      base_grant_url text,
      continue_url text,
      user_continue_url text,
      grant_url text,
      full_name text,
      public_ip text,
      user_agent text,
      accept_language text,
      extra text,
      meta jsonb NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  // daily tables for 5651 packaging
  await q(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day date NOT NULL,
      tz text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      record_count int NOT NULL,
      package jsonb NOT NULL,
      PRIMARY KEY(day, tz)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day date NOT NULL,
      tz text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      record_count int NOT NULL,
      day_hash text NOT NULL,
      signature text,
      PRIMARY KEY(day, tz)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day date NOT NULL,
      tz text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      prev_day_hash text,
      chain_hash text NOT NULL,
      PRIMARY KEY(day, tz)
    );
  `);

  console.log('DATABASE: table ready');

  // Backward-compat migrations (if table existed without columns)
  // This prevents "column does not exist" crashes.
  const cols = [
    ['continue_url', 'text'],
    ['user_continue_url', 'text'],
    ['grant_url', 'text'],
    ['full_name', 'text'],
    ['public_ip', 'text'],
    ['user_agent', 'text'],
    ['accept_language', 'text'],
    ['extra', 'text'],
    ['meta', 'jsonb'],
    ['base_grant_url', 'text'],
    ['ssid', 'text'],
    ['ap_name', 'text'],
    ['first_name', 'text'],
    ['last_name', 'text'],
    ['kvkk_accepted', 'bool'],
    ['kvkk_version', 'text'],
    ['marker', 'text'],
    ['client_mac', 'text'],
    ['client_ip', 'text'],
    ['phone', 'text'],
  ];

  for (const [name, typ] of cols) {
    try {
      await q(`ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ${name} ${typ};`);
      if (name === 'meta') {
        await q(`ALTER TABLE access_logs ALTER COLUMN meta SET DEFAULT '{}'::jsonb;`);
        await q(`UPDATE access_logs SET meta='{}'::jsonb WHERE meta IS NULL;`);
      }
    } catch (e) {
      console.warn('DB MIGRATION WARN:', name, e.message);
    }
  }
}

// -------------------- Redis / Rate limit --------------------
const redis = REDIS_URL && Redis ? new Redis(REDIS_URL, { maxRetriesPerRequest: 2 }) : null;
if (redis) {
  redis.on('connect', () => console.log('REDIS: connected'));
  redis.on('error', (e) => console.warn('REDIS: error', e.message));
} else {
  console.log('REDIS: not configured (or ioredis missing), using in-memory fallbacks');
}

const mem = new Map(); // fallback store

async function kvGet(key) {
  if (redis) return redis.get(key);
  const v = mem.get(key);
  if (!v) return null;
  if (v.expiresAt && Date.now() > v.expiresAt) { mem.delete(key); return null; }
  return v.value;
}
async function kvSet(key, value, ttlSeconds) {
  if (redis) return redis.set(key, value, 'EX', ttlSeconds);
  mem.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}
async function kvIncr(key, ttlSeconds) {
  if (redis) {
    const multi = redis.multi();
    multi.incr(key);
    multi.expire(key, ttlSeconds);
    const res = await multi.exec();
    return parseInt(res[0][1], 10);
  }
  const cur = parseInt((await kvGet(key)) || '0', 10) + 1;
  await kvSet(key, String(cur), ttlSeconds);
  return cur;
}

// -------------------- Helpers --------------------
function nowIso() {
  return new Date().toISOString();
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function hmacHex(secret, s) {
  return crypto.createHmac('sha256', secret).update(s).digest('hex');
}

function cleanPhone(p) {
  if (!p) return '';
  let x = String(p).trim();
  x = x.replace(/\s+/g, '');
  // keep + and digits only
  x = x.replace(/[^\d+]/g, '');
  return x;
}

function cleanMac(m) {
  if (!m) return '';
  return String(m).trim().toLowerCase();
}

function getClientIp(req) {
  // meraki sends client_ip in query; else use express ip
  return (req.query.client_ip || req.body.client_ip || req.ip || '').toString();
}

function getPublicIp(req) {
  // try common proxy headers; else blank
  const xff = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim();
  return xff || '';
}

function toDayStrInTZ(date = new Date(), tz = TZ) {
  // YYYY-MM-DD for a TZ using Intl
  const fmt = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
  return fmt.format(date); // "2026-02-16"
}

function fmtLocal(dtIsoOrDate, tz = TZ) {
  const d = (dtIsoOrDate instanceof Date) ? dtIsoOrDate : new Date(dtIsoOrDate);
  const fmt = new Intl.DateTimeFormat('tr-TR', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  return fmt.format(d).replace(',', '');
}

function parseBasicAuth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return null;
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const idx = raw.indexOf(':');
  if (idx < 0) return null;
  return { user: raw.slice(0, idx), pass: raw.slice(idx + 1) };
}

function requireAdmin(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(403).send('Admin credentials not set (ADMIN_USER/ADMIN_PASS).');
  }
  const creds = parseBasicAuth(req);
  if (!creds || creds.user !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Auth required');
  }
  return next();
}

// -------------------- Logging --------------------
async function logEvent(event, payload) {
  const {
    first_name, last_name, phone, kvkk_accepted, kvkk_version, marker,
    client_mac, client_ip, ssid, ap_name,
    base_grant_url, continue_url, user_continue_url, grant_url,
    full_name, public_ip, user_agent, accept_language, extra, meta
  } = payload || {};

  try {
    await q(`
      INSERT INTO access_logs(
        event, first_name, last_name, phone, kvkk_accepted, kvkk_version, marker,
        client_mac, client_ip, ssid, ap_name,
        base_grant_url, continue_url, user_continue_url, grant_url,
        full_name, public_ip, user_agent, accept_language, extra, meta
      )
      VALUES(
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,
        $12,$13,$14,$15,
        $16,$17,$18,$19,$20,$21::jsonb
      )
    `, [
      event,
      first_name || null,
      last_name || null,
      phone || null,
      (kvkk_accepted === undefined ? null : !!kvkk_accepted),
      kvkk_version || null,
      marker || null,
      client_mac || null,
      client_ip || null,
      ssid || null,
      ap_name || null,
      base_grant_url || null,
      continue_url || null,
      user_continue_url || null,
      grant_url || null,
      full_name || null,
      public_ip || null,
      user_agent || null,
      accept_language || null,
      extra || null,
      JSON.stringify(meta || {}),
    ]);
  } catch (e) {
    // do not crash on logging
    console.warn('DB LOG ERROR:', e.message);
  }
}

// -------------------- OTP --------------------
function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function genMarker() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function otpKey(mac) {
  return `otp:${mac}`;
}
async function wrongKey(mac) {
  return `wrong:${mac}`;
}
async function lockKey(mac) {
  return `lock:${mac}`;
}
async function rlKeyMac(mac) {
  return `rl:mac:${mac}`;
}
async function rlKeyPhone(phone) {
  return `rl:phone:${phone}`;
}

async function isLocked(mac) {
  const v = await kvGet(await lockKey(mac));
  return v === '1';
}

async function lock(mac) {
  await kvSet(await lockKey(mac), '1', LOCK_SECONDS);
}

async function rateLimitOrThrow({ mac, phone }) {
  const macCount = await kvIncr(await rlKeyMac(mac), RL_MAC_SECONDS);
  if (macCount > 20) throw new Error('Rate limit exceeded (MAC).');

  if (phone) {
    const phoneCount = await kvIncr(await rlKeyPhone(phone), RL_PHONE_SECONDS);
    if (phoneCount > 20) throw new Error('Rate limit exceeded (PHONE).');
  }
}

// -------------------- Splash UI --------------------
function splashHtml({ marker, client_mac, otpMode, otpScreenCode, msg }) {
  const darkCss = `
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b1020;color:#e8eefc;margin:0;padding:0}
    .wrap{max-width:820px;margin:40px auto;padding:24px}
    .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:18px}
    h1{font-size:22px;margin:0 0 12px}
    label{display:block;margin:10px 0 6px;color:#b9c7ff;font-size:13px}
    input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,0.12);background:rgba(0,0,0,0.25);color:#fff}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .btn{margin-top:14px;display:inline-block;background:#6d5efc;border:none;color:#fff;padding:10px 14px;border-radius:12px;cursor:pointer}
    .muted{color:#a9b6e6;font-size:12px;margin-top:10px}
    .otpbox{margin-top:10px;padding:12px;border-radius:12px;background:rgba(109,94,252,0.15);border:1px solid rgba(109,94,252,0.35)}
    code{font-size:18px;letter-spacing:2px}
    a{color:#9aa8ff}
  `;

  const otpBlock = (otpMode === 'screen' && otpScreenCode)
    ? `<div class="otpbox"><div class="muted">OTP (screen mode):</div><code>${otpScreenCode}</code></div>`
    : `<div class="muted">OTP SMS ile iletilecek (sms mode).</div>`;

  const info = msg ? `<div class="otpbox">${msg}</div>` : '';

  return `<!doctype html>
  <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Meraki Splash</title>
  <style>${darkCss}</style></head>
  <body><div class="wrap">
    <div class="card">
      <h1>Wi-Fi Erişimi</h1>
      <div class="muted">Marker: <b>${marker || ''}</b> · MAC: <b>${client_mac || ''}</b></div>
      ${otpBlock}
      ${info}
      <form method="POST" action="/otp/verify">
        <input type="hidden" name="marker" value="${marker || ''}">
        <input type="hidden" name="client_mac" value="${client_mac || ''}">
        <div class="row">
          <div>
            <label>Ad</label>
            <input name="first_name" autocomplete="given-name" required>
          </div>
          <div>
            <label>Soyad</label>
            <input name="last_name" autocomplete="family-name" required>
          </div>
        </div>
        <label>Telefon</label>
        <input name="phone" autocomplete="tel" placeholder="+905xxxxxxxxx" required>
        <label>OTP</label>
        <input name="otp" inputmode="numeric" placeholder="6 hane" required>
        <label style="display:flex;gap:8px;align-items:center;margin-top:10px">
          <input type="checkbox" name="kvkk_accepted" value="true" required style="width:auto">
          KVKK metnini okudum ve onaylıyorum.
        </label>
        <button class="btn" type="submit">Bağlan</button>
      </form>
      <div class="muted">KVKK_VERSION: ${KVKK_VERSION} · TZ: ${TZ}</div>
    </div>
  </div></body></html>`;
}

// -------------------- Routes --------------------
app.get('/', async (req, res) => {
  // Meraki splash open params (commonly)
  const base_grant_url = req.query.base_grant_url || '';
  const user_continue_url = req.query.user_continue_url || '';
  const continue_url = req.query.continue_url || '';
  const client_mac = cleanMac(req.query.client_mac || req.query.clientMac || '');
  const client_ip = (req.query.client_ip || '').toString();
  const ssid = (req.query.ssid || '').toString();
  const ap_name = (req.query.ap_name || '').toString();

  console.log('SPLASH_OPEN', {
    hasBaseGrant: !!base_grant_url,
    hasContinue: !!(user_continue_url || continue_url),
    hasClientMac: !!client_mac,
    mode: OTP_MODE
  });

  await logEvent('SPLASH_OPEN', {
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url,
    user_continue_url,
    kvkk_version: KVKK_VERSION,
    public_ip: getPublicIp(req),
    user_agent: (req.headers['user-agent'] || '').toString(),
    accept_language: (req.headers['accept-language'] || '').toString(),
    meta: { query: req.query || {}, mode: OTP_MODE }
  });

  if (!client_mac) {
    return res.status(400).send('client_mac missing');
  }

  // locked?
  if (await isLocked(client_mac)) {
    return res.status(429).send('Locked due to too many wrong attempts. Try later.');
  }

  // Create OTP + marker
  const otp = genOtp();
  const marker = genMarker();
  const record = {
    otp,
    marker,
    created_at: nowIso(),
    base_grant_url,
    continue_url,
    user_continue_url,
    client_ip,
    ssid,
    ap_name
  };

  try {
    await rateLimitOrThrow({ mac: client_mac, phone: null });
  } catch (e) {
    return res.status(429).send(e.message);
  }

  await kvSet(await otpKey(client_mac), JSON.stringify(record), OTP_TTL_SECONDS);

  console.log('OTP_CREATED', { marker, last4: '****', client_mac });
  await logEvent('OTP_CREATED', {
    marker,
    client_mac,
    client_ip,
    ssid,
    ap_name,
    base_grant_url,
    continue_url,
    user_continue_url,
    kvkk_version: KVKK_VERSION,
    public_ip: getPublicIp(req),
    user_agent: (req.headers['user-agent'] || '').toString(),
    accept_language: (req.headers['accept-language'] || '').toString(),
    meta: { mode: OTP_MODE }
  });

  // SCREEN mode shows OTP on page
  let otpScreenCode = null;
  if (OTP_MODE === 'screen') {
    otpScreenCode = otp;
    console.log('OTP_SCREEN_CODE', { marker, otp });
    await logEvent('OTP_SCREEN_CODE', { marker, client_mac, client_ip, kvkk_version: KVKK_VERSION, meta: { otp_shown: true } });
  } else {
    // SMS mode: call smsService.js if exists
    try {
      const smsService = require('./smsService');
      // smsService.sendOtp(phone, otp) will be called after user enters phone (or you can send here if phone is known)
      // We keep it minimal.
      await smsService.ping?.();
    } catch (_) {
      // ignore
    }
  }

  res.set('Cache-Control', 'no-store');
  return res.status(200).send(splashHtml({
    marker,
    client_mac,
    otpMode: OTP_MODE,
    otpScreenCode,
    msg: ''
  }));
});

app.post('/otp/verify', async (req, res) => {
  const client_mac = cleanMac(req.body.client_mac || '');
  const first_name = (req.body.first_name || '').toString().trim();
  const last_name = (req.body.last_name || '').toString().trim();
  const phone = cleanPhone(req.body.phone || '');
  const otp = (req.body.otp || '').toString().trim();
  const kvkk_accepted = (req.body.kvkk_accepted || '') === 'true';

  if (!client_mac) return res.status(400).send('client_mac missing');
  if (!phone) return res.status(400).send('phone missing');
  if (!otp) return res.status(400).send('otp missing');
  if (!kvkk_accepted) return res.status(400).send('kvkk missing');

  if (await isLocked(client_mac)) {
    return res.status(429).send('Locked. Try later.');
  }

  try {
    await rateLimitOrThrow({ mac: client_mac, phone });
  } catch (e) {
    return res.status(429).send(e.message);
  }

  const raw = await kvGet(await otpKey(client_mac));
  if (!raw) {
    return res.status(410).send('OTP expired. Open splash again.');
  }

  let rec;
  try { rec = JSON.parse(raw); } catch { rec = null; }
  if (!rec || !rec.otp) {
    return res.status(500).send('OTP state invalid');
  }

  if (rec.otp !== otp) {
    const wrong = await kvIncr(await wrongKey(client_mac), LOCK_SECONDS);
    await logEvent('OTP_VERIFY_FAIL', {
      marker: rec.marker,
      client_mac,
      client_ip: rec.client_ip || null,
      phone,
      first_name,
      last_name,
      full_name: `${first_name} ${last_name}`.trim(),
      kvkk_accepted: true,
      kvkk_version: KVKK_VERSION,
      meta: { wrong_count: wrong }
    });

    if (wrong >= MAX_WRONG_ATTEMPTS) {
      await lock(client_mac);
      return res.status(429).send('Too many wrong attempts. Locked.');
    }
    return res.status(401).send('Wrong OTP');
  }

  // Verified OK
  console.log('OTP_VERIFY_OK', { marker: rec.marker, client_mac });
  await logEvent('OTP_VERIFIED', {
    marker: rec.marker,
    client_mac,
    client_ip: rec.client_ip || null,
    phone,
    first_name,
    last_name,
    full_name: `${first_name} ${last_name}`.trim(),
    kvkk_accepted: true,
    kvkk_version: KVKK_VERSION,
    base_grant_url: rec.base_grant_url || null,
    continue_url: rec.continue_url || null,
    user_continue_url: rec.user_continue_url || null,
    meta: { verified_at: nowIso() }
  });

  // Build grant redirect URL (Meraki expects redirect to /grant with required params already in query)
  // We'll redirect to base_grant_url itself when available.
  const baseGrant = (rec.base_grant_url || '').toString();
  if (!baseGrant) {
    // No base_grant_url (some captures); just show success.
    return res.status(200).send(splashHtml({
      marker: rec.marker,
      client_mac,
      otpMode: OTP_MODE,
      otpScreenCode: null,
      msg: 'OTP doğrulandı. (base_grant_url yok) İnternete çıkış için Meraki tarafında base_grant_url gönderilmeli.'
    }));
  }

  // choose continue url
  const cont = (rec.user_continue_url || rec.continue_url || 'http://connectivitycheck.gstatic.com/generate_204').toString();
  const grantUrl = new URL(baseGrant);
  // Meraki: continue_url is typical, keep it if not already present
  if (!grantUrl.searchParams.get('continue_url')) {
    grantUrl.searchParams.set('continue_url', cont);
  }

  const finalGrant = grantUrl.toString();
  console.log('GRANT_CLIENT_REDIRECT:', finalGrant);

  await logEvent('GRANT_CLIENT_REDIRECT', {
    marker: rec.marker,
    client_mac,
    client_ip: rec.client_ip || null,
    phone,
    full_name: `${first_name} ${last_name}`.trim(),
    kvkk_version: KVKK_VERSION,
    grant_url: finalGrant,
    meta: { redirect: true }
  });

  // Meraki expects redirect
  res.set('Cache-Control', 'no-store');
  return res.redirect(302, finalGrant);
});

// -------------------- Admin UI --------------------
const adminCss = `
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b1020;color:#e8eefc;margin:0}
  .wrap{max-width:1200px;margin:26px auto;padding:0 16px}
  h1{margin:0 0 14px;font-size:22px}
  .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:16px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,0.08);vertical-align:top}
  th{color:#b9c7ff;font-weight:600;text-align:left}
  .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0 14px}
  input{padding:10px 10px;border-radius:12px;border:1px solid rgba(255,255,255,0.12);background:rgba(0,0,0,0.25);color:#fff}
  .btn{background:#6d5efc;color:#fff;border:none;border-radius:12px;padding:10px 12px;cursor:pointer}
  a{color:#9aa8ff;text-decoration:none}
  .muted{color:#a9b6e6;font-size:12px}
`;

function adminPage(title, bodyHtml) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title}</title><style>${adminCss}</style></head><body><div class="wrap">${bodyHtml}</div></body></html>`;
}

app.get('/admin', requireAdmin, (req, res) => {
  res.redirect('/admin/logs');
});

app.get('/admin/logs', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);
  const tz = (req.query.tz || TZ).toString();

  // If user wants JSON only:
  const wantsJson = (req.query.json === '1') || (req.headers.accept || '').includes('application/json');

  try {
    const rows = await qRows(`
      SELECT id, created_at, event, full_name, phone, client_mac, client_ip, marker, kvkk_version
      FROM access_logs
      ORDER BY id DESC
      LIMIT $1
    `, [limit]);

    if (wantsJson) {
      return res.json(rows);
    }

    const trs = rows.map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${fmtLocal(r.created_at, tz)}</td>
        <td>${(r.event || '')}</td>
        <td>${(r.full_name || '')}</td>
        <td>${(r.phone || '')}</td>
        <td>${(r.client_mac || '')}</td>
        <td>${(r.client_ip || '')}</td>
        <td>${(r.marker || '')}</td>
        <td>${(r.kvkk_version || '')}</td>
      </tr>
    `).join('');

    const body = `
      <div class="card">
        <h1>/admin/logs</h1>
        <div class="row">
          <form method="GET" action="/admin/logs" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <span class="muted">limit=${limit} · tz=${tz} ·</span>
            <a class="muted" href="/admin/logs?limit=${limit}&tz=${encodeURIComponent(tz)}&json=1">JSON</a>
            <input name="limit" value="${limit}" style="width:120px">
            <input name="tz" value="${tz}" style="width:180px">
            <button class="btn" type="submit">Refresh</button>
            <a class="btn" href="/admin/daily" style="display:inline-block;background:#2b365c">Daily</a>
          </form>
        </div>
        <table>
          <thead><tr>
            <th>id</th><th>time</th><th>event</th><th>name</th><th>phone</th><th>mac</th><th>ip</th><th>marker</th><th>kvkk</th>
          </tr></thead>
          <tbody>${trs}</tbody>
        </table>
      </div>
    `;
    return res.send(adminPage('admin logs', body));
  } catch (e) {
    console.error('admin logs error', e);
    return res.status(500).send('admin logs error: ' + e.message);
  }
});

// -------------------- 5651 Daily packaging / chain / sign --------------------
function canonicalRecord(r) {
  // Keep stable order and only key fields required for 5651 style auditing
  return {
    id: r.id,
    created_at: r.created_at,
    event: r.event,
    full_name: r.full_name || null,
    phone: r.phone || null,
    client_mac: r.client_mac || null,
    client_ip: r.client_ip || null,
    marker: r.marker || null,
    kvkk_version: r.kvkk_version || null,
    grant_url: r.grant_url || null,
    user_agent: r.user_agent || null,
    accept_language: r.accept_language || null,
    public_ip: r.public_ip || null,
  };
}

function stableStringify(obj) {
  // stable JSON stringify (sorted keys)
  const allKeys = [];
  JSON.stringify(obj, (k, v) => { allKeys.push(k); return v; });
  allKeys.sort();
  return JSON.stringify(obj, allKeys);
}

async function buildDaily(dayStr, tz = TZ) {
  // dayStr: YYYY-MM-DD in tz
  const rows = await qRows(`
    SELECT
      id, created_at, event, full_name, phone, client_mac, client_ip, marker, kvkk_version,
      grant_url, user_agent, accept_language, public_ip
    FROM access_logs
    WHERE (created_at AT TIME ZONE $2)::date = $1::date
    ORDER BY id ASC
  `, [dayStr, tz]);

  const packageObj = {
    schema: '5651-daily-v1',
    day: dayStr,
    tz,
    created_at: nowIso(),
    record_count: rows.length,
    records: rows.map(canonicalRecord),
  };

  const packageJson = stableStringify(packageObj);
  const day_hash = sha256hex(packageJson);

  // prev day hash from daily_hashes
  const prev = await qRows(`
    SELECT day_hash
    FROM daily_hashes
    WHERE day = ($1::date - interval '1 day')::date AND tz = $2
    LIMIT 1
  `, [dayStr, tz]);
  const prev_day_hash = prev[0]?.day_hash || null;

  const chain_material = stableStringify({
    day: dayStr,
    tz,
    day_hash,
    prev_day_hash,
  });
  const chain_hash = sha256hex(chain_material);

  const signature = DAILY_HMAC_SECRET ? hmacHex(DAILY_HMAC_SECRET, chain_hash) : null;

  // Upsert
  await q(`
    INSERT INTO daily_packages(day, tz, record_count, package)
    VALUES($1::date, $2, $3, $4::jsonb)
    ON CONFLICT(day, tz) DO UPDATE SET
      record_count=EXCLUDED.record_count,
      package=EXCLUDED.package,
      created_at=now()
  `, [dayStr, tz, rows.length, JSON.stringify(packageObj)]);

  await q(`
    INSERT INTO daily_hashes(day, tz, record_count, day_hash, signature)
    VALUES($1::date, $2, $3, $4, $5)
    ON CONFLICT(day, tz) DO UPDATE SET
      record_count=EXCLUDED.record_count,
      day_hash=EXCLUDED.day_hash,
      signature=EXCLUDED.signature,
      created_at=now()
  `, [dayStr, tz, rows.length, day_hash, signature]);

  await q(`
    INSERT INTO daily_chains(day, tz, prev_day_hash, chain_hash)
    VALUES($1::date, $2, $3, $4)
    ON CONFLICT(day, tz) DO UPDATE SET
      prev_day_hash=EXCLUDED.prev_day_hash,
      chain_hash=EXCLUDED.chain_hash,
      created_at=now()
  `, [dayStr, tz, prev_day_hash, chain_hash]);

  return { day: dayStr, tz, record_count: rows.length, day_hash, prev_day_hash, chain_hash, signature };
}

async function verifyDaily(dayStr, tz = TZ) {
  const p = await qRows(`SELECT package FROM daily_packages WHERE day=$1::date AND tz=$2 LIMIT 1`, [dayStr, tz]);
  const h = await qRows(`SELECT day_hash, signature, record_count FROM daily_hashes WHERE day=$1::date AND tz=$2 LIMIT 1`, [dayStr, tz]);
  const c = await qRows(`SELECT prev_day_hash, chain_hash, tz FROM daily_chains WHERE day=$1::date AND tz=$2 LIMIT 1`, [dayStr, tz]);

  if (!p[0] || !h[0] || !c[0]) {
    return { ok: false, reason: 'missing daily rows (build first?)' };
  }

  const packageJson = stableStringify(p[0].package);
  const recomputed_day_hash = sha256hex(packageJson);
  const dayHashOk = (recomputed_day_hash === h[0].day_hash);

  const chain_material = stableStringify({
    day: dayStr,
    tz,
    day_hash: h[0].day_hash,
    prev_day_hash: c[0].prev_day_hash || null,
  });
  const recomputed_chain_hash = sha256hex(chain_material);
  const chainOk = (recomputed_chain_hash === c[0].chain_hash);

  const sigOk = DAILY_HMAC_SECRET
    ? (hmacHex(DAILY_HMAC_SECRET, c[0].chain_hash) === (h[0].signature || ''))
    : null;

  return {
    ok: dayHashOk && chainOk && (sigOk === null ? true : sigOk),
    dayHashOk,
    chainOk,
    sigOk,
    recomputed_day_hash,
    recomputed_chain_hash,
    stored: {
      record_count: h[0].record_count,
      day_hash: h[0].day_hash,
      chain_hash: c[0].chain_hash,
      prev_day_hash: c[0].prev_day_hash,
      signature: h[0].signature,
      tz: c[0].tz, // NOTE: tz comes from c.tz (your case)
    }
  };
}

app.get('/admin/daily', requireAdmin, async (req, res) => {
  // show last 7 days summary
  const tz = (req.query.tz || TZ).toString();
  const today = toDayStrInTZ(new Date(), tz);

  try {
    const rows = await qRows(`
      SELECT h.day, c.tz, h.record_count, h.day_hash, c.prev_day_hash, c.chain_hash, h.signature
      FROM daily_hashes h
      JOIN daily_chains c ON c.day = h.day AND c.tz = h.tz
      WHERE h.tz = $1
      ORDER BY h.day DESC
      LIMIT 14
    `, [tz]); // IMPORTANT: c.tz is used; NO h.tz column reads except h.tz itself

    const trs = rows.map(r => `
      <tr>
        <td>${r.day}</td>
        <td>${r.record_count}</td>
        <td style="font-family:ui-monospace,Menlo,Consolas,monospace">${(r.day_hash || '').slice(0,16)}…</td>
        <td style="font-family:ui-monospace,Menlo,Consolas,monospace">${(r.chain_hash || '').slice(0,16)}…</td>
        <td>${r.signature ? 'yes' : 'no'}</td>
        <td>
          <a href="/admin/daily/build?day=${r.day}&tz=${encodeURIComponent(tz)}">build</a> ·
          <a href="/admin/daily/verify?day=${r.day}&tz=${encodeURIComponent(tz)}">verify</a> ·
          <a href="/admin/daily/package?day=${r.day}&tz=${encodeURIComponent(tz)}">package</a>
        </td>
      </tr>
    `).join('');

    const body = `
      <div class="card">
        <h1>/admin/daily</h1>
        <div class="row">
          <span class="muted">tz=${tz} · today=${today} ·</span>
          <a class="btn" href="/admin/daily/build?day=${today}&tz=${encodeURIComponent(tz)}">Build Today</a>
          <a class="btn" href="/admin/logs" style="background:#2b365c">Back to Logs</a>
        </div>
        <table>
          <thead><tr>
            <th>day</th><th>count</th><th>day_hash</th><th>chain_hash</th><th>signed</th><th>actions</th>
          </tr></thead>
          <tbody>${trs || ''}</tbody>
        </table>
        <div class="muted" style="margin-top:12px">
          DAILY_HMAC_SECRET set: <b>${DAILY_HMAC_SECRET ? 'yes' : 'no'}</b>
        </div>
      </div>
    `;
    return res.send(adminPage('admin daily', body));
  } catch (e) {
    console.error('daily page error', e);
    return res.status(500).send('daily error: ' + e.message);
  }
});

app.get('/admin/daily/build', requireAdmin, async (req, res) => {
  const tz = (req.query.tz || TZ).toString();
  const day = (req.query.day || toDayStrInTZ(new Date(), tz)).toString();

  try {
    const out = await buildDaily(day, tz);
    res.set('Cache-Control', 'no-store');
    return res.json(out);
  } catch (e) {
    console.error('daily build error', e);
    return res.status(500).send('daily build error: ' + e.message);
  }
});

app.get('/admin/daily/verify', requireAdmin, async (req, res) => {
  const tz = (req.query.tz || TZ).toString();
  const day = (req.query.day || toDayStrInTZ(new Date(), tz)).toString();

  try {
    const out = await verifyDaily(day, tz);
    res.set('Cache-Control', 'no-store');
    return res.json({ day, tz, ...out });
  } catch (e) {
    console.error('daily verify error', e);
    return res.status(500).send('daily verify error: ' + e.message);
  }
});

app.get('/admin/daily/package', requireAdmin, async (req, res) => {
  const tz = (req.query.tz || TZ).toString();
  const day = (req.query.day || toDayStrInTZ(new Date(), tz)).toString();

  try {
    const p = await qRows(`SELECT package FROM daily_packages WHERE day=$1::date AND tz=$2 LIMIT 1`, [day, tz]);
    if (!p[0]) return res.status(404).send('package not found (build first)');
    res.set('Content-Type', 'application/json; charset=utf-8');
    return res.send(JSON.stringify(p[0].package, null, 2));
  } catch (e) {
    console.error('daily package error', e);
    return res.status(500).send('daily package error: ' + e.message);
  }
});

// -------------------- Health --------------------
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// -------------------- Startup --------------------
(async () => {
  try {
    await q('SELECT 1');
    console.log('DATABASE: connected');
    await ensureSchema();
  } catch (e) {
    console.error('DB init failed:', e);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
