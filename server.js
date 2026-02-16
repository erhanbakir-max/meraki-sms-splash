'use strict';

/**
 * meraki-sms-splash - single file server
 * - Splash + OTP (screen/sms placeholder)
 * - Meraki Grant redirect (client-side redirect style)
 * - Postgres logging (TEXT columns; auto-migration on boot)
 * - Admin UI (/admin/logs) + Daily hash/chain build + verify
 *
 * Required deps: express, pg, basic-auth
 * Optional: ioredis (if present, uses Redis; otherwise in-memory)
 */

const crypto = require('crypto');
const express = require('express');
const basicAuth = require('basic-auth');
const { Pool } = require('pg');

let Redis = null;
try {
  // optional dependency
  Redis = require('ioredis');
} catch (e) {
  Redis = null;
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb' }));

// -------------------- ENV --------------------
const ENV = {
  PORT: Number(process.env.PORT || 8080),

  // Core
  DATABASE_URL: process.env.DATABASE_URL || process.env.DATABASE_PRIVATE_URL || '',

  // Redis optional
  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PRIVATE_URL || '',

  // OTP + rate-limit
  OTP_MODE: (process.env.OTP_MODE || 'screen').toLowerCase(), // screen | sms
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),
  RL_MAC_SECONDS: Number(process.env.RL_MAC_SECONDS || 30),
  RL_PHONE_SECONDS: Number(process.env.RL_PHONE_SECONDS || 60),
  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  // KVKK label
  KVKK_VERSION: process.env.KVKK_VERSION || 'kvkk-unknown',

  // Admin
  ADMIN_USER: process.env.ADMIN_USER || '',
  ADMIN_PASS: process.env.ADMIN_PASS || '',

  // Timezone display only (we keep DB timestamps UTC)
  TZ: process.env.TZ || 'Europe/Istanbul',

  // Daily signature secret (optional)
  DAILY_HMAC_SECRET: process.env.DAILY_HMAC_SECRET || '',

  // base url (optional)
  BASE_URL: process.env.BASE_URL || '',
};

console.log('ENV:', {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
  RL_PHONE_SECONDS: ENV.RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS: ENV.LOCK_SECONDS,
  KVKK_VERSION: ENV.KVKK_VERSION,
  TZ: ENV.TZ,
  DB_SET: Boolean(ENV.DATABASE_URL),
  REDIS_SET: Boolean(ENV.REDIS_URL),
  ADMIN_USER_SET: Boolean(ENV.ADMIN_USER),
  ADMIN_PASS_SET: Boolean(ENV.ADMIN_PASS),
  DAILY_HMAC_SET: Boolean(ENV.DAILY_HMAC_SECRET),
});

// -------------------- DB --------------------
if (!ENV.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL missing');
  process.exit(1);
}

const pool = new Pool({
  connectionString: ENV.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// -------------------- Redis (optional) --------------------
const mem = {
  otpByMarker: new Map(),       // marker -> {otp, exp, mac, phone, wrong, lockedUntil}
  rlMac: new Map(),             // mac -> ts
  rlPhone: new Map(),           // phone -> ts
};

let redis = null;
if (Redis && ENV.REDIS_URL) {
  try {
    redis = new Redis(ENV.REDIS_URL, {
      maxRetriesPerRequest: 2,
      enableReadyCheck: true,
      lazyConnect: true,
    });
    redis.on('error', (e) => console.error('REDIS error:', e?.message || e));
    redis.connect().then(() => console.log('REDIS: connected')).catch((e) => {
      console.error('REDIS connect failed, falling back to in-memory:', e?.message || e);
      redis = null;
    });
  } catch (e) {
    console.error('REDIS init failed, falling back to in-memory:', e?.message || e);
    redis = null;
  }
} else {
  console.log('REDIS: disabled (ioredis not installed or REDIS_URL missing)');
}

// -------------------- Helpers --------------------
function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function hmacHex(secret, input) {
  return crypto.createHmac('sha256', secret).update(input).digest('hex');
}

function nowMs() {
  return Date.now();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function getClientIp(req) {
  // Railway/Proxy headers
  const xff = (req.headers['x-forwarded-for'] || '').toString();
  if (xff) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) ? String(req.socket.remoteAddress) : '';
}

function getPublicIp(req) {
  // If you forward public ip via a header or env, put it here. Otherwise use xff as best-effort.
  // In your logs you had PUBLIC_IP printed; we’ll compute best-effort:
  return getClientIp(req);
}

function normMac(mac) {
  if (!mac) return '';
  return String(mac).trim().toLowerCase();
}

function normPhone(phone) {
  if (!phone) return '';
  return String(phone).trim();
}

function genOtp6() {
  // 6 digit
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, '0');
}

function genMarker6() {
  // 6 digit marker
  const n = crypto.randomInt(100000, 1000000);
  return String(n);
}

// --- Rate limit (simple) ---
function rateLimitCheck(keyMap, key, seconds) {
  if (!key) return true;
  const t = keyMap.get(key);
  const now = nowMs();
  if (!t || (now - t) > seconds * 1000) {
    keyMap.set(key, now);
    return true;
  }
  return false;
}

async function redisSetJson(key, obj, ttlSeconds) {
  if (!redis) return false;
  await redis.set(key, JSON.stringify(obj), 'EX', ttlSeconds);
  return true;
}

async function redisGetJson(key) {
  if (!redis) return null;
  const v = await redis.get(key);
  if (!v) return null;
  try { return JSON.parse(v); } catch { return null; }
}

async function redisDel(key) {
  if (!redis) return false;
  await redis.del(key);
  return true;
}

// -------------------- Auto-migration (NO psql needed) --------------------
async function migrate() {
  // NOTE: we keep everything as TEXT to avoid inet parsing issues.
  // created_at is timestamptz for ordering.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS access_logs (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        event TEXT NOT NULL,

        first_name TEXT NULL,
        last_name TEXT NULL,
        full_name TEXT NULL,
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
        user_continue_url TEXT NULL,
        grant_url TEXT NULL,

        gateway_id TEXT NULL,
        node_id TEXT NULL,
        node_mac TEXT NULL,

        public_ip TEXT NULL,
        accept_language TEXT NULL,
        user_agent TEXT NULL,

        extra TEXT NULL,
        meta JSONB NULL
      );
    `);

    // Add missing columns safely (your DB had older schema at times)
    await client.query(`
      ALTER TABLE access_logs
        ADD COLUMN IF NOT EXISTS public_ip TEXT NULL,
        ADD COLUMN IF NOT EXISTS accept_language TEXT NULL,
        ADD COLUMN IF NOT EXISTS user_agent TEXT NULL,
        ADD COLUMN IF NOT EXISTS continue_url TEXT NULL,
        ADD COLUMN IF NOT EXISTS user_continue_url TEXT NULL,
        ADD COLUMN IF NOT EXISTS grant_url TEXT NULL;
    `);

    // daily hashes
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_hashes (
        day DATE PRIMARY KEY,
        tz TEXT NOT NULL,
        record_count INTEGER NOT NULL,
        day_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // chain table links days
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_chains (
        day DATE PRIMARY KEY,
        prev_day DATE NULL,
        prev_day_hash TEXT NULL,
        chain_hash TEXT NOT NULL,
        signature_hmac TEXT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // export packages (optional)
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_packages (
        day DATE PRIMARY KEY,
        content_json JSONB NOT NULL,
        content_hash TEXT NOT NULL,
        signature_hmac TEXT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // indexes
    await client.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);

    await client.query('COMMIT');
    console.log('DATABASE: table ready');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('DATABASE migrate failed:', e);
    throw e;
  } finally {
    client.release();
  }
}

// -------------------- Logging --------------------
async function logEvent(req, event, fields = {}) {
  // Make fields safe; all TEXT columns accept '' or null.
  const payload = {
    event: String(event),

    first_name: fields.first_name ?? null,
    last_name: fields.last_name ?? null,
    full_name: fields.full_name ?? null,
    phone: fields.phone ?? null,

    kvkk_accepted: (typeof fields.kvkk_accepted === 'boolean') ? fields.kvkk_accepted : null,
    kvkk_version: fields.kvkk_version ?? ENV.KVKK_VERSION ?? null,

    marker: fields.marker ?? null,

    client_mac: fields.client_mac ?? null,
    client_ip: fields.client_ip ?? null,

    ssid: fields.ssid ?? null,
    ap_name: fields.ap_name ?? null,

    base_grant_url: fields.base_grant_url ?? null,
    continue_url: fields.continue_url ?? null,
    user_continue_url: fields.user_continue_url ?? null,
    grant_url: fields.grant_url ?? null,

    gateway_id: fields.gateway_id ?? null,
    node_id: fields.node_id ?? null,
    node_mac: fields.node_mac ?? null,

    public_ip: fields.public_ip ?? null,
    accept_language: fields.accept_language ?? null,
    user_agent: fields.user_agent ?? null,

    extra: fields.extra ?? null,
    meta: fields.meta ?? null,
  };

  const sql = `
    INSERT INTO access_logs(
      event, first_name, last_name, full_name, phone,
      kvkk_accepted, kvkk_version, marker,
      client_mac, client_ip, ssid, ap_name,
      base_grant_url, continue_url, user_continue_url, grant_url,
      gateway_id, node_id, node_mac,
      public_ip, accept_language, user_agent,
      extra, meta
    ) VALUES (
      $1,$2,$3,$4,$5,
      $6,$7,$8,
      $9,$10,$11,$12,
      $13,$14,$15,$16,
      $17,$18,$19,
      $20,$21,$22,
      $23,$24::jsonb
    )
  `;

  const values = [
    payload.event,
    payload.first_name, payload.last_name, payload.full_name, payload.phone,
    payload.kvkk_accepted, payload.kvkk_version, payload.marker,
    payload.client_mac, payload.client_ip, payload.ssid, payload.ap_name,
    payload.base_grant_url, payload.continue_url, payload.user_continue_url, payload.grant_url,
    payload.gateway_id, payload.node_id, payload.node_mac,
    payload.public_ip, payload.accept_language, payload.user_agent,
    payload.extra, payload.meta ? JSON.stringify(payload.meta) : null,
  ];

  try {
    await pool.query(sql, values);
  } catch (e) {
    // Don't crash app for logging errors
    console.error('DB LOG ERROR:', e.message);
  }
}

// -------------------- OTP store (Redis or memory) --------------------
function otpKey(marker) {
  return `otp:${marker}`;
}

async function otpPut(marker, obj) {
  const ttl = Math.max(30, ENV.OTP_TTL_SECONDS);
  if (redis) {
    await redisSetJson(otpKey(marker), obj, ttl);
    return;
  }
  mem.otpByMarker.set(marker, obj);
  // no async GC needed; we check expiry on read
}

async function otpGet(marker) {
  if (redis) return await redisGetJson(otpKey(marker));
  const v = mem.otpByMarker.get(marker);
  if (!v) return null;
  if (v.exp && nowMs() > v.exp) {
    mem.otpByMarker.delete(marker);
    return null;
  }
  return v;
}

async function otpDel(marker) {
  if (redis) return await redisDel(otpKey(marker));
  mem.otpByMarker.delete(marker);
}

// -------------------- Splash UI --------------------
function pageHtml({ title, body }) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#0b1220; color:#e6edf3; }
    .wrap { max-width: 860px; margin: 28px auto; padding: 0 16px; }
    .card { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.10); border-radius: 14px; padding: 18px; }
    h1,h2 { margin: 0 0 12px 0; }
    label { display:block; margin: 10px 0 6px; opacity:.9; }
    input { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.04); color:#e6edf3; }
    button { padding: 10px 14px; border-radius: 10px; border:0; background:#7c3aed; color:white; cursor:pointer; }
    button.secondary { background: rgba(255,255,255,.10); }
    .row { display:flex; gap:10px; flex-wrap: wrap; }
    .row > * { flex: 1; min-width: 160px; }
    .muted { opacity:.75; font-size: 13px; }
    .ok { color:#34d399; }
    .warn { color:#fbbf24; }
    .err { color:#fb7185; }
    a { color: #93c5fd; text-decoration: none; }
    code { background: rgba(0,0,0,.25); padding: 2px 6px; border-radius: 8px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      ${body}
    </div>
    <div class="muted" style="margin-top:10px">
      ${ENV.BASE_URL ? `Base: <code>${ENV.BASE_URL}</code>` : ''}
    </div>
  </div>
</body>
</html>`;
}

function parseMerakiParams(q) {
  // Meraki sends different query params depending on setup.
  // We'll pick what we can.
  const gateway_id = q.gateway_id || q.gateway || q.gw_id || '';
  const node_id = q.node_id || q.node || '';
  const client_ip = q.client_ip || q.ip || '';
  const client_mac = q.client_mac || q.mac || '';
  const node_mac = q.node_mac || q.ap_mac || '';
  const continue_url = q.continue_url || q.continue || '';
  const base_grant_url = q.base_grant_url || q.base_grant || ''; // optional
  const user_continue_url = q.user_continue_url || q.user_continue || ''; // optional
  return {
    gateway_id: String(gateway_id || ''),
    node_id: String(node_id || ''),
    client_ip: String(client_ip || ''),
    client_mac: normMac(client_mac || ''),
    node_mac: normMac(node_mac || ''),
    continue_url: String(continue_url || ''),
    base_grant_url: String(base_grant_url || ''),
    user_continue_url: String(user_continue_url || ''),
  };
}

// -------------------- Routes --------------------
app.get('/health', (req, res) => res.status(200).send('ok'));

app.get('/', async (req, res) => {
  const q = req.query || {};
  const p = parseMerakiParams(q);

  const ua = String(req.headers['user-agent'] || '');
  const al = String(req.headers['accept-language'] || '');
  const public_ip = getPublicIp(req);

  console.log('SPLASH_OPEN', {
    hasBaseGrant: Boolean(p.base_grant_url),
    hasContinue: Boolean(p.continue_url),
    hasClientMac: Boolean(p.client_mac),
    mode: ENV.OTP_MODE,
  });

  await logEvent(req, 'SPLASH_OPEN', {
    client_mac: p.client_mac || null,
    client_ip: p.client_ip || null,
    base_grant_url: p.base_grant_url || null,
    continue_url: p.continue_url || null,
    user_continue_url: p.user_continue_url || null,
    gateway_id: p.gateway_id || null,
    node_id: p.node_id || null,
    node_mac: p.node_mac || null,
    public_ip,
    accept_language: al || null,
    user_agent: ua || null,
    meta: { mode: ENV.OTP_MODE, referrer: req.headers.referer || null },
  });

  const body = `
    <h1>Wi-Fi Giriş</h1>
    <p class="muted">Telefon numaranızı girin, KVKK onaylayın ve doğrulama kodunu girin.</p>

    <form method="POST" action="/otp/create">
      <input type="hidden" name="gateway_id" value="${escapeHtml(p.gateway_id)}"/>
      <input type="hidden" name="node_id" value="${escapeHtml(p.node_id)}"/>
      <input type="hidden" name="client_ip" value="${escapeHtml(p.client_ip)}"/>
      <input type="hidden" name="client_mac" value="${escapeHtml(p.client_mac)}"/>
      <input type="hidden" name="node_mac" value="${escapeHtml(p.node_mac)}"/>
      <input type="hidden" name="continue_url" value="${escapeHtml(p.continue_url)}"/>
      <input type="hidden" name="base_grant_url" value="${escapeHtml(p.base_grant_url)}"/>
      <input type="hidden" name="user_continue_url" value="${escapeHtml(p.user_continue_url)}"/>

      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" placeholder="Ad" autocomplete="given-name"/>
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" placeholder="Soyad" autocomplete="family-name"/>
        </div>
      </div>

      <label>Telefon</label>
      <input name="phone" placeholder="05xx..." autocomplete="tel" required/>

      <label style="margin-top:12px;">
        <input type="checkbox" name="kvkk_accepted" value="true" required/>
        KVKK metnini okudum, onaylıyorum. (Sürüm: <code>${escapeHtml(ENV.KVKK_VERSION)}</code>)
      </label>

      <div style="margin-top:14px" class="row">
        <button type="submit">Kodu Gönder</button>
        <a class="muted" href="/admin/logs" style="align-self:center">Admin</a>
      </div>
      <p class="muted">Not: OTP mode = <code>${escapeHtml(ENV.OTP_MODE)}</code></p>
    </form>
  `;

  res.status(200).send(pageHtml({ title: 'Splash', body }));
});

app.post('/otp/create', async (req, res) => {
  const phone = normPhone(req.body.phone || '');
  const first_name = (req.body.first_name || '').trim() || null;
  const last_name = (req.body.last_name || '').trim() || null;
  const full_name = [first_name, last_name].filter(Boolean).join(' ') || null;

  const kvkk_accepted = String(req.body.kvkk_accepted || '') === 'true';

  const q = req.body || {};
  const p = parseMerakiParams(q);
  const mac = p.client_mac || normMac(req.body.client_mac || '');

  // rate-limit
  const okMac = rateLimitCheck(mem.rlMac, mac, ENV.RL_MAC_SECONDS);
  const okPhone = rateLimitCheck(mem.rlPhone, phone, ENV.RL_PHONE_SECONDS);
  if (!okMac || !okPhone) {
    await logEvent(req, 'OTP_RATE_LIMIT', {
      phone, client_mac: mac || null, client_ip: p.client_ip || null,
      first_name, last_name, full_name,
      kvkk_accepted, kvkk_version: ENV.KVKK_VERSION,
      meta: { okMac, okPhone },
    });
    return res.status(429).send(pageHtml({
      title: 'Rate limit',
      body: `<h2 class="warn">Çok sık deneme</h2><p>Lütfen ${ENV.RL_PHONE_SECONDS} sn bekleyip tekrar deneyin.</p><p><a href="javascript:history.back()">Geri</a></p>`
    }));
  }

  const marker = genMarker6();
  const otp = genOtp6();
  const exp = nowMs() + ENV.OTP_TTL_SECONDS * 1000;

  await otpPut(marker, {
    otp,
    exp,
    mac,
    phone,
    wrong: 0,
    lockedUntil: 0,
    // keep meraki params to continue flow
    meraki: p,
    user: { first_name, last_name, full_name, kvkk_accepted, kvkk_version: ENV.KVKK_VERSION },
  });

  console.log('OTP_CREATED', { marker, last4: phone.slice(-4), client_mac: mac });
  await logEvent(req, 'OTP_CREATED', {
    first_name, last_name, full_name,
    phone,
    kvkk_accepted,
    kvkk_version: ENV.KVKK_VERSION,
    marker,
    client_mac: mac || null,
    client_ip: p.client_ip || null,
    base_grant_url: p.base_grant_url || null,
    continue_url: p.continue_url || null,
    user_continue_url: p.user_continue_url || null,
    gateway_id: p.gateway_id || null,
    node_id: p.node_id || null,
    node_mac: p.node_mac || null,
    public_ip: getPublicIp(req),
    accept_language: String(req.headers['accept-language'] || '') || null,
    user_agent: String(req.headers['user-agent'] || '') || null,
    meta: { mode: ENV.OTP_MODE },
  });

  // Screen OTP shows code on page
  if (ENV.OTP_MODE === 'screen') {
    console.log('OTP_SCREEN_CODE', { marker, otp });
  }

  const body = `
    <h1>Doğrulama</h1>
    <p class="muted">Marker: <code>${escapeHtml(marker)}</code></p>
    ${ENV.OTP_MODE === 'screen'
      ? `<p class="ok">OTP (screen mode): <code style="font-size:18px">${escapeHtml(otp)}</code></p>`
      : `<p class="muted">SMS mode: burada SMS gönderen servis çağrılır (smsService.js / provider).</p>`
    }

    <form method="POST" action="/otp/verify">
      <input type="hidden" name="marker" value="${escapeHtml(marker)}"/>
      <label>OTP</label>
      <input name="otp" placeholder="6 haneli kod" required/>
      <div style="margin-top:14px" class="row">
        <button type="submit">Doğrula ve İnternete Bağlan</button>
        <button class="secondary" type="button" onclick="location.href='/'">İptal</button>
      </div>
    </form>
  `;

  res.status(200).send(pageHtml({ title: 'OTP Verify', body }));
});

app.post('/otp/verify', async (req, res) => {
  const marker = String(req.body.marker || '').trim();
  const otp = String(req.body.otp || '').trim();

  const rec = await otpGet(marker);
  if (!rec) {
    await logEvent(req, 'OTP_VERIFY_FAIL', { marker, extra: 'marker_not_found', public_ip: getPublicIp(req) });
    return res.status(400).send(pageHtml({
      title: 'OTP Hata',
      body: `<h2 class="err">Geçersiz veya süresi dolmuş marker</h2><p><a href="/">Başa dön</a></p>`
    }));
  }

  const now = nowMs();
  if (rec.lockedUntil && now < rec.lockedUntil) {
    await logEvent(req, 'OTP_LOCKED', { marker, phone: rec.phone, client_mac: rec.mac, extra: 'locked', public_ip: getPublicIp(req) });
    return res.status(429).send(pageHtml({
      title: 'Kilit',
      body: `<h2 class="warn">Çok fazla hatalı deneme</h2><p>${Math.ceil((rec.lockedUntil - now)/1000)} sn sonra tekrar deneyin.</p>`
    }));
  }

  if (rec.otp !== otp) {
    rec.wrong = (rec.wrong || 0) + 1;
    if (rec.wrong >= ENV.MAX_WRONG_ATTEMPTS) {
      rec.lockedUntil = now + ENV.LOCK_SECONDS * 1000;
    }
    await otpPut(marker, rec);

    await logEvent(req, 'OTP_VERIFY_FAIL', {
      marker,
      phone: rec.phone,
      client_mac: rec.mac,
      client_ip: rec.meraki?.client_ip || null,
      extra: `wrong=${rec.wrong}`,
      public_ip: getPublicIp(req),
    });

    return res.status(401).send(pageHtml({
      title: 'OTP Hata',
      body: `<h2 class="err">Kod yanlış</h2><p>Kalan deneme: ${Math.max(0, ENV.MAX_WRONG_ATTEMPTS - rec.wrong)}</p><p><a href="javascript:history.back()">Geri</a></p>`
    }));
  }

  // OTP ok -> log + redirect to grant
  console.log('OTP_VERIFY_OK', { marker, client_mac: rec.mac });
  await logEvent(req, 'OTP_VERIFIED', {
    marker,
    first_name: rec.user?.first_name || null,
    last_name: rec.user?.last_name || null,
    full_name: rec.user?.full_name || null,
    phone: rec.phone || null,
    kvkk_accepted: !!rec.user?.kvkk_accepted,
    kvkk_version: rec.user?.kvkk_version || ENV.KVKK_VERSION,
    client_mac: rec.mac || null,
    client_ip: rec.meraki?.client_ip || null,
    base_grant_url: rec.meraki?.base_grant_url || null,
    continue_url: rec.meraki?.continue_url || null,
    user_continue_url: rec.meraki?.user_continue_url || null,
    gateway_id: rec.meraki?.gateway_id || null,
    node_id: rec.meraki?.node_id || null,
    node_mac: rec.meraki?.node_mac || null,
    public_ip: getPublicIp(req),
    accept_language: String(req.headers['accept-language'] || '') || null,
    user_agent: String(req.headers['user-agent'] || '') || null,
    meta: { ok: true },
  });

  // If meraki base_grant_url not provided, we still can redirect to /grant with params
  const p = rec.meraki || {};
  // Build /grant redirect query
  const grantParams = new URLSearchParams();
  for (const k of ['gateway_id', 'node_id', 'client_ip', 'client_mac', 'node_mac', 'continue_url', 'base_grant_url', 'user_continue_url']) {
    if (p[k]) grantParams.set(k, String(p[k]));
  }
  grantParams.set('marker', marker);

  // one-time marker is fine; keep for auditing but you can delete it now:
  await otpDel(marker);

  return res.redirect(302, `/grant?${grantParams.toString()}`);
});

app.get('/grant', async (req, res) => {
  const q = req.query || {};
  const p = parseMerakiParams(q);

  const marker = String(q.marker || '').trim() || null;

  // If you have a fixed base grant URL, put it here; otherwise we attempt to use meraki-provided pattern
  // In your logs you had: https://eu.network-auth.com/splash/<id>/grant
  // We'll require base_grant_url if provided, else try to infer from referrer? We'll do minimal safe approach:
  let base = p.base_grant_url;
  if (!base) {
    // Fallback (works only if your deployment uses eu.network-auth.com known format)
    // If you want strict behavior: return error instead of guessing.
    base = 'https://eu.network-auth.com/splash/GFpvpc2c.6.197/grant';
  }

  const grantUrl = new URL(base);
  // Required-ish params for Meraki grant parsing; you already validated these earlier.
  if (p.gateway_id) grantUrl.searchParams.set('gateway_id', p.gateway_id);
  if (p.node_id) grantUrl.searchParams.set('node_id', p.node_id);
  if (p.client_ip) grantUrl.searchParams.set('client_ip', p.client_ip);
  if (p.client_mac) grantUrl.searchParams.set('client_mac', p.client_mac);
  if (p.node_mac) grantUrl.searchParams.set('node_mac', p.node_mac);

  // continue_url is important for captive portal behavior
  const cont = p.continue_url || 'http://connectivitycheck.gstatic.com/generate_204';
  grantUrl.searchParams.set('continue_url', cont);

  console.log('GRANT_CLIENT_REDIRECT:', grantUrl.toString());

  await logEvent(req, 'GRANT_CLIENT_REDIRECT', {
    marker,
    client_mac: p.client_mac || null,
    client_ip: p.client_ip || null,
    base_grant_url: base,
    continue_url: cont,
    grant_url: grantUrl.toString(),
    gateway_id: p.gateway_id || null,
    node_id: p.node_id || null,
    node_mac: p.node_mac || null,
    public_ip: getPublicIp(req),
    accept_language: String(req.headers['accept-language'] || '') || null,
    user_agent: String(req.headers['user-agent'] || '') || null,
    meta: { redirect: true },
  });

  // client-side redirect avoids Meraki parsing issues you saw with server-side fetch.
  res.redirect(302, grantUrl.toString());
});

// -------------------- Admin auth --------------------
function adminRequired(req, res, next) {
  if (!ENV.ADMIN_USER || !ENV.ADMIN_PASS) {
    return res.status(500).send('Admin user/pass not set');
  }
  const user = basicAuth(req);
  if (!user || user.name !== ENV.ADMIN_USER || user.pass !== ENV.ADMIN_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Auth required');
  }
  next();
}

async function qRows(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows || [];
}

function fmtDateTR(ts) {
  try {
    const d = new Date(ts);
    return new Intl.DateTimeFormat('tr-TR', {
      timeZone: ENV.TZ,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    }).format(d);
  } catch {
    return String(ts);
  }
}

function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

// -------------------- Admin UI: logs --------------------
app.get('/admin/logs', adminRequired, async (req, res) => {
  const limit = Math.min(1000, Math.max(1, Number(req.query.limit || 200)));
  const asJson = String(req.query.format || '').toLowerCase() === 'json' || String(req.query.json || '') === '1';

  const rows = await qRows(
    `SELECT id, created_at, event, full_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     ORDER BY id DESC
     LIMIT $1`,
    [limit]
  );

  if (asJson) return res.json(rows);

  const head = `
    <h1>/admin/logs</h1>
    <div class="muted">limit=${limit} • tz=${escapeHtml(ENV.TZ)} • <a href="/admin/logs?limit=${limit}&format=json">JSON</a></div>
    <div style="margin:12px 0" class="row">
      <form method="GET" action="/admin/logs" style="display:flex; gap:10px; flex-wrap:wrap;">
        <input name="limit" value="${limit}" style="max-width:140px" />
        <button type="submit">Refresh</button>
        <a href="/admin/daily" style="align-self:center">Daily</a>
      </form>
    </div>
  `;

  const table = `
    <table style="width:100%; border-collapse: collapse; overflow:hidden; border-radius:12px;">
      <thead>
        <tr style="background:rgba(255,255,255,.06); text-align:left;">
          <th style="padding:10px;">id</th>
          <th style="padding:10px;">time</th>
          <th style="padding:10px;">event</th>
          <th style="padding:10px;">name</th>
          <th style="padding:10px;">phone</th>
          <th style="padding:10px;">mac</th>
          <th style="padding:10px;">ip</th>
          <th style="padding:10px;">marker</th>
          <th style="padding:10px;">kvkk</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(r => `
          <tr style="border-top: 1px solid rgba(255,255,255,.08)">
            <td style="padding:10px;">${r.id}</td>
            <td style="padding:10px;">${escapeHtml(fmtDateTR(r.created_at))}</td>
            <td style="padding:10px;">${escapeHtml(r.event)}</td>
            <td style="padding:10px;">${escapeHtml(r.full_name || '')}</td>
            <td style="padding:10px;">${escapeHtml(r.phone || '')}</td>
            <td style="padding:10px;">${escapeHtml(r.client_mac || '')}</td>
            <td style="padding:10px;">${escapeHtml(r.client_ip || '')}</td>
            <td style="padding:10px;">${escapeHtml(r.marker || '')}</td>
            <td style="padding:10px;">${escapeHtml(r.kvkk_version || '')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  res.send(pageHtml({ title: 'Admin Logs', body: head + table }));
});

// -------------------- Daily hash/chain --------------------
function parseDay(dayStr) {
  // Expect YYYY-MM-DD
  if (!dayStr) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dayStr).trim());
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

function canonicalLine(r) {
  // Stable string: use a subset of fields for daily hash (you can extend)
  // IMPORTANT: created_at in UTC, keep ISO.
  const obj = {
    id: r.id,
    created_at: new Date(r.created_at).toISOString(),
    event: r.event || '',
    phone: r.phone || '',
    full_name: r.full_name || '',
    client_mac: r.client_mac || '',
    client_ip: r.client_ip || '',
    marker: r.marker || '',
    kvkk_version: r.kvkk_version || '',
  };
  return JSON.stringify(obj);
}

async function getLogsForDay(day) {
  // Use DB-side timezone conversion with AT TIME ZONE to select local-day boundaries
  // day is YYYY-MM-DD in local TZ.
  // We compute: [day 00:00 local, day+1 00:00 local) -> UTC timestamps and filter created_at
  const rows = await qRows(
    `
    WITH bounds AS (
      SELECT
        ( ($1::date)::timestamp AT TIME ZONE $2 ) AS start_utc,
        ( ($1::date + 1)::timestamp AT TIME ZONE $2 ) AS end_utc
    )
    SELECT id, created_at, event, full_name, phone, client_mac, client_ip, marker, kvkk_version
    FROM access_logs, bounds
    WHERE created_at >= bounds.start_utc
      AND created_at <  bounds.end_utc
    ORDER BY id ASC
    `,
    [day, ENV.TZ]
  );
  return rows;
}

async function upsertDaily(day, tz, record_count, day_hash) {
  await pool.query(
    `
    INSERT INTO daily_hashes(day, tz, record_count, day_hash)
    VALUES ($1::date, $2, $3, $4)
    ON CONFLICT (day) DO UPDATE
      SET tz=EXCLUDED.tz,
          record_count=EXCLUDED.record_count,
          day_hash=EXCLUDED.day_hash,
          created_at=NOW()
    `,
    [day, tz, record_count, day_hash]
  );
}

async function upsertChain(day, prev_day, prev_day_hash, chain_hash, signature_hmac) {
  await pool.query(
    `
    INSERT INTO daily_chains(day, prev_day, prev_day_hash, chain_hash, signature_hmac)
    VALUES ($1::date, $2::date, $3, $4, $5)
    ON CONFLICT (day) DO UPDATE
      SET prev_day=EXCLUDED.prev_day,
          prev_day_hash=EXCLUDED.prev_day_hash,
          chain_hash=EXCLUDED.chain_hash,
          signature_hmac=EXCLUDED.signature_hmac,
          created_at=NOW()
    `,
    [day, prev_day, prev_day_hash, chain_hash, signature_hmac]
  );
}

async function upsertPackage(day, content_json, content_hash, signature_hmac) {
  await pool.query(
    `
    INSERT INTO daily_packages(day, content_json, content_hash, signature_hmac)
    VALUES ($1::date, $2::jsonb, $3, $4)
    ON CONFLICT (day) DO UPDATE
      SET content_json=EXCLUDED.content_json,
          content_hash=EXCLUDED.content_hash,
          signature_hmac=EXCLUDED.signature_hmac,
          created_at=NOW()
    `,
    [day, JSON.stringify(content_json), content_hash, signature_hmac]
  );
}

app.get('/admin/daily', adminRequired, async (req, res) => {
  const rows = await qRows(
    `SELECT h.day, h.tz, h.record_count, h.day_hash, c.chain_hash, c.signature_hmac
     FROM daily_hashes h
     LEFT JOIN daily_chains c ON c.day=h.day
     ORDER BY h.day DESC
     LIMIT 60`
  );

  const body = `
    <h1>/admin/daily</h1>
    <p class="muted">Günlük hash ve zincir kayıtları</p>
    <div class="row" style="margin-bottom:12px;">
      <a href="/admin/logs" style="align-self:center">Logs</a>
      <form method="GET" action="/admin/daily/build" style="display:flex; gap:10px; flex-wrap:wrap;">
        <input name="day" placeholder="YYYY-MM-DD" style="max-width:160px" />
        <button type="submit">Build</button>
      </form>
      <form method="GET" action="/admin/daily/verify" style="display:flex; gap:10px; flex-wrap:wrap;">
        <input name="day" placeholder="YYYY-MM-DD" style="max-width:160px" />
        <button type="submit">Verify</button>
      </form>
    </div>

    <table style="width:100%; border-collapse: collapse; overflow:hidden; border-radius:12px;">
      <thead>
        <tr style="background:rgba(255,255,255,.06); text-align:left;">
          <th style="padding:10px;">day</th>
          <th style="padding:10px;">count</th>
          <th style="padding:10px;">day_hash</th>
          <th style="padding:10px;">chain_hash</th>
          <th style="padding:10px;">sig</th>
          <th style="padding:10px;">actions</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(r => `
          <tr style="border-top: 1px solid rgba(255,255,255,.08)">
            <td style="padding:10px;">${escapeHtml(String(r.day).slice(0,10))}</td>
            <td style="padding:10px;">${escapeHtml(String(r.record_count))}</td>
            <td style="padding:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px;">${escapeHtml(r.day_hash || '')}</td>
            <td style="padding:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px;">${escapeHtml(r.chain_hash || '')}</td>
            <td style="padding:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px;">${escapeHtml(r.signature_hmac || '')}</td>
            <td style="padding:10px;">
              <a href="/admin/daily/build?day=${escapeHtml(String(r.day).slice(0,10))}">build</a>
              • <a href="/admin/daily/verify?day=${escapeHtml(String(r.day).slice(0,10))}">verify</a>
              • <a href="/admin/daily/export?day=${escapeHtml(String(r.day).slice(0,10))}">export</a>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  res.send(pageHtml({ title: 'Daily', body }));
});

app.get('/admin/daily/build', adminRequired, async (req, res) => {
  const day = parseDay(req.query.day);
  if (!day) return res.status(400).send('day=YYYY-MM-DD required');

  const logs = await getLogsForDay(day);
  const lines = logs.map(canonicalLine);
  const dayHash = sha256Hex(lines.join('\n'));
  const recordCount = logs.length;

  // prev day
  const prevRows = await qRows(
    `SELECT day, day_hash FROM daily_hashes WHERE day < $1::date ORDER BY day DESC LIMIT 1`,
    [day]
  );
  const prev = prevRows[0] || null;

  const prev_day = prev ? String(prev.day).slice(0,10) : null;
  const prev_day_hash = prev ? prev.day_hash : null;

  const chainMaterial = JSON.stringify({
    day,
    tz: ENV.TZ,
    record_count: recordCount,
    day_hash: dayHash,
    prev_day,
    prev_day_hash,
  });
  const chainHash = sha256Hex(chainMaterial);

  const sig = ENV.DAILY_HMAC_SECRET ? hmacHex(ENV.DAILY_HMAC_SECRET, chainHash) : null;

  await upsertDaily(day, ENV.TZ, recordCount, dayHash);
  await upsertChain(day, prev_day, prev_day_hash, chainHash, sig);

  // optionally persist daily package (export)
  const pkg = {
    day,
    tz: ENV.TZ,
    record_count: recordCount,
    day_hash: dayHash,
    prev_day,
    prev_day_hash,
    chain_hash: chainHash,
    signature_hmac: sig,
    rows: logs,
  };
  const pkgJson = pkg;
  const pkgHash = sha256Hex(JSON.stringify(pkgJson));
  const pkgSig = ENV.DAILY_HMAC_SECRET ? hmacHex(ENV.DAILY_HMAC_SECRET, pkgHash) : null;
  await upsertPackage(day, pkgJson, pkgHash, pkgSig);

  if (String(req.query.ui || '') === '1') {
    return res.redirect(302, '/admin/daily');
  }

  res.json({
    day,
    tz: ENV.TZ,
    record_count: recordCount,
    day_hash: dayHash,
    prev_day,
    prev_day_hash,
    chain_hash: chainHash,
    signature_hmac: sig,
  });
});

app.get('/admin/daily/export', adminRequired, async (req, res) => {
  const day = parseDay(req.query.day);
  if (!day) return res.status(400).send('day=YYYY-MM-DD required');

  const rows = await qRows(`SELECT * FROM daily_packages WHERE day=$1::date`, [day]);
  if (!rows[0]) return res.status(404).send('package not found. build first.');

  // Force download JSON
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="daily-${day}.json"`);
  res.send(JSON.stringify(rows[0], null, 2));
});

app.get('/admin/daily/verify', adminRequired, async (req, res) => {
  const day = parseDay(req.query.day);
  if (!day) return res.status(400).send('day=YYYY-MM-DD required');

  // recompute
  const logs = await getLogsForDay(day);
  const lines = logs.map(canonicalLine);
  const recomputedDayHash = sha256Hex(lines.join('\n'));

  const storedHashRow = (await qRows(`SELECT * FROM daily_hashes WHERE day=$1::date`, [day]))[0] || null;
  const storedChainRow = (await qRows(`SELECT * FROM daily_chains WHERE day=$1::date`, [day]))[0] || null;

  const dayHashOk = storedHashRow ? (storedHashRow.day_hash === recomputedDayHash) : false;

  let chainOk = false;
  let sigOk = null;

  if (storedHashRow && storedChainRow) {
    const chainMaterial = JSON.stringify({
      day,
      tz: storedHashRow.tz,
      record_count: storedHashRow.record_count,
      day_hash: storedHashRow.day_hash,
      prev_day: storedChainRow.prev_day ? String(storedChainRow.prev_day).slice(0,10) : null,
      prev_day_hash: storedChainRow.prev_day_hash || null,
    });
    const recomputedChainHash = sha256Hex(chainMaterial);
    chainOk = (recomputedChainHash === storedChainRow.chain_hash);

    if (ENV.DAILY_HMAC_SECRET && storedChainRow.signature_hmac) {
      const expected = hmacHex(ENV.DAILY_HMAC_SECRET, storedChainRow.chain_hash);
      sigOk = (expected === storedChainRow.signature_hmac);
    }
  }

  const result = {
    day,
    tz: ENV.TZ,
    record_count: logs.length,
    recomputed_day_hash: recomputedDayHash,
    stored_day_hash: storedHashRow?.day_hash || null,
    day_hash_ok: dayHashOk,
    stored_chain_hash: storedChainRow?.chain_hash || null,
    chain_ok: chainOk,
    signature_ok: sigOk,
  };

  // If user wants UI:
  if (String(req.query.ui || '') === '1') {
    const body = `
      <h1>Verify ${escapeHtml(day)}</h1>
      <p class="${result.day_hash_ok ? 'ok' : 'err'}">Day hash: ${result.day_hash_ok ? 'OK' : 'FAIL'}</p>
      <p class="${result.chain_ok ? 'ok' : 'err'}">Chain: ${result.chain_ok ? 'OK' : 'FAIL'}</p>
      <p class="muted">Sig: ${sigOk === null ? 'N/A' : (sigOk ? 'OK' : 'FAIL')}</p>
      <pre style="white-space:pre-wrap; background:rgba(0,0,0,.25); padding:12px; border-radius:12px;">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
      <p><a href="/admin/daily">Back</a></p>
    `;
    return res.send(pageHtml({ title: 'Verify', body }));
  }

  res.json(result);
});

// -------------------- Start --------------------
(async () => {
  try {
    console.log('DATABASE: connected');
    await migrate();
  } catch (e) {
    console.error('Startup failed:', e);
    process.exit(1);
  }

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
