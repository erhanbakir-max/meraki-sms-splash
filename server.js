'use strict';

/**
 * meraki-sms-splash (single-file)
 * - OTP (screen mode)
 * - Stores splash context by marker (Redis if available, otherwise in-memory)
 * - After OTP verify: 302 redirect to Meraki grant URL (NOT "OK" page)
 * - Postgres logging (stable columns + meta jsonb)
 * - Admin UI + daily hash chain (HMAC optional)
 */

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

let RedisCtor = null;
try {
  RedisCtor = require('ioredis');
} catch (_) {
  RedisCtor = null;
}

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
app.use(express.json({ limit: '200kb' }));

// -------------------- ENV --------------------
const ENV = {
  OTP_MODE: process.env.OTP_MODE || 'screen', // screen | sms (sms not implemented here)
  OTP_TTL_SECONDS: parseInt(process.env.OTP_TTL_SECONDS || '180', 10),
  RL_MAC_SECONDS: parseInt(process.env.RL_MAC_SECONDS || '30', 10),
  RL_PHONE_SECONDS: parseInt(process.env.RL_PHONE_SECONDS || '60', 10),
  MAX_WRONG_ATTEMPTS: parseInt(process.env.MAX_WRONG_ATTEMPTS || '5', 10),
  LOCK_SECONDS: parseInt(process.env.LOCK_SECONDS || '600', 10),
  KVKK_VERSION: process.env.KVKK_VERSION || 'kvkk-unknown',
  TZ: process.env.TZ || 'Europe/Istanbul',
  ADMIN_USER: process.env.ADMIN_USER || '',
  ADMIN_PASS: process.env.ADMIN_PASS || '',
  DAILY_HMAC_KEY: process.env.DAILY_HMAC_KEY || '' // optional
};

const SAFE_ENV_PRINT = {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
  RL_PHONE_SECONDS: ENV.RL_PHONE_SECONDS,
  MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS: ENV.LOCK_SECONDS,
  KVKK_VERSION: ENV.KVKK_VERSION,
  TZ: ENV.TZ,
  DB_SET: !!process.env.DATABASE_URL,
  REDIS_SET: !!process.env.REDIS_URL,
  ADMIN_USER_SET: !!ENV.ADMIN_USER,
  ADMIN_PASS_SET: !!ENV.ADMIN_PASS,
  DAILY_HMAC_SET: !!ENV.DAILY_HMAC_KEY
};

console.log('ENV:', SAFE_ENV_PRINT);

// -------------------- DB --------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : (process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false })
});

async function qRows(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}

async function initDb() {
  console.log('DATABASE: connected');

  // Stable schema. Do not add random columns (accept_language, tz, package vs.) to avoid future mismatch crashes.
  await qRows(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id           BIGSERIAL PRIMARY KEY,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      event        TEXT NOT NULL,
      first_name   TEXT,
      last_name    TEXT,
      phone        TEXT,
      client_mac   TEXT,
      client_ip    TEXT,
      ssid         TEXT,
      ap_name      TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      marker       TEXT,
      kvkk_accepted BOOLEAN,
      kvkk_version TEXT,
      meta         JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at DESC);`);
  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_marker ON access_logs(marker);`);
  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);
  await qRows(`CREATE INDEX IF NOT EXISTS idx_access_logs_phone ON access_logs(phone);`);

  await qRows(`
    CREATE TABLE IF NOT EXISTS daily_chains (
      day          DATE PRIMARY KEY,
      tz           TEXT NOT NULL,
      record_count INT NOT NULL,
      day_hash     TEXT NOT NULL,
      prev_day_hash TEXT,
      chain_hash   TEXT NOT NULL,
      signed_hmac  TEXT,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log('DATABASE: table ready');
}

function nowMs() { return Date.now(); }
function sha256Hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function hmacHex(key, s) { return crypto.createHmac('sha256', key).update(s).digest('hex'); }

// -------------------- REDIS (optional) --------------------
let redis = null;
if (process.env.REDIS_URL && RedisCtor) {
  try {
    redis = new RedisCtor(process.env.REDIS_URL, { lazyConnect: true });
    redis.on('error', (e) => console.log('REDIS error:', e?.message || e));
  } catch (e) {
    redis = null;
  }
}

async function initRedis() {
  if (!redis) {
    console.log('REDIS: not configured (memory fallback)');
    return;
  }
  await redis.connect();
  console.log('REDIS: connected');
}

const mem = {
  otpByMarker: new Map(),     // marker -> record
  rlByMac: new Map(),         // mac -> ts
  rlByPhone: new Map()        // phone -> ts
};

async function kvGet(key) {
  if (redis) {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  return mem.otpByMarker.get(key) || null;
}

async function kvSet(key, val, ttlSeconds) {
  if (redis) {
    await redis.setex(key, ttlSeconds, JSON.stringify(val));
    return;
  }
  mem.otpByMarker.set(key, val);
  // simple TTL cleanup
  setTimeout(() => {
    const cur = mem.otpByMarker.get(key);
    if (cur && cur.expires_at_ms && cur.expires_at_ms <= nowMs()) mem.otpByMarker.delete(key);
  }, (ttlSeconds + 5) * 1000);
}

function rlHit(map, key, windowSeconds) {
  if (!key) return false;
  const t = map.get(key);
  const n = nowMs();
  if (t && (n - t) < windowSeconds * 1000) return true;
  map.set(key, n);
  return false;
}

// -------------------- ADMIN AUTH (no external module) --------------------
function parseBasicAuth(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Basic ')) return null;
  const b64 = h.slice(6).trim();
  let decoded = '';
  try {
    decoded = Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    return null;
  }
  const idx = decoded.indexOf(':');
  if (idx < 0) return null;
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
}

function requireAdmin(req, res, next) {
  if (!ENV.ADMIN_USER || !ENV.ADMIN_PASS) {
    return res.status(403).send('ADMIN_USER / ADMIN_PASS not set.');
  }
  const creds = parseBasicAuth(req);
  if (!creds || creds.user !== ENV.ADMIN_USER || creds.pass !== ENV.ADMIN_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Auth required.');
  }
  next();
}

// -------------------- LOGGING --------------------
async function dbLog(event, data) {
  try {
    const row = {
      event,
      first_name: data.first_name || null,
      last_name: data.last_name || null,
      phone: data.phone || null,
      client_mac: data.client_mac || null,
      client_ip: data.client_ip || null,
      ssid: data.ssid || null,
      ap_name: data.ap_name || null,
      base_grant_url: data.base_grant_url || null,
      continue_url: data.continue_url || null,
      marker: data.marker || null,
      kvkk_accepted: (typeof data.kvkk_accepted === 'boolean') ? data.kvkk_accepted : null,
      kvkk_version: data.kvkk_version || ENV.KVKK_VERSION || null,
      meta: data.meta || {}
    };

    await qRows(
      `INSERT INTO access_logs(
        event, first_name, last_name, phone,
        client_mac, client_ip, ssid, ap_name,
        base_grant_url, continue_url, marker,
        kvkk_accepted, kvkk_version, meta
      ) VALUES (
        $1,$2,$3,$4,
        $5,$6,$7,$8,
        $9,$10,$11,
        $12,$13,$14::jsonb
      );`,
      [
        row.event, row.first_name, row.last_name, row.phone,
        row.client_mac, row.client_ip, row.ssid, row.ap_name,
        row.base_grant_url, row.continue_url, row.marker,
        row.kvkk_accepted, row.kvkk_version, JSON.stringify(row.meta)
      ]
    );
  } catch (e) {
    console.log('DB LOG ERROR:', e?.message || e);
  }
}

// -------------------- MERAKI SPLASH CONTEXT PARSE --------------------
function getClientIp(req) {
  // trust proxy enabled
  const ip = req.ip || req.connection?.remoteAddress || '';
  return ip || '';
}

function parseSplashContext(req) {
  const q = req.query || {};

  // Meraki / Network-auth param variations (be tolerant)
  const base_grant_url =
    (q.base_grant_url || q.base_grant || q.baseGrantUrl || q.grant_url || '').toString();

  const continue_url =
    (q.continue_url || q.user_continue_url || q.user_continue || q.continue || '').toString();

  const client_mac =
    (q.client_mac || q.clientMac || '').toString();

  const client_ip =
    (q.client_ip || q.clientIp || '').toString() || getClientIp(req);

  const node_mac = (q.node_mac || q.nodeMac || '').toString();
  const gateway_id = (q.gateway_id || '').toString();
  const node_id = (q.node_id || '').toString();

  return {
    base_grant_url,
    continue_url,
    client_mac,
    client_ip,
    node_mac,
    gateway_id,
    node_id,
    rawQuery: q
  };
}

function buildGrantRedirectUrl(ctx) {
  const base = (ctx.base_grant_url || '').trim();
  if (!base) return '';

  // If base already has ?... keep it; otherwise add query.
  // Ensure continue_url is attached (if we have it).
  const hasQ = base.includes('?');
  let url = base;

  if (ctx.continue_url) {
    const sep = hasQ ? '&' : '?';
    // Do not double-add
    if (!/([?&])continue_url=/.test(url)) {
      url += `${sep}continue_url=${encodeURIComponent(ctx.continue_url)}`;
    }
  }
  return url;
}

// -------------------- UI HELPERS --------------------
function page(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    :root{color-scheme:dark;}
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1020; color:#e8eefc; margin:0; padding:24px;}
    .card{max-width:760px; margin:0 auto; background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12); border-radius:16px; padding:20px;}
    input,button{font-size:16px; padding:12px 14px; border-radius:10px; border:1px solid rgba(255,255,255,.18); background:rgba(0,0,0,.25); color:#e8eefc;}
    button{background:#6d5efc; border:none; cursor:pointer; font-weight:700;}
    button:hover{filter:brightness(1.05);}
    .row{display:flex; gap:10px; flex-wrap:wrap;}
    .row > *{flex:1;}
    .muted{opacity:.85; font-size:13px;}
    .otp{font-size:32px; letter-spacing:2px; font-weight:900; padding:12px 14px; background:rgba(0,0,0,.35); border-radius:12px; display:inline-block;}
    a{color:#b8b0ff;}
    .err{color:#ffb4b4; font-weight:700;}
  </style>
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;
}

function safe(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function randDigits(n) {
  let out = '';
  for (let i=0;i<n;i++) out += Math.floor(Math.random()*10).toString();
  return out;
}

// -------------------- ROUTES --------------------

// Splash landing
app.get('/', async (req, res) => {
  const ctx = parseSplashContext(req);

  console.log('SPLASH_OPEN', {
    hasBaseGrant: !!ctx.base_grant_url,
    hasContinue: !!ctx.continue_url,
    hasClientMac: !!ctx.client_mac,
    mode: ENV.OTP_MODE
  });

  await dbLog('SPLASH_OPEN', {
    client_mac: ctx.client_mac,
    client_ip: ctx.client_ip,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url,
    meta: {
      ua: req.headers['user-agent'] || '',
      referrer: req.headers['referer'] || '',
      rawQuery: ctx.rawQuery
    }
  });

  const body = `
    <h1>GUEST üzerinde oturum açın</h1>
    <p class="muted">Telefon numaranızı girin, OTP doğrulayın. Doğrulama sonrası otomatik internete yönlendirilirsiniz.</p>
    ${!ctx.base_grant_url ? `<p class="err">Uyarı: base_grant_url gelmemiş. Meraki splash parametreleri yoksa internet açılmaz.</p>` : ''}
    <form method="POST" action="/otp/request">
      <div class="row">
        <input name="first_name" placeholder="Ad" required />
        <input name="last_name" placeholder="Soyad" required />
      </div>
      <div class="row">
        <input name="phone" placeholder="05xxxxxxxxx veya +905..." required />
      </div>

      <div style="margin:12px 0;">
        <label>
          <input type="checkbox" name="kvkk_accepted" value="true" required />
          KVKK metnini okudum ve kabul ediyorum.
        </label>
        <div class="muted">KVKK versiyon: ${safe(ENV.KVKK_VERSION)}</div>
      </div>

      <!-- carry context in hidden fields (backup). We still store server-side by marker. -->
      <input type="hidden" name="base_grant_url" value="${safe(ctx.base_grant_url)}" />
      <input type="hidden" name="continue_url" value="${safe(ctx.continue_url)}" />
      <input type="hidden" name="client_mac" value="${safe(ctx.client_mac)}" />
      <input type="hidden" name="client_ip" value="${safe(ctx.client_ip)}" />
      <input type="hidden" name="node_mac" value="${safe(ctx.node_mac)}" />
      <input type="hidden" name="gateway_id" value="${safe(ctx.gateway_id)}" />
      <input type="hidden" name="node_id" value="${safe(ctx.node_id)}" />

      <button type="submit">OTP Gönder</button>
    </form>
    <p class="muted" style="margin-top:14px;">Admin: <a href="/admin/logs">/admin/logs</a></p>
  `;
  res.status(200).send(page('Meraki SMS Splash', body));
});

app.post('/otp/request', async (req, res) => {
  const first_name = (req.body.first_name || '').trim();
  const last_name = (req.body.last_name || '').trim();
  const phone = (req.body.phone || '').trim();
  const kvkk_accepted = String(req.body.kvkk_accepted || '') === 'true';

  const ctx = {
    base_grant_url: (req.body.base_grant_url || '').trim(),
    continue_url: (req.body.continue_url || '').trim(),
    client_mac: (req.body.client_mac || '').trim(),
    client_ip: (req.body.client_ip || '').trim() || getClientIp(req),
    node_mac: (req.body.node_mac || '').trim(),
    gateway_id: (req.body.gateway_id || '').trim(),
    node_id: (req.body.node_id || '').trim()
  };

  // rate-limit (soft)
  if (rlHit(mem.rlByMac, ctx.client_mac, ENV.RL_MAC_SECONDS) || rlHit(mem.rlByPhone, phone, ENV.RL_PHONE_SECONDS)) {
    return res.status(429).send(page('Rate limit', `<h2>Çok sık deneme</h2><p class="err">Lütfen birkaç saniye sonra tekrar deneyin.</p><p><a href="/">Geri</a></p>`));
  }

  const marker = randDigits(6);
  const otp = randDigits(6);
  const expires_at_ms = nowMs() + ENV.OTP_TTL_SECONDS * 1000;

  const rec = {
    marker,
    otp,
    expires_at_ms,
    first_name,
    last_name,
    phone,
    kvkk_accepted,
    kvkk_version: ENV.KVKK_VERSION,
    wrong_attempts: 0,
    locked_until_ms: 0,
    ctx
  };

  await kvSet(`otp:${marker}`, rec, ENV.OTP_TTL_SECONDS + ENV.LOCK_SECONDS + 60);

  console.log('OTP_CREATED', { marker, last4: phone.slice(-4), client_mac: ctx.client_mac });
  await dbLog('OTP_CREATED', {
    marker,
    first_name,
    last_name,
    phone,
    kvkk_accepted,
    client_mac: ctx.client_mac,
    client_ip: ctx.client_ip,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url,
    meta: { mode: ENV.OTP_MODE }
  });

  const otpBlock = (ENV.OTP_MODE === 'screen')
    ? `<div style="margin:14px 0;">
         <div class="muted">OTP Kodu (ekranda)</div>
         <div class="otp">${safe(otp)}</div>
       </div>`
    : `<p class="muted">OTP SMS ile gönderildi (sms modu bu örnekte uygulanmadı).</p>`;

  if (ENV.OTP_MODE === 'screen') {
    console.log('OTP_SCREEN_CODE', { marker, otp });
  }

  const body = `
    <h2>OTP Doğrula</h2>
    <p class="muted">OTP süresi: ${ENV.OTP_TTL_SECONDS}s</p>
    ${otpBlock}
    <form method="POST" action="/otp/verify">
      <input type="hidden" name="marker" value="${safe(marker)}" />
      <div class="row">
        <input name="otp" placeholder="OTP (6 hane)" required />
      </div>
      <button type="submit">Doğrula ve İnternete Bağlan</button>
    </form>
    <p class="muted" style="margin-top:12px;"><a href="/">Başa dön</a></p>
  `;
  res.status(200).send(page('OTP Verify', body));
});

app.post('/otp/verify', async (req, res) => {
  const marker = (req.body.marker || '').trim();
  const otp = (req.body.otp || '').trim();

  const rec = await kvGet(`otp:${marker}`);
  if (!rec) {
    return res.status(400).send(page('Hata', `<h2>OTP bulunamadı</h2><p class="err">Marker geçersiz veya süresi dolmuş.</p><p><a href="/">Geri</a></p>`));
  }

  if (rec.locked_until_ms && rec.locked_until_ms > nowMs()) {
    const sec = Math.ceil((rec.locked_until_ms - nowMs())/1000);
    return res.status(429).send(page('Kilitli', `<h2>Kısa süre kilitli</h2><p class="err">${sec}s sonra tekrar deneyin.</p>`));
  }

  if (rec.expires_at_ms <= nowMs()) {
    return res.status(400).send(page('Süre doldu', `<h2>OTP süresi doldu</h2><p><a href="/">Yeniden deneyin</a></p>`));
  }

  if (otp !== rec.otp) {
    rec.wrong_attempts = (rec.wrong_attempts || 0) + 1;
    if (rec.wrong_attempts >= ENV.MAX_WRONG_ATTEMPTS) {
      rec.locked_until_ms = nowMs() + ENV.LOCK_SECONDS * 1000;
    }
    await kvSet(`otp:${marker}`, rec, ENV.OTP_TTL_SECONDS + ENV.LOCK_SECONDS + 60);

    await dbLog('OTP_WRONG', {
      marker,
      phone: rec.phone,
      first_name: rec.first_name,
      last_name: rec.last_name,
      client_mac: rec.ctx?.client_mac,
      client_ip: rec.ctx?.client_ip,
      base_grant_url: rec.ctx?.base_grant_url,
      continue_url: rec.ctx?.continue_url,
      meta: { wrong_attempts: rec.wrong_attempts }
    });

    return res.status(400).send(page('Hatalı OTP', `<h2>Hatalı OTP</h2><p class="err">Tekrar deneyin.</p><p><a href="/">Başa dön</a></p>`));
  }

  console.log('OTP_VERIFY_OK', { marker, client_mac: rec.ctx?.client_mac || '' });

  await dbLog('OTP_VERIFIED', {
    marker,
    phone: rec.phone,
    first_name: rec.first_name,
    last_name: rec.last_name,
    kvkk_accepted: rec.kvkk_accepted,
    client_mac: rec.ctx?.client_mac,
    client_ip: rec.ctx?.client_ip,
    base_grant_url: rec.ctx?.base_grant_url,
    continue_url: rec.ctx?.continue_url,
    meta: { tz: ENV.TZ }
  });

  // IMPORTANT: Do NOT show "OK". Redirect to Meraki grant URL.
  const ctx = rec.ctx || {};
  const redirectUrl = buildGrantRedirectUrl(ctx);

  if (!redirectUrl) {
    // This is your current bug: verify sees no base_grant_url. Here we show a clear error.
    return res.status(400).send(page(
      'Hata',
      `<h2>OTP verified but base_grant_url missing.</h2>
       <p class="err">Meraki parametreleri verify aşamasında kaybolmuş. Splash sayfasını Meraki captive portal üzerinden açtığınızdan emin olun.</p>
       <p class="muted">İpucu: İlk açılış URL’sinde base_grant_url parametresi olmalı.</p>
       <p><a href="/">Başa dön</a></p>`
    ));
  }

  console.log('GRANT_CLIENT_REDIRECT:', redirectUrl);

  await dbLog('GRANT_CLIENT_REDIRECT', {
    marker,
    phone: rec.phone,
    client_mac: ctx.client_mac,
    client_ip: ctx.client_ip,
    base_grant_url: ctx.base_grant_url,
    continue_url: ctx.continue_url,
    meta: { redirectUrl }
  });

  // 302 redirect
  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(302, redirectUrl);
});

// -------------------- ADMIN UI --------------------
app.get('/admin', requireAdmin, (req, res) => {
  res.redirect(302, '/admin/logs');
});

app.get('/admin/logs', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '200', 10) || 200, 2000);
  const tz = (req.query.tz || ENV.TZ || 'Europe/Istanbul').toString();

  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_version
     FROM access_logs
     ORDER BY id DESC
     LIMIT $1;`,
    [limit]
  );

  const head = `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
      <div>
        <h1 style="margin:0;">/admin/logs</h1>
        <div class="muted">limit=${limit} • tz=${safe(tz)} • <a href="/admin/logs.json?limit=${limit}">JSON</a></div>
      </div>
      <div class="row" style="max-width:320px;">
        <form method="GET" action="/admin/logs" style="display:flex;gap:8px;align-items:center;">
          <input name="limit" value="${safe(limit)}" style="width:120px;" />
          <button type="submit">Refresh</button>
        </form>
        <form method="GET" action="/admin/daily" style="display:flex;gap:8px;align-items:center;">
          <button type="submit">Daily</button>
        </form>
      </div>
    </div>
  `;

  const table = `
    <div style="overflow:auto;margin-top:14px;">
      <table style="width:100%;border-collapse:collapse;">
        <thead>
          <tr style="text-align:left;opacity:.9;">
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">id</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">time</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">event</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">name</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">phone</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">mac</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">ip</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">marker</th>
            <th style="padding:10px;border-bottom:1px solid rgba(255,255,255,.12);">kvkk</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => {
            const name = [r.first_name, r.last_name].filter(Boolean).join(' ');
            const d = new Date(r.created_at);
            // simple local display using server TZ is hard; keep ISO-like but readable
            const t = d.toLocaleString('tr-TR', { timeZone: tz });
            return `
              <tr>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${r.id}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);white-space:nowrap;">${safe(t)}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${safe(r.event)}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${safe(name)}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${safe(r.phone || '')}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);white-space:nowrap;">${safe(r.client_mac || '')}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);white-space:nowrap;">${safe(r.client_ip || '')}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${safe(r.marker || '')}</td>
                <td style="padding:10px;border-bottom:1px solid rgba(255,255,255,.06);">${safe(r.kvkk_version || '')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;

  res.status(200).send(page('Admin Logs', `${head}${table}`));
});

app.get('/admin/logs.json', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '200', 10) || 200, 5000);
  const rows = await qRows(
    `SELECT * FROM access_logs ORDER BY id DESC LIMIT $1;`,
    [limit]
  );
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.status(200).send(JSON.stringify(rows));
});

app.get('/admin/daily', requireAdmin, (req, res) => {
  const today = new Date();
  const day = req.query.day || today.toISOString().slice(0, 10);
  const body = `
    <h1 style="margin:0 0 8px 0;">Daily</h1>
    <p class="muted">5651 için: günlük paket hash + zincir hash üretimi ve doğrulama.</p>
    <form method="GET" action="/admin/daily" class="row" style="margin:10px 0;">
      <input name="day" value="${safe(day)}" />
      <button type="submit">Seç</button>
    </form>

    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <a href="/admin/daily/build?day=${safe(day)}" style="display:inline-block;padding:10px 12px;border:1px solid rgba(255,255,255,.14);border-radius:10px;">Build</a>
      <a href="/admin/daily/verify?day=${safe(day)}" style="display:inline-block;padding:10px 12px;border:1px solid rgba(255,255,255,.14);border-radius:10px;">Verify</a>
      <a href="/admin/logs" style="display:inline-block;padding:10px 12px;border:1px solid rgba(255,255,255,.14);border-radius:10px;">Back</a>
    </div>
  `;
  res.status(200).send(page('Daily', body));
});

async function canonicalDailyRows(dayStr, tz) {
  // dayStr: YYYY-MM-DD
  // group by local date in tz using created_at at time zone tz
  const rows = await qRows(
    `SELECT id, created_at, event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_accepted, kvkk_version, base_grant_url, continue_url, meta
     FROM access_logs
     WHERE ((created_at AT TIME ZONE $2)::date = ($1::date))
     ORDER BY id ASC;`,
    [dayStr, tz]
  );

  // canonical line per row: stable key order
  const lines = rows.map(r => {
    const obj = {
      id: r.id,
      created_at: new Date(r.created_at).toISOString(),
      event: r.event || '',
      first_name: r.first_name || '',
      last_name: r.last_name || '',
      phone: r.phone || '',
      client_mac: r.client_mac || '',
      client_ip: r.client_ip || '',
      marker: r.marker || '',
      kvkk_accepted: (r.kvkk_accepted === true),
      kvkk_version: r.kvkk_version || '',
      base_grant_url: r.base_grant_url || '',
      continue_url: r.continue_url || '',
      meta: r.meta || {}
    };
    return JSON.stringify(obj);
  });

  const payload = lines.join('\n');
  return { rows, payload };
}

app.get('/admin/daily/build', requireAdmin, async (req, res) => {
  try {
    const day = (req.query.day || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
      return res.status(400).send('day must be YYYY-MM-DD');
    }
    const tz = (req.query.tz || ENV.TZ || 'Europe/Istanbul').toString();

    const { rows, payload } = await canonicalDailyRows(day, tz);
    const record_count = rows.length;
    const day_hash = sha256Hex(payload);

    // previous day (chain)
    const prev = await qRows(`SELECT day_hash, chain_hash FROM daily_chains WHERE day < $1::date ORDER BY day DESC LIMIT 1;`, [day]);
    const prev_day_hash = prev[0]?.day_hash || null;
    const prev_chain_hash = prev[0]?.chain_hash || '';

    const chain_hash = sha256Hex(`${prev_chain_hash}:${day_hash}`);
    const signed_hmac = ENV.DAILY_HMAC_KEY ? hmacHex(ENV.DAILY_HMAC_KEY, `${day}|${tz}|${record_count}|${day_hash}|${prev_day_hash || ''}|${chain_hash}`) : null;

    await qRows(
      `INSERT INTO daily_chains(day, tz, record_count, day_hash, prev_day_hash, chain_hash, signed_hmac)
       VALUES($1::date,$2,$3,$4,$5,$6,$7)
       ON CONFLICT(day) DO UPDATE SET
         tz=EXCLUDED.tz,
         record_count=EXCLUDED.record_count,
         day_hash=EXCLUDED.day_hash,
         prev_day_hash=EXCLUDED.prev_day_hash,
         chain_hash=EXCLUDED.chain_hash,
         signed_hmac=EXCLUDED.signed_hmac;`,
      [day, tz, record_count, day_hash, prev_day_hash, chain_hash, signed_hmac]
    );

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify({
      day,
      tz,
      record_count,
      day_hash,
      prev_day_hash,
      chain_hash,
      signed_hmac_set: !!signed_hmac
    }, null, 2) + `\n\n<a href="/admin/daily?day=${day}">Back</a>`);
  } catch (e) {
    console.log('daily build error', e);
    res.status(500).send(`daily build error: ${e?.message || e}`);
  }
});

app.get('/admin/daily/verify', requireAdmin, async (req, res) => {
  try {
    const day = (req.query.day || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
      return res.status(400).send('day must be YYYY-MM-DD');
    }
    const tz = (req.query.tz || ENV.TZ || 'Europe/Istanbul').toString();

    const stored = await qRows(`SELECT * FROM daily_chains WHERE day=$1::date LIMIT 1;`, [day]);
    if (!stored.length) {
      return res.status(404).send(`No daily_chains record for ${day}. Build first.`);
    }

    const { rows, payload } = await canonicalDailyRows(day, tz);
    const record_count = rows.length;
    const day_hash = sha256Hex(payload);

    const ok_day_hash = day_hash === stored[0].day_hash;
    const ok_count = record_count === stored[0].record_count;

    let ok_hmac = null;
    if (stored[0].signed_hmac) {
      if (!ENV.DAILY_HMAC_KEY) {
        ok_hmac = false; // cannot verify without key
      } else {
        const expected = hmacHex(ENV.DAILY_HMAC_KEY, `${day}|${stored[0].tz}|${stored[0].record_count}|${stored[0].day_hash}|${stored[0].prev_day_hash || ''}|${stored[0].chain_hash}`);
        ok_hmac = (expected === stored[0].signed_hmac);
      }
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(200).send(JSON.stringify({
      day,
      tz_requested: tz,
      stored_tz: stored[0].tz,
      stored_record_count: stored[0].record_count,
      computed_record_count: record_count,
      stored_day_hash: stored[0].day_hash,
      computed_day_hash: day_hash,
      ok_day_hash,
      ok_count,
      has_hmac: !!stored[0].signed_hmac,
      ok_hmac
    }, null, 2) + `\n\n<a href="/admin/daily?day=${day}">Back</a>`);
  } catch (e) {
    console.log('daily verify error', e);
    res.status(500).send(`daily verify error: ${e?.message || e}`);
  }
});

// Basic health
app.get('/health', (req, res) => res.status(200).send('ok'));

// -------------------- START --------------------
(async () => {
  try {
    await initDb();
    await initRedis();
    const port = parseInt(process.env.PORT || '8080', 10);
    app.listen(port, () => console.log(`Server running on port ${port}`));
  } catch (e) {
    console.error('BOOT ERROR:', e);
    process.exit(1);
  }
})();
