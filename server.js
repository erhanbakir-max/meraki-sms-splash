'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

let redisCreateClient = null;
try { ({ createClient: redisCreateClient } = require('redis')); } catch (_) {}

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* =======================
 * ENV
 * ======================= */
const ENV = {
  PORT: Number(process.env.PORT || 8080),

  // OTP
  OTP_MODE: (process.env.OTP_MODE || 'screen').toLowerCase(), // screen | sms (sms sonra)
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  // Security
  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  // UI / KVKK
  KVKK_VERSION: process.env.KVKK_VERSION || '2026-02-12-placeholder',
  BRAND_NAME: process.env.BRAND_NAME || 'Guest Wi-Fi',
  COMPANY_LOGO_URL: process.env.COMPANY_LOGO_URL || '',

  // Redis / Postgres
  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || '',
  DATABASE_URL: process.env.DATABASE_URL || '',
};

console.log('ENV:', {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS: ENV.LOCK_SECONDS,
  KVKK_VERSION: ENV.KVKK_VERSION,
});

/* =======================
 * REDIS
 * ======================= */
let redis = null;
let redisReady = false;

async function initRedis() {
  if (!ENV.REDIS_URL || !redisCreateClient) {
    console.log('REDIS: not configured.');
    return;
  }
  redis = redisCreateClient({ url: ENV.REDIS_URL });
  redis.on('error', (e) => console.error('REDIS ERROR:', e?.message || e));
  await redis.connect();
  redisReady = true;
  console.log('REDIS: connected');
}

async function kvSet(key, obj, ttlSeconds) {
  if (!redisReady) return;
  await redis.set(key, JSON.stringify(obj), { EX: ttlSeconds });
}
async function kvGet(key) {
  if (!redisReady) return null;
  const v = await redis.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvDel(key) {
  if (!redisReady) return;
  await redis.del(key);
}

function sessKey(mac) {
  const h = crypto.createHash('sha256').update(mac).digest('hex').slice(0, 24);
  return `sess:${h}`;
}

/* =======================
 * POSTGRES (5651 logs) + auto migration
 * ======================= */
const pool = ENV.DATABASE_URL ? new Pool({ connectionString: ENV.DATABASE_URL }) : null;

async function initDatabase() {
  if (!pool) {
    console.log('DATABASE: not configured.');
    return;
  }
  await pool.query('SELECT 1');
  console.log('DATABASE: connected');

  // Create if missing
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
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
      meta JSONB
    );
  `);

  // Auto-migrate older schemas safely
  const alters = [
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS client_mac TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS client_ip TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ssid TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS ap_name TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS base_grant_url TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS continue_url TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS marker TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS phone TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS full_name TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS kvkk_version TEXT;`,
    `ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS meta JSONB;`,
  ];
  for (const sql of alters) {
    try { await pool.query(sql); } catch (_) {}
  }

  console.log('DATABASE: table ready');
}

async function logDb(event, data) {
  if (!pool) return;
  try {
    await pool.query(
      `INSERT INTO access_logs(event, client_mac, client_ip, ssid, ap_name, base_grant_url, continue_url, marker, phone, full_name, kvkk_version, meta)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
      [
        event,
        data.client_mac || null,
        data.client_ip || null,
        data.ssid || null,
        data.ap_name || null,
        data.base_grant_url || null,
        data.continue_url || null,
        data.marker || null,
        data.phone || null,
        data.full_name || null,
        data.kvkk_version || ENV.KVKK_VERSION,
        JSON.stringify(data.meta || {}),
      ]
    );
  } catch (e) {
    console.error('DB LOG ERROR:', e?.message || e);
  }
}

/* =======================
 * Helpers
 * ======================= */
function safeStr(x, max = 1500) {
  if (x == null) return '';
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function getClientIp(req, q) {
  const xf = req.headers['x-forwarded-for'];
  const fromHeader = (typeof xf === 'string' && xf.length) ? xf.split(',')[0].trim() : '';
  return safeStr(q?.client_ip || fromHeader || req.ip || '');
}

function parseMeraki(req) {
  const q = req.query || {};
  return {
    baseGrantUrl: safeStr(q.base_grant_url || ''),
    continueUrl: safeStr(q.user_continue_url || q.continue_url || ''),
    clientMac: safeStr(q.client_mac || '').toLowerCase(),
    clientIp: getClientIp(req, q),
    ssid: safeStr(q.ssid_name || q.ssid || ''),
    apName: safeStr(q.ap_name || ''),
    rawQuery: req.originalUrl.includes('?') ? req.originalUrl.split('?').slice(1).join('?') : ''
  };
}

function randOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function renderPage(title, inner) {
  const logo = ENV.COMPANY_LOGO_URL
    ? `<div style="text-align:center;margin-bottom:10px"><img src="${safeStr(ENV.COMPANY_LOGO_URL,500)}" style="max-height:64px;max-width:240px"/></div>`
    : '';
  return `<!doctype html><html lang="tr"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${title}</title>
  <style>
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#111;padding:22px}
    .card{max-width:460px;margin:0 auto;background:#fff;border-radius:18px;padding:18px;box-shadow:0 12px 32px rgba(0,0,0,.25)}
    .mut{color:#6b7280;font-size:12px}
    input,button{width:100%;padding:12px 12px;border-radius:12px;border:1px solid #d1d5db;font-size:14px}
    button{border:0;background:#4f46e5;color:#fff;font-weight:700;cursor:pointer;margin-top:10px}
    .otp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:34px;letter-spacing:4px;font-weight:900;
         text-align:center;padding:10px;border:1px dashed #9ca3af;border-radius:14px;background:#f9fafb;margin:10px 0}
    .ok{background:#ecfdf5;border:1px solid #86efac;color:#166534;padding:10px;border-radius:12px;margin-top:10px}
    .err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px;border-radius:12px;margin-top:10px}
    .row{display:flex;gap:10px}
    .row>div{flex:1}
    label{display:block;margin-top:10px;margin-bottom:6px;font-size:13px;color:#374151}
    .kvkk{border:1px solid #e5e7eb;border-radius:12px;padding:12px;background:#fafafa;max-height:160px;overflow:auto;font-size:12px;color:#4b5563}
  </style>
  </head><body><div class="card">${logo}${inner}</div></body></html>`;
}

function kvkkPlaceholderHtml() {
  return `
  <strong>KVKK Metni (Placeholder)</strong><br/>
  Bu metin şimdilik örnektir. Gerçek metin daha sonra eklenecek.<br/><br/>
  İşlenen veriler: Ad, Soyad, Telefon, MAC, IP, zaman damgaları.<br/>
  Amaç: Misafir internet erişimi + 5651 loglama.<br/>
  Versiyon: ${ENV.KVKK_VERSION}
  `;
}

/* =======================
 * Grant URL builder
 * ======================= */
function buildGrantUrl(baseGrantUrl, rawQuery) {
  const q = new URLSearchParams(rawQuery);

  // Remove things that can break parsing or shouldn't be repeated
  q.delete('user_continue_url');
  q.delete('continue_url');
  q.delete('duration');
  q.delete('base_grant_url');

  const qs = q.toString();
  if (!qs) return baseGrantUrl;

  const glue = baseGrantUrl.includes('?') ? '&' : '?';
  return baseGrantUrl + glue + qs;
}

/* =======================
 * Routes
 * ======================= */
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/', async (req, res) => {
  const m = parseMeraki(req);

  console.log('SPLASH_OPEN', {
    hasBaseGrant: !!m.baseGrantUrl,
    hasContinue: !!m.continueUrl,
    hasClientMac: !!m.clientMac,
    mode: ENV.OTP_MODE
  });

  if (!m.baseGrantUrl || !m.clientMac) {
    return res.status(400).send(renderPage('Hata', `<h3>Eksik parametre</h3><div class="err">base_grant_url / client_mac yok.</div>`));
  }

  const sk = sessKey(m.clientMac);
  await kvSet(sk, { meraki: m, otp: null, user: null }, ENV.OTP_TTL_SECONDS);

  await logDb('SPLASH_OPEN', {
    client_mac: m.clientMac,
    client_ip: m.clientIp,
    ssid: m.ssid,
    ap_name: m.apName,
    base_grant_url: m.baseGrantUrl,
    continue_url: m.continueUrl,
    meta: { rawQuery_len: m.rawQuery.length }
  });

  res.send(renderPage('Giriş', `
    <h2 style="margin:0 0 6px 0">${safeStr(ENV.BRAND_NAME,60)}</h2>
    <div class="mut">Misafir internet erişimi</div>

    <form method="POST" action="/start" style="margin-top:12px">
      <input type="hidden" name="client_mac" value="${m.clientMac}"/>

      <label>Ad Soyad</label>
      <input name="full_name" required maxlength="120"/>

      <label>Cep telefonu</label>
      <input name="phone" required maxlength="25" placeholder="05xx..." inputmode="tel"/>

      <label>KVKK</label>
      <div class="kvkk">${kvkkPlaceholderHtml()}</div>

      <label style="display:flex;gap:10px;align-items:flex-start;margin-top:12px">
        <input type="checkbox" name="kvkk_accepted" value="1" required style="width:18px;height:18px;margin-top:3px"/>
        <span class="mut" style="font-size:13px;color:#374151">KVKK metnini okudum ve kabul ediyorum.</span>
      </label>

      <button type="submit">Devam et</button>
    </form>
  `));
});

app.post('/start', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).toLowerCase();
  const full_name = safeStr(req.body.full_name, 120).trim();
  const phone = safeStr(req.body.phone, 25).trim();
  const kvkk_accepted = req.body.kvkk_accepted === '1';

  const sk = sessKey(client_mac);
  const sess = await kvGet(sk);
  if (!sess?.meraki?.baseGrantUrl) {
    return res.status(400).send(renderPage('Hata', `<h3>Oturum yok</h3><div class="err">Tekrar başlayın.</div>`));
  }

  const otp = randOtp();
  const marker = String(Math.floor(100000 + Math.random() * 900000));

  sess.user = { full_name, phone, kvkk_accepted: !!kvkk_accepted, kvkk_version: ENV.KVKK_VERSION };
  sess.otp = { otp, marker, expiresAt: Date.now() + ENV.OTP_TTL_SECONDS * 1000 };

  await kvSet(sk, sess, ENV.OTP_TTL_SECONDS);

  console.log('OTP_CREATED', { marker, last4: phone.slice(-4), client_mac });

  await logDb('OTP_CREATED', {
    client_mac,
    client_ip: sess.meraki.clientIp,
    ssid: sess.meraki.ssid,
    ap_name: sess.meraki.apName,
    base_grant_url: sess.meraki.baseGrantUrl,
    continue_url: sess.meraki.continueUrl,
    marker,
    phone,
    full_name
  });

  res.send(renderPage('OTP', `
    <h2 style="margin:0 0 6px 0">Doğrulama</h2>
    <div class="mut">SMS kapalı. Kod ekranda gösteriliyor.</div>
    <div class="otp">${otp}</div>

    <form method="POST" action="/verify">
      <input type="hidden" name="client_mac" value="${client_mac}"/>
      <label>Kodu girin</label>
      <input name="otp" required inputmode="numeric" maxlength="10"/>
      <button type="submit">Doğrula ve Bağlan</button>
    </form>
  `));
});

app.post('/verify', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).toLowerCase();
  const otp_in = safeStr(req.body.otp, 10).trim();

  const sk = sessKey(client_mac);
  const sess = await kvGet(sk);
  if (!sess?.otp?.otp || !sess?.meraki?.baseGrantUrl) {
    return res.status(400).send(renderPage('Hata', `<h3>Oturum yok</h3><div class="err">Tekrar başlayın.</div>`));
  }

  if (Date.now() > sess.otp.expiresAt) {
    await kvDel(sk);
    return res.status(400).send(renderPage('Süre doldu', `<h3>Kod süresi doldu</h3><div class="err">Tekrar deneyin.</div>`));
  }

  if (otp_in !== sess.otp.otp) {
    return res.status(401).send(renderPage('Hatalı', `<h3>Hatalı OTP</h3><div class="err">Tekrar deneyin.</div>`));
  }

  console.log('OTP_VERIFY_OK', { marker: sess.otp.marker, client_mac });

  await logDb('OTP_VERIFIED', {
    client_mac,
    client_ip: sess.meraki.clientIp,
    ssid: sess.meraki.ssid,
    ap_name: sess.meraki.apName,
    base_grant_url: sess.meraki.baseGrantUrl,
    continue_url: sess.meraki.continueUrl,
    marker: sess.otp.marker,
    phone: sess.user?.phone,
    full_name: sess.user?.full_name
  });

  // IMPORTANT FIX:
  // network-auth.com grant returns 400 when called server-side (needs browser session/cookies).
  // So we redirect the CLIENT browser to grantUrl.
  const grantUrl = buildGrantUrl(sess.meraki.baseGrantUrl, sess.meraki.rawQuery);

  console.log('GRANT_CLIENT_REDIRECT:', grantUrl);

  await logDb('GRANT_CLIENT_REDIRECT', {
    client_mac,
    client_ip: sess.meraki.clientIp,
    base_grant_url: sess.meraki.baseGrantUrl,
    continue_url: sess.meraki.continueUrl,
    marker: sess.otp.marker,
    meta: { grantUrl }
  });

  // cleanup (optional)
  await kvDel(sk);

  const cont = sess.meraki.continueUrl || 'http://example.com';

  return res.status(200).send(renderPage('Bağlanıyor', `
    <h3>Bağlanılıyor…</h3>
    <div class="ok">İzin veriliyor (Meraki Grant).</div>
    <div class="mut">Yönlendirme olmazsa 2 saniye içinde devam sayfasına geçeceğiz.</div>

    <script>
      window.location.href = ${JSON.stringify(grantUrl)};
      setTimeout(() => { window.location.href = ${JSON.stringify(cont)}; }, 2000);
    </script>

    <div class="mut" style="margin-top:10px">Yönlendirme olmazsa:</div>
    <a href="${grantUrl}">Grant linki</a><br/>
    <a href="${cont}">Devam linki</a>
  `));
});

/* =======================
 * START
 * ======================= */
(async () => {
  await initDatabase();
  await initRedis();

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
