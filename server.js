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

  OTP_MODE: (process.env.OTP_MODE || 'screen').toLowerCase(),
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  RL_MAC_SECONDS: Number(process.env.RL_MAC_SECONDS || 30),
  RL_PHONE_SECONDS: Number(process.env.RL_PHONE_SECONDS || 60),

  KVKK_VERSION: process.env.KVKK_VERSION || '2026-02-12-placeholder',

  BRAND_NAME: process.env.BRAND_NAME || 'Guest Wi-Fi',
  COMPANY_LOGO_URL: process.env.COMPANY_LOGO_URL || '',

  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || '',
  DATABASE_URL: process.env.DATABASE_URL || '',

  // Public IP cache
  PUBLIC_IP_REFRESH_SECONDS: Number(process.env.PUBLIC_IP_REFRESH_SECONDS || 3600),
};

console.log('ENV:', {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
  RL_PHONE_SECONDS: ENV.RL_PHONE_SECONDS,
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
    console.log('REDIS: not configured. (Sessions will break across requests.)');
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
async function kvSetNX(key, value, ttlSeconds) {
  if (!redisReady) return false;
  const ok = await redis.set(key, value, { NX: true, EX: ttlSeconds });
  return ok === 'OK';
}

function hashShort(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 24);
}
function sessKey(mac) { return `sess:${hashShort(mac)}`; }
function rlMacKey(mac) { return `rl:mac:${hashShort(mac)}`; }
function rlPhoneKey(phone) { return `rl:ph:${hashShort(phone)}`; }
function lockKey(mac) { return `lock:${hashShort(mac)}`; }

/* =======================
 * POSTGRES (5651 logs) + migration
 * ======================= */
const pool = ENV.DATABASE_URL ? new Pool({ connectionString: ENV.DATABASE_URL }) : null;

async function initDatabase() {
  if (!pool) {
    console.log('DATABASE: not configured.');
    return;
  }
  await pool.query('SELECT 1');
  console.log('DATABASE: connected');

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
  for (const sql of alters) { try { await pool.query(sql); } catch (_) {} }

  console.log('DATABASE: table ready');
}

async function logDb(event, data = {}) {
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
 * Public IP (cached)
 * ======================= */
let cachedPublicIp = '';
let cachedPublicIpAt = 0;

async function fetchPublicIp() {
  try {
    // /ip returns plain text IP; avoids HTML noise
    const r = await fetch('https://ifconfig.me/ip', { method: 'GET' });
    const t = (await r.text()).trim();
    // naive validation
    if (t && t.length < 64) return t;
  } catch (_) {}
  return '';
}

async function getPublicIpCached() {
  const now = Date.now();
  if (cachedPublicIp && (now - cachedPublicIpAt) < ENV.PUBLIC_IP_REFRESH_SECONDS * 1000) {
    return cachedPublicIp;
  }
  const ip = await fetchPublicIp();
  if (ip) {
    cachedPublicIp = ip;
    cachedPublicIpAt = now;
    console.log('PUBLIC_IP:', cachedPublicIp);
  }
  return cachedPublicIp || '';
}

/* =======================
 * Helpers
 * ======================= */
function safeStr(x, max = 1600) {
  if (x == null) return '';
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function getClientIp(req, q) {
  const xf = req.headers['x-forwarded-for'];
  const fromHeader = (typeof xf === 'string' && xf.length) ? xf.split(',')[0].trim() : '';
  return safeStr(q?.client_ip || fromHeader || req.ip || '');
}

function requestMeta(req) {
  return {
    user_agent: safeStr(req.headers['user-agent'] || '', 400),
    accept_language: safeStr(req.headers['accept-language'] || '', 120),
    referer: safeStr(req.headers['referer'] || '', 400),
  };
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

function normalizePhoneTR(input) {
  const digits = (input || '').replace(/[^\d]/g, '');
  if (digits.length === 11 && digits.startsWith('0') && digits[1] === '5') return digits.slice(1);
  if (digits.length === 10 && digits.startsWith('5')) return digits;
  if (digits.length === 12 && digits.startsWith('90') && digits[2] === '5') return digits.slice(2);
  return digits;
}

function randOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/* =======================
 * UI
 * ======================= */
function kvkkPlaceholderHtml() {
  return `
  <strong>KVKK Aydınlatma Metni (Placeholder)</strong><br/>
  Bu metin şimdilik örnektir. Gerçek metin daha sonra eklenecek.<br/><br/>
  İşlenen veriler: Ad, Soyad, Telefon, MAC, IP, zaman damgaları.<br/>
  Amaç: Misafir internet erişimi + 5651 loglama.<br/>
  Versiyon: ${ENV.KVKK_VERSION}
  `;
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
    .card{max-width:520px;margin:0 auto;background:#fff;border-radius:18px;padding:18px;box-shadow:0 12px 32px rgba(0,0,0,.25)}
    h2{margin:0 0 6px 0}
    .mut{color:#6b7280;font-size:12px}
    input,button{width:100%;padding:12px 12px;border-radius:12px;border:1px solid #d1d5db;font-size:14px}
    button{border:0;background:#4f46e5;color:#fff;font-weight:800;cursor:pointer;margin-top:12px}
    button:disabled{opacity:.7;cursor:not-allowed}
    .otp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:34px;letter-spacing:4px;font-weight:900;
         text-align:center;padding:10px;border:1px dashed #9ca3af;border-radius:14px;background:#f9fafb;margin:10px 0}
    .ok{background:#ecfdf5;border:1px solid #86efac;color:#166534;padding:10px;border-radius:12px;margin-top:10px}
    .err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px;border-radius:12px;margin-top:10px}
    .row{display:flex;gap:10px}
    .row>div{flex:1}
    label{display:block;margin-top:10px;margin-bottom:6px;font-size:13px;color:#374151}
    .kvkk{border:1px solid #e5e7eb;border-radius:12px;padding:12px;background:#fafafa;max-height:170px;overflow:auto;font-size:12px;color:#4b5563}
    .topline{display:flex;align-items:center;justify-content:space-between;gap:12px}
    .badge{font-size:11px;color:#111;background:#eef2ff;border:1px solid #c7d2fe;border-radius:999px;padding:6px 10px}
  </style>
  </head><body><div class="card">${logo}${inner}</div></body></html>`;
}

/* =======================
 * Grant URL builder
 * ======================= */
function buildGrantUrl(baseGrantUrl, rawQuery, continueUrl) {
  const q = new URLSearchParams(rawQuery);
  q.delete('user_continue_url');
  q.delete('base_grant_url');
  q.delete('duration');
  if (continueUrl) q.set('continue_url', continueUrl);
  const qs = q.toString();
  if (!qs) return baseGrantUrl;
  const glue = baseGrantUrl.includes('?') ? '&' : '?';
  return baseGrantUrl + glue + qs;
}

/* =======================
 * Routes
 * ======================= */
app.get('/health', async (req, res) => {
  const publicIp = await getPublicIpCached();
  res.json({ ok: true, public_ip: publicIp || null });
});

app.get('/', async (req, res) => {
  const m = parseMeraki(req);
  const metaReq = requestMeta(req);
  const publicIp = await getPublicIpCached();

  console.log('SPLASH_OPEN', {
    hasBaseGrant: !!m.baseGrantUrl,
    hasContinue: !!m.continueUrl,
    hasClientMac: !!m.clientMac,
    mode: ENV.OTP_MODE
  });

  if (!m.baseGrantUrl || !m.clientMac) {
    await logDb('SPLASH_BAD_REQUEST', { meta: { missing: true, q: req.query || {}, ...metaReq, public_ip: publicIp } });
    return res.status(400).send(renderPage('Hata', `
      <h2>Eksik parametre</h2>
      <div class="err">base_grant_url / client_mac yok. Bu sayfa Meraki Splash üzerinden açılmalı.</div>
    `));
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
    meta: { rawQuery_len: m.rawQuery.length, ...metaReq, public_ip: publicIp }
  });

  res.send(renderPage('Giriş', `
    <div class="topline">
      <div>
        <h2>${safeStr(ENV.BRAND_NAME,60)}</h2>
        <div class="mut">Misafir internet erişimi</div>
      </div>
      <div class="badge">KVKK ${ENV.KVKK_VERSION}</div>
    </div>

    <form method="POST" action="/start" style="margin-top:14px" onsubmit="document.getElementById('btn').disabled=true;">
      <input type="hidden" name="client_mac" value="${m.clientMac}"/>

      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" required maxlength="50" autocomplete="given-name"/>
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" required maxlength="50" autocomplete="family-name"/>
        </div>
      </div>

      <label>Cep telefonu</label>
      <input name="phone" required maxlength="25" placeholder="05xx..." inputmode="tel" autocomplete="tel"/>

      <label>KVKK</label>
      <div class="kvkk">${kvkkPlaceholderHtml()}</div>

      <label style="display:flex;gap:10px;align-items:flex-start;margin-top:12px">
        <input type="checkbox" name="kvkk_accepted" value="1" required style="width:18px;height:18px;margin-top:3px"/>
        <span class="mut" style="font-size:13px;color:#374151">KVKK metnini okudum ve kabul ediyorum.</span>
      </label>

      <button id="btn" type="submit">Devam et</button>
      <div class="mut" style="margin-top:8px">Doğrulama kodu şimdilik ekranda gösterilir (SMS sonra).</div>
    </form>
  `));
});

app.post('/start', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).toLowerCase();
  const first_name = safeStr(req.body.first_name, 50).trim();
  const last_name = safeStr(req.body.last_name, 50).trim();
  const phone_raw = safeStr(req.body.phone, 25).trim();
  const phone = normalizePhoneTR(phone_raw);
  const kvkk_accepted = req.body.kvkk_accepted === '1';

  const sk = sessKey(client_mac);
  const sess = await kvGet(sk);
  if (!sess?.meraki?.baseGrantUrl) {
    await logDb('START_NO_SESSION', { client_mac, meta: { reason: 'no_session' } });
    return res.status(400).send(renderPage('Hata', `<h2>Oturum bulunamadı</h2><div class="err">Lütfen tekrar deneyin.</div>`));
  }

  const metaReq = requestMeta(req);
  const publicIp = await getPublicIpCached();

  const locked = await kvGet(lockKey(client_mac));
  if (locked) {
    return res.status(429).send(renderPage('Kilitli', `<h2>Çok fazla deneme</h2><div class="err">Lütfen biraz bekleyip tekrar deneyin.</div>`));
  }

  const macOk = await kvSetNX(rlMacKey(client_mac), '1', ENV.RL_MAC_SECONDS);
  const phOk = await kvSetNX(rlPhoneKey(phone || phone_raw), '1', ENV.RL_PHONE_SECONDS);
  if (!macOk || !phOk) {
    await logDb('OTP_RATE_LIMIT', {
      client_mac,
      client_ip: sess.meraki.clientIp,
      ssid: sess.meraki.ssid,
      ap_name: sess.meraki.apName,
      base_grant_url: sess.meraki.baseGrantUrl,
      continue_url: sess.meraki.continueUrl,
      meta: { by: !macOk ? 'mac' : 'phone', ...metaReq, public_ip: publicIp }
    });
    return res.status(429).send(renderPage('Yavaş', `
      <h2>Çok hızlı deneme</h2>
      <div class="err">Lütfen ${!macOk ? ENV.RL_MAC_SECONDS : ENV.RL_PHONE_SECONDS} saniye bekleyip tekrar deneyin.</div>
    `));
  }

  const otp = randOtp();
  const marker = String(Math.floor(100000 + Math.random() * 900000));
  const full_name = `${first_name} ${last_name}`.trim();

  sess.user = { first_name, last_name, full_name, phone, phone_raw, kvkk_accepted: !!kvkk_accepted, kvkk_version: ENV.KVKK_VERSION };
  sess.otp = { value: otp, marker, wrong: 0, expiresAt: Date.now() + ENV.OTP_TTL_SECONDS * 1000 };

  await kvSet(sk, sess, ENV.OTP_TTL_SECONDS);

  console.log('OTP_CREATED', { marker, last4: (phone || phone_raw).slice(-4), client_mac });

  await logDb('OTP_CREATED', {
    client_mac,
    client_ip: sess.meraki.clientIp,
    ssid: sess.meraki.ssid,
    ap_name: sess.meraki.apName,
    base_grant_url: sess.meraki.baseGrantUrl,
    continue_url: sess.meraki.continueUrl,
    marker,
    phone,
    full_name,
    kvkk_version: ENV.KVKK_VERSION,
    meta: { ...metaReq, public_ip: publicIp }
  });

  res.send(renderPage('OTP', `
    <h2>Doğrulama</h2>
    <div class="mut">SMS kapalı. Kod ekranda gösteriliyor.</div>
    <div class="otp">${otp}</div>

    <form method="POST" action="/verify" onsubmit="document.getElementById('btn2').disabled=true;">
      <input type="hidden" name="client_mac" value="${client_mac}"/>
      <label>Kodu girin</label>
      <input name="otp" required inputmode="numeric" maxlength="10" autocomplete="one-time-code"/>
      <button id="btn2" type="submit">Doğrula ve Bağlan</button>
    </form>
    <div class="mut" style="margin-top:10px">Kod süresi: ${ENV.OTP_TTL_SECONDS} saniye.</div>
  `));
});

app.post('/verify', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).toLowerCase();
  const otp_in = safeStr(req.body.otp, 10).trim();

  const sk = sessKey(client_mac);
  const sess = await kvGet(sk);
  if (!sess?.otp?.value || !sess?.meraki?.baseGrantUrl) {
    await logDb('VERIFY_NO_SESSION', { client_mac, meta: { reason: 'no_session_or_otp' } });
    return res.status(400).send(renderPage('Hata', `<h2>Oturum yok</h2><div class="err">Lütfen tekrar başlayın.</div>`));
  }

  const metaReq = requestMeta(req);
  const publicIp = await getPublicIpCached();

  if (Date.now() > sess.otp.expiresAt) {
    await logDb('OTP_EXPIRED', { client_mac, client_ip: sess.meraki.clientIp, marker: sess.otp.marker, meta: { ...metaReq, public_ip: publicIp } });
    await kvDel(sk);
    return res.status(400).send(renderPage('Süre doldu', `<h2>Kod süresi doldu</h2><div class="err">Lütfen tekrar deneyin.</div>`));
  }

  if (otp_in !== sess.otp.value) {
    sess.otp.wrong = Number(sess.otp.wrong || 0) + 1;

    await logDb('OTP_WRONG', { client_mac, client_ip: sess.meraki.clientIp, marker: sess.otp.marker, meta: { wrong: sess.otp.wrong, ...metaReq, public_ip: publicIp } });

    if (sess.otp.wrong >= ENV.MAX_WRONG_ATTEMPTS) {
      await kvSet(lockKey(client_mac), { at: Date.now() }, ENV.LOCK_SECONDS);
      await kvDel(sk);
      return res.status(429).send(renderPage('Kilitli', `<h2>Çok fazla hatalı deneme</h2><div class="err">${ENV.LOCK_SECONDS} saniye kilitlendi.</div>`));
    }

    await kvSet(sk, sess, Math.ceil((sess.otp.expiresAt - Date.now()) / 1000));
    return res.status(401).send(renderPage('Hatalı', `
      <h2>Hatalı kod</h2>
      <div class="err">Tekrar deneyin. (${sess.otp.wrong}/${ENV.MAX_WRONG_ATTEMPTS})</div>
      <form method="POST" action="/verify" onsubmit="document.getElementById('btn3').disabled=true;">
        <input type="hidden" name="client_mac" value="${client_mac}"/>
        <label>Kodu girin</label>
        <input name="otp" required inputmode="numeric" maxlength="10" autocomplete="one-time-code"/>
        <button id="btn3" type="submit">Tekrar Doğrula</button>
      </form>
    `));
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
    full_name: sess.user?.full_name,
    kvkk_version: ENV.KVKK_VERSION,
    meta: { ...metaReq, public_ip: publicIp }
  });

  const grantUrl = buildGrantUrl(sess.meraki.baseGrantUrl, sess.meraki.rawQuery, sess.meraki.continueUrl);
  console.log('GRANT_CLIENT_REDIRECT:', grantUrl);

  await logDb('GRANT_CLIENT_REDIRECT', {
    client_mac,
    client_ip: sess.meraki.clientIp,
    ssid: sess.meraki.ssid,
    ap_name: sess.meraki.apName,
    base_grant_url: sess.meraki.baseGrantUrl,
    continue_url: sess.meraki.continueUrl,
    marker: sess.otp.marker,
    phone: sess.user?.phone,
    full_name: sess.user?.full_name,
    kvkk_version: ENV.KVKK_VERSION,
    meta: { grantUrl, ...metaReq, public_ip: publicIp }
  });

  await kvDel(sk);

  const cont = sess.meraki.continueUrl || 'http://example.com';

  return res.status(200).send(renderPage('Bağlanıyor', `
    <h2>Bağlanılıyor…</h2>
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
  await getPublicIpCached(); // warm cache

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
