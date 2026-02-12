/* meraki-sms-splash - server.js
 * Features:
 * - Meraki Captive Portal (custom splash URL)
 * - OTP_MODE=screen (OTP shown on screen; SMS disabled)
 * - Redis store for OTP sessions (fallback memory store if Redis not set)
 * - Postgres (Railway) access_logs table auto-create + 5651-style logging
 * - KVKK placeholder HTML + mandatory consent checkbox
 * - Clean UI (single page)
 */

'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

let redisCreateClient = null;
try {
  // optional dependency; if not installed you can remove redis usage
  ({ createClient: redisCreateClient } = require('redis'));
} catch (_) {
  // ignore
}

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/** ---------------------------
 * ENV / CONFIG
 * --------------------------- */
const ENV = {
  PORT: Number(process.env.PORT || 8080),

  // OTP behavior
  OTP_MODE: (process.env.OTP_MODE || 'screen').toLowerCase(), // screen | sms (sms disabled for now)
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  // Rate limits / lock
  RL_MAC_SECONDS: Number(process.env.RL_MAC_SECONDS || 30),
  RL_MSISDN_SECONDS: Number(process.env.RL_MSISDN_SECONDS || 60),
  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  // Branding / UI
  BRAND_NAME: process.env.BRAND_NAME || 'Guest Wi-Fi',
  COMPANY_LOGO_URL: process.env.COMPANY_LOGO_URL || '', // optional
  KVKK_VERSION: process.env.KVKK_VERSION || 'v0-placeholder',

  // Storage
  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || '',
  DATABASE_URL: process.env.DATABASE_URL || '',

  // Optional: if you want to force allow even when meraki params missing (dev)
  DEV_ALLOW_NO_MERAKI: (process.env.DEV_ALLOW_NO_MERAKI || '0') === '1',
};

console.log('ENV:', {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
  RL_MSISDN_SECONDS: ENV.RL_MSISDN_SECONDS,
  MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS: ENV.LOCK_SECONDS,
  KVKK_VERSION: ENV.KVKK_VERSION,
});

/** ---------------------------
 * REDIS (optional)
 * --------------------------- */
let redis = null;
let redisReady = false;

// in-memory fallback store (works but NOT persistent)
const memStore = new Map();

async function initRedis() {
  if (!ENV.REDIS_URL || !redisCreateClient) {
    console.log('REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing). Using memory store.');
    return;
  }

  try {
    redis = redisCreateClient({ url: ENV.REDIS_URL });
    redis.on('error', (e) => console.error('REDIS ERROR:', e?.message || e));
    await redis.connect();
    redisReady = true;
    console.log('REDIS: connected');
  } catch (e) {
    console.error('REDIS: connect failed -> falling back to memory store:', e?.message || e);
    redis = null;
    redisReady = false;
  }
}

async function kvSet(key, valueObj, ttlSeconds) {
  const v = JSON.stringify(valueObj);
  if (redisReady && redis) {
    await redis.set(key, v, { EX: ttlSeconds });
    return;
  }
  memStore.set(key, { v, exp: Date.now() + ttlSeconds * 1000 });
}

async function kvGet(key) {
  if (redisReady && redis) {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  const item = memStore.get(key);
  if (!item) return null;
  if (Date.now() > item.exp) {
    memStore.delete(key);
    return null;
  }
  return JSON.parse(item.v);
}

async function kvDel(key) {
  if (redisReady && redis) {
    await redis.del(key);
    return;
  }
  memStore.delete(key);
}

/** ---------------------------
 * POSTGRES (optional but recommended)
 * --------------------------- */
const pool = ENV.DATABASE_URL ? new Pool({ connectionString: ENV.DATABASE_URL }) : null;

async function initDatabase() {
  if (!pool) {
    console.log('DATABASE: not configured (DATABASE_URL missing).');
    return;
  }

  try {
    await pool.query('SELECT 1');
    console.log('DATABASE: connected');

    // Basic access logs table (5651-style event logging)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS access_logs (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT now(),
        event TEXT DEFAULT 'LOGIN',
        first_name TEXT,
        last_name TEXT,
        phone TEXT,
        kvkk_accepted BOOLEAN DEFAULT false,
        kvkk_version TEXT,
        marker TEXT,
        client_mac TEXT,
        client_ip INET,
        ssid TEXT,
        ap_name TEXT,
        base_grant_url TEXT,
        user_continue_url TEXT,
        user_agent TEXT,
        extra JSONB
      );
    `);

    // Helpful indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_access_logs_client_mac ON access_logs(client_mac);`);
    console.log('DATABASE: table ready');
  } catch (err) {
    console.error('DATABASE ERROR:', err?.message || err);
  }
}

async function logAccess(event, data) {
  if (!pool) return;

  const payload = {
    event: event || 'LOGIN',
    first_name: data.first_name || null,
    last_name: data.last_name || null,
    phone: data.phone || null,
    kvkk_accepted: !!data.kvkk_accepted,
    kvkk_version: data.kvkk_version || ENV.KVKK_VERSION,
    marker: data.marker || null,
    client_mac: data.client_mac || null,
    client_ip: data.client_ip || null,
    ssid: data.ssid || null,
    ap_name: data.ap_name || null,
    base_grant_url: data.base_grant_url || null,
    user_continue_url: data.user_continue_url || null,
    user_agent: data.user_agent || null,
    extra: data.extra ? JSON.stringify(data.extra) : null,
  };

  try {
    await pool.query(
      `
      INSERT INTO access_logs (
        event, first_name, last_name, phone, kvkk_accepted, kvkk_version,
        marker, client_mac, client_ip, ssid, ap_name, base_grant_url, user_continue_url, user_agent, extra
      ) VALUES (
        $1,$2,$3,$4,$5,$6,
        $7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb
      )
      `,
      [
        payload.event,
        payload.first_name,
        payload.last_name,
        payload.phone,
        payload.kvkk_accepted,
        payload.kvkk_version,
        payload.marker,
        payload.client_mac,
        payload.client_ip,
        payload.ssid,
        payload.ap_name,
        payload.base_grant_url,
        payload.user_continue_url,
        payload.user_agent,
        payload.extra,
      ]
    );
  } catch (e) {
    console.error('DB LOG ERROR:', e?.message || e);
  }
}

/** ---------------------------
 * Helpers
 * --------------------------- */
function randOtp() {
  // 6 digits
  return String(Math.floor(100000 + Math.random() * 900000));
}

function maskPhone(phone) {
  if (!phone) return '';
  const digits = String(phone).replace(/\D/g, '');
  if (digits.length < 4) return '****';
  return '****' + digits.slice(-4);
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length > 0) return xf.split(',')[0].trim();
  return req.ip || null;
}

function safeStr(x, max = 512) {
  if (x == null) return '';
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function parseMerakiParams(req) {
  // Meraki sends these as query params to the Custom Splash URL.
  // Common ones: base_grant_url, user_continue_url, client_mac, client_ip, ssid_name, ap_name
  const q = req.query || {};
  const baseGrantUrl = safeStr(q.base_grant_url || '');
  const continueUrl = safeStr(q.user_continue_url || q.continue_url || '');
  const clientMac = safeStr(q.client_mac || q.clientMac || '');
  const clientIp = safeStr(q.client_ip || q.clientIp || '');
  const ssid = safeStr(q.ssid_name || q.ssid || '');
  const apName = safeStr(q.ap_name || q.apName || '');

  const hasBaseGrant = !!baseGrantUrl;
  const hasContinue = !!continueUrl;
  const hasClientMac = !!clientMac;

  return {
    baseGrantUrl,
    continueUrl,
    clientMac,
    clientIp,
    ssid,
    apName,
    hasBaseGrant,
    hasContinue,
    hasClientMac,
  };
}

function sessionKeyFrom(clientMac) {
  // keep keys compact
  const h = crypto.createHash('sha256').update(clientMac).digest('hex').slice(0, 24);
  return `sess:${h}`;
}

/** ---------------------------
 * UI HTML
 * --------------------------- */
function renderPage({ title, body }) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    :root {
      --bg: #0b0b12;
      --card: rgba(255,255,255,0.06);
      --border: rgba(255,255,255,0.12);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.66);
      --accent: #7c3aed;
      --danger: #ef4444;
      --ok: #22c55e;
      --shadow: 0 18px 60px rgba(0,0,0,.45);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color: var(--text); background: radial-gradient(1200px 900px at 30% 10%, #1a1030 0%, rgba(26,16,48,0) 55%),
      radial-gradient(900px 600px at 80% 20%, #102a3a 0%, rgba(16,42,58,0) 55%),
      var(--bg);
      min-height: 100vh; display: grid; place-items: center; padding: 28px 14px;
    }
    .wrap { width: 100%; max-width: 520px; }
    .brand { display:flex; align-items:center; gap: 12px; margin-bottom: 16px; }
    .brand img { width: 44px; height: 44px; border-radius: 12px; object-fit: cover; border: 1px solid var(--border); }
    .brand .t1 { font-size: 18px; font-weight: 700; line-height: 1.1; }
    .brand .t2 { font-size: 13px; color: var(--muted); margin-top: 4px; }
    .card {
      background: var(--card); border: 1px solid var(--border); border-radius: 18px;
      box-shadow: var(--shadow); padding: 18px;
      backdrop-filter: blur(8px);
    }
    h1 { font-size: 18px; margin: 0 0 6px; }
    p { margin: 0 0 14px; color: var(--muted); font-size: 13px; line-height: 1.45; }
    .row { display:flex; gap: 10px; }
    .row > div { flex: 1; }
    label { display:block; font-size: 12px; color: var(--muted); margin: 12px 0 6px; }
    input, button, textarea {
      width: 100%; border-radius: 12px; border: 1px solid var(--border);
      background: rgba(0,0,0,0.18); color: var(--text);
      padding: 12px 12px; outline: none; font-size: 14px;
    }
    textarea { min-height: 120px; resize: vertical; }
    input:focus, textarea:focus { border-color: rgba(124,58,237,.6); box-shadow: 0 0 0 4px rgba(124,58,237,.18); }
    .btn {
      margin-top: 14px; background: linear-gradient(135deg, rgba(124,58,237,1), rgba(59,130,246,1));
      border: none; cursor: pointer; font-weight: 700;
    }
    .btn:active { transform: translateY(1px); }
    .mut { font-size: 12px; color: var(--muted); margin-top: 12px; }
    .err { color: #fecaca; background: rgba(239,68,68,.12); border: 1px solid rgba(239,68,68,.3); padding: 10px 12px; border-radius: 12px; margin-top: 10px; }
    .ok { color: #bbf7d0; background: rgba(34,197,94,.12); border: 1px solid rgba(34,197,94,.3); padding: 10px 12px; border-radius: 12px; margin-top: 10px; }
    .kvkkbox {
      margin-top: 10px;
      padding: 12px; border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(0,0,0,0.14);
      max-height: 180px; overflow: auto;
      font-size: 12px; color: var(--muted); line-height: 1.5;
    }
    .check {
      display:flex; gap: 10px; align-items:flex-start; margin-top: 12px;
      padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border);
      background: rgba(0,0,0,0.14);
    }
    .check input { width: 18px; height: 18px; margin-top: 2px; }
    .check span { font-size: 12px; color: var(--muted); }
    .otp {
      margin-top: 12px;
      padding: 12px; border-radius: 12px;
      border: 1px dashed rgba(124,58,237,.55);
      background: rgba(124,58,237,.10);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 22px; letter-spacing: 3px; text-align: center;
    }
    .small { font-size: 12px; color: var(--muted); margin-top: 8px; }
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
    <div class="mut" style="text-align:center;margin-top:14px;opacity:.75">
      ${safeStr(ENV.BRAND_NAME, 80)} • KVKK ${safeStr(ENV.KVKK_VERSION, 40)}
    </div>
  </div>
</body>
</html>`;
}

function kvkkPlaceholderHtml() {
  return `
  <strong>KVKK Aydınlatma Metni (Placeholder)</strong><br/>
  Bu metin şimdilik örnek/placeholder olarak eklenmiştir.<br/><br/>
  - İşlenen veriler: Ad, Soyad, Telefon, MAC, IP, bağlantı zaman damgaları.<br/>
  - Amaç: Misafir internet erişiminin sağlanması ve yasal loglama (5651).<br/>
  - Saklama: Yasal süreler boyunca güvenli biçimde.<br/><br/>
  Gerçek metin daha sonra şirket hukuk ekibi tarafından sağlanacaktır.
  `;
}

/** ---------------------------
 * Routes
 * --------------------------- */

// Health
app.get('/health', (req, res) => res.status(200).json({ ok: true }));

// Main Splash
app.get('/', async (req, res) => {
  const m = parseMerakiParams(req);
  console.log('SPLASH_OPEN', { hasBaseGrant: m.hasBaseGrant, hasContinue: m.hasContinue, hasClientMac: m.hasClientMac, mode: ENV.OTP_MODE });

  // if not coming from Meraki and not allowed in dev
  if ((!m.hasBaseGrant || !m.hasClientMac) && !ENV.DEV_ALLOW_NO_MERAKI) {
    return res.status(400).send(
      renderPage({
        title: 'Invalid Request',
        body: `
          <div class="card">
            <h1>Geçersiz istek</h1>
            <p>Bu sayfa Meraki Captive Portal üzerinden açılmalıdır.</p>
            <div class="err">base_grant_url / client_mac eksik görünüyor.</div>
          </div>
        `,
      })
    );
  }

  // Store meraki params tied to MAC
  if (m.clientMac) {
    const sk = sessionKeyFrom(m.clientMac);
    await kvSet(
      sk,
      {
        meraki: {
          baseGrantUrl: m.baseGrantUrl,
          continueUrl: m.continueUrl,
          clientMac: m.clientMac,
          clientIp: m.clientIp,
          ssid: m.ssid,
          apName: m.apName,
        },
        state: 'OPEN',
        createdAt: Date.now(),
      },
      ENV.OTP_TTL_SECONDS
    );
  }

  const logo = ENV.COMPANY_LOGO_URL
    ? `<img src="${safeStr(ENV.COMPANY_LOGO_URL, 400)}" alt="logo" />`
    : `<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Crect rx='24' width='120' height='120' fill='%237c3aed'/%3E%3Ctext x='50%25' y='56%25' font-size='56' text-anchor='middle' fill='white' font-family='Arial'%3EWi%3C/text%3E%3C/svg%3E" alt="logo"/>`;

  const body = `
    <div class="brand">
      ${logo}
      <div>
        <div class="t1">${safeStr(ENV.BRAND_NAME, 80)}</div>
        <div class="t2">Misafir internet erişimi</div>
      </div>
    </div>

    <div class="card">
      <h1>Giriş</h1>
      <p>Lütfen bilgilerinizi girin ve KVKK metnini onaylayın. Ardından doğrulama kodu ile internete bağlanacaksınız.</p>

      <form method="POST" action="/start">
        <input type="hidden" name="client_mac" value="${safeStr(m.clientMac)}" />

        <div class="row">
          <div>
            <label>Ad</label>
            <input name="first_name" autocomplete="given-name" required maxlength="50" />
          </div>
          <div>
            <label>Soyad</label>
            <input name="last_name" autocomplete="family-name" required maxlength="50" />
          </div>
        </div>

        <label>Cep telefonu</label>
        <input name="phone" inputmode="tel" placeholder="05xx xxx xx xx" required maxlength="25" />

        <label>KVKK Aydınlatma Metni</label>
        <div class="kvkkbox">${kvkkPlaceholderHtml()}</div>

        <div class="check">
          <input type="checkbox" name="kvkk_accepted" value="1" required />
          <span>KVKK aydınlatma metnini okudum ve onaylıyorum.</span>
        </div>

        <button class="btn" type="submit">Devam et</button>
      </form>

      <div class="mut">
        Bilgiler güvenli şekilde saklanır. (5651 log kaydı tutulur.)
      </div>
    </div>
  `;

  res.status(200).send(renderPage({ title: 'Guest Wi-Fi', body }));
});

// Start: create OTP
app.post('/start', async (req, res) => {
  const first_name = safeStr(req.body.first_name, 50).trim();
  const last_name = safeStr(req.body.last_name, 50).trim();
  const phone = safeStr(req.body.phone, 25).trim();
  const kvkk_accepted = req.body.kvkk_accepted === '1';

  // Meraki MAC is required
  const client_mac = safeStr(req.body.client_mac, 64).trim();

  if (!first_name || !last_name || !phone || !kvkk_accepted) {
    return res.status(400).send(
      renderPage({
        title: 'Hata',
        body: `
          <div class="card">
            <h1>Eksik bilgi</h1>
            <p>Lütfen tüm alanları doldurun ve KVKK onayını işaretleyin.</p>
            <a href="/" style="color: var(--accent); text-decoration:none;">Geri dön</a>
          </div>
        `,
      })
    );
  }

  if (!client_mac && !ENV.DEV_ALLOW_NO_MERAKI) {
    return res.status(400).send(
      renderPage({
        title: 'Hata',
        body: `<div class="card"><h1>Hata</h1><div class="err">client_mac bulunamadı.</div></div>`,
      })
    );
  }

  const otp = randOtp();
  const marker = String(Math.floor(100000 + Math.random() * 900000)); // tracking id

  // load existing session (meraki params)
  const sk = sessionKeyFrom(client_mac || ('dev-' + crypto.randomUUID()));
  const sess = (await kvGet(sk)) || {};
  const meraki = sess.meraki || {};

  const newSess = {
    meraki,
    user: { first_name, last_name, phone, kvkk_accepted: true, kvkk_version: ENV.KVKK_VERSION },
    otp: {
      marker,
      value: otp,
      wrong: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + ENV.OTP_TTL_SECONDS * 1000,
      verified: false,
    },
    state: 'OTP_CREATED',
    createdAt: sess.createdAt || Date.now(),
  };

  await kvSet(sk, newSess, ENV.OTP_TTL_SECONDS);

  console.log('OTP_CREATED', { marker, last4: maskPhone(phone).replace('****', ''), client_mac });

  // SMS disabled -> show OTP on screen
  const logo = ENV.COMPANY_LOGO_URL
    ? `<img src="${safeStr(ENV.COMPANY_LOGO_URL, 400)}" alt="logo" />`
    : '';

  const body = `
    <div class="brand">
      ${logo || ''}
      <div>
        <div class="t1">${safeStr(ENV.BRAND_NAME, 80)}</div>
        <div class="t2">Doğrulama</div>
      </div>
    </div>

    <div class="card">
      <h1>Doğrulama Kodu</h1>
      <p>SMS devre dışı. Kod ekranda gösteriliyor.</p>

      <div class="otp">${otp}</div>
      <div class="small">Bu kod ${ENV.OTP_TTL_SECONDS} saniye geçerlidir.</div>

      <form method="POST" action="/verify">
        <input type="hidden" name="client_mac" value="${safeStr(client_mac)}" />
        <label>Kodu girin</label>
        <input name="otp" inputmode="numeric" autocomplete="one-time-code" required maxlength="10" />
        <button class="btn" type="submit">Doğrula</button>
      </form>
    </div>
  `;

  res.status(200).send(renderPage({ title: 'OTP', body }));
});

// Verify OTP
app.post('/verify', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).trim();
  const otp_in = safeStr(req.body.otp, 10).trim();

  if (!client_mac && !ENV.DEV_ALLOW_NO_MERAKI) {
    return res.status(400).send(renderPage({ title: 'Hata', body: `<div class="card"><div class="err">client_mac yok</div></div>` }));
  }

  const sk = sessionKeyFrom(client_mac || ('dev-' + crypto.randomUUID()));
  const sess = await kvGet(sk);
  if (!sess || !sess.otp) {
    return res.status(400).send(
      renderPage({
        title: 'Süre doldu',
        body: `<div class="card"><h1>Süre doldu</h1><p>Oturum bulunamadı. Lütfen tekrar başlayın.</p><a href="/" style="color:var(--accent);text-decoration:none;">Başa dön</a></div>`,
      })
    );
  }

  // expired
  if (Date.now() > sess.otp.expiresAt) {
    await kvDel(sk);
    return res.status(400).send(
      renderPage({
        title: 'Süre doldu',
        body: `<div class="card"><h1>Kod süresi doldu</h1><p>Lütfen tekrar deneyin.</p><a href="/" style="color:var(--accent);text-decoration:none;">Başa dön</a></div>`,
      })
    );
  }

  if (otp_in !== sess.otp.value) {
    sess.otp.wrong = (sess.otp.wrong || 0) + 1;
    await kvSet(sk, sess, Math.ceil((sess.otp.expiresAt - Date.now()) / 1000));

    if (sess.otp.wrong >= ENV.MAX_WRONG_ATTEMPTS) {
      await kvDel(sk);
      return res.status(400).send(
        renderPage({
          title: 'Kilit',
          body: `<div class="card"><h1>Çok fazla deneme</h1><p>Lütfen daha sonra tekrar deneyin.</p></div>`,
        })
      );
    }

    return res.status(400).send(
      renderPage({
        title: 'Hatalı kod',
        body: `
          <div class="card">
            <h1>Hatalı kod</h1>
            <p>Lütfen tekrar deneyin. (${sess.otp.wrong}/${ENV.MAX_WRONG_ATTEMPTS})</p>
            <form method="POST" action="/verify">
              <input type="hidden" name="client_mac" value="${safeStr(client_mac)}" />
              <label>Kodu girin</label>
              <input name="otp" inputmode="numeric" required maxlength="10" />
              <button class="btn" type="submit">Doğrula</button>
            </form>
          </div>
        `,
      })
    );
  }

  // OK
  sess.otp.verified = true;
  sess.state = 'OTP_VERIFIED';
  await kvSet(sk, sess, Math.ceil((sess.otp.expiresAt - Date.now()) / 1000));

  console.log('OTP_VERIFY_OK', { marker: sess.otp.marker, client_mac });

  // Next step: grant access
  const body = `
    <div class="card">
      <h1>Doğrulandı</h1>
      <p>Bağlantı izni veriliyor…</p>
      <form method="POST" action="/grant">
        <input type="hidden" name="client_mac" value="${safeStr(client_mac)}" />
        <button class="btn" type="submit">Bağlan</button>
      </form>
      <div class="mut">Butona basınca internet erişiminiz aktif olur.</div>
    </div>
  `;
  res.status(200).send(renderPage({ title: 'Verified', body }));
});

// Grant access via Meraki base_grant_url
app.post('/grant', async (req, res) => {
  const client_mac = safeStr(req.body.client_mac, 64).trim();
  const sk = sessionKeyFrom(client_mac || ('dev-' + crypto.randomUUID()));
  const sess = await kvGet(sk);

  if (!sess || !sess.otp?.verified) {
    return res.status(400).send(
      renderPage({
        title: 'Hata',
        body: `<div class="card"><h1>Hata</h1><div class="err">Önce doğrulama yapılmalı.</div></div>`,
      })
    );
  }

  const meraki = sess.meraki || {};
  const user = sess.user || {};

  // Log attempt
  await logAccess('OTP_VERIFIED', {
    first_name: user.first_name,
    last_name: user.last_name,
    phone: user.phone,
    kvkk_accepted: true,
    kvkk_version: user.kvkk_version,
    marker: sess.otp.marker,
    client_mac: meraki.clientMac || client_mac,
    client_ip: meraki.clientIp || getClientIp(req),
    ssid: meraki.ssid,
    ap_name: meraki.apName,
    base_grant_url: meraki.baseGrantUrl,
    user_continue_url: meraki.continueUrl,
    user_agent: safeStr(req.headers['user-agent'], 300),
    extra: { mode: ENV.OTP_MODE },
  });

  // If no Meraki params (dev)
  if ((!meraki.baseGrantUrl || !meraki.clientMac) && ENV.DEV_ALLOW_NO_MERAKI) {
    await kvDel(sk);
    return res.status(200).send(
      renderPage({
        title: 'Dev OK',
        body: `<div class="card"><h1>Dev mod</h1><div class="ok">Meraki olmadan tamamlandı.</div></div>`,
      })
    );
  }

  if (!meraki.baseGrantUrl) {
    return res.status(400).send(
      renderPage({
        title: 'Hata',
        body: `<div class="card"><h1>Hata</h1><div class="err">base_grant_url eksik.</div></div>`,
      })
    );
  }

  // Meraki grant: call base_grant_url with continue_url
  // Usually: base_grant_url?continue_url=<...>
  // Some deployments also require "duration", "redirect_url" etc.
  let grantUrl = meraki.baseGrantUrl;

  try {
    const u = new URL(grantUrl);
    if (meraki.continueUrl) u.searchParams.set('continue_url', meraki.continueUrl);
    // you can optionally set session duration:
    // u.searchParams.set('duration', '3600'); // seconds
    grantUrl = u.toString();
  } catch (_) {
    // if base_grant_url is not a full URL, just append
    if (meraki.continueUrl) {
      const glue = grantUrl.includes('?') ? '&' : '?';
      grantUrl = `${grantUrl}${glue}continue_url=${encodeURIComponent(meraki.continueUrl)}`;
    }
  }

  try {
    const r = await fetch(grantUrl, { method: 'GET' });
    const txt = await r.text();

    // Log success-ish
    await logAccess('GRANT_CALLED', {
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      kvkk_accepted: true,
      kvkk_version: user.kvkk_version,
      marker: sess.otp.marker,
      client_mac: meraki.clientMac || client_mac,
      client_ip: meraki.clientIp || getClientIp(req),
      ssid: meraki.ssid,
      ap_name: meraki.apName,
      base_grant_url: meraki.baseGrantUrl,
      user_continue_url: meraki.continueUrl,
      user_agent: safeStr(req.headers['user-agent'], 300),
      extra: { http_status: r.status },
    });

    // cleanup session
    await kvDel(sk);

    // If Meraki returns a redirect HTML or JSON; best is to send user to continue_url
    if (meraki.continueUrl) {
      return res.redirect(302, meraki.continueUrl);
    }

    // fallback display
    return res.status(200).send(
      renderPage({
        title: 'Bağlandı',
        body: `
          <div class="card">
            <h1>Bağlantı sağlandı</h1>
            <div class="ok">Erişim izni verildi.</div>
            <div class="mut">Meraki yanıtı (kısaltılmış):</div>
            <pre style="white-space:pre-wrap;word-break:break-word;color:var(--muted);font-size:12px;margin-top:10px">${safeStr(txt, 1200)}</pre>
          </div>
        `,
      })
    );
  } catch (e) {
    console.error('GRANT ERROR:', e?.message || e);

    await logAccess('GRANT_ERROR', {
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      kvkk_accepted: true,
      kvkk_version: user.kvkk_version,
      marker: sess.otp.marker,
      client_mac: meraki.clientMac || client_mac,
      client_ip: meraki.clientIp || getClientIp(req),
      ssid: meraki.ssid,
      ap_name: meraki.apName,
      base_grant_url: meraki.baseGrantUrl,
      user_continue_url: meraki.continueUrl,
      user_agent: safeStr(req.headers['user-agent'], 300),
      extra: { error: safeStr(e?.message || e, 300) },
    });

    return res.status(500).send(
      renderPage({
        title: 'Hata',
        body: `<div class="card"><h1>Bağlantı hatası</h1><div class="err">${safeStr(e?.message || e, 300)}</div></div>`,
      })
    );
  }
});

/** ---------------------------
 * Start / Shutdown
 * --------------------------- */
let server = null;

async function start() {
  await initRedis();
  await initDatabase();

  server = app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
}

start().catch((e) => {
  console.error('BOOT ERROR:', e?.message || e);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Shutting down...');
  try {
    if (server) await new Promise((r) => server.close(r));
    if (redisReady && redis) await redis.quit();
    if (pool) await pool.end();
  } catch (_) {}
  process.exit(0);
});
