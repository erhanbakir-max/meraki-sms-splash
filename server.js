'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

let redisCreateClient = null;
try {
  ({ createClient: redisCreateClient } = require('redis'));
} catch (_) {}

const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* =======================
 * ENV
 * ======================= */
const ENV = {
  PORT: Number(process.env.PORT || 8080),

  OTP_MODE: (process.env.OTP_MODE || 'screen').toLowerCase(), // screen
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  KVKK_VERSION: process.env.KVKK_VERSION || '2026-02-12-placeholder',
  BRAND_NAME: process.env.BRAND_NAME || 'Guest Wi-Fi',
  COMPANY_LOGO_URL: process.env.COMPANY_LOGO_URL || '',

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
 * REDIS (required for stable flow)
 * ======================= */
let redis = null;
let redisReady = false;

async function initRedis() {
  if (!ENV.REDIS_URL || !redisCreateClient) {
    console.log('REDIS: not configured. (This will break stable flow.)');
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
 * POSTGRES (optional but you have it)
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
function safeStr(x, max = 800) {
  if (x == null) return '';
  const s = String(x);
  return s.length > max ? s.slice(0, max) : s;
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length > 0) return xf.split(',')[0].trim();
  return req.ip || '';
}

function parseMeraki(req) {
  const q = req.query || {};
  return {
    baseGrantUrl: safeStr(q.base_grant_url || ''),
    continueUrl: safeStr(q.user_continue_url || q.continue_url || ''),
    clientMac: safeStr(q.client_mac || '').toLowerCase(),
    clientIp: safeStr(q.client_ip || ''),
    ssid: safeStr(q.ssid_name || q.ssid || ''),
    apName: safeStr(q.ap_name || ''),
    hasBaseGrant: !!q.base_grant_url,
    hasContinue: !!(q.user_continue_url || q.continue_url),
    hasClientMac: !!q.client_mac,
  };
}

function randOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function kvkkPlaceholderHtml() {
  return `
  <strong>KVKK Aydınlatma Metni (Placeholder)</strong><br/>
  Bu metin şimdilik örnektir. Gerçek metin daha sonra eklenecek.<br/><br/>
  İşlenen veriler: Ad, Soyad, Telefon, MAC, IP, zaman damgaları.<br/>
  Amaç: Misafir internet erişimi + 5651 loglama.
  `;
}

function renderPage(title, inner) {
  return `<!doctype html><html lang="tr"><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${title}</title>
  <style>
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#111;padding:22px}
    .card{max-width:460px;margin:0 auto;background:#fff;border-radius:18px;padding:18px;box-shadow:0 12px 32px rgba(0,0,0,.25)}
    .mut{color:#6b7280;font-size:12px}
    input,button{width:100%;padding:12px 12px;border-radius:12px;border:1px solid #d1d5db;font-size:14px}
    button{border:0;background:#4f46e5;color:#fff;font-weight:700;cursor:pointer;margin-top:10px}
    .kvkk{border:1px solid #e5e7eb;border-radius:12px;padding:12px;background:#fafafa;max-height:170px;overflow:auto;font-size:12px;color:#4b5563}
    .otp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:34px;letter-spacing:4px;font-weight:900;
         text-align:center;padding:10px;border:1px dashed #9ca3af;border-radius:14px;background:#f9fafb;margin:10px 0}
    .ok{background:#ecfdf5;border:1px solid #86efac;color:#166534;padding:10px;border-radius:12px;margin-top:10px}
    .err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px;border-radius:12px;margin-top:10px}
    .row{display:flex;gap:10px}
    .row>div{flex:1}
    label{display:block;margin-top:10px;margin-bottom:6px;font-size:13px;color:#374151}
  </style>
  </head><body><div class="card">${inner}</div></body></html>`;
}

/* =======================
 * Meraki grant caller
 * ======================= */
async function callMerakiGrant(baseGrantUrl, continueUrl) {
  // base_grant_url + continue_url + duration
  let url = baseGrantUrl;
  try {
    const u = new URL(baseGrantUrl);
    if (continueUrl) u.searchParams.set('continue_url', continueUrl);
    u.searchParams.set('duration', '3600');
    url = u.toString();
  } catch (_) {
    const glue = url.includes('?') ? '&' : '?';
    url = `${url}${glue}continue_url=${encodeURIComponent(continueUrl)}&duration=3600`;
  }

  console.log('GRANT_URL:', url);

  const r = await fetch(url, { method: 'GET' });
  const txt = await r.text();

  console.log('GRANT_HTTP:', r.status);
  console.log('GRANT_BODY_SNIP:', safeStr(txt, 200));

  return { status: r.status, ok: r.ok, body: txt };
}

/* =======================
 * Routes
 * ======================= */
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/', async (req, res) => {
  const m = parseMeraki(req);
  console.log('SPLASH_OPEN', { hasBaseGrant: m.hasBaseGrant, hasContinue: m.hasContinue, hasClientMac: m.hasClientMac, mode: ENV.OTP_MODE });

  if (!m.clientMac || !m.baseGrantUrl) {
    return res.status(400).send(renderPage('Hata', `<h3>Geçersiz istek</h3><div class="err">client_mac / base_grant_url eksik.</div>`));
  }

  // session store
  const sk = sessKey(m.clientMac);
  await kvSet(sk, {
    meraki: {
      baseGrantUrl: m.baseGrantUrl,
      continueUrl: m.continueUrl,
      clientMac: m.clientMac,
      clientIp: m.clientIp || getClientIp(req),
      ssid: m.ssid,
      apName: m.apName
    }
  }, ENV.OTP_TTL_SECONDS);

  await logDb('SPLASH_OPEN', {
    client_mac: m.clientMac,
    client_ip: m.clientIp || getClientIp(req),
    ssid: m.ssid,
    ap_name: m.apName,
    base_grant_url: m.baseGrantUrl,
    continue_url: m.continueUrl,
  });

  const logo = ENV.COMPANY_LOGO_URL
    ? `<div style="text-align:center;margin-bottom:10px"><img src="${safeStr(ENV.COMPANY_LOGO_URL,400)}" style="max-height:64px;max-width:240px"/></div>`
    : '';

  res.send(renderPage('Guest Wi-Fi', `
    ${logo}
    <h2 style="margin:0 0 6px 0">${safeStr(ENV.BRAND_NAME,60)}</h2>
    <div class="mut">Misafir internet erişimi</div>

    <form method="POST" action="/start" style="margin-top:12px">
      <input type="hidden" name="client_mac" value="${m.clientMac}"/>

      <div class="row">
        <div>
          <label>Ad</label>
          <input name="first_name" required maxlength="50"/>
        </div>
        <div>
          <label>Soyad</label>
          <input name="last_name" required maxlength="50"/>
        </div>
      </div>

      <label>Cep telefonu</label>
      <input name="phone" required maxlength="25" placeholder="05xx..."/>

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
  const first_name = safeStr(req.body.first_name, 50).trim();
  const last_name = safeStr(req.body.last_name, 50).trim();
  const phone = safeStr(req.body.phone, 25).trim();
  const kvkk_accepted = req.body.kvkk_accepted === '1';

  const sk = sessKey(client_mac);
  const sess = await kvGet(sk);
  if (!sess?.meraki?.baseGrantUrl) {
    return res.status(400).send(renderPage('Hata', `<h3>Oturum bulunamadı</h3><div class="err">Lütfen tekrar splash açın.</div>`));
  }

  const otp = randOtp();
  const marker = String(Math.floor(100000 + Math.random() * 900000));
  sess.user = { first_name, last_name, phone, kvkk_version: ENV.KVKK_VERSION, kvkk_accepted: !!kvkk_accepted };
  sess.otp = { value: otp, marker, wrong: 0, expiresAt: Date.now() + ENV.OTP_TTL_SECONDS * 1000 };

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
    full_name: `${first_name} ${last_name}`.trim(),
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

  if (!sess?.otp?.value || !sess?.meraki?.baseGrantUrl) {
    return res.status(400).send(renderPage('Hata', `<h3>Oturum yok</h3><div class="err">Tekrar başlayın.</div>`));
  }

  if (Date.now() > sess.otp.expiresAt) {
    await kvDel(sk);
    return res.status(400).send(renderPage('Süre doldu', `<h3>Kod süresi doldu</h3><div class="err">Lütfen tekrar deneyin.</div>`));
  }

  if (otp_in !== sess.otp.value) {
    sess.otp.wrong = (sess.otp.wrong || 0) + 1;
    await kvSet(sk, sess, Math.ceil((sess.otp.expiresAt - Date.now()) / 1000));

    return res.status(401).send(renderPage('Hatalı', `
      <h3>Hatalı kod</h3>
      <div class="err">${sess.otp.wrong}/${ENV.MAX_WRONG_ATTEMPTS}</div>
      <form method="POST" action="/verify">
        <input type="hidden" name="client_mac" value="${client_mac}"/>
        <label>Tekrar girin</label>
        <input name="otp" required inputmode="numeric" maxlength="10"/>
        <button type="submit">Doğrula</button>
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
    full_name: `${sess.user?.first_name || ''} ${sess.user?.last_name || ''}`.trim(),
  });

  // ✅ AUTO GRANT
  try {
    await logDb('GRANT_CALLED', {
      client_mac,
      client_ip: sess.meraki.clientIp,
      base_grant_url: sess.meraki.baseGrantUrl,
      continue_url: sess.meraki.continueUrl,
      marker: sess.otp.marker,
      phone: sess.user?.phone,
      full_name: `${sess.user?.first_name || ''} ${sess.user?.last_name || ''}`.trim(),
    });

    const grant = await callMerakiGrant(sess.meraki.baseGrantUrl, sess.meraki.continueUrl);

    if (!grant.ok) {
      await logDb('GRANT_FAIL', {
        client_mac,
        client_ip: sess.meraki.clientIp,
        base_grant_url: sess.meraki.baseGrantUrl,
        continue_url: sess.meraki.continueUrl,
        marker: sess.otp.marker,
        meta: { http: grant.status, body_snip: safeStr(grant.body, 200) }
      });

      return res.status(502).send(renderPage('Grant Hata', `
        <h3>Meraki grant başarısız</h3>
        <div class="err">HTTP ${grant.status}</div>
        <div class="mut">Loglarda GRANT_BODY_SNIP var.</div>
      `));
    }

    await logDb('GRANT_OK', {
      client_mac,
      client_ip: sess.meraki.clientIp,
      base_grant_url: sess.meraki.baseGrantUrl,
      continue_url: sess.meraki.continueUrl,
      marker: sess.otp.marker,
    });

    // session cleanup
    await kvDel(sk);

    // ✅ loop kırıcı: 1 sn bekle ve devam et
    const cont = sess.meraki.continueUrl || '/';
    return res.status(200).send(renderPage('Bağlanıyor', `
      <h3>Bağlantı verildi</h3>
      <div class="ok">1 saniye sonra devam edilecek…</div>
      <script>setTimeout(()=>{ window.location.href=${JSON.stringify(cont)}; }, 1000);</script>
      <div class="mut" style="margin-top:10px">Olmazsa bu linke tıkla:</div>
      <a href="${cont}">${cont}</a>
    `));
  } catch (e) {
    console.error('GRANT_ERROR:', e?.message || e);
    await logDb('GRANT_ERROR', {
      client_mac,
      client_ip: sess.meraki.clientIp,
      base_grant_url: sess.meraki.baseGrantUrl,
      continue_url: sess.meraki.continueUrl,
      marker: sess.otp.marker,
      meta: { error: safeStr(e?.message || e, 250) }
    });

    return res.status(500).send(renderPage('Hata', `<h3>Grant hata</h3><div class="err">${safeStr(e?.message || e, 250)}</div>`));
  }
});

/* =======================
 * START
 * ======================= */
(async () => {
  await initRedis();
  await initDatabase();

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
