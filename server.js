import express from "express";
import { createClient } from "redis";
import crypto from "crypto";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = Number(process.env.PORT || 8080);

// Mod: şimdilik screen
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms'i sonra açacağız)

// Süreler
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180);            // OTP geçerlilik
const RL_MAC_SECONDS = Number(process.env.OTP_RL_MAC_SECONDS || 30);           // aynı MAC için
const RL_MSISDN_SECONDS = Number(process.env.OTP_RL_MSISDN_SECONDS || 60);     // aynı numara için
const MAX_WRONG_ATTEMPTS = Number(process.env.OTP_MAX_WRONG || 5);             // yanlış deneme limiti
const LOCK_SECONDS = Number(process.env.OTP_LOCK_SECONDS || 600);              // kilit süresi (10 dk)
const SUCCESS_REDIRECT_MS = Number(process.env.SUCCESS_REDIRECT_MS || 2000);   // success sayfasında bekleme
const DEBUG_TOOLS = String(process.env.DEBUG_TOOLS || "").toLowerCase() === "true";

// Redis
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL;
let redis = null;

// ---------- Utils ----------
const s = (v) => (v === undefined || v === null ? "" : String(v));
const onlyDigits = (v) => s(v).replace(/\D/g, "");

function maskLast4(digits) {
  return digits.length >= 4 ? digits.slice(-4) : null;
}

// TR normalize: 0XXXXXXXXXX / 90XXXXXXXXXX / +90... -> 5XXXXXXXXX
function normalizeTrMsisdn(inputRaw) {
  const raw = onlyDigits(inputRaw);

  let x = raw;
  if (x.startsWith("90") && x.length === 12) x = x.slice(2);
  if (x.startsWith("0") && x.length === 11) x = x.slice(1);

  const ok = /^5\d{9}$/.test(x);
  return { ok, msisdn: ok ? x : "", raw: inputRaw, reason: ok ? null : "Expected 5XXXXXXXXX (10 digits)" };
}

function genOtp6() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function genMarker() {
  return String(crypto.randomInt(100000, 999999));
}

// ---------- Redis init ----------
async function initRedis() {
  if (!REDIS_URL) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing).");
    return null;
  }
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err) => console.log("REDIS_ERROR:", err?.message || err));
  await client.connect();
  console.log("REDIS: connected");
  return client;
}

// ---------- Redis helpers ----------
async function setJsonEx(key, ttlSec, obj) {
  await redis.setEx(key, ttlSec, JSON.stringify(obj));
}
async function getJson(key) {
  const v = await redis.get(key);
  return v ? JSON.parse(v) : null;
}

async function rateLimitOrThrow(key, ttlSec, humanMsg) {
  // SET key NX EX ttlSec
  const ok = await redis.set(key, "1", { NX: true, EX: ttlSec });
  if (!ok) {
    const ttl = await redis.ttl(key);
    const wait = ttl > 0 ? ttl : ttlSec;
    const err = new Error(`${humanMsg} (${wait} sn bekleyin)`);
    err.status = 429;
    err.wait = wait;
    throw err;
  }
}

// Wrong attempts + lock
async function ensureNotLocked(lockKey) {
  const locked = await redis.get(lockKey);
  if (locked) {
    const ttl = await redis.ttl(lockKey);
    const wait = ttl > 0 ? ttl : LOCK_SECONDS;
    const err = new Error(`Çok fazla hatalı deneme. ${wait} sn sonra tekrar deneyin.`);
    err.status = 429;
    err.wait = wait;
    throw err;
  }
}

async function incWrongAndMaybeLock(wrongKey, lockKey) {
  const n = await redis.incr(wrongKey);
  if (n === 1) await redis.expire(wrongKey, LOCK_SECONDS);
  if (n >= MAX_WRONG_ATTEMPTS) await redis.setEx(lockKey, LOCK_SECONDS, "1");
  return n;
}

async function getWrongCount(wrongKey) {
  const v = await redis.get(wrongKey);
  const n = Number(v || 0);
  return Number.isFinite(n) ? n : 0;
}

// ---------- Routes ----------
app.get("/healthz", (_req, res) => res.status(200).json({ ok: true, mode: OTP_MODE }));

// Opsiyonel debug (default kapalı)
app.get("/debug/state", async (req, res) => {
  if (!DEBUG_TOOLS) return res.status(404).send("not found");
  const client_mac = s(req.query.client_mac);
  const msisdn = s(req.query.msisdn);

  const out = {
    client_mac,
    msisdn_last4: msisdn ? maskLast4(msisdn) : null,
    keys: {}
  };

  if (client_mac && msisdn) {
    out.keys.active = await redis.get(`otp:active:${client_mac}:${msisdn}`);
  }
  if (client_mac) {
    out.keys.lock_mac = await redis.ttl(`otp:lock:mac:${client_mac}`);
    out.keys.wrong_mac = await redis.get(`otp:wrong:mac:${client_mac}`);
    out.keys.rl_mac = await redis.ttl(`otp:rl:mac:${client_mac}`);
  }
  if (msisdn) {
    out.keys.lock_msisdn = await redis.ttl(`otp:lock:msisdn:${msisdn}`);
    out.keys.wrong_msisdn = await redis.get(`otp:wrong:msisdn:${msisdn}`);
    out.keys.rl_msisdn = await redis.ttl(`otp:rl:msisdn:${msisdn}`);
  }

  return res.json(out);
});

// Meraki custom splash URL -> GET /
app.get("/", (req, res) => {
  const base_grant_url = s(req.query.base_grant_url);
  const user_continue_url = s(req.query.user_continue_url || req.query.continue_url);
  const client_mac = s(req.query.client_mac);

  console.log("SPLASH_OPEN", {
    hasBaseGrant: Boolean(base_grant_url),
    hasContinue: Boolean(user_continue_url),
    hasClientMac: Boolean(client_mac),
    mode: OTP_MODE
  });

  if (!base_grant_url || !user_continue_url) {
    return res.status(200).send("meraki-sms-splash is running");
  }

  return res.status(200).send(renderPhoneForm({ base_grant_url, user_continue_url, client_mac }));
});

// OTP Request
app.post("/otp/request", async (req, res) => {
  try {
    const base_grant_url = s(req.body.base_grant_url);
    const user_continue_url = s(req.body.user_continue_url);
    const client_mac = s(req.body.client_mac);
    const phoneRaw = s(req.body.phone);

    if (!base_grant_url || !user_continue_url || !client_mac) {
      return res.status(400).send(renderError("Eksik parametre (base_grant_url / user_continue_url / client_mac)", {}));
    }

    const norm = normalizeTrMsisdn(phoneRaw);
    if (!norm.ok) {
      return res.status(400).send(renderError(`MSISDN format invalid. ${norm.reason}. Got: ${phoneRaw}`, {
        base_grant_url, user_continue_url, client_mac
      }));
    }

    const msisdn = norm.msisdn;
    const last4 = maskLast4(msisdn);

    // Lock kontrol (msisdn + mac)
    await ensureNotLocked(`otp:lock:msisdn:${msisdn}`);
    await ensureNotLocked(`otp:lock:mac:${client_mac}`);

    // Rate limits
    await rateLimitOrThrow(`otp:rl:mac:${client_mac}`, RL_MAC_SECONDS, "Cihaz için çok hızlı deneme");
    await rateLimitOrThrow(`otp:rl:msisdn:${msisdn}`, RL_MSISDN_SECONDS, "Numara için çok hızlı deneme");

    const marker = genMarker();
    const code = genOtp6();

    const payload = {
      marker,
      code,
      msisdn,
      last4,
      client_mac,
      base_grant_url,
      user_continue_url,
      created_at: Date.now()
    };

    await setJsonEx(`otp:marker:${marker}`, OTP_TTL_SECONDS, payload);
    await redis.setEx(`otp:active:${client_mac}:${msisdn}`, OTP_TTL_SECONDS, marker);

    console.log("OTP_CREATED", { marker, last4, client_mac });

    return res.status(200).send(renderOtpPage({
      marker,
      last4,
      base_grant_url,
      user_continue_url,
      client_mac,
      code
    }));
  } catch (e) {
    const status = e?.status || 500;
    return res.status(status).send(renderError(e?.message || "OTP request failed", {}));
  }
});

// OTP Verify
app.post("/otp/verify", async (req, res) => {
  try {
    const marker = s(req.body.marker).trim();
    const code = s(req.body.code).trim();

    if (!marker || !code) {
      return res.status(400).send(renderError("Eksik marker veya code", {}));
    }

    const data = await getJson(`otp:marker:${marker}`);
    if (!data) {
      return res.status(400).send(renderError("Kod süresi doldu veya bulunamadı. Tekrar kod isteyin.", {}));
    }

    const msisdn = data.msisdn;
    const client_mac = data.client_mac;

    await ensureNotLocked(`otp:lock:msisdn:${msisdn}`);
    await ensureNotLocked(`otp:lock:mac:${client_mac}`);

    const activeMarker = await redis.get(`otp:active:${client_mac}:${msisdn}`);
    if (!activeMarker || activeMarker !== marker) {
      return res.status(400).send(renderError("Bu kod artık geçerli değil. Lütfen yeniden kod isteyin.", {
        base_grant_url: data.base_grant_url,
        user_continue_url: data.user_continue_url,
        client_mac
      }));
    }

    if (code !== s(data.code)) {
      const wrongMsisdnKey = `otp:wrong:msisdn:${msisdn}`;
      const lockMsisdnKey = `otp:lock:msisdn:${msisdn}`;
      const wrongMacKey = `otp:wrong:mac:${client_mac}`;
      const lockMacKey = `otp:lock:mac:${client_mac}`;

      const n1 = await incWrongAndMaybeLock(wrongMsisdnKey, lockMsisdnKey);
      const n2 = await incWrongAndMaybeLock(wrongMacKey, lockMacKey);

      const remain = Math.max(0, MAX_WRONG_ATTEMPTS - Math.max(n1, n2));

      console.log("OTP_VERIFY_FAIL", { marker, client_mac, wrong_msisdn: n1, wrong_mac: n2 });

      return res.status(401).send(renderVerifyError({
        message: "Kod hatalı.",
        remain,
        base_grant_url: data.base_grant_url,
        user_continue_url: data.user_continue_url,
        client_mac,
        marker
      }));
    }

    console.log("OTP_VERIFY_OK", { marker, client_mac });

    await redis.del(`otp:marker:${marker}`);
    await redis.del(`otp:active:${client_mac}:${msisdn}`);
    await redis.del(`otp:wrong:msisdn:${msisdn}`);
    await redis.del(`otp:wrong:mac:${client_mac}`);

    // Success sayfası -> 2sn sonra Meraki grant'a gider
    return res.status(200).send(renderSuccess({
      redirectTo: data.base_grant_url,
      ms: SUCCESS_REDIRECT_MS
    }));
  } catch (e) {
    const status = e?.status || 500;
    return res.status(status).send(renderError(e?.message || "OTP verify failed", {}));
  }
});

// ---------- HTML ----------
function renderPhoneForm({ base_grant_url, user_continue_url, client_mac }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WiFi Doğrulama</title>
  <style>
    body{font-family:system-ui,Arial;margin:24px;max-width:520px}
    input,button{font-size:16px;padding:10px;width:100%;margin:8px 0}
    .small{color:#666;font-size:13px}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  </style>
</head>
<body>
  <h2>Telefon Doğrulama</h2>
  <p class="small">Numarayı <b>5XXXXXXXXX</b> (10 hane) gir. (0 yok, +90 yok)</p>
  <p class="small">Cihaz: <span class="mono">${escapeHtml(client_mac)}</span></p>

  <form method="post" action="/otp/request">
    <input name="phone" placeholder="5333312520" autocomplete="tel" required />
    <input type="hidden" name="base_grant_url" value="${escapeAttr(base_grant_url)}" />
    <input type="hidden" name="user_continue_url" value="${escapeAttr(user_continue_url)}" />
    <input type="hidden" name="client_mac" value="${escapeAttr(client_mac)}" />
    <button type="submit">Kod Al</button>
  </form>

  <p class="small">Mode: <b>${escapeHtml(OTP_MODE)}</b></p>
</body>
</html>`;
}

function renderOtpPage({ marker, last4, base_grant_url, user_continue_url, client_mac, code }) {
  const codeBlock = OTP_MODE === "screen"
    ? `<p><b>Kod (test):</b> <span style="font-size:28px;letter-spacing:2px">${escapeHtml(code)}</span></p>`
    : `<p class="small">Kod SMS ile gönderildi. (Son 4: ${escapeHtml(last4 || "")})</p>`;

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Kod Doğrulama</title>
  <style>
    body{font-family:system-ui,Arial;margin:24px;max-width:520px}
    input,button{font-size:16px;padding:10px;width:100%;margin:8px 0}
    .small{color:#666;font-size:13px}
  </style>
</head>
<body>
  <h2>Kod Doğrulama</h2>
  ${codeBlock}

  <form method="post" action="/otp/verify">
    <input name="code" placeholder="6 haneli kod" inputmode="numeric" pattern="\\d{6}" required />
    <input type="hidden" name="marker" value="${escapeAttr(marker)}" />
    <button type="submit">Onayla & İnternete Bağlan</button>
  </form>

  <form method="get" action="/">
    <input type="hidden" name="base_grant_url" value="${escapeAttr(base_grant_url)}" />
    <input type="hidden" name="user_continue_url" value="${escapeAttr(user_continue_url)}" />
    <input type="hidden" name="client_mac" value="${escapeAttr(client_mac)}" />
    <button type="submit">Baştan Başla</button>
  </form>

  <p class="small">Marker: ${escapeHtml(marker)}</p>
</body>
</html>`;
}

function renderVerifyError({ message, remain, base_grant_url, user_continue_url, client_mac, marker }) {
  const remainTxt = Number.isFinite(remain) ? `Kalan deneme hakkı: ${remain}` : "";
  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hata</title>
<style>
body{font-family:system-ui,Arial;margin:24px;max-width:520px}
input,button{font-size:16px;padding:10px;width:100%;margin:8px 0}
.small{color:#666;font-size:13px}
</style>
</head>
<body>
  <h3>${escapeHtml(message)}</h3>
  <p class="small">${escapeHtml(remainTxt)}</p>

  <form method="post" action="/otp/verify">
    <input name="code" placeholder="6 haneli kod" inputmode="numeric" pattern="\\d{6}" required />
    <input type="hidden" name="marker" value="${escapeAttr(marker)}" />
    <button type="submit">Tekrar Dene</button>
  </form>

  <a href="/?base_grant_url=${encodeURIComponent(base_grant_url)}&user_continue_url=${encodeURIComponent(user_continue_url)}&client_mac=${encodeURIComponent(client_mac)}">Baştan başla</a>
</body></html>`;
}

function renderSuccess({ redirectTo, ms }) {
  const safeMs = Number.isFinite(ms) ? ms : 2000;
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Başarılı</title>
  <style>
    body{font-family:system-ui,Arial;margin:24px;max-width:520px}
    .ok{font-size:18px}
    .small{color:#666;font-size:13px}
  </style>
  <meta http-equiv="refresh" content="${Math.max(1, Math.round(safeMs / 1000))};url=${escapeAttr(redirectTo)}" />
</head>
<body>
  <h2 class="ok">✅ Doğrulama başarılı</h2>
  <p class="small">${Math.round(safeMs/1000)} sn içinde internete yönlendiriliyorsunuz…</p>
  <p class="small">Olmazsa <a href="${escapeAttr(redirectTo)}">buraya tıklayın</a>.</p>
</body>
</html>`;
}

function renderError(msg, { base_grant_url = "", user_continue_url = "", client_mac = "" }) {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hata</title></head>
<body style="font-family:system-ui,Arial;margin:24px;max-width:520px">
  <h3>Hata</h3>
  <p>${escapeHtml(msg)}</p>
  <a href="/?base_grant_url=${encodeURIComponent(base_grant_url)}&user_continue_url=${encodeURIComponent(user_continue_url)}&client_mac=${encodeURIComponent(client_mac)}">Geri dön</a>
</body>
</html>`;
}

function escapeHtml(v) {
  return s(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function escapeAttr(v) {
  return escapeHtml(v).replaceAll("`", "&#096;");
}

// ---------- Start ----------
let server;

(async () => {
  redis = await initRedis();
  if (!redis) {
    console.log("WARN: Redis not available; rate-limit/lock features disabled.");
  } else {
    console.log("ENV:", {
      OTP_MODE,
      OTP_TTL_SECONDS,
      RL_MAC_SECONDS,
      RL_MSISDN_SECONDS,
      MAX_WRONG_ATTEMPTS,
      LOCK_SECONDS
    });
  }

  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();

// Graceful shutdown (Railway SIGTERM)
process.on("SIGTERM", async () => {
  try {
    console.log("SIGTERM received. Shutting down...");
    if (server) server.close(() => console.log("HTTP server closed."));
    if (redis) await redis.quit();
  } catch (e) {
    console.log("Shutdown error:", e?.message || e);
  } finally {
    process.exit(0);
  }
});
