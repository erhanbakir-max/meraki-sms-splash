import express from "express";
import { createClient } from "redis";
import { normalizeTrMsisdn, sendSmsViaIletimerkezi } from "./smsService.js";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Railway PORT
const PORT = Number(process.env.PORT || 8080);

// OTP ayarları
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180); // 3 dk
const OTP_RATE_LIMIT_SECONDS = Number(process.env.OTP_RATE_LIMIT_SECONDS || 60); // 60 sn
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms

// Redis
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL;
let redis = null;

async function initRedis() {
  if (!REDIS_URL) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing). Running WITHOUT persistent store.");
    return null;
  }
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err) => console.log("REDIS_ERROR:", err?.message || err));
  await client.connect();
  console.log("REDIS: connected");
  return client;
}

// Sağlık kontrolü
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

// Splash entry
app.get("/", async (req, res) => {
  const base_grant_url = req.query.base_grant_url || "";
  const user_continue_url = req.query.user_continue_url || req.query.continue_url || "";
  const client_mac = req.query.client_mac || "";

  console.log("SPLASH_OPEN", {
    hasBaseGrant: Boolean(base_grant_url),
    hasContinue: Boolean(user_continue_url),
    hasClientMac: Boolean(client_mac),
    mode: OTP_MODE
  });

  // Meraki paramları yoksa sadece running göster
  if (!base_grant_url || !user_continue_url) {
    return res.status(200).send("meraki-sms-splash is running");
  }

  return res.status(200).send(renderPhoneForm({ base_grant_url, user_continue_url, client_mac }));
});

// OTP request
app.post("/otp/request", async (req, res) => {
  const base_grant_url = req.body.base_grant_url || "";
  const user_continue_url = req.body.user_continue_url || "";
  const client_mac = req.body.client_mac || "";
  const phoneRaw = req.body.phone || "";

  const norm = normalizeTrMsisdn(phoneRaw);

  if (!base_grant_url || !user_continue_url) {
    return res.status(400).send("Missing base_grant_url or user_continue_url");
  }
  if (!norm.ok) {
    return res.status(400).send(renderError(`MSISDN format invalid. ${norm.reason}. Got: ${phoneRaw}`, { base_grant_url, user_continue_url, client_mac }));
  }

  const msisdn = norm.msisdn;
  const last4 = norm.last4;

  // Rate limit: aynı numaraya 60 sn içinde tekrar OTP verme
  if (redis) {
    const rlKey = `otp:rl:${msisdn}`;
    const exists = await redis.exists(rlKey);
    if (exists) {
      return res.status(429).send(renderError(`Lütfen ${OTP_RATE_LIMIT_SECONDS} sn bekleyip tekrar deneyin.`, { base_grant_url, user_continue_url, client_mac }));
    }
    await redis.setEx(rlKey, OTP_RATE_LIMIT_SECONDS, "1");
  }

  const code = genOtp6();
  const marker = String(Math.floor(100000 + Math.random() * 900000)); // log için

  const payload = {
    code,
    msisdn,
    last4,
    client_mac,
    base_grant_url,
    user_continue_url,
    created_at: Date.now()
  };

  console.log("OTP_CREATED", { marker, last4, client_mac });

  // Redis’e yaz
  if (redis) {
    await redis.setEx(`otp:${marker}`, OTP_TTL_SECONDS, JSON.stringify(payload));
  } else {
    // Redis yoksa in-memory fallback (restart’ta gider)
    globalThis.__OTP_MEM__ = globalThis.__OTP_MEM__ || new Map();
    globalThis.__OTP_MEM__.set(`otp:${marker}`, { payload, exp: Date.now() + OTP_TTL_SECONDS * 1000 });
  }

  // SMS mode ise gönder
  if (OTP_MODE === "sms") {
    const msg = `Doğrulama kodunuz: ${code}`;
    const debug = String(process.env.SMS_DEBUG || "false").toLowerCase() === "true";

    const smsResp = await sendSmsViaIletimerkezi({ msisdn, text: msg, debug });

    if (!smsResp.ok) {
      console.log("OTP_SMS_FAILED", {
        marker,
        error: smsResp.code || "ILETIMERKEZI_ERROR",
        http: smsResp.http,
        message: smsResp.message
      });
      // SMS başarısızsa ekrana düşelim (testte işimizi görür)
      return res.status(200).send(renderOtpPage({ marker, last4, base_grant_url, user_continue_url, client_mac, code, screenFallback: true }));
    }
  }

  // screen mode: kodu ekranda göster
  return res.status(200).send(renderOtpPage({ marker, last4, base_grant_url, user_continue_url, client_mac, code, screenFallback: OTP_MODE !== "sms" }));
});

// OTP verify
app.post("/otp/verify", async (req, res) => {
  const marker = String(req.body.marker || "").trim();
  const code = String(req.body.code || "").trim();

  if (!marker || !code) return res.status(400).send("Missing marker or code");

  const key = `otp:${marker}`;
  const data = await loadOtp(key);
  if (!data) {
    return res.status(400).send(renderError("Kod süresi doldu veya bulunamadı. Tekrar isteyin.", {}));
  }

  const expected = String(data.code);
  if (code !== expected) {
    return res.status(401).send(renderError("Kod hatalı.", {
      base_grant_url: data.base_grant_url,
      user_continue_url: data.user_continue_url,
      client_mac: data.client_mac
    }));
  }

  console.log("OTP_VERIFY_OK", { marker, client_mac: data.client_mac });

  // Tek kullanımlık: sil
  await deleteOtp(key);

  // Meraki’ye grant için redirect
  // base_grant_url çoğu zaman gerekli query’leri içerir; direkt oraya gönderiyoruz.
  return res.redirect(data.base_grant_url);
});

// ---- helpers: OTP store ----

async function loadOtp(key) {
  if (redis) {
    const raw = await redis.get(key);
    return raw ? JSON.parse(raw) : null;
  }
  const m = globalThis.__OTP_MEM__;
  if (!m) return null;
  const entry = m.get(key);
  if (!entry) return null;
  if (Date.now() > entry.exp) {
    m.delete(key);
    return null;
  }
  return entry.payload;
}

async function deleteOtp(key) {
  if (redis) return redis.del(key);
  const m = globalThis.__OTP_MEM__;
  if (m) m.delete(key);
  return 0;
}

function genOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ---- HTML ----

function renderPhoneForm({ base_grant_url, user_continue_url, client_mac }) {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Doğrulama</title>
<style>
body{font-family:system-ui,Arial;margin:24px;max-width:520px}
input,button{font-size:16px;padding:10px;width:100%;margin:8px 0}
.small{color:#666;font-size:13px}
</style>
</head>
<body>
<h2>Telefon Doğrulama</h2>
<p class="small">Numarayı <b>5XXXXXXXXX</b> (10 hane) gir. (0 yok, +90 yok)</p>

<form method="post" action="/otp/request">
  <input name="phone" placeholder="5333312520" autocomplete="tel" required />
  <input type="hidden" name="base_grant_url" value="${escapeAttr(base_grant_url)}" />
  <input type="hidden" name="user_continue_url" value="${escapeAttr(user_continue_url)}" />
  <input type="hidden" name="client_mac" value="${escapeAttr(client_mac)}" />
  <button type="submit">Kod Al</button>
</form>

<p class="small">Mode: <b>${escapeHtml(OTP_MODE)}</b> (OTP_MODE env ile değişir)</p>
</body>
</html>`;
}

function renderOtpPage({ marker, last4, base_grant_url, user_continue_url, client_mac, code, screenFallback }) {
  const codeBlock = screenFallback
    ? `<p><b>Kod (test):</b> <span style="font-size:28px;letter-spacing:2px">${escapeHtml(code)}</span></p>`
    : `<p class="small">Kod SMS ile gönderildi. (Son 4: ${escapeHtml(last4)})</p>`;

  return `<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
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

function renderError(msg, { base_grant_url = "", user_continue_url = "", client_mac = "" }) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hata</title></head><body style="font-family:system-ui,Arial;margin:24px;max-width:520px">
<h3>Hata</h3>
<p>${escapeHtml(msg)}</p>
<a href="/?base_grant_url=${encodeURIComponent(base_grant_url)}&user_continue_url=${encodeURIComponent(user_continue_url)}&client_mac=${encodeURIComponent(client_mac)}">Geri dön</a>
</body></html>`;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function escapeAttr(s) {
  return escapeHtml(s).replaceAll("`", "&#096;");
}

// ---- start ----
let server = null;

(async () => {
  redis = await initRedis();

  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();

// Railway SIGTERM normal (redeploy/scale). Graceful shutdown:
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
