// server.js (ESM)
import express from "express";
import crypto from "crypto";
import { createClient } from "redis";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = Number(process.env.PORT || 8080);

// -------------------- Config --------------------
const MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // screen | sms (sms later)
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180); // 3 min
const OTP_RESEND_BLOCK_SECONDS = Number(process.env.OTP_RESEND_BLOCK_SECONDS || 60); // 60s
const OTP_LEN = Number(process.env.OTP_LEN || 6);

// Meraki params come from querystring usually
const Q_BASE = "base_grant_url";
const Q_CONTINUE = "user_continue_url";
const Q_MAC = "client_mac";

// -------------------- Helpers --------------------
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function maskLast4(s) {
  if (!s) return null;
  return s.slice(-4);
}

function normalizeMac(mac) {
  if (!mac) return "";
  return String(mac).trim().toLowerCase();
}

// Expected: 5XXXXXXXXX (10 digits, TR mobile without leading 0 / +90)
function normalizeMsisdn(input) {
  const raw = String(input || "").trim();
  const digits = raw.replace(/\D/g, "");

  // handle +90 / 90 / 0 prefixes gracefully
  if (digits.startsWith("90") && digits.length === 12) return digits.slice(2); // 90 + 10
  if (digits.startsWith("0") && digits.length === 11) return digits.slice(1); // 0 + 10

  return digits; // ideally 10 digits
}

function isValidMsisdn(msisdn10) {
  return /^5\d{9}$/.test(msisdn10);
}

function genOtp(len = 6) {
  // numeric OTP
  const max = 10 ** len;
  const n = crypto.randomInt(0, max);
  return String(n).padStart(len, "0");
}

function genMarker() {
  // short id for log correlation
  return String(crypto.randomInt(100000, 999999));
}

function htmlPage(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0f17;color:#e8eefc;margin:0}
    .wrap{max-width:460px;margin:0 auto;padding:24px}
    .card{background:#121a29;border:1px solid #1e2a40;border-radius:14px;padding:18px}
    label{display:block;font-size:14px;margin:12px 0 6px;opacity:.9}
    input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid #2a3b5b;background:#0e1522;color:#e8eefc;font-size:16px;box-sizing:border-box}
    button{margin-top:14px;width:100%;padding:12px;border-radius:12px;border:0;background:#5b7cfa;color:white;font-size:16px;font-weight:600;cursor:pointer}
    .muted{opacity:.75;font-size:13px}
    .error{background:#2a0f18;border:1px solid #5a1a2d;color:#ffd7e2;padding:10px;border-radius:12px;margin-top:12px}
    .ok{background:#0f2a1d;border:1px solid #1a5a3a;color:#d7ffe7;padding:10px;border-radius:12px;margin-top:12px}
    code{background:#0e1522;border:1px solid #22314d;padding:2px 6px;border-radius:8px}
  </style>
</head>
<body>
  <div class="wrap">
    <h2 style="margin:0 0 12px">${title}</h2>
    <div class="card">${body}</div>
    <div class="muted" style="margin-top:12px">meraki-sms-splash</div>
  </div>
</body>
</html>`;
}

// -------------------- Store (Redis preferred) --------------------
let redis = null;
let storeType = "memory";

// Memory fallback (NOT persistent across restarts)
const memOtp = new Map(); // key: otp:<msisdn> -> {otp, mac, exp, marker}
const memRate = new Map(); // key: rl:<msisdn> -> {until, marker}

async function initRedisIfAvailable() {
  const url = process.env.REDIS_URL;
  if (!url) {
    console.log("STORE: memory (REDIS_URL not set)");
    return;
  }

  redis = createClient({ url });
  redis.on("error", (err) => console.error("REDIS_ERROR", err?.message || err));
  await redis.connect();

  storeType = "redis";
  console.log("STORE: redis connected");
}

async function storeOtp(msisdn, otp, clientMac, marker) {
  const key = `otp:${msisdn}`;
  const value = JSON.stringify({
    otp,
    clientMac,
    marker,
    exp: nowSec() + OTP_TTL_SECONDS,
  });

  if (storeType === "redis") {
    await redis.set(key, value, { EX: OTP_TTL_SECONDS });
  } else {
    memOtp.set(key, { otp, clientMac, marker, exp: nowSec() + OTP_TTL_SECONDS });
    setTimeout(() => memOtp.delete(key), OTP_TTL_SECONDS * 1000).unref();
  }
}

async function getOtp(msisdn) {
  const key = `otp:${msisdn}`;
  if (storeType === "redis") {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  const v = memOtp.get(key);
  if (!v) return null;
  if (v.exp && v.exp < nowSec()) {
    memOtp.delete(key);
    return null;
  }
  return v;
}

async function deleteOtp(msisdn) {
  const key = `otp:${msisdn}`;
  if (storeType === "redis") {
    await redis.del(key);
  } else {
    memOtp.delete(key);
  }
}

async function setRateLimit(msisdn, marker) {
  const key = `rl:${msisdn}`;
  const until = nowSec() + OTP_RESEND_BLOCK_SECONDS;
  const value = JSON.stringify({ until, marker });

  if (storeType === "redis") {
    await redis.set(key, value, { EX: OTP_RESEND_BLOCK_SECONDS });
  } else {
    memRate.set(key, { until, marker });
    setTimeout(() => memRate.delete(key), OTP_RESEND_BLOCK_SECONDS * 1000).unref();
  }
}

async function getRateLimit(msisdn) {
  const key = `rl:${msisdn}`;
  if (storeType === "redis") {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  }
  const v = memRate.get(key);
  if (!v) return null;
  if (v.until && v.until < nowSec()) {
    memRate.delete(key);
    return null;
  }
  return v;
}

// -------------------- Routes --------------------
app.get("/health", async (_req, res) => {
  res.json({
    ok: true,
    mode: MODE,
    store: storeType,
    ttl: OTP_TTL_SECONDS,
    resendBlock: OTP_RESEND_BLOCK_SECONDS,
  });
});

// Meraki splash landing
app.get("/", async (req, res) => {
  const baseGrantUrl = req.query[Q_BASE] ? String(req.query[Q_BASE]) : "";
  const continueUrl = req.query[Q_CONTINUE] ? String(req.query[Q_CONTINUE]) : "";
  const clientMac = normalizeMac(req.query[Q_MAC]);

  console.log("SPLASH_OPEN", {
    hasBaseGrant: Boolean(baseGrantUrl),
    hasContinue: Boolean(continueUrl),
    hasClientMac: Boolean(clientMac),
    mode: MODE,
  });

  const err = !baseGrantUrl || !continueUrl
    ? `<div class="error">Eksik parametre: <code>${Q_BASE}</code> ve/veya <code>${Q_CONTINUE}</code> gelmedi.</div>`
    : "";

  const body = `
    <div class="muted">İnternete çıkmak için telefon numaranızı girin.</div>
    ${err}
    <form method="POST" action="/otp">
      <label>Telefon (5XXXXXXXXX)</label>
      <input name="msisdn" inputmode="numeric" placeholder="5XXXXXXXXX" required />
      <input type="hidden" name="${Q_BASE}" value="${escapeHtml(baseGrantUrl)}" />
      <input type="hidden" name="${Q_CONTINUE}" value="${escapeHtml(continueUrl)}" />
      <input type="hidden" name="${Q_MAC}" value="${escapeHtml(clientMac)}" />
      <button type="submit">Kod al</button>
    </form>
  `;

  res.status(200).send(htmlPage("Wi-Fi Doğrulama", body));
});

// Create OTP
app.post("/otp", async (req, res) => {
  const marker = genMarker();

  const msisdn = normalizeMsisdn(req.body.msisdn);
  const baseGrantUrl = String(req.body[Q_BASE] || "");
  const continueUrl = String(req.body[Q_CONTINUE] || "");
  const clientMac = normalizeMac(req.body[Q_MAC]);

  if (!isValidMsisdn(msisdn)) {
    return res
      .status(400)
      .send(
        htmlPage(
          "Hatalı Numara",
          `<div class="error">Numara formatı hatalı. Örnek: <code>5XXXXXXXXX</code></div>
           <div class="muted">Gelen: <code>${escapeHtml(String(req.body.msisdn || ""))}</code></div>
           <div style="margin-top:12px"><a href="/" style="color:#9fb6ff">Geri</a></div>`
        )
      );
  }

  // rate limit check
  const rl = await getRateLimit(msisdn);
  if (rl?.until && rl.until > nowSec()) {
    const wait = rl.until - nowSec();
    return res
      .status(429)
      .send(
        htmlPage(
          "Lütfen bekleyin",
          `<div class="error">Tekrar denemeden önce <b>${wait}</b> saniye bekleyin.</div>`
        )
      );
  }

  const otp = genOtp(OTP_LEN);
  await storeOtp(msisdn, otp, clientMac, marker);
  await setRateLimit(msisdn, marker);

  console.log("OTP_CREATED", {
    marker,
    last4: maskLast4(msisdn),
    client_mac: clientMac || null,
  });

  // SCREEN MODE: show OTP on page (no SMS)
  if (MODE === "screen") {
    const body = `
      <div class="ok">Kodunuz: <code style="font-size:20px">${otp}</code></div>
      <div class="muted" style="margin-top:10px">Kod ${OTP_TTL_SECONDS} saniye geçerlidir.</div>

      <form method="POST" action="/verify" style="margin-top:16px">
        <label>Kodu girin</label>
        <input name="otp" inputmode="numeric" placeholder="${"0".repeat(OTP_LEN)}" required />
        <input type="hidden" name="msisdn" value="${escapeHtml(msisdn)}" />
        <input type="hidden" name="marker" value="${escapeHtml(marker)}" />
        <input type="hidden" name="${Q_BASE}" value="${escapeHtml(baseGrantUrl)}" />
        <input type="hidden" name="${Q_CONTINUE}" value="${escapeHtml(continueUrl)}" />
        <input type="hidden" name="${Q_MAC}" value="${escapeHtml(clientMac)}" />
        <button type="submit">Doğrula</button>
      </form>
    `;
    return res.status(200).send(htmlPage("Kod", body));
  }

  // SMS mode will be enabled later
  return res
    .status(501)
    .send(
      htmlPage(
        "SMS kapalı",
        `<div class="error">SMS modu şu an kapalı. <code>OTP_MODE=screen</code> ile devam edin.</div>`
      )
    );
});

// Verify OTP + MAC binding
app.post("/verify", async (req, res) => {
  const marker = String(req.body.marker || genMarker());
  const msisdn = normalizeMsisdn(req.body.msisdn);
  const enteredOtp = String(req.body.otp || "").replace(/\D/g, "");
  const baseGrantUrl = String(req.body[Q_BASE] || "");
  const continueUrl = String(req.body[Q_CONTINUE] || "");
  const clientMac = normalizeMac(req.body[Q_MAC]);

  const rec = await getOtp(msisdn);

  if (!rec) {
    console.log("OTP_VERIFY_FAIL", { marker, reason: "NO_RECORD", last4: maskLast4(msisdn) });
    return res
      .status(400)
      .send(htmlPage("Hata", `<div class="error">Kod bulunamadı veya süresi doldu.</div>`));
  }

  // MAC binding (if we have both)
  if (rec.clientMac && clientMac && rec.clientMac !== clientMac) {
    console.log("OTP_VERIFY_FAIL", {
      marker,
      reason: "MAC_MISMATCH",
      stored: rec.clientMac,
      got: clientMac,
    });
    return res
      .status(403)
      .send(
        htmlPage(
          "Hata",
          `<div class="error">Cihaz doğrulaması başarısız (MAC uyuşmadı).</div>`
        )
      );
  }

  if (rec.otp !== enteredOtp) {
    console.log("OTP_VERIFY_FAIL", { marker, reason: "OTP_MISMATCH", last4: maskLast4(msisdn) });
    return res
      .status(400)
      .send(htmlPage("Hata", `<div class="error">Kod hatalı.</div>`));
  }

  await deleteOtp(msisdn);

  console.log("OTP_VERIFY_OK", {
    marker,
    client_mac: clientMac || rec.clientMac || null,
  });

  // Meraki grant: redirect to base_grant_url with continue
  const grantUrl = buildGrantUrl(baseGrantUrl, continueUrl);

  // Redirect user to grant URL (Meraki expects browser redirect)
  return res.redirect(grantUrl);
});

// -------------------- Utilities --------------------
function buildGrantUrl(baseGrantUrl, continueUrl) {
  try {
    const u = new URL(baseGrantUrl);
    // Keep existing query; set/override continue URL if provided
    if (continueUrl) {
      // Meraki normally uses "continue_url" - but many setups accept "user_continue_url" already in base
      // We'll add "continue_url" if not present
      if (!u.searchParams.get("continue_url")) u.searchParams.set("continue_url", continueUrl);
    }
    return u.toString();
  } catch {
    // If baseGrantUrl isn't a valid URL, fallback
    return baseGrantUrl || continueUrl || "/";
  }
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// -------------------- Start + Shutdown --------------------
const server = app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
});

async function shutdown(signal) {
  console.log(`SHUTDOWN ${signal}`);
  try {
    if (redis) await redis.quit();
  } catch {}
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
  setTimeout(() => {
    console.log("Force shutdown");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// Init Redis after server starts (non-blocking start)
initRedisIfAvailable().catch((e) => {
  console.error("STORE_INIT_FAIL", e?.message || e);
  // ---- Graceful shutdown (Railway SIGTERM fix) ----
let shuttingDown = false;

async function gracefulExit(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`SHUTDOWN ${signal}`);

  try {
    // Eğer redis client kullanıyorsan ve değişkenin adı "redis" ise:
    if (globalThis.redis && typeof globalThis.redis.quit === "function") {
      await globalThis.redis.quit();
      console.log("REDIS_QUIT_OK");
    }
  } catch (e) {
    console.log("REDIS_QUIT_FAIL", e?.message || String(e));
  }

  // Express/http server varsa:
  try {
    if (globalThis.server && typeof globalThis.server.close === "function") {
      globalThis.server.close(() => {
        console.log("HTTP_CLOSED");
        process.exit(0);
      });
      // 2 sn sonra zorla çık
      setTimeout(() => process.exit(0), 2000).unref();
      return;
    }
  } catch {}

  process.exit(0);
}

process.on("SIGTERM", () => gracefulExit("SIGTERM"));
process.on("SIGINT", () => gracefulExit("SIGINT"));

});

