// server.js (ESM)
import express from "express";
import crypto from "crypto";
import { sendOtpSms, normalizeTrMsisdn } from "./smsService.js";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = Number(process.env.PORT || 8080);

// screen: kodu ekranda göster (test)
// sms: sms gönder (onay gelince)
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase();

const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 180); // 3 dk
const OTP_RESEND_BLOCK_SECONDS = Number(process.env.OTP_RESEND_BLOCK_SECONDS || 60); // 60 sn

// In-memory store (Redis sonraki adım)
const otpStore = new Map(); // marker -> { otp, expMs, msisdn, last4, base, cont, mac }
const resendStore = new Map(); // msisdn -> untilMs

function now() {
  return Date.now();
}

function genOtp() {
  return String(crypto.randomInt(100000, 999999));
}

function genMarker() {
  return String(crypto.randomInt(100000, 999999));
}

function normalizeMac(mac) {
  return String(mac || "").trim().toLowerCase();
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cleanup() {
  const t = now();
  for (const [k, v] of otpStore.entries()) {
    if (t > v.expMs) otpStore.delete(k);
  }
  for (const [k, until] of resendStore.entries()) {
    if (t > until) resendStore.delete(k);
  }
}

function render(title, body) {
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
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
    <h2 style="margin:0 0 12px">${escapeHtml(title)}</h2>
    <div class="card">${body}</div>
    <div class="muted" style="margin-top:12px">mode: ${escapeHtml(OTP_MODE)}</div>
  </div>
</body>
</html>`;
}

app.get("/health", (req, res) => {
  res.json({ ok: true, mode: OTP_MODE });
});

app.get("/", (req, res) => {
  cleanup();

  const base_grant_url = String(req.query.base_grant_url || "");
  const user_continue_url = String(req.query.user_continue_url || "");
  const client_mac = normalizeMac(req.query.client_mac || "");

  console.log("SPLASH_OPEN", {
    hasBaseGrant: !!base_grant_url,
    hasContinue: !!user_continue_url,
    hasClientMac: !!client_mac,
    mode: OTP_MODE,
  });

  const err =
    !base_grant_url || !user_continue_url
      ? `<div class="error">Eksik parametre: base_grant_url / user_continue_url gelmedi.</div>`
      : "";

  const body = `
    <div class="muted">İnternete çıkmak için telefon numaranızı girin.</div>
    ${err}
    <form method="POST" action="/otp">
      <label>Telefon</label>
      <input name="phone" inputmode="numeric" placeholder="05XXXXXXXXX" required />
      <input type="hidden" name="base_grant_url" value="${escapeHtml(base_grant_url)}" />
      <input type="hidden" name="user_continue_url" value="${escapeHtml(user_continue_url)}" />
      <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}" />
      <button type="submit">Kod al</button>
    </form>
  `;
  res.status(200).send(render("Wi-Fi Doğrulama", body));
});

app.post("/otp", async (req, res) => {
  cleanup();

  const phoneRaw = String(req.body.phone || "");
  const msisdn = normalizeTrMsisdn(phoneRaw);

  const base_grant_url = String(req.body.base_grant_url || "");
  const user_continue_url = String(req.body.user_continue_url || "");
  const client_mac = normalizeMac(req.body.client_mac || "");

  if (!msisdn) {
    return res
      .status(400)
      .send(render("Hatalı Numara", `<div class="error">Numara formatı hatalı. Örn: <code>0533...</code></div>`));
  }

  const until = resendStore.get(msisdn) || 0;
  if (now() < until) {
    const wait = Math.ceil((until - now()) / 1000);
    return res
      .status(429)
      .send(render("Bekleyin", `<div class="error">Tekrar denemeden önce <b>${wait}</b> saniye bekleyin.</div>`));
  }

  const otp = genOtp();
  const marker = genMarker();

  otpStore.set(marker, {
    otp,
    expMs: now() + OTP_TTL_SECONDS * 1000,
    msisdn,
    last4: msisdn.slice(-4),
    base_grant_url,
    user_continue_url,
    mac: client_mac,
  });

  resendStore.set(msisdn, now() + OTP_RESEND_BLOCK_SECONDS * 1000);

  console.log("OTP_CREATED", { marker, last4: msisdn.slice(-4), client_mac: client_mac || null });

  if (OTP_MODE === "screen") {
    const body = `
      <div class="ok">TEST MODU: Kodunuz <code style="font-size:20px">${otp}</code></div>
      <div class="muted" style="margin-top:10px">Kod ${OTP_TTL_SECONDS} saniye geçerlidir.</div>

      <form method="POST" action="/verify" style="margin-top:16px">
        <label>Kodu girin</label>
        <input name="code" inputmode="numeric" placeholder="******" required />
        <input type="hidden" name="marker" value="${escapeHtml(marker)}" />
        <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}" />
        <button type="submit">Doğrula</button>
      </form>
    `;
    return res.status(200).send(render("Kod", body));
  }

  // SMS modu (onay gelince)
  const smsText = `WiFi kodunuz: ${otp}`;
  const result = await sendOtpSms({ phone: msisdn, text: smsText });

  if (!result.ok) {
    console.log("OTP_SMS_FAILED", { marker, code: result.code, message: result.message });
    return res.status(502).send(render("Hata", `<div class="error">SMS gönderilemedi.</div>`));
  }

  console.log("OTP_SMS_SENT", { marker, orderId: result.orderId || null });

  const body = `
    <div class="muted">Telefonunuza gelen kodu girin.</div>
    <form method="POST" action="/verify" style="margin-top:16px">
      <label>Kodu girin</label>
      <input name="code" inputmode="numeric" placeholder="******" required />
      <input type="hidden" name="marker" value="${escapeHtml(marker)}" />
      <input type="hidden" name="client_mac" value="${escapeHtml(client_mac)}" />
      <button type="submit">Doğrula</button>
    </form>
  `;
  return res.status(200).send(render("Kod", body));
});

app.post("/verify", (req, res) => {
  cleanup();

  const marker = String(req.body.marker || "");
  const entered = String(req.body.code || "").replace(/\D/g, "");
  const client_mac = normalizeMac(req.body.client_mac || "");

  const entry = otpStore.get(marker);
  if (!entry) {
    return res.status(400).send(render("Hata", `<div class="error">Kod bulunamadı veya süresi doldu.</div>`));
  }

  if (entry.mac && client_mac && entry.mac !== client_mac) {
    console.log("OTP_VERIFY_FAIL", { marker, reason: "MAC_MISMATCH", stored: entry.mac, got: client_mac });
    return res.status(403).send(render("Hata", `<div class="error">MAC uyuşmadı.</div>`));
  }

  if (entry.otp !== entered) {
    console.log("OTP_VERIFY_FAIL", { marker, reason: "WRONG_CODE", last4: entry.last4 });
    return res.status(400).send(render("Hata", `<div class="error">Kod hatalı.</div>`));
  }

  otpStore.delete(marker);

  console.log("OTP_VERIFY_OK", { marker, client_mac: client_mac || entry.mac || null });

  const redirectUrl = buildGrantUrl(entry.base_grant_url, entry.user_continue_url);
  return res.redirect(302, redirectUrl);
});

function buildGrantUrl(baseGrantUrl, continueUrl) {
  try {
    const u = new URL(baseGrantUrl);
    if (continueUrl && !u.searchParams.get("continue_url")) u.searchParams.set("continue_url", continueUrl);
    return u.toString();
  } catch {
    return baseGrantUrl || continueUrl || "/";
  }
}

// ---- start ----
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// ---- SIGTERM cleanup: Railway restart loglarını düzelt ----
let shuttingDown = false;
function fastExit(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`SHUTDOWN ${signal}`);
  try {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
  } catch {
    process.exit(0);
  }
}
process.on("SIGTERM", () => fastExit("SIGTERM"));
process.on("SIGINT", () => fastExit("SIGINT"));
