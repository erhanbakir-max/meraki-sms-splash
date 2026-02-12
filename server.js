import { createClient } from 'redis';

const redis = createClient({
  url: process.env.REDIS_URL
});

redis.on('error', (err) => console.error('Redis Client Error', err));

await redis.connect();

console.log("Redis connected");

import http from "http";
import { URL } from "url";
import { randomInt } from "crypto";
import { sendOtpSms, normalizeTrMsisdn } from "./smsService.js";

const PORT = process.env.PORT || 8080;
const OTP_MODE = (process.env.OTP_MODE || "screen").toLowerCase(); // "screen" | "sms"

// marker -> { code, expires, phoneLast4, base_grant_url, user_continue_url, client_mac }
const otpStore = new Map();
// phone -> nextAllowedAt
const cooldownByPhone = new Map();

const OTP_TTL_MS = 5 * 60 * 1000;       // 5 dk
const RESEND_COOLDOWN_MS = 120 * 1000;  // 120 sn (451 için daha güvenli)

function generateOtp() {
  return String(randomInt(100000, 999999));
}

function htmlEscape(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function cleanupOld() {
  const now = Date.now();
  for (const [marker, v] of otpStore.entries()) {
    if (now > v.expires) otpStore.delete(marker);
  }
}

function renderForm(params, notice = "") {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WiFi Doğrulama</title>
</head>
<body>
  <h2>Telefon Doğrulama</h2>
  ${notice ? `<p style="color:#b00">${htmlEscape(notice)}</p>` : ""}

  <form method="POST" action="/send-otp">
    <input type="hidden" name="base_grant_url" value="${htmlEscape(params.base_grant_url)}" />
    <input type="hidden" name="user_continue_url" value="${htmlEscape(params.user_continue_url)}" />
    <input type="hidden" name="client_mac" value="${htmlEscape(params.client_mac)}" />
    <input type="text" name="phone" placeholder="05XXXXXXXXX" required />
    <button type="submit">Kod Gönder</button>
  </form>

  <hr/>
  <small>Mode: ${htmlEscape(OTP_MODE)}</small>
</body>
</html>`;
}

function renderVerify({ phoneLast4, marker, client_mac }, notice = "", debugCode = "") {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OTP Doğrulama</title>
</head>
<body>
  <h2>SMS Kodu</h2>
  <p>Numara sonu: ****${htmlEscape(phoneLast4)}</p>
  ${client_mac ? `<p>MAC: ${htmlEscape(client_mac)}</p>` : ""}

  ${notice ? `<p style="color:#b00">${htmlEscape(notice)}</p>` : ""}

  ${
    debugCode
      ? `<p style="padding:8px;border:1px dashed #999;">
            <b>TEST MODU:</b> Kodunuz: <b style="font-size:18px;">${htmlEscape(debugCode)}</b>
         </p>`
      : ""
  }

  <form method="POST" action="/verify-otp">
    <input type="hidden" name="marker" value="${htmlEscape(marker)}" />
    <input type="text" name="code" placeholder="6 haneli kod" required />
    <button type="submit">Onayla</button>
  </form>
</body>
</html>`;
}

function parseBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      const params = new URLSearchParams(data);
      const obj = {};
      for (const [k, v] of params.entries()) obj[k] = v;
      resolve(obj);
    });
  });
}

const server = http.createServer(async (req, res) => {
  cleanupOld();

  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method || "GET";

  // Splash
  if (method === "GET" && url.pathname === "/") {
    const params = Object.fromEntries(url.searchParams.entries());
    console.log("SPLASH_OPEN", {
      hasBaseGrant: !!params.base_grant_url,
      hasContinue: !!params.user_continue_url,
      hasClientMac: !!params.client_mac,
      mode: OTP_MODE,
    });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderForm(params));
    return;
  }

  // Health
  if (method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, mode: OTP_MODE }));
    return;
  }

  // Send OTP
  if (method === "POST" && url.pathname === "/send-otp") {
    const body = await parseBody(req);

    const phone = normalizeTrMsisdn(body.phone);
    const base_grant_url = body.base_grant_url || "";
    const user_continue_url = body.user_continue_url || "";
    const client_mac = body.client_mac || "";

    if (!phone) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url, client_mac }, "Telefon formatı hatalı."));
      return;
    }

    const now = Date.now();
    const nextAllowed = cooldownByPhone.get(phone) || 0;
    if (now < nextAllowed) {
      const waitSec = Math.ceil((nextAllowed - now) / 1000);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url, client_mac }, `Lütfen ${waitSec} saniye bekleyin.`));
      return;
    }

    const code = generateOtp();
    const marker = Date.now().toString().slice(-6);

    otpStore.set(marker, {
      code,
      expires: now + OTP_TTL_MS,
      phoneLast4: phone.slice(-4),
      base_grant_url,
      user_continue_url,
      client_mac,
    });

    cooldownByPhone.set(phone, now + RESEND_COOLDOWN_MS);

    console.log("OTP_CREATED", { marker, last4: phone.slice(-4), client_mac: client_mac || null });

    // MODE: screen => ekranda göster
    if (OTP_MODE === "screen") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(
        renderVerify(
          { phoneLast4: phone.slice(-4), marker, client_mac },
          "",
          code // debug göster
        )
      );
      return;
    }

    // MODE: sms => gerçek SMS gönder
    const smsText = `WiFi kodunuz: ${code}`;
    const result = await sendOtpSms({ phone, text: smsText });

    if (!result.ok) {
      console.log("OTP_SMS_FAILED", { marker, code: result.code, msg: result.message });
      res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url, client_mac }, "SMS gönderilemedi. Lütfen tekrar deneyin."));
      return;
    }

    console.log("OTP_SMS_SENT", { marker, orderId: result.orderId || null });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderVerify({ phoneLast4: phone.slice(-4), marker, client_mac }));
    return;
  }

  // Verify OTP
  if (method === "POST" && url.pathname === "/verify-otp") {
    const body = await parseBody(req);
    const marker = body.marker || "";
    const code = (body.code || "").trim();

    const entry = otpStore.get(marker);
    if (!entry) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify({ phoneLast4: "????", marker, client_mac: "" }, "Kod hatalı veya süresi dolmuş."));
      return;
    }

    if (Date.now() > entry.expires) {
      otpStore.delete(marker);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify({ phoneLast4: entry.phoneLast4, marker, client_mac: entry.client_mac }, "Kodun süresi doldu. Yeniden kod isteyin."));
      return;
    }

    if (entry.code !== code) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify({ phoneLast4: entry.phoneLast4, marker, client_mac: entry.client_mac }, "Kod hatalı. Tekrar deneyin."));
      return;
    }

    otpStore.delete(marker);

    const redirectUrl = `${entry.base_grant_url}?continue_url=${encodeURIComponent(entry.user_continue_url)}`;
    console.log("OTP_VERIFY_OK", { marker, client_mac: entry.client_mac || null });

    res.writeHead(302, { Location: redirectUrl });
    res.end();
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
