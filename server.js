import http from "http";
import { sendOtpSms, normalizeTrMsisdn } from "./smsService.js";
import { randomInt } from "crypto";
import { URL } from "url";

const PORT = process.env.PORT || 8080;

// OTP kayıtları: marker -> { code, expires, phoneLast4, base_grant_url, user_continue_url }
const otpStore = new Map();

// Rate limit: phone -> nextAllowedAt (ms)
const cooldownByPhone = new Map();

// Ayarlar
const OTP_TTL_MS = 5 * 60 * 1000;       // 5 dk
const RESEND_COOLDOWN_MS = 60 * 1000;   // 60 sn

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

function renderForm(params, notice = "") {
  return `
<!doctype html>
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
    <input type="text" name="phone" placeholder="Telefon (05...)" required />
    <button type="submit">Kod Gönder</button>
  </form>
</body>
</html>
  `;
}

function renderVerify(phoneLast4, marker, notice = "") {
  return `
<!doctype html>
<html>
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
<body>
  <h2>SMS Kodunu Gir</h2>
  <p>Numara sonu: ****${htmlEscape(phoneLast4)}</p>
  ${notice ? `<p style="color:#b00">${htmlEscape(notice)}</p>` : ""}
  <form method="POST" action="/verify-otp">
    <input type="hidden" name="marker" value="${htmlEscape(marker)}" />
    <input type="text" name="code" placeholder="6 haneli kod" required />
    <button type="submit">Onayla</button>
  </form>
</body>
</html>
  `;
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

function cleanupOld() {
  const now = Date.now();
  for (const [marker, v] of otpStore.entries()) {
    if (now > v.expires) otpStore.delete(marker);
  }
  for (const [phone, t] of cooldownByPhone.entries()) {
    if (now > t + 10 * 60 * 1000) cooldownByPhone.delete(phone); // 10 dk sonra unut
  }
}

const server = http.createServer(async (req, res) => {
  cleanupOld();

  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method || "GET";

  if (method === "GET" && url.pathname === "/") {
    const params = Object.fromEntries(url.searchParams.entries());
    console.log("SPLASH_OPEN", {
      hasBaseGrant: !!params.base_grant_url,
      hasContinue: !!params.user_continue_url,
    });
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderForm(params));
    return;
  }

  if (method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (method === "POST" && url.pathname === "/send-otp") {
    const body = await parseBody(req);

    const phone = normalizeTrMsisdn(body.phone);
    const base_grant_url = body.base_grant_url || "";
    const user_continue_url = body.user_continue_url || "";

    if (!phone) {
      console.log("SEND_OTP_REJECT", { reason: "INVALID_PHONE" });
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url }, "Telefon formatı hatalı (05xx, +90xx, 90xx veya 5xx)."));
      return;
    }

    // Rate limit (451 ve spam’i engeller)
    const now = Date.now();
    const nextAllowed = cooldownByPhone.get(phone) || 0;
    if (now < nextAllowed) {
      const waitSec = Math.ceil((nextAllowed - now) / 1000);
      console.log("SEND_OTP_COOLDOWN", { last4: phone.slice(-4), waitSec });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url }, `Lütfen ${waitSec} saniye bekleyip tekrar deneyin.`));
      return;
    }

    // OTP oluştur
    const code = generateOtp();
    const marker = Date.now().toString().slice(-6);
    const suffix = String(randomInt(10, 99)); // ekstra benzersizlik

    otpStore.set(marker, {
      code,
      expires: now + OTP_TTL_MS,
      phoneLast4: phone.slice(-4),
      base_grant_url,
      user_continue_url,
    });

    // 60 sn cooldown başlat
    cooldownByPhone.set(phone, now + RESEND_COOLDOWN_MS);

    console.log("OTP_CREATED", { last4: phone.slice(-4), marker });

    // Mesajı kesin benzersiz yap
    const smsText = `WiFi kodunuz: ${code} (M:${marker}-${suffix})`;

    const result = await sendOtpSms({ phone, text: smsText });

    if (!result.ok) {
      console.log("OTP_SMS_FAILED", {
        marker,
        error: result.error,
        code: result.code,
        message: result.message,
      });

      // 451 tekrar eden sipariş => kullanıcıya bekle mesajı
      if (String(result.code) === "451") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(renderForm({ base_grant_url, user_continue_url }, "Çok sık deneme yapıldı. Lütfen 60 saniye bekleyip tekrar deneyin."));
        return;
      }

      res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderForm({ base_grant_url, user_continue_url }, "SMS gönderilemedi. Lütfen tekrar deneyin."));
      return;
    }

    console.log("OTP_SMS_SENT", { marker, orderId: result.orderId || null });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderVerify(phone.slice(-4), marker));
    return;
  }

  if (method === "POST" && url.pathname === "/verify-otp") {
    const body = await parseBody(req);
    const marker = body.marker || "";
    const code = (body.code || "").trim();

    const entry = otpStore.get(marker);
    if (!entry) {
      console.log("OTP_VERIFY_FAIL", { marker, reason: "NO_ENTRY" });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify("????", marker, "Kod hatalı veya süresi dolmuş."));
      return;
    }

    if (Date.now() > entry.expires) {
      otpStore.delete(marker);
      console.log("OTP_VERIFY_FAIL", { marker, reason: "EXPIRED" });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify(entry.phoneLast4, marker, "Kodun süresi doldu. Lütfen yeniden kod isteyin."));
      return;
    }

    if (entry.code !== code) {
      console.log("OTP_VERIFY_FAIL", { marker, reason: "WRONG_CODE" });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderVerify(entry.phoneLast4, marker, "Kod hatalı. Tekrar deneyin."));
      return;
    }

    otpStore.delete(marker);

    const redirectUrl =
      `${entry.base_grant_url}?continue_url=${encodeURIComponent(entry.user_continue_url)}`;

    console.log("OTP_VERIFY_OK", { marker, last4: entry.phoneLast4 });

    res.writeHead(302, { Location: redirectUrl });
    res.end();
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
