import http from "http";
import { sendOtpSms, normalizeTrMsisdn } from "./smsService.js";
import { randomInt } from "crypto";
import { URL } from "url";

const PORT = process.env.PORT || 8080;

// phone -> { code, expires, marker, params }
const otpStore = new Map();

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

function renderForm(params) {
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

function renderVerify(phoneLast4, params, marker) {
  return `
<!doctype html>
<html>
<head><meta charset="utf-8" /></head>
<body>
  <h2>SMS Kodunu Gir</h2>
  <p>Numara sonu: ****${htmlEscape(phoneLast4)} (M:${htmlEscape(marker)})</p>
  <form method="POST" action="/verify-otp">
    <input type="hidden" name="marker" value="${htmlEscape(marker)}" />
    <input type="hidden" name="base_grant_url" value="${htmlEscape(params.base_grant_url)}" />
    <input type="hidden" name="user_continue_url" value="${htmlEscape(params.user_continue_url)}" />
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

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method || "GET";

  // Splash page
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

  // Health
  if (method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // Send OTP
  if (method === "POST" && url.pathname === "/send-otp") {
    const body = await parseBody(req);
    const phone = normalizeTrMsisdn(body.phone);

    const base_grant_url = body.base_grant_url || "";
    const user_continue_url = body.user_continue_url || "";

    if (!phone) {
      console.log("SEND_OTP_REJECT", { reason: "INVALID_PHONE" });
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Telefon formatı hatalı");
      return;
    }

    const code = generateOtp();
    const marker = Date.now().toString().slice(-6);

    otpStore.set(marker, {
      code,
      expires: Date.now() + 5 * 60 * 1000,
      phoneLast4: phone.slice(-4),
      base_grant_url,
      user_continue_url,
    });

    console.log("OTP_CREATED", { last4: phone.slice(-4), marker });

    const smsText = `WiFi kodunuz: ${code} (M:${marker})`;

    const result = await sendOtpSms({ phone, text: smsText });

    if (!result.ok) {
      console.log("OTP_SMS_FAILED", { marker, error: result.error, code: result.code, message: result.message });
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("SMS gönderilemedi");
      return;
    }

    console.log("OTP_SMS_SENT", { marker, orderId: result.orderId || null });

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderVerify(phone.slice(-4), { base_grant_url, user_continue_url }, marker));
    return;
  }

  // Verify OTP
  if (method === "POST" && url.pathname === "/verify-otp") {
    const body = await parseBody(req);
    const marker = body.marker || "";
    const code = (body.code || "").trim();

    const entry = otpStore.get(marker);

    if (!entry) {
      console.log("OTP_VERIFY_FAIL", { marker, reason: "NO_ENTRY" });
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Kod hatalı veya süresi dolmuş");
      return;
    }

    if (Date.now() > entry.expires) {
      otpStore.delete(marker);
      console.log("OTP_VERIFY_FAIL", { marker, reason: "EXPIRED" });
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Kod hatalı veya süresi dolmuş");
      return;
    }

    if (entry.code !== code) {
      console.log("OTP_VERIFY_FAIL", { marker, reason: "WRONG_CODE" });
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Kod hatalı");
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
