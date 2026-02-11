import http from "http";
import { sendOtpSms, normalizeTrMsisdn } from "./smsService.js";
import { randomInt } from "crypto";
import { URL } from "url";

const PORT = process.env.PORT || 8080;

// Basit in-memory OTP store
const otpStore = new Map(); // phone -> { code, expires }

function generateOtp() {
  return String(randomInt(100000, 999999));
}

function renderForm(params) {
  return `
  <html>
  <head>
    <title>WiFi Doğrulama</title>
  </head>
  <body>
    <h2>Telefon Doğrulama</h2>
    <form method="POST" action="/send-otp">
      <input type="hidden" name="base_grant_url" value="${params.base_grant_url || ""}" />
      <input type="hidden" name="user_continue_url" value="${params.user_continue_url || ""}" />
      <input type="text" name="phone" placeholder="Telefon (05...)" required />
      <button type="submit">Kod Gönder</button>
    </form>
  </body>
  </html>
  `;
}

function renderVerify(phone, params) {
  return `
  <html>
  <body>
    <h2>SMS Kodunu Gir</h2>
    <form method="POST" action="/verify-otp">
      <input type="hidden" name="phone" value="${phone}" />
      <input type="hidden" name="base_grant_url" value="${params.base_grant_url || ""}" />
      <input type="hidden" name="user_continue_url" value="${params.user_continue_url || ""}" />
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
    req.on("data", chunk => data += chunk);
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

  if (req.method === "GET") {
    const params = Object.fromEntries(url.searchParams.entries());
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(renderForm(params));
    return;
  }

  if (req.method === "POST" && req.url === "/send-otp") {
    const body = await parseBody(req);
    const phone = normalizeTrMsisdn(body.phone);

    if (!phone) {
      res.end("Telefon formatı hatalı");
      return;
    }

    const code = generateOtp();
    otpStore.set(phone, {
      code,
      expires: Date.now() + 5 * 60 * 1000
    });

    await sendOtpSms({
      phone,
      text: `WiFi giris kodunuz: ${code}`
    });

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(renderVerify(phone, body));
    return;
  }

  if (req.method === "POST" && req.url === "/verify-otp") {
    const body = await parseBody(req);
    const entry = otpStore.get(body.phone);

    if (!entry || entry.code !== body.code || Date.now() > entry.expires) {
      res.end("Kod hatalı veya süresi dolmuş");
      return;
    }

    otpStore.delete(body.phone);

    // Meraki authorize
    const redirectUrl = `${body.base_grant_url}?continue_url=${encodeURIComponent(body.user_continue_url)}`;

    res.writeHead(302, { Location: redirectUrl });
    res.end();
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
