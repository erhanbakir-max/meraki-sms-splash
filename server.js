"use strict";

/**
 * smsService.js
 * Default: MOCK SMS (does not fail)
 *
 * Env:
 *  SMS_PROVIDER=mock | http
 *  SMS_HTTP_URL=https://...
 *  SMS_HTTP_TOKEN=...
 *
 * Expected interface:
 *  sendSms(phone, text) -> Promise<void>
 */

async function sendSms(phone, text) {
  const provider = (process.env.SMS_PROVIDER || "mock").toLowerCase();

  if (provider === "mock") {
    console.log("[SMS MOCK] to:", phone, "text:", text);
    return;
  }

  if (provider === "http") {
    const url = process.env.SMS_HTTP_URL || "";
    const token = process.env.SMS_HTTP_TOKEN || "";
    if (!url) throw new Error("SMS_HTTP_URL missing");
    // Minimal HTTP POST without extra deps:
    const payload = JSON.stringify({ phone, text });
    const u = new URL(url);

    const mod = u.protocol === "https:" ? await import("https") : await import("http");
    await new Promise((resolve, reject) => {
      const req = mod.request(
        {
          method: "POST",
          hostname: u.hostname,
          port: u.port || (u.protocol === "https:" ? 443 : 80),
          path: u.pathname + (u.search || ""),
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(payload),
            ...(token ? { authorization: `Bearer ${token}` } : {})
          }
        },
        (res) => {
          let data = "";
          res.on("data", (d) => (data += d));
          res.on("end", () => {
            if (res.statusCode >= 200 && res.statusCode < 300) return resolve();
            return reject(new Error(`SMS HTTP error ${res.statusCode}: ${data}`));
          });
        }
      );
      req.on("error", reject);
      req.write(payload);
      req.end();
    });
    return;
  }

  throw new Error("Unknown SMS_PROVIDER: " + provider);
}

module.exports = { sendSms };

/**
 * TODO (örnek):
 * - kendi SMS gateway’ine göre http payload’ı düzenle
 * - response parsing ekle
 */
