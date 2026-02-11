// server.js (ESM)

import http from "http";
import { sendOtpSms } from "./smsService.js";

const PORT = process.env.PORT || 8080;

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // örnek: POST /send-otp  { "phone": "...", "code": "123456" }
  if (req.url === "/send-otp" && req.method === "POST") {
    try {
      const body = await readJson(req);
      const phone = body.phone;
      const code = body.code;

      // OTP metni – bunu siz özelleştirin
      const text = `Giris kodunuz: ${code}`;

      const result = await sendOtpSms({ phone, text });

      if (result.ok) {
        // PROD log: numara / mesaj basma. Sadece orderId yeter.
        console.log("OTP_SMS_SENT", { orderId: result.orderId });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, orderId: result.orderId }));
        return;
      }

      console.log("OTP_SMS_FAILED", { error: result.error, code: result.code, message: result.message });

      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, ...result }));
      return;
    } catch (e) {
      console.log("OTP_SMS_EXCEPTION", { message: e?.message || String(e) });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "SERVER_ERROR" }));
      return;
    }
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: false, error: "NOT_FOUND" }));
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
