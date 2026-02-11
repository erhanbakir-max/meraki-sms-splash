// server.js (ESM - package.json: { "type": "module" })

import http from "http";
import { URLSearchParams } from "url";

// -------------------------
// Config / Env
// -------------------------
const PORT = process.env.PORT || 3000;

// İletiMerkezi env değişkenleri (Railway Variables'tan gir)
const ILETI_KEY = process.env.ILETI_KEY || "";
const ILETI_HASH = process.env.ILETI_HASH || "";
const ILETI_SENDER = process.env.ILETI_SENDER || "";
const ILETI_TEST_MSISDN = process.env.ILETI_TEST_MSISDN || ""; // örn: 5XXXXXXXXX (0 yok)
const SMS_DEBUG = (process.env.SMS_DEBUG || "false").toLowerCase() === "true";

// -------------------------
// Helpers
// -------------------------
async function fetchText(url, opts = {}) {
  const res = await fetch(url, { ...opts, redirect: "follow" });
  const text = await res.text();
  return { res, text };
}

async function netSmokeTest() {
  try {
    const { text: ipText } = await fetchText("https://ifconfig.me", {
  headers: { "Accept": "text/plain" },
});
console.log("PUBLIC_IP:", ipText.trim());
  } catch (e) {
    console.log("IP_ERROR:", e?.message || e);
  }

  try {
    const { res } = await fetchText("https://api.iletimerkezi.com");
    console.log("ILETIMERKEZI_HTTP:", res.status);
  } catch (e) {
    console.log("ILETIMERKEZI_ERROR:", e?.message || e);
  }
}

async function iletimerkeziSmsTestGet() {
  // Zorunlu env’ler yoksa test yapma
  const missing = [];
  if (!ILETI_KEY) missing.push("ILETI_KEY");
  if (!ILETI_HASH) missing.push("ILETI_HASH");
  if (!ILETI_SENDER) missing.push("ILETI_SENDER");
  if (!ILETI_TEST_MSISDN) missing.push("ILETI_TEST_MSISDN");

  if (missing.length) {
    console.log(
      "SMS_TEST_SKIPPED: missing env ->",
      missing.join(", ")
    );
    return;
  }

  // İletiMerkezi GET endpoint params
  // Dokümana göre: key, hash, text, receipents, sender (+ iys/iysList opsiyonel/bağlı)
  const params = new URLSearchParams({
    key: ILETI_KEY,
    hash: ILETI_HASH,
    text: "Test OTP (railway debug)",
    receipents: ILETI_TEST_MSISDN,
    sender: ILETI_SENDER,
    iys: "1",
    iysList: "BIREYSEL",
  });

  const url = `https://api.iletimerkezi.com/v1/send-sms/get/?${params.toString()}`;

  try {
    const { res, text } = await fetchText(url);
    console.log("SMS_HTTP:", res.status);
    console.log("SMS_BODY:", text);
  } catch (e) {
    console.log("SMS_TEST_ERROR:", e?.message || e);
  }
}

// -------------------------
// Simple server (health endpoint)
// -------------------------
const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("meraki-sms-splash is running\n");
});

server.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);

  // 1) Net test her startta 1 kez
  await netSmokeTest();

  // 2) İstersen SMS debug test (env ile aç/kapat)
  if (SMS_DEBUG) {
    await iletimerkeziSmsTestGet();
  } else {
    console.log("SMS_DEBUG disabled (set SMS_DEBUG=true to run SMS test once on startup)");
  }
});
