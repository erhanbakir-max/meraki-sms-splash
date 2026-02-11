// server.js (ESM - package.json: { "type": "module" })

import http from "http";
import { URLSearchParams } from "url";

// -------------------------
// Config / Env
// -------------------------
const PORT = process.env.PORT || 3000;

const ILETI_KEY = process.env.ILETI_KEY || "";
const ILETI_HASH = process.env.ILETI_HASH || "";
const ILETI_SENDER = process.env.ILETI_SENDER || "";
const ILETI_TEST_MSISDN = process.env.ILETI_TEST_MSISDN || ""; // 10 hane: 5XXXXXXXXX

const SMS_DEBUG = (process.env.SMS_DEBUG || "false").toLowerCase() === "true";

// -------------------------
// Helpers
// -------------------------
async function fetchText(url, opts = {}) {
  const res = await fetch(url, { ...opts, redirect: "follow" });
  const text = await res.text();
  return { res, text };
}

function normalizeMsisdn(input) {
  // trim + sadece rakam
  return String(input || "").trim().replace(/\D/g, "");
}

function logEnvAndMsisdn() {
  const cleaned = normalizeMsisdn(ILETI_TEST_MSISDN);

  console.log("ENV_CHECK:", {
    SMS_DEBUG,
    hasKey: !!ILETI_KEY,
    hasHash: !!ILETI_HASH,
    hasSender: !!ILETI_SENDER,
    hasTestMsisdn: !!ILETI_TEST_MSISDN,
    sender: ILETI_SENDER || null,
  });

  console.log("MSISDN_DEBUG:", {
    raw: ILETI_TEST_MSISDN,
    cleanedLen: cleaned.length,
    cleanedLast4: cleaned ? cleaned.slice(-4) : null,
    // İstersen bunu kaldırabilirsin; debug için bıraktım:
    cleaned,
  });
}

async function netSmokeTest() {
  // Public IP (plain)
  try {
    const { text: ipText } = await fetchText("https://ifconfig.me/ip");
    console.log("PUBLIC_IP:", ipText.trim());
  } catch (e) {
    console.log("IP_ERROR:", e?.message || e);
  }

  // İletiMerkezi erişim
  try {
    const { res } = await fetchText("https://api.iletimerkezi.com");
    console.log("ILETIMERKEZI_HTTP:", res.status);
  } catch (e) {
    console.log("ILETIMERKEZI_ERROR:", e?.message || e);
  }
}

async function sendSmsTestOnce() {
  const cleaned = normalizeMsisdn(ILETI_TEST_MSISDN);

  const missing = [];
  if (!ILETI_KEY) missing.push("ILETI_KEY");
  if (!ILETI_HASH) missing.push("ILETI_HASH");
  if (!ILETI_SENDER) missing.push("ILETI_SENDER");
  if (!cleaned) missing.push("ILETI_TEST_MSISDN(empty after cleaning)");

  if (missing.length) {
    console.log("SMS_TEST_SKIPPED: missing env ->", missing.join(", "));
    return;
  }

  // TR GSM format: 10 hane, 5 ile başlar
  if (!/^5\d{9}$/.test(cleaned)) {
    console.log(
      "SMS_TEST_SKIPPED: MSISDN format invalid. Expected 5XXXXXXXXX (10 digits). Got:",
      cleaned
    );
    return;
  }

  const params = new URLSearchParams({
    key: ILETI_KEY,
    hash: ILETI_HASH,
    text: "Test OTP (railway debug)",
    receipents: cleaned, // DOĞRU param adı
    sender: ILETI_SENDER, // 450 alırsan -> başlık uygun değil / onaylı değil / farklı yazım
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
// Simple server
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

  logEnvAndMsisdn();
  await netSmokeTest();

  if (SMS_DEBUG) {
    await sendSmsTestOnce();
  } else {
    console.log("SMS_DEBUG disabled (set SMS_DEBUG=true to run SMS test once on startup)");
  }
});
