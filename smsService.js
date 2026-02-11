// smsService.js (ESM)

import { URLSearchParams } from "url";

const ILETI_KEY = process.env.ILETI_KEY || "";
const ILETI_HASH = process.env.ILETI_HASH || "";
const ILETI_SENDER = process.env.ILETI_SENDER || ""; // örn: APITEST

function requireEnv() {
  const missing = [];
  if (!ILETI_KEY) missing.push("ILETI_KEY");
  if (!ILETI_HASH) missing.push("ILETI_HASH");
  if (!ILETI_SENDER) missing.push("ILETI_SENDER");
  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }
}

export function normalizeTrMsisdn(input) {
  let s = String(input || "").trim().replace(/\D/g, "");
  if (s.startsWith("90")) s = s.slice(2);
  if (s.startsWith("0")) s = s.slice(1);
  return /^5\d{9}$/.test(s) ? s : null;
}

function extractXmlTag(xml, tag) {
  // basit XML tag extractor (dış bağımlılık yok)
  const re = new RegExp(`<${tag}>([^<]+)</${tag}>`);
  const m = xml.match(re);
  return m ? m[1] : null;
}

export async function sendOtpSms({ phone, text }) {
  requireEnv();

  const msisdn = normalizeTrMsisdn(phone);
  if (!msisdn) {
    return {
      ok: false,
      error: "INVALID_PHONE_FORMAT",
      detail: "Expected TR GSM like 5XXXXXXXXX (10 digits).",
    };
  }

  if (!text || typeof text !== "string" || text.trim().length === 0) {
    return { ok: false, error: "EMPTY_TEXT" };
  }

  // İletiMerkezi GET endpoint
  const params = new URLSearchParams({
    key: ILETI_KEY,
    hash: ILETI_HASH,
    text: text,
    receipents: msisdn,     // DOĞRU param adı
    sender: ILETI_SENDER,   // onaylı başlık (APITEST)
    iys: "1",
    iysList: "BIREYSEL",
  });

  const url = `https://api.iletimerkezi.com/v1/send-sms/get/?${params.toString()}`;

  let res;
  let body;
  try {
    res = await fetch(url, { method: "GET", redirect: "follow" });
    body = await res.text();
  } catch (e) {
    return { ok: false, error: "NETWORK_ERROR", detail: e?.message || String(e) };
  }

  const code = extractXmlTag(body, "code") || String(res.status);
  const message = extractXmlTag(body, "message") || null;
  const orderId = extractXmlTag(body, "id") || null;

  if (String(code) === "200") {
    return { ok: true, code: 200, orderId };
  }

  // Yaygın hatalar için etiketleme (opsiyonel)
  const mapped =
    String(code) === "450" ? "SENDER_NOT_ALLOWED" :
    String(code) === "452" ? "INVALID_RECEIPENTS" :
    String(code) === "401" ? "UNAUTHORIZED_OR_IP_RESTRICTED" :
    "ILETIMERKEZI_ERROR";

  return {
    ok: false,
    error: mapped,
    code: Number.isFinite(Number(code)) ? Number(code) : code,
    message,
  };
}
