import axios from "axios";

function maskMsisdn(msisdn) {
  if (!msisdn) return null;
  return msisdn.length >= 4 ? msisdn.slice(-4) : "****";
}

// İletimerkezi genelde 10 haneli (5XXXXXXXXX) ister.
// Kullanıcı 0 ile, +90 ile, 90 ile girse de normalize ediyoruz.
export function normalizeTrMsisdn(input) {
  const raw = String(input ?? "").trim();
  const digits = raw.replace(/[^\d]/g, "");

  // +90 / 90 / 0 ile başlayanları kırp
  let cleaned = digits;
  if (cleaned.startsWith("90") && cleaned.length === 12) cleaned = cleaned.slice(2);
  if (cleaned.startsWith("0") && cleaned.length === 11) cleaned = cleaned.slice(1);

  // artık 10 hane ve 5 ile başlamalı
  if (!/^5\d{9}$/.test(cleaned)) {
    return { ok: false, msisdn: "", last4: null, reason: "Expected 5XXXXXXXXX (10 digits)" };
  }
  return { ok: true, msisdn: cleaned, last4: maskMsisdn(cleaned), reason: null };
}

export async function sendSmsViaIletimerkezi({ msisdn, text, debug = false }) {
  const ILETIMERKEZI_URL =
    process.env.ILETIMERKEZI_URL || "https://api.iletimerkezi.com/v1/send-sms";

  const key = process.env.ILETIMERKEZI_KEY;
  const hash = process.env.ILETIMERKEZI_HASH;
  const sender = process.env.ILETIMERKEZI_SENDER;

  if (!key || !hash || !sender) {
    return {
      ok: false,
      code: "MISSING_ENV",
      message: "ILETIMERKEZI_KEY / ILETIMERKEZI_HASH / ILETIMERKEZI_SENDER eksik"
    };
  }

  // XML payload (İletimerkezi API buna çok sık gidiyor)
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<request>
  <authentication>
    <key>${key}</key>
    <hash>${hash}</hash>
  </authentication>
  <order>
    <sender>${sender}</sender>
    <message>
      <text>${escapeXml(text)}</text>
      <receipents>
        <number>${msisdn}</number>
      </receipents>
    </message>
  </order>
</request>`;

  try {
    const resp = await axios.post(ILETIMERKEZI_URL, xml, {
      headers: { "Content-Type": "application/xml" },
      timeout: 15000
    });

    if (debug) {
      console.log("ILETIMERKEZI_HTTP:", resp.status);
      console.log("ILETIMERKEZI_BODY:", typeof resp.data === "string" ? resp.data.slice(0, 500) : resp.data);
    }

    // API 200 dönse bile içerikte status code olabilir; burada basitçe 200 ise OK sayıyoruz.
    return { ok: resp.status === 200, http: resp.status, body: resp.data };
  } catch (e) {
    const http = e?.response?.status;
    const body = e?.response?.data;
    return {
      ok: false,
      code: "ILETIMERKEZI_ERROR",
      http,
      message: e?.message || "Request failed",
      body
    };
  }
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
