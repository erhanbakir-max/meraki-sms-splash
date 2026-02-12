// smsService.js (ESM)
// İletiMerkezi SMS gönderimi + TR MSISDN normalize

const ILETIMERKEZI_URL =
  process.env.ILETIMERKEZI_URL ||
  "https://api.iletimerkezi.com/v1/send-sms"; // sizde farklıysa ENV ile override edin

function onlyDigits(s) {
  return String(s || "").replace(/\D/g, "");
}

// Kullanıcı: 0533..., +90533..., 90533..., 533... => API'ye: 533...
export function normalizeTrMsisdn(input) {
  const raw = String(input || "").trim();
  let d = onlyDigits(raw);

  if (!d) return "";

  // +90 / 90 / 0 prefix düzeltmeleri
  if (d.startsWith("90") && d.length >= 12) d = d.slice(2);
  if (d.startsWith("0") && d.length === 11) d = d.slice(1);

  // 10 hane olmalı ve 5 ile başlamalı (TR GSM)
  if (!/^5\d{9}$/.test(d)) return "";

  return d;
}

function escapeXml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function parseIletiXml(xml) {
  // Minimal parse: <code>200</code>, <message>...</message>, <id>...</id>
  const code = (xml.match(/<code>(\d+)<\/code>/) || [])[1] || null;
  const message = (xml.match(/<message>([\s\S]*?)<\/message>/) || [])[1] || null;
  const orderId = (xml.match(/<id>(\d+)<\/id>/) || [])[1] || null;
  return { code: code ? Number(code) : null, message: message ? message.trim() : null, orderId };
}

export async function sendOtpSms({ phone, text }) {
  const key = process.env.ILETI_KEY || "";
  const hash = process.env.ILETI_HASH || "";
  const sender = process.env.ILETI_SENDER || "";

  if (!key || !hash || !sender) {
    return { ok: false, error: "ENV_MISSING", code: null, message: "ILETI_KEY/ILETI_HASH/ILETI_SENDER missing" };
  }

  const msisdn = normalizeTrMsisdn(phone);
  if (!msisdn) {
    return { ok: false, error: "INVALID_MSISDN", code: null, message: "Invalid MSISDN" };
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<request>
  <authentication>
    <key>${escapeXml(key)}</key>
    <hash>${escapeXml(hash)}</hash>
  </authentication>
  <order>
    <sender>${escapeXml(sender)}</sender>
    <message>
      <text>${escapeXml(text)}</text>
      <receipents>
        <number>${escapeXml(msisdn)}</number>
      </receipents>
    </message>
  </order>
</request>`;

  let respText = "";
  try {
    const r = await fetch(ILETIMERKEZI_URL, {
      method: "POST",
      headers: {
        "Content-Type": "text/xml; charset=UTF-8"
      },
      body: xml
    });

    respText = await r.text();

    const parsed = parseIletiXml(respText);
    const code = parsed.code;

    if (code === 200) {
      return { ok: true, orderId: parsed.orderId || null };
    }

    return {
      ok: false,
      error: "ILETIMERKEZI_ERROR",
      code,
      message: parsed.message || "Unknown error",
      raw: respText
    };
  } catch (e) {
    return { ok: false, error: "NETWORK_ERROR", code: null, message: e?.message || String(e), raw: respText };
  }
}
