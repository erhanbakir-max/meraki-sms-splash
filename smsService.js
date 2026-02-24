const axios = require("axios");

function normalizeTRPhone(phone) {
  // Kabul: +90xxxxxxxxxx veya 05xxxxxxxxx veya 5xxxxxxxxx
  let p = String(phone || "").trim();
  p = p.replace(/\s+/g, "").replace(/-/g, "");

  if (p.startsWith("00")) p = "+" + p.slice(2);
  if (p.startsWith("0")) p = p.slice(1);        // 05xx -> 5xx
  if (p.startsWith("+90")) p = p.slice(3);      // +90 -> 5xx
  if (p.startsWith("90")) p = p.slice(2);       // 90 -> 5xx

  // artık 5xxxxxxxxx bekliyoruz (10 hane)
  if (!/^5\d{9}$/.test(p)) return null;
  return "90" + p; // İleti Merkezi çoğu senaryoda 905xxxxxxxxx ister
}

async function sendSMS(phone, message) {
  const testMode = String(process.env.SMS_TEST_MODE || "false").toLowerCase() === "true";
  const url = process.env.IM_API_URL;
  const user = process.env.IM_USER;
  const pass = process.env.IM_PASS;
  const sender = process.env.IM_SENDER;

  const to = normalizeTRPhone(phone);
  if (!to) throw new Error(`Invalid phone format: ${phone}`);

  if (!url || !user || !pass || !sender) {
    throw new Error("Missing SMS env vars: IM_API_URL / IM_USER / IM_PASS / IM_SENDER");
  }

  // ✅ REST/JSON örneği (İleti Merkezi hesabına göre payload alan adları değişebilir)
  // Panel dökümanında "username/password" veya "user/pass" veya "api_key" gibi isimler olabilir.
  const payload = {
    username: user,
    password: pass,
    sender: sender,
    message: message,
    recipients: [to] // bazen "gsm" / "to" / "numbers" oluyor
  };

  if (testMode) {
    console.log("SMS_TEST_MODE=TRUE. Would send:", { to, sender, message });
    return { ok: true, test: true };
  }

  try {
    const res = await axios.post(url, payload, {
      timeout: 15000,
      headers: { "Content-Type": "application/json" }
    });

    // Bazı API’ler 200 dönüp body’de hata kodu verir
    const data = res.data;
    // Burayı dökümana göre sıkılaştırırız:
    // ör: data.status === "success" vb.
    return data;
  } catch (err) {
    const detail = err?.response?.data || err.message;
    console.error("IM SMS ERROR:", detail);
    throw new Error("SMS send failed");
  }
}

module.exports = { sendSMS };
