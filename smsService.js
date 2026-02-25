/**
 * Optional standalone SMS service file (İleti Merkezi).
 * Not required by server.js (it has inline sendOtpSms()) but provided if you prefer separation.
 */
const axios = require("axios");

function normalizeTRPhoneForOtp(input) {
  let p = String(input || "").trim().replace(/\s+/g, "").replace(/-/g, "");
  if (p.startsWith("00")) p = "+" + p.slice(2);
  if (p.startsWith("+90")) p = p.slice(3);
  if (p.startsWith("90")) p = p.slice(2);
  if (p.startsWith("0")) p = p.slice(1);
  if (!/^5\d{9}$/.test(p)) return null;
  return p;
}
function normalizeTRPhoneForSms(input) {
  const p10 = normalizeTRPhoneForOtp(input);
  if (!p10) return null;
  return "90" + p10;
}

async function sendSmsIletiMerkezi(phoneRaw, message) {
  const testMode = String(process.env.SMS_TEST_MODE || "false").toLowerCase() === "true";
  const url = process.env.IM_API_URL;
  const user = process.env.IM_USER;
  const pass = process.env.IM_PASS;
  const sender = process.env.IM_SENDER;

  const to = normalizeTRPhoneForSms(phoneRaw);
  if (!to) throw new Error("MSISDN invalid");
  if (!url || !user || !pass || !sender) throw new Error("IM env missing");

  const payload = { username: user, password: pass, sender, message, recipients: [to] };

  if (testMode) return { ok: true, test: true, payload };

  const res = await axios.post(url, payload, { timeout: 15000, headers: { "Content-Type": "application/json" } });
  return res.data;
}

module.exports = { sendSmsIletiMerkezi };
