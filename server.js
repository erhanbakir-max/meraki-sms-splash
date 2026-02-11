import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const OTP_TTL_MS = 3 * 60 * 1000;
const store = new Map(); // PROD: Redis önerilir

function normalizeTrPhone(p) {
  const digits = (p || "").replace(/\D/g, "");
  if (digits.startsWith("90") && digits.length === 12) return "+" + digits;   // 905xxxxxxxxx
  if (digits.startsWith("0") && digits.length === 11) return "+9" + digits;   // 05xxxxxxxxx
  if (digits.length === 10) return "+90" + digits;                            // 5xxxxxxxxx
  return null;
}

function makeOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

app.get("/", (req, res) => {
  const { base_grant_url, user_continue_url, client_mac, node_id, gateway_id } = req.query;

  if (!base_grant_url || !user_continue_url) {
    return res.status(400).send("Meraki parametreleri eksik (base_grant_url / user_continue_url).");
  }

  res.send(`
    <h3>Misafir İnternet Girişi</h3>
    <form method="POST" action="/send-otp">
      <input type="hidden" name="base_grant_url" value="${base_grant_url}">
      <input type="hidden" name="user_continue_url" value="${user_continue_url}">
      <input type="hidden" name="client_mac" value="${client_mac || ""}">
      <input type="hidden" name="node_id" value="${node_id || ""}">
      <input type="hidden" name="gateway_id" value="${gateway_id || ""}">

      <div>Ad: <input name="firstName" required></div>
      <div>Soyad: <input name="lastName" required></div>
      <div>Telefon: <input name="phone" placeholder="05xx..." required></div>

      <button type="submit">SMS Gönder</button>
    </form>
  `);
});

app.post("/send-otp", async (req, res) => {
  const { firstName, lastName, phone, base_grant_url, user_continue_url, client_mac, gateway_id } = req.body;

  const normPhone = normalizeTrPhone(phone);
  if (!normPhone) return res.status(400).send("Telefon formatı hatalı.");

  const otp = makeOtp();

  const key = crypto
    .createHash("sha256")
    .update(`${normPhone}|${client_mac || ""}|${gateway_id || ""}`)
    .digest("hex");

  store.set(key, {
    otp,
    expiresAt: Date.now() + OTP_TTL_MS,
    firstName,
    lastName,
    base_grant_url,
    user_continue_url,
  });

  // TODO: Buraya SMS sağlayıcı entegrasyonu gelecek
  // await sendSms(normPhone, `Doğrulama kodunuz: ${otp}`);

  res.send(`
    <h3>SMS gönderildi</h3>
    <form method="POST" action="/verify-otp">
      <input type="hidden" name="key" value="${key}">
      <div>Kod: <input name="otp" maxlength="6" required></div>
      <button type="submit">Doğrula</button>
    </form>
  `);
});

app.post("/verify-otp", (req, res) => {
  const { key, otp } = req.body;
  const rec = store.get(key);
  if (!rec) return res.status(400).send("Oturum bulunamadı / süresi doldu.");

  if (Date.now() > rec.expiresAt) {
    store.delete(key);
    return res.status(400).send("Kod süresi doldu.");
  }

  if (String(otp).trim() !== rec.otp) return res.status(400).send("Kod yanlış.");

  store.delete(key);

  // İnternete çıkış (Meraki grant)
  res.redirect(rec.base_grant_url);
});

app.listen(process.env.PORT || 8080, () => console.log("Server up"));
const axios = require("axios");

(async () => {
  try {
    const ip = await axios.get("https://ifconfig.me");
    console.log("PUBLIC_IP:", ip.data);
  } catch (err) {
    console.log("IP_ERROR:", err.message);
  }
})();
