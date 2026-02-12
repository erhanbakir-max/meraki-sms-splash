// server.js
import express from "express";
import { createClient as createRedisClient } from "redis";
import pg from "pg";
import crypto from "crypto";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/** =========================
 *  ENV (defaults)
 *  ========================= */
const ENV = {
  PORT: Number(process.env.PORT || 8080),

  OTP_MODE: (process.env.OTP_MODE || "screen").toLowerCase(), // screen | sms (sms sonra)
  OTP_TTL_SECONDS: Number(process.env.OTP_TTL_SECONDS || 180),

  RL_MAC_SECONDS: Number(process.env.RL_MAC_SECONDS || 30),
  RL_MSISDN_SECONDS: Number(process.env.RL_MSISDN_SECONDS || 60),
  MAX_WRONG_ATTEMPTS: Number(process.env.MAX_WRONG_ATTEMPTS || 5),
  LOCK_SECONDS: Number(process.env.LOCK_SECONDS || 600),

  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",
  LOGO_URL: process.env.LOGO_URL || "",

  // Redis
  REDIS_URL: process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL || "",

  // Postgres
  DATABASE_URL: process.env.DATABASE_URL || process.env.POSTGRES_URL || ""
};

console.log("ENV:", {
  OTP_MODE: ENV.OTP_MODE,
  OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
  RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
  RL_MSISDN_SECONDS: ENV.RL_MSISDN_SECONDS,
  MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
  LOCK_SECONDS: ENV.LOCK_SECONDS,
  KVKK_VERSION: ENV.KVKK_VERSION
});

/** =========================
 *  Redis init
 *  ========================= */
let redis = null;
async function initRedis() {
  if (!ENV.REDIS_URL) {
    console.log("REDIS: not configured (REDIS_URL / REDIS_PUBLIC_URL missing). Running WITHOUT persistent store.");
    return null;
  }
  redis = createRedisClient({ url: ENV.REDIS_URL });
  redis.on("error", (e) => console.log("REDIS_ERROR", e?.message || e));
  await redis.connect();
  console.log("REDIS: connected");
  return redis;
}

/** =========================
 *  Postgres init + schema
 *  ========================= */
let db = null;
async function initDb() {
  if (!ENV.DATABASE_URL) {
    console.log("DATABASE: not configured (DATABASE_URL missing). 5651 logs will be skipped.");
    return null;
  }
  const { Pool } = pg;
  db = new Pool({ connectionString: ENV.DATABASE_URL });
  await db.query("select 1");
  console.log("DATABASE: connected");

  // Minimal 5651-ish access log table
  await db.query(`
    create table if not exists access_logs (
      id bigserial primary key,
      created_at timestamptz not null default now(),

      event text not null,              -- SPLASH_OPEN, OTP_CREATED, OTP_VERIFIED, GRANT_CALLED, GRANT_OK, GRANT_FAIL
      client_mac text,
      client_ip text,
      ap_name text,
      ssid text,

      full_name text,
      msisdn text,
      kvkk_accepted boolean,
      kvkk_version text,

      marker text,
      last4 text,

      base_grant_url text,
      continue_url text,

      meta jsonb
    );
  `);
  console.log("DATABASE: table ready");
  return db;
}

async function logDb(event, payload = {}) {
  try {
    if (!db) return;
    const row = {
      event,
      client_mac: payload.client_mac || null,
      client_ip: payload.client_ip || null,
      ap_name: payload.ap_name || null,
      ssid: payload.ssid || null,
      full_name: payload.full_name || null,
      msisdn: payload.msisdn || null,
      kvkk_accepted: typeof payload.kvkk_accepted === "boolean" ? payload.kvkk_accepted : null,
      kvkk_version: payload.kvkk_version || null,
      marker: payload.marker || null,
      last4: payload.last4 || null,
      base_grant_url: payload.base_grant_url || null,
      continue_url: payload.continue_url || null,
      meta: payload.meta ? JSON.stringify(payload.meta) : JSON.stringify({})
    };

    await db.query(
      `
      insert into access_logs
      (event, client_mac, client_ip, ap_name, ssid, full_name, msisdn, kvkk_accepted, kvkk_version, marker, last4, base_grant_url, continue_url, meta)
      values
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
      `,
      [
        row.event,
        row.client_mac,
        row.client_ip,
        row.ap_name,
        row.ssid,
        row.full_name,
        row.msisdn,
        row.kvkk_accepted,
        row.kvkk_version,
        row.marker,
        row.last4,
        row.base_grant_url,
        row.continue_url,
        row.meta
      ]
    );
  } catch (e) {
    console.log("DATABASE_LOG_FAIL", e?.message || e);
  }
}

/** =========================
 *  Helpers
 *  ========================= */
function pickContinueUrl(q) {
  // Meraki bazen continue_url / user_continue_url kullanır.
  return q.continue_url || q.user_continue_url || q.redirect || "";
}
function pickBaseGrantUrl(q) {
  return q.base_grant_url || q.base_grant || "";
}
function getClientMac(q) {
  return (q.client_mac || q.clientMac || "").toLowerCase();
}
function getClientIp(req, q) {
  // Meraki query’de client_ip olabiliyor
  const ip = q.client_ip || req.headers["x-forwarded-for"]?.toString()?.split(",")[0]?.trim() || req.socket?.remoteAddress || "";
  return ip;
}
function makeOtp() {
  // 6 digit
  return String(crypto.randomInt(0, forEach = 1000000).toString().padStart(6, "0"));
}
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function otpKey(clientMac) {
  return `otp:${clientMac}`;
}
function ctxKey(clientMac) {
  return `ctx:${clientMac}`;
}
function lockKey(clientMac) {
  return `lock:${clientMac}`;
}
function wrongKey(clientMac) {
  return `wrong:${clientMac}`;
}

async function isLocked(clientMac) {
  if (!redis) return false;
  const v = await redis.get(lockKey(clientMac));
  return v === "1";
}

async function incWrong(clientMac) {
  if (!redis) return 0;
  const k = wrongKey(clientMac);
  const n = await redis.incr(k);
  await redis.expire(k, ENV.LOCK_SECONDS);
  if (n >= ENV.MAX_WRONG_ATTEMPTS) {
    await redis.set(lockKey(clientMac), "1", { EX: ENV.LOCK_SECONDS });
  }
  return n;
}

async function clearWrongAndLock(clientMac) {
  if (!redis) return;
  await redis.del(wrongKey(clientMac));
  await redis.del(lockKey(clientMac));
}

async function saveCtx(clientMac, ctx) {
  if (!redis) return;
  await redis.set(ctxKey(clientMac), JSON.stringify(ctx), { EX: 60 * 60 }); // 1 saat
}
async function loadCtx(clientMac) {
  if (!redis) return null;
  const v = await redis.get(ctxKey(clientMac));
  return v ? JSON.parse(v) : null;
}

async function saveOtp(clientMac, otpObj) {
  if (!redis) return;
  await redis.set(otpKey(clientMac), JSON.stringify(otpObj), { EX: ENV.OTP_TTL_SECONDS });
}
async function loadOtp(clientMac) {
  if (!redis) return null;
  const v = await redis.get(otpKey(clientMac));
  return v ? JSON.parse(v) : null;
}
async function clearOtp(clientMac) {
  if (!redis) return;
  await redis.del(otpKey(clientMac));
}

/** =========================
 *  Meraki GRANT
 *  ========================= */
async function callMerakiGrant({ baseGrantUrl, continueUrl, durationSeconds = 60 * 60 }) {
  // Meraki base_grant_url’e GET atarak izin verilir.
  // Tipik: <base_grant_url>?continue_url=<...>&duration=<sec>
  const u = new URL(baseGrantUrl);
  if (continueUrl) u.searchParams.set("continue_url", continueUrl);
  u.searchParams.set("duration", String(durationSeconds));

  console.log("GRANT_CALLED", { url: u.toString() });

  const res = await fetch(u.toString(), { method: "GET" });
  const text = await res.text().catch(() => "");
  return { ok: res.ok, status: res.status, body: text?.slice(0, 2000) };
}

/** =========================
 *  Routes
 *  ========================= */

// Splash entry
app.get("/", async (req, res) => {
  const q = req.query || {};
  const baseGrantUrl = pickBaseGrantUrl(q);
  const continueUrl = pickContinueUrl(q);
  const clientMac = getClientMac(q);
  const clientIp = getClientIp(req, q);

  const hasBaseGrant = !!baseGrantUrl;
  const hasContinue = !!continueUrl;
  const hasClientMac = !!clientMac;

  console.log("SPLASH_OPEN", { hasBaseGrant, hasContinue, hasClientMac, mode: ENV.OTP_MODE });

  // Persist ctx for later grant
  if (redis && clientMac) {
    await saveCtx(clientMac, {
      baseGrantUrl,
      continueUrl,
      clientMac,
      clientIp,
      apName: q.ap_name || q.ap || "",
      ssid: q.ssid || "",
      seenAt: Date.now()
    });
  }

  await logDb("SPLASH_OPEN", {
    client_mac: clientMac,
    client_ip: clientIp,
    ap_name: q.ap_name || q.ap || "",
    ssid: q.ssid || "",
    base_grant_url: baseGrantUrl,
    continue_url: continueUrl,
    kvkk_version: ENV.KVKK_VERSION,
    meta: { q }
  });

  // Render login UI
  const logoHtml = ENV.LOGO_URL
    ? `<div style="text-align:center;margin:16px 0;"><img src="${ENV.LOGO_URL}" alt="logo" style="max-height:64px;max-width:240px"/></div>`
    : "";

  const kvkkHtml = `
    <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:#fafafa;max-height:160px;overflow:auto;">
      <strong>KVKK Metni (Placeholder)</strong><br/>
      Bu bir placeholder KVKK metnidir. Gerçek metin daha sonra eklenecek.
      <br/><br/>Versiyon: ${ENV.KVKK_VERSION}
    </div>`;

  // Not: SMS şimdilik kapalı, hep screen OTP
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
<!doctype html>
<html lang="tr">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Misafir Wi-Fi Giriş</title>
</head>
<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1220; margin:0; padding:24px;">
  <div style="max-width:420px;margin:0 auto;background:#fff;border-radius:18px;padding:22px;box-shadow:0 10px 30px rgba(0,0,0,.25);">
    ${logoHtml}
    <h2 style="margin:0 0 6px 0;">Misafir Wi-Fi</h2>
    <p style="margin:0 0 16px 0;color:#4b5563;">Bağlanmak için bilgilerinizi girin ve doğrulayın.</p>

    <form method="POST" action="/otp/create" style="display:flex;flex-direction:column;gap:10px;">
      <input type="hidden" name="client_mac" value="${clientMac || ""}"/>
      <input type="hidden" name="base_grant_url" value="${baseGrantUrl || ""}"/>
      <input type="hidden" name="continue_url" value="${continueUrl || ""}"/>

      <label style="font-size:13px;color:#374151;">Ad Soyad</label>
      <input name="full_name" required placeholder="Ad Soyad" style="padding:12px;border:1px solid #d1d5db;border-radius:12px;"/>

      <label style="font-size:13px;color:#374151;">Cep Telefonu</label>
      <input name="msisdn" required placeholder="05xx..." inputmode="tel" style="padding:12px;border:1px solid #d1d5db;border-radius:12px;"/>

      ${kvkkHtml}

      <label style="display:flex;gap:10px;align-items:flex-start;margin-top:6px;">
        <input type="checkbox" name="kvkk_accepted" value="1" required style="margin-top:4px;"/>
        <span style="font-size:13px;color:#374151;">KVKK metnini okudum ve kabul ediyorum.</span>
      </label>

      <button type="submit" style="margin-top:8px;padding:12px 14px;border:0;border-radius:12px;background:#4f46e5;color:white;font-weight:600;cursor:pointer;">
        Devam Et (OTP oluştur)
      </button>

      <div style="margin-top:6px;color:#6b7280;font-size:12px;">
        Client MAC: <code>${clientMac || "-"}</code>
      </div>
    </form>
  </div>
</body>
</html>
  `);
});

// OTP create
app.post("/otp/create", async (req, res) => {
  const body = req.body || {};
  const clientMac = (body.client_mac || "").toLowerCase();
  const fullName = (body.full_name || "").trim();
  const msisdn = (body.msisdn || "").trim();
  const kvkkAccepted = body.kvkk_accepted === "1" || body.kvkk_accepted === "on";

  // ctx fallback (eğer hidden gelmezse redis'ten çek)
  let ctx = redis && clientMac ? await loadCtx(clientMac) : null;

  const baseGrantUrl = body.base_grant_url || ctx?.baseGrantUrl || "";
  const continueUrl = body.continue_url || ctx?.continueUrl || "";
  const clientIp = ctx?.clientIp || "";

  if (!clientMac) return res.status(400).send("client_mac missing");
  if (!baseGrantUrl) return res.status(400).send("base_grant_url missing");
  if (!continueUrl) return res.status(400).send("continue_url missing");
  if (!kvkkAccepted) return res.status(400).send("KVKK onayı gerekli");

  if (redis && (await isLocked(clientMac))) {
    return res.status(429).send("Çok fazla hatalı deneme. Lütfen sonra tekrar deneyin.");
  }

  // OTP
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const marker = String(crypto.randomInt(100000, 999999));
  const last4 = msisdn.slice(-4);

  // store otp & ctx
  if (redis) {
    await saveOtp(clientMac, {
      otp,
      marker,
      last4,
      createdAt: Date.now(),
      fullName,
      msisdn,
      kvkkAccepted,
      kvkkVersion: ENV.KVKK_VERSION
    });
    await saveCtx(clientMac, {
      ...(ctx || {}),
      baseGrantUrl,
      continueUrl,
      clientMac,
      clientIp,
      fullName,
      msisdn,
      kvkkAccepted,
      kvkkVersion: ENV.KVKK_VERSION
    });
  }

  console.log("OTP_CREATED", { marker, last4, client_mac: clientMac });
  await logDb("OTP_CREATED", {
    client_mac: clientMac,
    client_ip: clientIp,
    full_name: fullName,
    msisdn,
    kvkk_accepted: kvkkAccepted,
    kvkk_version: ENV.KVKK_VERSION,
    marker,
    last4,
    base_grant_url: baseGrantUrl,
    continue_url: continueUrl
  });

  // SCREEN mode: ekranda OTP göster, kullanıcı girsin
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
<!doctype html>
<html lang="tr">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>OTP Doğrulama</title>
</head>
<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b1220; margin:0; padding:24px;">
  <div style="max-width:420px;margin:0 auto;background:#fff;border-radius:18px;padding:22px;box-shadow:0 10px 30px rgba(0,0,0,.25);">
    <h2 style="margin:0 0 6px 0;">OTP Doğrulama</h2>
    <p style="margin:0 0 14px 0;color:#4b5563;">Test modunda OTP ekranda gösterilir.</p>

    <div style="border:1px dashed #9ca3af;border-radius:14px;padding:12px;background:#f9fafb;margin-bottom:12px;">
      <div style="font-size:13px;color:#6b7280;">OTP (screen mode)</div>
      <div style="font-size:34px;letter-spacing:4px;font-weight:800;">${otp}</div>
      <div style="font-size:12px;color:#6b7280;">Marker: ${marker} — Tel son4: ${last4}</div>
    </div>

    <form method="POST" action="/otp/verify" style="display:flex;flex-direction:column;gap:10px;">
      <input type="hidden" name="client_mac" value="${clientMac}"/>
      <input type="hidden" name="marker" value="${marker}"/>

      <label style="font-size:13px;color:#374151;">OTP Kodu</label>
      <input name="otp" required placeholder="6 haneli" inputmode="numeric" style="padding:12px;border:1px solid #d1d5db;border-radius:12px;"/>

      <button type="submit" style="margin-top:6px;padding:12px 14px;border:0;border-radius:12px;background:#16a34a;color:white;font-weight:700;cursor:pointer;">
        Doğrula ve Bağlan
      </button>
    </form>
  </div>
</body>
</html>
  `);
});

// OTP verify -> AUTO GRANT
app.post("/otp/verify", async (req, res) => {
  const body = req.body || {};
  const clientMac = (body.client_mac || "").toLowerCase();
  const otpIn = (body.otp || "").trim();
  const markerIn = (body.marker || "").trim();

  if (!clientMac) return res.status(400).send("client_mac missing");

  if (redis && (await isLocked(clientMac))) {
    return res.status(429).send("Çok fazla hatalı deneme. Lütfen sonra tekrar deneyin.");
  }

  const otpObj = redis ? await loadOtp(clientMac) : null;
  const ctx = redis ? await loadCtx(clientMac) : null;

  if (!otpObj || !ctx) {
    return res.status(400).send("OTP süresi dolmuş veya oturum bilgisi bulunamadı. Lütfen yeniden deneyin.");
  }

  const ok = otpObj.otp === otpIn && otpObj.marker === markerIn;
  if (!ok) {
    const wrong = await incWrong(clientMac);
    await logDb("OTP_FAIL", {
      client_mac: clientMac,
      client_ip: ctx?.clientIp || "",
      marker: otpObj.marker,
      last4: otpObj.last4,
      base_grant_url: ctx?.baseGrantUrl || "",
      continue_url: ctx?.continueUrl || "",
      meta: { wrong }
    });
    return res.status(401).send("OTP hatalı");
  }

  await clearWrongAndLock(clientMac);

  console.log("OTP_VERIFY_OK", { marker: otpObj.marker, client_mac: clientMac });
  await logDb("OTP_VERIFIED", {
    client_mac: clientMac,
    client_ip: ctx?.clientIp || "",
    full_name: ctx?.fullName || otpObj.fullName,
    msisdn: ctx?.msisdn || otpObj.msisdn,
    kvkk_accepted: true,
    kvkk_version: ctx?.kvkkVersion || ENV.KVKK_VERSION,
    marker: otpObj.marker,
    last4: otpObj.last4,
    base_grant_url: ctx?.baseGrantUrl || "",
    continue_url: ctx?.continueUrl || ""
  });

  // AUTO GRANT
  const baseGrantUrl = ctx?.baseGrantUrl || "";
  const continueUrl = ctx?.continueUrl || "";

  if (!baseGrantUrl || !continueUrl) {
    return res.status(500).send("Grant context missing (base_grant_url / continue_url)");
  }

  await logDb("GRANT_CALLED", {
    client_mac: clientMac,
    client_ip: ctx?.clientIp || "",
    base_grant_url: baseGrantUrl,
    continue_url: continueUrl,
    marker: otpObj.marker,
    last4: otpObj.last4
  });

  const grant = await callMerakiGrant({
    baseGrantUrl,
    continueUrl,
    durationSeconds: 60 * 60 // 1 saat örnek
  });

  if (!grant.ok) {
    console.log("GRANT_FAIL", { status: grant.status });
    await logDb("GRANT_FAIL", {
      client_mac: clientMac,
      client_ip: ctx?.clientIp || "",
      base_grant_url: baseGrantUrl,
      continue_url: continueUrl,
      marker: otpObj.marker,
      last4: otpObj.last4,
      meta: { status: grant.status, body: grant.body?.slice(0, 500) }
    });
    return res.status(502).send("Meraki grant başarısız. Logları kontrol et.");
  }

  console.log("GRANT_OK", { client_mac: clientMac });
  await logDb("GRANT_OK", {
    client_mac: clientMac,
    client_ip: ctx?.clientIp || "",
    base_grant_url: baseGrantUrl,
    continue_url: continueUrl,
    marker: otpObj.marker,
    last4: otpObj.last4
  });

  // OTP tek kullanımlık olsun
  await clearOtp(clientMac);

  // Meraki continue_url’ye yönlendir
  res.redirect(continueUrl);
});

// Health
app.get("/health", async (req, res) => {
  res.json({
    ok: true,
    redis: !!redis,
    db: !!db,
    mode: ENV.OTP_MODE,
    kvkk: ENV.KVKK_VERSION
  });
});

/** =========================
 *  Boot
 *  ========================= */
(async () => {
  await initRedis();
  await initDb();

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
})();
