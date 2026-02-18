"use strict";

/**
 * meraki-sms-splash - server.js (robust ctx carry)
 * FIXES:
 *  - Carries Meraki ctx via cookie-based SID (ctx:sid:<sid>)
 *  - Also includes ctx hidden inputs (best-effort)
 *  - Also tries to parse ctx from Referer header on /otp/request and /otp/verify (fallback)
 *  - Does NOT require basic-auth package (custom parser)
 *
 * ENV:
 *  PORT=8080
 *  DATABASE_URL=...
 *  REDIS_URL=... (optional)
 *  ADMIN_USER=...
 *  ADMIN_PASS=...
 *  OTP_MODE=screen|sms
 *  OTP_TTL_SECONDS=180
 *  RL_MAC_SECONDS=30
 *  RL_PHONE_SECONDS=60
 *  MAX_WRONG_ATTEMPTS=5
 *  LOCK_SECONDS=600
 *  KVKK_VERSION=...
 *  TZ=Europe/Istanbul
 *  DAILY_HMAC_KEY=... (optional)
 */

const http = require("http");
const url = require("url");
const crypto = require("crypto");
const { Pool } = require("pg");

let Redis = null;
try { Redis = require("ioredis"); } catch { Redis = null; }

// -------------------- ENV --------------------
const ENV = {
  PORT: parseInt(process.env.PORT || "8080", 10),
  DATABASE_URL: process.env.DATABASE_URL || "",
  REDIS_URL: process.env.REDIS_URL || "",

  OTP_MODE: (process.env.OTP_MODE || "screen").toLowerCase(),
  OTP_TTL_SECONDS: parseInt(process.env.OTP_TTL_SECONDS || "180", 10),
  RL_MAC_SECONDS: parseInt(process.env.RL_MAC_SECONDS || "30", 10),
  RL_PHONE_SECONDS: parseInt(process.env.RL_PHONE_SECONDS || "60", 10),
  MAX_WRONG_ATTEMPTS: parseInt(process.env.MAX_WRONG_ATTEMPTS || "5", 10),
  LOCK_SECONDS: parseInt(process.env.LOCK_SECONDS || "600", 10),

  KVKK_VERSION: process.env.KVKK_VERSION || "2026-02-12-placeholder",
  TZ: process.env.TZ || "Europe/Istanbul",

  ADMIN_USER: process.env.ADMIN_USER || "",
  ADMIN_PASS: process.env.ADMIN_PASS || "",

  DAILY_HMAC_KEY: process.env.DAILY_HMAC_KEY || "",
};

function safeLogEnv() {
  console.log("ENV:", {
    OTP_MODE: ENV.OTP_MODE,
    OTP_TTL_SECONDS: ENV.OTP_TTL_SECONDS,
    RL_MAC_SECONDS: ENV.RL_MAC_SECONDS,
    RL_PHONE_SECONDS: ENV.RL_PHONE_SECONDS,
    MAX_WRONG_ATTEMPTS: ENV.MAX_WRONG_ATTEMPTS,
    LOCK_SECONDS: ENV.LOCK_SECONDS,
    KVKK_VERSION: ENV.KVKK_VERSION,
    TZ: ENV.TZ,
    DB_SET: !!ENV.DATABASE_URL,
    REDIS_SET: !!ENV.REDIS_URL,
    ADMIN_USER_SET: !!ENV.ADMIN_USER,
    ADMIN_PASS_SET: !!ENV.ADMIN_PASS,
    DAILY_HMAC_SET: !!ENV.DAILY_HMAC_KEY,
  });
}
safeLogEnv();

// -------------------- Helpers --------------------
function nowISO() { return new Date().toISOString(); }
function sha256hex(s) { return crypto.createHash("sha256").update(String(s)).digest("hex"); }
function hmacHex(key, msg) { return crypto.createHmac("sha256", key).update(String(msg)).digest("hex"); }
function randDigits(n) { let o=""; for (let i=0;i<n;i++) o += Math.floor(Math.random()*10); return o; }
function randHex(nBytes=16) { return crypto.randomBytes(nBytes).toString("hex"); }

function normalizePhone(p) {
  const s = String(p || "").trim();
  if (!s) return "";
  const digits = s.replace(/[^\d+]/g, "");
  if (digits.startsWith("+")) return "+" + digits.slice(1).replace(/[^\d]/g, "");
  return digits.replace(/[^\d]/g, "");
}
function normalizeMac(m) {
  const s = String(m || "").trim().toLowerCase();
  if (!s) return "";
  const cleaned = s.replace(/[^0-9a-f]/g, "");
  if (cleaned.length !== 12) return "";
  return cleaned.match(/.{1,2}/g).join(":");
}
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}
function send(res, status, body, headers={}) {
  const b = Buffer.from(String(body));
  res.writeHead(status, { "content-type":"text/plain; charset=utf-8", "content-length": b.length, ...headers });
  res.end(b);
}
function sendJson(res, status, obj, headers={}) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { "content-type":"application/json; charset=utf-8", "content-length": b.length, ...headers });
  res.end(b);
}
function sendHtml(res, status, html, headers={}) {
  const b = Buffer.from(String(html));
  res.writeHead(status, { "content-type":"text/html; charset=utf-8", "content-length": b.length, ...headers });
  res.end(b);
}
function getClientIp(req) {
  const xf = String(req.headers["x-forwarded-for"] || "");
  if (xf) return xf.split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "";
}
function parseJsonBody(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (d) => (buf += d));
    req.on("end", () => { try { resolve(buf ? JSON.parse(buf) : {}); } catch { resolve({}); } });
  });
}
function parseForm(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (d) => (buf += d));
    req.on("end", () => {
      const out = {};
      buf.split("&").forEach((kvp) => {
        if (!kvp) return;
        const [k,v] = kvp.split("=");
        const key = decodeURIComponent(k||"").replace(/\+/g," ");
        const val = decodeURIComponent(v||"").replace(/\+/g," ");
        out[key] = val;
      });
      resolve(out);
    });
  });
}

// -------------------- Cookie --------------------
function parseCookies(req) {
  const h = String(req.headers["cookie"] || "");
  const out = {};
  h.split(";").forEach(part => {
    const p = part.trim();
    if (!p) return;
    const idx = p.indexOf("=");
    if (idx < 0) return;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx+1).trim();
    out[k] = v;
  });
  return out;
}
function setCookie(res, name, value, opts={}) {
  // opts: { maxAge, path, httpOnly, sameSite, secure }
  const parts = [`${name}=${value}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  // Captive portal webviews sometimes hate SameSite=Strict. Lax is safer.
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  if (opts.secure) parts.push("Secure");
  const prev = res.getHeader("Set-Cookie");
  const arr = Array.isArray(prev) ? prev : (prev ? [prev] : []);
  arr.push(parts.join("; "));
  res.setHeader("Set-Cookie", arr);
}

// -------------------- Basic auth (no deps) --------------------
function basicAuth(req) {
  const h = String(req.headers["authorization"] || "");
  if (!h.startsWith("Basic ")) return null;
  const raw = Buffer.from(h.slice(6), "base64").toString("utf8");
  const idx = raw.indexOf(":");
  if (idx < 0) return null;
  return { user: raw.slice(0, idx), pass: raw.slice(idx + 1) };
}
function requireAdmin(req, res) {
  if (!ENV.ADMIN_USER || !ENV.ADMIN_PASS) { send(res, 500, "ADMIN_USER / ADMIN_PASS not set"); return false; }
  const c = basicAuth(req);
  if (!c || c.user !== ENV.ADMIN_USER || c.pass !== ENV.ADMIN_PASS) {
    res.writeHead(401, { "WWW-Authenticate": 'Basic realm="admin"' });
    res.end("Unauthorized");
    return false;
  }
  return true;
}

// -------------------- Meraki ctx parsing --------------------
function mergeCtx(preferA, fillB) {
  const out = { ...(fillB||{}) };
  for (const k of Object.keys(preferA||{})) {
    const v = preferA[k];
    if (v !== undefined && v !== null && String(v).length) out[k] = v;
  }
  out.client_mac = normalizeMac(out.client_mac || "");
  out.node_mac = normalizeMac(out.node_mac || "");
  return out;
}
function parseMerakiReturnUrl(returnUrl) {
  try {
    const ru = new URL(returnUrl);
    const q = ru.searchParams;
    const ctx = {
      gateway_id: q.get("gateway_id") || "",
      node_id: q.get("node_id") || "",
      client_ip: q.get("client_ip") || "",
      client_mac: normalizeMac(q.get("client_mac") || ""),
      node_mac: normalizeMac(q.get("node_mac") || ""),
      continue_url: q.get("continue_url") || "",
      base_grant_url: q.get("base_grant_url") || "",
      user_continue_url: q.get("user_continue_url") || "",
    };
    if (!ctx.base_grant_url) {
      try {
        if (ru.pathname.endsWith("/grant")) ctx.base_grant_url = ru.origin + ru.pathname;
        else if (ru.pathname.includes("/splash/")) ctx.base_grant_url = ru.origin + ru.pathname.replace(/\/$/,"") + "/grant";
      } catch {}
    }
    return ctx;
  } catch {
    return {};
  }
}
function parseMerakiDirectQuery(q) {
  const ctx = {
    gateway_id: (q.gateway_id || q.gw_id || "").toString(),
    node_id: (q.node_id || "").toString(),
    client_ip: (q.client_ip || "").toString(),
    client_mac: normalizeMac((q.client_mac || "").toString()),
    node_mac: normalizeMac((q.node_mac || "").toString()),
    continue_url: (q.continue_url || q.user_continue_url || "").toString(),
    base_grant_url: (q.base_grant_url || q.grant_url || "").toString(),
    user_continue_url: (q.user_continue_url || "").toString(),
  };
  return ctx;
}
function ctxFromReferer(req) {
  const ref = String(req.headers["referer"] || "");
  if (!ref) return {};
  try {
    const ru = new URL(ref);
    const q = Object.fromEntries(ru.searchParams.entries());
    const direct = parseMerakiDirectQuery(q);
    const fromReturn = q.return_url ? parseMerakiReturnUrl(q.return_url) : {};
    return mergeCtx(direct, fromReturn);
  } catch {
    return {};
  }
}
function buildGrantRedirect(ctx) {
  if (!ctx || !ctx.base_grant_url) return null;
  let g;
  try { g = new URL(ctx.base_grant_url); } catch { return null; }
  const add = (k,v)=>{ if (v !== undefined && v !== null && String(v).length) g.searchParams.set(k,String(v)); };
  add("gateway_id", ctx.gateway_id);
  add("node_id", ctx.node_id);
  add("client_ip", ctx.client_ip);
  add("client_mac", ctx.client_mac);
  add("node_mac", ctx.node_mac);
  if (ctx.continue_url) add("continue_url", ctx.continue_url);
  return g.toString();
}

// -------------------- KV (Redis or Memory) --------------------
class MemoryKV {
  constructor(){ this.m=new Map(); }
  async get(k){
    const v=this.m.get(k);
    if (!v) return null;
    if (v.exp && Date.now()>v.exp){ this.m.delete(k); return null; }
    return v.val;
  }
  async setex(k, ttl, val){ this.m.set(k,{ val, exp: Date.now()+ttl*1000 }); }
  async del(k){ this.m.delete(k); }
}

let kv = new MemoryKV();
let redis = null;

async function initKV(){
  if (Redis && ENV.REDIS_URL){
    try{
      redis = new Redis(ENV.REDIS_URL, { lazyConnect:true, maxRetriesPerRequest:1 });
      await redis.connect();
      kv = {
        get: async (k)=> await redis.get(k),
        setex: async (k,ttl,v)=> await redis.setex(k,ttl,v),
        del: async (k)=> await redis.del(k),
      };
      console.log("REDIS: connected");
      return;
    }catch(e){
      console.log("REDIS: failed, fallback to memory:", e && e.message);
      redis=null;
      kv=new MemoryKV();
    }
  } else {
    console.log("REDIS: not configured, using memory");
  }
}

// -------------------- DB --------------------
const pool = ENV.DATABASE_URL ? new Pool({
  connectionString: ENV.DATABASE_URL,
  ssl: { rejectUnauthorized:false },
  max: 5,
}) : null;

async function qRows(sql, params){ if(!pool) return []; const r=await pool.query(sql,params); return r.rows||[]; }
async function qExec(sql, params){ if(!pool) return; await pool.query(sql,params); }

async function ensureColumn(table, col, typeSql) {
  try { await qExec(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${col} ${typeSql};`); } catch {}
}

async function ensureTables(){
  if(!pool){ console.log("DATABASE: not configured"); return; }
  await qExec(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      event TEXT NOT NULL,
      full_name TEXT,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      marker TEXT,
      client_mac TEXT,
      client_ip TEXT,
      base_grant_url TEXT,
      continue_url TEXT,
      user_continue_url TEXT,
      kvkk_accepted BOOLEAN,
      kvkk_version TEXT,
      user_agent TEXT,
      accept_language TEXT,
      meta JSONB
    );
  `);

  await qExec(`
    CREATE TABLE IF NOT EXISTS daily_packages (
      day DATE PRIMARY KEY,
      tz TEXT NOT NULL,
      payload JSONB NOT NULL,
      signature TEXT,
      algo TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  console.log("DATABASE: table ready");
}

async function logAccess(event, data){
  if(!pool) return;

  await ensureColumn("access_logs","accept_language","TEXT");
  await ensureColumn("access_logs","meta","JSONB");
  await ensureColumn("access_logs","continue_url","TEXT");
  await ensureColumn("access_logs","user_continue_url","TEXT");
  await ensureColumn("access_logs","base_grant_url","TEXT");

  const row = {
    event: event || "UNKNOWN",
    full_name: data.full_name || null,
    first_name: data.first_name || null,
    last_name: data.last_name || null,
    phone: data.phone || null,
    marker: data.marker || null,
    client_mac: data.client_mac || null,
    client_ip: data.client_ip || null,
    base_grant_url: data.base_grant_url || null,
    continue_url: data.continue_url || null,
    user_continue_url: data.user_continue_url || null,
    kvkk_accepted: typeof data.kvkk_accepted === "boolean" ? data.kvkk_accepted : null,
    kvkk_version: data.kvkk_version || ENV.KVKK_VERSION || null,
    user_agent: data.user_agent || null,
    accept_language: data.accept_language || null,
    meta: data.meta || {},
  };

  const cols = Object.keys(row);
  const vals = cols.map((_,i)=>`$${i+1}`);
  const params = cols.map(k => (k==="meta" ? JSON.stringify(row[k]||{}) : row[k]));

  try {
    await qExec(`INSERT INTO access_logs(${cols.join(",")}) VALUES(${vals.join(",")})`, params);
  } catch(e) {
    console.log("DB LOG ERROR:", e && e.message);
  }
}

// -------------------- OTP / RL --------------------
const keyOtp = (marker)=>`otp:${marker}`;
const keyMac = (mac)=>`rl:mac:${mac}`;
const keyPhone = (p)=>`rl:phone:${p}`;
const keyLock = (marker)=>`lock:${marker}`;
const keySid = (sid)=>`ctx:sid:${sid}`;
const keyMarkerCtx = (marker)=>`ctx:marker:${marker}`;

async function isRateLimited(mac, phone){
  if(mac){
    const v = await kv.get(keyMac(mac));
    if(v) return { ok:false, why:"mac" };
  }
  if(phone){
    const v = await kv.get(keyPhone(phone));
    if(v) return { ok:false, why:"phone" };
  }
  return { ok:true };
}
async function setRate(mac, phone){
  if(mac) await kv.setex(keyMac(mac), ENV.RL_MAC_SECONDS, "1");
  if(phone) await kv.setex(keyPhone(phone), ENV.RL_PHONE_SECONDS, "1");
}
async function isLocked(marker){ return !!(await kv.get(keyLock(marker))); }
async function lockMarker(marker){ await kv.setex(keyLock(marker), ENV.LOCK_SECONDS, "1"); }

// -------------------- UI --------------------
function splashPage({ marker, sid, message, showOtp, otp, ctx }) {
  const hidden = (k,v)=>`<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v||"")}"/>`;

  const ctxHidden =
    hidden("sid", sid || "") +
    hidden("marker", marker || "") +
    hidden("base_grant_url", ctx.base_grant_url || "") +
    hidden("continue_url", ctx.continue_url || "") +
    hidden("user_continue_url", ctx.user_continue_url || "") +
    hidden("gateway_id", ctx.gateway_id || "") +
    hidden("node_id", ctx.node_id || "") +
    hidden("node_mac", ctx.node_mac || "") +
    hidden("client_ip", ctx.client_ip || "") +
    hidden("client_mac", ctx.client_mac || "");

  const otpBlock = (showOtp && otp) ? `
    <div style="margin-top:14px;padding:12px;border-radius:12px;background:rgba(255,255,255,.08);display:inline-block">
      <div style="opacity:.85;font-size:13px">OTP (screen mode)</div>
      <div style="font-size:28px;font-weight:800;letter-spacing:2px">${escapeHtml(otp)}</div>
    </div>` : "";

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WiFi Login</title>
  <style>
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#0b1220;color:#e6eefc}
    .wrap{max-width:900px;margin:30px auto;padding:0 16px}
    .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:18px;box-shadow:0 10px 40px rgba(0,0,0,.2)}
    h1{margin:0 0 8px;font-size:26px}
    label{display:block;margin:10px 0 6px;opacity:.85}
    input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#fff;font-size:16px}
    button{margin-top:12px;background:#6d57ff;border:0;color:white;padding:12px 14px;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer}
    .muted{opacity:.75;font-size:13px}
    hr{border:0;border-top:1px solid rgba(255,255,255,.10);margin:18px 0}
  </style></head><body>
  <div class="wrap"><div class="card">
    <h1>WiFi Giriş</h1>
    <div class="muted">${escapeHtml(message || "")}</div>

    <form method="POST" action="/otp/request">
      ${ctxHidden}
      <label>Ad</label><input name="first_name" placeholder="Ad" />
      <label>Soyad</label><input name="last_name" placeholder="Soyad" />
      <label>Telefon</label><input name="phone" placeholder="05xxxxxxxxx" />
      <label><input type="checkbox" name="kvkk_accepted" value="1" checked /> KVKK metnini okudum, kabul ediyorum</label>
      <div class="muted">KVKK versiyon: ${escapeHtml(ENV.KVKK_VERSION)}</div>
      <button type="submit">OTP Gönder</button>
    </form>

    ${otpBlock}

    <hr/>

    <form method="POST" action="/otp/verify">
      ${ctxHidden}
      <label>OTP</label><input name="otp" placeholder="6 haneli kod" />
      <button type="submit">Doğrula ve Bağlan</button>
    </form>
  </div></div></body></html>`;
}

// -------------------- Core handler --------------------
async function handle(req, res) {
  const u = url.parse(req.url, true);
  const path = u.pathname || "/";
  const q = u.query || {};

  if (path === "/" || path === "/health") return send(res, 200, "ok");

  // Admin: (minimal)
  if (path.startsWith("/admin")) {
    if (!requireAdmin(req, res)) return;
    if (path === "/admin" || path === "/admin/") {
      res.writeHead(302, { Location: "/admin/logs" }); return res.end();
    }
    if (path === "/admin/logs") {
      const limit = Math.max(1, Math.min(500, parseInt(q.limit || "200", 10)));
      const rows = await qRows(`SELECT id, created_at, event, full_name, phone, client_mac, client_ip, marker, kvkk_version FROM access_logs ORDER BY id DESC LIMIT $1`, [limit]);
      return sendJson(res, 200, rows);
    }
    return send(res, 404, "Not Found");
  }

  // Splash
  if (path === "/splash") {
    const return_url = String(q.return_url || "");
    const ctxDirect = parseMerakiDirectQuery(q);
    const ctxFromReturn = return_url ? parseMerakiReturnUrl(return_url) : {};
    let ctx = mergeCtx(ctxDirect, ctxFromReturn);

    // If still missing base_grant_url, try derive from current URL if it includes /splash/<id>
    if (!ctx.base_grant_url) {
      try {
        const full = new URL((req.headers["x-forwarded-proto"] || "https") + "://" + req.headers.host + req.url);
        if (full.pathname.includes("/splash/")) ctx.base_grant_url = full.origin + full.pathname.replace(/\/$/,"") + "/grant";
      } catch {}
    }

    const sid = randHex(16);
    const marker = randDigits(6);

    // Store ctx by SID (strongest)
    await kv.setex(keySid(sid), ENV.OTP_TTL_SECONDS * 10, JSON.stringify({ ctx, return_url, created_at: nowISO() }));
    // Also store by marker (secondary)
    await kv.setex(keyMarkerCtx(marker), ENV.OTP_TTL_SECONDS * 2, JSON.stringify({ ctx, return_url, created_at: nowISO() }));

    // Set cookie
    setCookie(res, "sid", sid, { maxAge: ENV.OTP_TTL_SECONDS * 10, path: "/", httpOnly: true, sameSite: "Lax" });

    console.log(`SPLASH_OPEN sid=${sid} marker=${marker} mac=${ctx.client_mac || ""} baseGrant=${ctx.base_grant_url ? "yes" : "no"}`);

    await logAccess("SPLASH_OPEN", {
      marker,
      kvkk_version: ENV.KVKK_VERSION,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || return_url || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: { sid },
    });

    const html = splashPage({ marker, sid, message: "Telefonunu yaz, OTP ile doğrula.", showOtp: false, otp: "", ctx });
    return sendHtml(res, 200, html);
  }

  // OTP request
  if (path === "/otp/request" && req.method === "POST") {
    const ct = String(req.headers["content-type"] || "");
    const data = ct.includes("application/json") ? await parseJsonBody(req) : await parseForm(req);

    const cookies = parseCookies(req);
    const sid = String(data.sid || cookies.sid || "").trim();
    const marker = String(data.marker || "").trim() || randDigits(6);

    const first_name = String(data.first_name || "").trim() || null;
    const last_name  = String(data.last_name  || "").trim() || null;
    const full_name  = [first_name, last_name].filter(Boolean).join(" ") || null;
    const phone = normalizePhone(data.phone || "");
    const kvkk_accepted = !!data.kvkk_accepted;

    // ctx from form hidden inputs
    const ctxFromForm = mergeCtx({
      base_grant_url: String(data.base_grant_url || ""),
      continue_url: String(data.continue_url || ""),
      user_continue_url: String(data.user_continue_url || ""),
      gateway_id: String(data.gateway_id || ""),
      node_id: String(data.node_id || ""),
      node_mac: String(data.node_mac || ""),
      client_ip: String(data.client_ip || ""),
      client_mac: String(data.client_mac || ""),
    }, {});

    // ctx from SID (strongest)
    let ctxFromSid = {};
    if (sid) {
      const rawSid = await kv.get(keySid(sid));
      if (rawSid) { try { ctxFromSid = JSON.parse(rawSid).ctx || {}; } catch {} }
    }

    // ctx from marker (secondary)
    let ctxFromMarker = {};
    const rawMarker = await kv.get(keyMarkerCtx(marker));
    if (rawMarker) { try { ctxFromMarker = JSON.parse(rawMarker).ctx || {}; } catch {} }

    // ctx from referer (fallback)
    const ctxRef = ctxFromReferer(req);

    const ctx = mergeCtx(ctxFromForm, mergeCtx(ctxFromSid, mergeCtx(ctxFromMarker, ctxRef)));

    const client_mac = ctx.client_mac || "";
    const client_ip = ctx.client_ip || getClientIp(req) || "";

    // Rate limit
    const rl = await isRateLimited(client_mac, phone);
    if (!rl.ok) {
      await logAccess("OTP_RATE_LIMIT", { marker, phone, full_name, client_mac, client_ip, kvkk_accepted, meta: { why: rl.why, sid } });
      return sendJson(res, 429, { ok:false, error:"rate_limited", why: rl.why });
    }
    await setRate(client_mac, phone);

    const otp = randDigits(6);
    const rec = {
      marker, sid,
      otp, phone,
      first_name, last_name, full_name,
      kvkk_accepted, kvkk_version: ENV.KVKK_VERSION,
      wrong: 0,
      created_at: nowISO(),
      client_mac, client_ip,
      ctx,
    };
    await kv.setex(keyOtp(marker), ENV.OTP_TTL_SECONDS, JSON.stringify(rec));

    console.log("OTP_CREATED", { marker, last4: phone ? phone.slice(-4) : null, client_mac });

    await logAccess("OTP_CREATED", {
      marker, phone, first_name, last_name, full_name,
      kvkk_accepted, kvkk_version: ENV.KVKK_VERSION,
      client_mac, client_ip,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: { sid, mode: ENV.OTP_MODE },
    });

    if (ENV.OTP_MODE === "screen") {
      console.log("OTP_SCREEN_CODE", { marker, otp });
      // IMPORTANT: keep same SID cookie alive
      if (sid) setCookie(res, "sid", sid, { maxAge: ENV.OTP_TTL_SECONDS * 10, path: "/", httpOnly: true, sameSite: "Lax" });
      return sendHtml(res, 200, splashPage({ marker, sid, message: "OTP oluşturuldu. Kodu girerek bağlan.", showOtp:true, otp, ctx }));
    }

    return sendJson(res, 200, { ok:true, marker });
  }

  // OTP verify
  if (path === "/otp/verify" && req.method === "POST") {
    const ct = String(req.headers["content-type"] || "");
    const data = ct.includes("application/json") ? await parseJsonBody(req) : await parseForm(req);

    const cookies = parseCookies(req);
    const sid = String(data.sid || cookies.sid || "").trim();
    const marker = String(data.marker || "").trim();
    const otp = String(data.otp || "").trim();

    if (!marker || !otp) return sendJson(res, 400, { ok:false, error:"missing_marker_or_otp" });
    if (await isLocked(marker)) return sendJson(res, 423, { ok:false, error:"locked" });

    const raw = await kv.get(keyOtp(marker));
    if (!raw) return sendJson(res, 404, { ok:false, error:"otp_not_found" });

    let rec = null;
    try { rec = JSON.parse(raw); } catch {}
    if (!rec) return sendJson(res, 500, { ok:false, error:"bad_otp_record" });

    if (String(rec.otp) !== otp) {
      rec.wrong = (rec.wrong || 0) + 1;
      await kv.setex(keyOtp(marker), ENV.OTP_TTL_SECONDS, JSON.stringify(rec));
      await logAccess("OTP_WRONG", { marker, phone: rec.phone||null, client_mac: rec.client_mac||null, meta:{ wrong: rec.wrong, sid } });
      if (rec.wrong >= ENV.MAX_WRONG_ATTEMPTS) { await lockMarker(marker); return sendJson(res, 423, { ok:false, error:"locked" }); }
      return sendJson(res, 401, { ok:false, error:"wrong_otp", wrong: rec.wrong });
    }

    console.log("OTP_VERIFY_OK", { marker, client_mac: rec.client_mac || "" });

    // ctx from form hidden inputs
    const ctxFromForm = mergeCtx({
      base_grant_url: String(data.base_grant_url || ""),
      continue_url: String(data.continue_url || ""),
      user_continue_url: String(data.user_continue_url || ""),
      gateway_id: String(data.gateway_id || ""),
      node_id: String(data.node_id || ""),
      node_mac: String(data.node_mac || ""),
      client_ip: String(data.client_ip || ""),
      client_mac: String(data.client_mac || ""),
    }, {});

    // ctx from sid
    let ctxFromSid = {};
    if (sid) {
      const rawSid = await kv.get(keySid(sid));
      if (rawSid) { try { ctxFromSid = JSON.parse(rawSid).ctx || {}; } catch {} }
    }

    // ctx from referer fallback
    const ctxRef = ctxFromReferer(req);

    const ctx = mergeCtx(ctxFromForm, mergeCtx(rec.ctx || {}, mergeCtx(ctxFromSid, ctxRef)));
    if (!ctx.client_mac) ctx.client_mac = rec.client_mac || "";
    if (!ctx.client_ip) ctx.client_ip = rec.client_ip || getClientIp(req) || "";

    await logAccess("OTP_VERIFIED", {
      marker,
      phone: rec.phone || null,
      first_name: rec.first_name || null,
      last_name: rec.last_name || null,
      full_name: rec.full_name || null,
      kvkk_accepted: !!rec.kvkk_accepted,
      kvkk_version: rec.kvkk_version || ENV.KVKK_VERSION,
      client_mac: ctx.client_mac || null,
      client_ip: ctx.client_ip || null,
      base_grant_url: ctx.base_grant_url || null,
      continue_url: ctx.continue_url || null,
      user_continue_url: ctx.user_continue_url || null,
      user_agent: req.headers["user-agent"] || null,
      accept_language: req.headers["accept-language"] || null,
      meta: { sid },
    });

    await kv.del(keyOtp(marker));

    const redirect = buildGrantRedirect(ctx);
    if (redirect) {
      console.log("GRANT_CLIENT_REDIRECT:", redirect);
      await logAccess("GRANT_CLIENT_REDIRECT", { marker, phone: rec.phone||null, full_name: rec.full_name||null, client_mac: ctx.client_mac||null, client_ip: ctx.client_ip||null, base_grant_url: ctx.base_grant_url||null, continue_url: ctx.continue_url||null, meta:{ sid, redirect } });
      res.writeHead(302, { Location: redirect });
      return res.end();
    }

    // If still missing (should not happen if Meraki sent it)
    await logAccess("GRANT_MISSING_CTX", { marker, meta:{ sid, ctx } });
    return send(res, 500, "OTP verified but base_grant_url missing.");
  }

  return send(res, 404, "Not Found");
}

// -------------------- Boot --------------------
async function main() {
  await initKV();

  if (pool) {
    try { await pool.query("SELECT 1"); console.log("DATABASE: connected"); } catch(e){ console.log("DATABASE: connect failed:", e && e.message); }
    await ensureTables();
  }

  const server = http.createServer(async (req, res) => {
    try { await handle(req, res); }
    catch (e) {
      console.error("UNCAUGHT:", e && e.stack ? e.stack : e);
      try { send(res, 500, "internal error"); } catch {}
    }
  });

  server.listen(ENV.PORT, "0.0.0.0", () => console.log(`Server running on port ${ENV.PORT}`));
}

main().catch((e) => { console.error("BOOT FAILED:", e && e.stack ? e.stack : e); process.exit(1); });
