// ===============================
// MERAKI SMS SPLASH + 5651 FINAL
// ===============================

const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { Pool } = require("pg");
const Redis = require("ioredis");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ===============================
// ENV
// ===============================

const {
  DATABASE_URL,
  REDIS_URL,
  OTP_TTL_SECONDS = 180,
  KVKK_VERSION = "placeholder",
  ADMIN_USER,
  ADMIN_PASS
} = process.env;

// ===============================
// DB
// ===============================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===============================
// REDIS
// ===============================

const redis = new Redis(REDIS_URL);

// ===============================
// ADMIN AUTH
// ===============================

function adminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send("Auth required");

  const [user, pass] = Buffer.from(auth.split(" ")[1], "base64")
    .toString()
    .split(":");

  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    return next();
  }
  return res.status(403).send("Forbidden");
}

// ===============================
// UTIL
// ===============================

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function dayKey() {
  return new Date().toISOString().slice(0, 10);
}

// ===============================
// TABLE INIT
// ===============================

async function initTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT now(),
      event TEXT,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      client_mac TEXT,
      client_ip TEXT,
      marker TEXT,
      kvkk_accepted BOOLEAN,
      kvkk_version TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_hashes (
      day TEXT PRIMARY KEY,
      record_count INT,
      day_hash TEXT,
      prev_day_hash TEXT,
      chain_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  console.log("DATABASE: table ready");
}

initTable();

// ===============================
// LOG INSERT
// ===============================

async function logEvent(data) {
  await pool.query(
    `INSERT INTO access_logs
     (event, first_name, last_name, phone, client_mac, client_ip, marker, kvkk_accepted, kvkk_version)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      data.event,
      data.first_name,
      data.last_name,
      data.phone,
      data.client_mac,
      data.client_ip || "",
      data.marker,
      data.kvkk_accepted,
      KVKK_VERSION
    ]
  );
}

// ===============================
// DAILY BUILD
// ===============================

app.get("/admin/daily/build", adminAuth, async (req, res) => {
  const day = req.query.day || dayKey();

  const rows = await pool.query(
    `SELECT * FROM access_logs
     WHERE created_at::date = $1::date
     ORDER BY id`,
    [day]
  );

  const payload = JSON.stringify(rows.rows);
  const day_hash = sha256(payload);

  const prev = await pool.query(
    `SELECT day_hash FROM daily_hashes
     WHERE day < $1
     ORDER BY day DESC LIMIT 1`,
    [day]
  );

  const prev_day_hash = prev.rows[0]?.day_hash || null;
  const chain_hash = sha256((prev_day_hash || "") + day_hash);

  await pool.query(
    `INSERT INTO daily_hashes
     (day, record_count, day_hash, prev_day_hash, chain_hash)
     VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (day)
     DO UPDATE SET
       record_count = EXCLUDED.record_count,
       day_hash = EXCLUDED.day_hash,
       prev_day_hash = EXCLUDED.prev_day_hash,
       chain_hash = EXCLUDED.chain_hash`,
    [day, rows.rowCount, day_hash, prev_day_hash, chain_hash]
  );

  res.json({
    day,
    record_count: rows.rowCount,
    day_hash,
    prev_day_hash,
    chain_hash
  });
});

// ===============================
// DAILY VERIFY
// ===============================

app.get("/admin/daily/verify", adminAuth, async (req, res) => {
  const day = req.query.day;

  const stored = await pool.query(
    `SELECT * FROM daily_hashes WHERE day=$1`,
    [day]
  );

  if (!stored.rowCount)
    return res.json({ ok: false, error: "No daily record" });

  const rows = await pool.query(
    `SELECT * FROM access_logs
     WHERE created_at::date = $1::date
     ORDER BY id`,
    [day]
  );

  const recalculated_day_hash = sha256(JSON.stringify(rows.rows));
  const recalculated_chain_hash = sha256(
    (stored.rows[0].prev_day_hash || "") + recalculated_day_hash
  );

  const ok =
    recalculated_day_hash === stored.rows[0].day_hash &&
    recalculated_chain_hash === stored.rows[0].chain_hash;

  res.json({
    ok,
    recalculated_day_hash,
    stored_day_hash: stored.rows[0].day_hash,
    recalculated_chain_hash,
    stored_chain_hash: stored.rows[0].chain_hash
  });
});

// ===============================
// DAILY EXPORT
// ===============================

app.get("/admin/daily/export", adminAuth, async (req, res) => {
  const day = req.query.day;

  const rows = await pool.query(
    `SELECT * FROM access_logs
     WHERE created_at::date = $1::date
     ORDER BY id`,
    [day]
  );

  const hash = await pool.query(
    `SELECT * FROM daily_hashes WHERE day=$1`,
    [day]
  );

  res.json({
    day,
    records: rows.rows,
    hash: hash.rows[0] || null
  });
});

// ===============================
// ADMIN LOG LIST
// ===============================

app.get("/admin/logs", adminAuth, async (req, res) => {
  const rows = await pool.query(
    `SELECT * FROM access_logs
     ORDER BY id DESC LIMIT 200`
  );

  res.json(rows.rows);
});

// ===============================

app.listen(8080, () =>
  console.log("Server running on port 8080")
);
