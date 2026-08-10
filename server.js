/**
 * clicks brain — internal knowledge dashboard
 * - Data flows IN from sources; nothing is deletable from the dashboard.
 * - Connectors added from the UI; credentials AES-256-GCM encrypted, write-only.
 * - Gorgias tickets sync into Postgres so stats cover any period.
 * - Embedded Claude assistant with data-query tools.
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '8mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));

// ---------- session auth (per-user login) ----------
// Exempt: Slack (signs its own requests), health checks, the login page and auth endpoints.
const AUTH_EXEMPT = (p) =>
  p.startsWith('/api/slack/') || p === '/api/health' || p === '/login.html' || p.startsWith('/api/auth/')
  || p === '/api/report/daily'; // does its own token check so an external cron can trigger it

const sessionSign = (s) => crypto.createHmac('sha256', KEY).update('session:' + s).digest('base64url');
const makeSession = (email) => {
  const body = `${email}|${Date.now() + 7 * 864e5}`; // 7 days
  return Buffer.from(body).toString('base64url') + '.' + sessionSign(body);
};
const readSession = (req) => {
  const raw = (req.headers.cookie || '').split(';').map(s => s.trim())
    .find(s => s.startsWith('cb_session='))?.slice('cb_session='.length);
  if (!raw) return null;
  const [b64, sig] = raw.split('.');
  if (!b64 || !sig) return null;
  const body = Buffer.from(b64, 'base64url').toString();
  const a = Buffer.from(sessionSign(body)), b = Buffer.from(sig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const [email, exp] = body.split('|');
  return Date.now() < +exp ? email : null;
};
const setSessionCookie = (res, email) =>
  res.set('Set-Cookie', `cb_session=${makeSession(email)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 86400}`);

app.use((req, res, next) => {
  const email = readSession(req);
  if (email) req.userEmail = email; // populate identity even on exempt paths (e.g. admin hitting the report endpoint)
  if (AUTH_EXEMPT(req.path)) return next();
  if (email) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'not signed in' });
  res.redirect('/login.html');
});
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.set('Cache-Control', 'no-cache'); // always revalidate pages after deploys
  }
}));

const ALLOWED_USERS = ['fran@clicks.tech', 'kp@clicks.tech'];
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

// ---------- login rate limiting (per-IP, in-memory) ----------
// Blocks brute-force: after LOGIN_MAX failed auth attempts within the window, that IP is refused
// until the window elapses. A successful sign-in clears the counter.
const LOGIN_WINDOW_MS = 15 * 60 * 1000, LOGIN_MAX = 10;
const loginAttempts = new Map(); // ip -> { fails, resetAt }
const loginIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
function loginBlocked(req) {
  const e = loginAttempts.get(loginIp(req));
  return !!(e && Date.now() < e.resetAt && e.fails >= LOGIN_MAX);
}
function loginFail(req) {
  const ip = loginIp(req), now = Date.now();
  let e = loginAttempts.get(ip);
  if (!e || now >= e.resetAt) e = { fails: 0, resetAt: now + LOGIN_WINDOW_MS };
  e.fails++; loginAttempts.set(ip, e);
}
const loginReset = (req) => loginAttempts.delete(loginIp(req));
const TOO_MANY = { error: 'Too many attempts. Please wait a few minutes and try again.' };
// keep the map from growing unbounded
setInterval(() => { const now = Date.now(); for (const [ip, e] of loginAttempts) if (now >= e.resetAt) loginAttempts.delete(ip); }, 10 * 60 * 1000);

app.post('/api/auth/setup', async (req, res) => {
  if (loginBlocked(req)) return res.status(429).json(TOO_MANY);
  const { email, password, invite_code } = req.body || {};
  const invite = process.env.ADMIN_PASSWORD || process.env.DASHBOARD_PASSWORD;
  if (!invite) return res.status(400).json({ error: 'No ADMIN_PASSWORD set on the server — set it in Render → Environment first.' });
  if (invite_code !== invite) { loginFail(req); return res.status(403).json({ error: 'Wrong invite code.' }); }
  const em = String(email || '').toLowerCase().trim();
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [em])).rows[0];
  if (!u) return res.status(403).json({ error: 'This email is not on the member list.' });
  if (u.pass_hash) return res.status(409).json({ error: 'Password already set — use Sign in.' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE users SET pass_hash=$1 WHERE email=$2', [`${salt}:${hashPw(password, salt)}`, em]);
  setSessionCookie(res, em);
  res.json({ ok: true, email: em });
});

// Reset an EXISTING member's password. Gated by the same admin-held code as setup;
// only works for an email already on the member list (never creates users).
app.post('/api/auth/reset', async (req, res) => {
  if (loginBlocked(req)) return res.status(429).json(TOO_MANY);
  const { email, password, invite_code } = req.body || {};
  const resetCode = process.env.RESET_CODE; // dedicated reset code, separate from the admin/invite code
  if (!resetCode) return res.status(400).json({ error: 'Password reset is disabled — an admin must set RESET_CODE in Render → Environment first.' });
  if (invite_code !== resetCode) { loginFail(req); return res.status(403).json({ error: 'Wrong reset code (ask an admin).' }); }
  const em = String(email || '').toLowerCase().trim();
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [em])).rows[0];
  if (!u) return res.status(403).json({ error: 'This email is not on the member list.' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE users SET pass_hash=$1 WHERE email=$2', [`${salt}:${hashPw(password, salt)}`, em]);
  setSessionCookie(res, em);
  res.json({ ok: true, email: em });
});

app.post('/api/auth/login', async (req, res) => {
  if (loginBlocked(req)) return res.status(429).json(TOO_MANY);
  const em = String(req.body?.email || '').toLowerCase().trim();
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [em])).rows[0];
  if (!u?.pass_hash) { loginFail(req); return res.status(403).json({ error: u ? 'No password set yet — use First time? below.' : 'Unknown email.' }); }
  const [salt, hash] = u.pass_hash.split(':');
  const a = Buffer.from(hashPw(String(req.body?.password || ''), salt)), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) { loginFail(req); return res.status(403).json({ error: 'Wrong password.' }); }
  loginReset(req);
  setSessionCookie(res, em);
  res.json({ ok: true, email: em });
});

app.post('/api/auth/logout', (_req, res) => {
  res.set('Set-Cookie', 'cb_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ---------- member management (admins only) ----------
const INVITE_TTL_DAYS = 7;
const newInvite = () => ({ token: crypto.randomBytes(24).toString('hex'),
  expires: new Date(Date.now() + INVITE_TTL_DAYS * 864e5).toISOString() });

app.get('/api/users', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { rows } = await pool.query(
    `SELECT email, role, coalesce(shipping,false) shipping, (pass_hash IS NOT NULL) AS activated, invite_token, invite_expires, created_at FROM users ORDER BY created_at`);
  res.json(rows);
});
app.post('/api/users', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const em = String(req.body?.email || '').toLowerCase().trim();
  const role = req.body?.role === 'admin' ? 'admin' : 'member';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ error: 'valid email required' });
  const inv = newInvite();
  // new member (or re-added not-yet-activated one) gets a fresh single-use invite token; activated members keep their token null
  const { rows } = await pool.query(
    `INSERT INTO users (email, role, invite_token, invite_expires) VALUES ($1,$2,$3,$4)
     ON CONFLICT (email) DO UPDATE SET role=$2,
       invite_token   = CASE WHEN users.pass_hash IS NULL THEN EXCLUDED.invite_token   ELSE users.invite_token   END,
       invite_expires = CASE WHEN users.pass_hash IS NULL THEN EXCLUDED.invite_expires ELSE users.invite_expires END
     RETURNING email, role, (pass_hash IS NOT NULL) AS activated, invite_token, invite_expires`,
    [em, role, inv.token, inv.expires]);
  res.status(201).json(rows[0]);
});
// remove a member entirely (admin only). Can't delete your own logged-in account.
app.post('/api/users/remove', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const em = String(req.body?.email || '').toLowerCase().trim();
  const me = readSession(req);
  if (em && em === String(me || '').toLowerCase()) return res.status(400).json({ error: "You can't remove your own account." });
  const r = await pool.query('DELETE FROM users WHERE email=$1', [em]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found.' });
  res.json({ ok: true });
});
// regenerate a fresh invite link for a member who hasn't activated yet
app.post('/api/users/invite', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const em = String(req.body?.email || '').toLowerCase().trim();
  const inv = newInvite();
  const { rows } = await pool.query(
    `UPDATE users SET invite_token=$2, invite_expires=$3 WHERE email=$1 AND pass_hash IS NULL
     RETURNING email, role, (pass_hash IS NOT NULL) AS activated, invite_token, invite_expires`, [em, inv.token, inv.expires]);
  if (!rows[0]) return res.status(400).json({ error: 'User not found or already activated.' });
  res.json(rows[0]);
});

// look up an invite token (public) → returns the email it's for, if still valid
app.get('/api/auth/invite', async (req, res) => {
  const token = String(req.query.token || '');
  if (!token) return res.status(400).json({ error: 'missing token' });
  const u = (await pool.query('SELECT email, invite_expires FROM users WHERE invite_token=$1 AND pass_hash IS NULL', [token])).rows[0];
  if (!u) return res.status(404).json({ error: 'This invite link is invalid or has already been used.' });
  if (u.invite_expires && new Date(u.invite_expires) < new Date()) return res.status(410).json({ error: 'This invite link has expired — ask an admin for a new one.' });
  res.json({ email: u.email });
});

// activate an account via invite token (public): sets the password, consumes the token, signs in
app.post('/api/auth/activate', async (req, res) => {
  const { token, password } = req.body || {};
  const u = (await pool.query('SELECT email, invite_expires FROM users WHERE invite_token=$1 AND pass_hash IS NULL', [String(token || '')])).rows[0];
  if (!u) return res.status(403).json({ error: 'This invite link is invalid or has already been used.' });
  if (u.invite_expires && new Date(u.invite_expires) < new Date()) return res.status(410).json({ error: 'This invite link has expired — ask an admin for a new one.' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  await pool.query('UPDATE users SET pass_hash=$1, invite_token=NULL, invite_expires=NULL WHERE email=$2',
    [`${salt}:${hashPw(password, salt)}`, u.email]);
  setSessionCookie(res, u.email);
  res.json({ ok: true, email: u.email });
});

app.get('/api/auth/me', async (req, res) => {
  const email = readSession(req);
  if (!email) return res.json({ email: null });
  const { rows } = await pool.query('SELECT role, coalesce(shipping,false) shipping FROM users WHERE email=$1', [email]);
  const role = rows[0]?.role || 'member';
  // "shipping" sub-role (or admin) may view freight documents
  res.json({ email, role, shipping: !!rows[0]?.shipping, freight_docs: role === 'admin' || !!rows[0]?.shipping });
});
// admin: toggle a member's "shipping" sub-role (lets them see freight documents)
app.post('/api/users/shipping', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const em = String(req.body?.email || '').toLowerCase().trim();
  const on = req.body?.shipping === true;
  const r = await pool.query('UPDATE users SET shipping=$2 WHERE email=$1 RETURNING email, shipping', [em, on]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found.' });
  res.json({ ok: true, email: em, shipping: on });
});
// admin or a member with the shipping sub-role
async function canSeeFreightDocs(req) {
  if (!req.userEmail) return false;
  const { rows } = await pool.query('SELECT role, coalesce(shipping,false) shipping FROM users WHERE email=$1', [req.userEmail]);
  return rows[0]?.role === 'admin' || rows[0]?.shipping === true;
}

// ---------- Postgres ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false,
  max: 8,                       // stay under the free-tier connection cap even with two instances during a deploy
  idleTimeoutMillis: 30000,     // recycle idle connections
  connectionTimeoutMillis: 10000, // fail fast if the pool can't hand out a connection instead of hanging forever
  statement_timeout: 20000,     // kill any single query that runs longer than 20s so it can't block the pool
  query_timeout: 20000
});
pool.on('error', (e) => console.error('pg pool error:', e.message)); // don't let an idle-client error crash the process
// Safety net: a transient DB timeout inside one request must not take down the whole server.
// Log and keep serving rather than crash-restarting (which is what happened over the weekend).
process.on('unhandledRejection', (e) => console.error('unhandledRejection (ignored):', e?.message || e));
process.on('uncaughtException', (e) => console.error('uncaughtException (ignored):', e?.message || e));

async function initDb() {
  // serialize schema setup across instances: overlapping deploys were deadlocking on the DDL.
  // An advisory lock makes the second booting instance wait, then its IF-NOT-EXISTS statements no-op.
  // The free DB can be cold at boot, so retry the first connection instead of crashing immediately.
  let lockClient;
  for (let attempt = 1; ; attempt++) {
    try { lockClient = await pool.connect(); break; }
    catch (e) {
      if (attempt >= 8) throw e;
      console.error(`initDb: database not ready (attempt ${attempt}/8): ${e.message} — retrying in 3s`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  try {
    await lockClient.query('SET statement_timeout = 0'); // migrations + the lock wait must not be killed by the pool's 20s cap
    await lockClient.query('SELECT pg_advisory_lock(728341)');
  await lockClient.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, sku TEXT DEFAULT '', specs TEXT DEFAULT '',
      warranty TEXT DEFAULT '', source TEXT DEFAULT 'manual import', created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS key_dates (
      id SERIAL PRIMARY KEY, date DATE NOT NULL, event TEXT NOT NULL,
      source TEXT DEFAULT 'manual import', created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS kb_suggestions (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
      suggested_by TEXT DEFAULT 'anonymous', status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS kb_pages (
      id SERIAL PRIMARY KEY, kb_id INT NOT NULL REFERENCES kb_suggestions(id),
      title TEXT NOT NULL, content TEXT DEFAULT '',
      added_by TEXT DEFAULT 'anonymous', updated_by TEXT,
      created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
    CREATE INDEX IF NOT EXISTS idx_kb_pages_fts ON kb_pages USING GIN (to_tsvector('english', title || ' ' || content));
    ALTER TABLE kb_pages ADD COLUMN IF NOT EXISTS link TEXT DEFAULT '';
    ALTER TABLE kb_pages ADD COLUMN IF NOT EXISTS file_data TEXT;      -- base64
    ALTER TABLE kb_pages ADD COLUMN IF NOT EXISTS file_name TEXT DEFAULT '';
    ALTER TABLE kb_pages ADD COLUMN IF NOT EXISTS file_mime TEXT DEFAULT '';
    -- member-submitted docs/links/files awaiting an admin's approval into a KB
    CREATE TABLE IF NOT EXISTS kb_submissions (
      id SERIAL PRIMARY KEY, kb_id INT NOT NULL REFERENCES kb_suggestions(id),
      title TEXT NOT NULL, notes TEXT DEFAULT '', link TEXT DEFAULT '',
      file_data TEXT, file_name TEXT DEFAULT '', file_mime TEXT DEFAULT '',
      submitted_by TEXT DEFAULT 'anonymous', status TEXT DEFAULT 'pending',
      decided_by TEXT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE kb_suggestions ADD COLUMN IF NOT EXISTS is_main BOOLEAN DEFAULT false;
    ALTER TABLE kb_suggestions ADD COLUMN IF NOT EXISTS migrated BOOLEAN DEFAULT false;
    CREATE TABLE IF NOT EXISTS kb_page_revisions (
      id SERIAL PRIMARY KEY, page_id INT NOT NULL, title TEXT, content TEXT,
      replaced_by TEXT, replaced_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS connectors (
      id SERIAL PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
      config_encrypted TEXT NOT NULL, meta JSONB DEFAULT '{}',
      active BOOLEAN DEFAULT true, added_by TEXT DEFAULT 'anonymous', created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS tickets_cache (
      gorgias_id BIGINT PRIMARY KEY, status TEXT, subject TEXT DEFAULT '', channel TEXT DEFAULT '',
      tags JSONB DEFAULT '[]', created_datetime TIMESTAMPTZ, closed_datetime TIMESTAMPTZ,
      updated_datetime TIMESTAMPTZ, synced_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS spam BOOLEAN DEFAULT false;
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS messages_count INT;
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS customer_email TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS customer_name TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_category TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_model TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_colour TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_country TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_solved_by TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS cf_ai_intent TEXT DEFAULT '';
    ALTER TABLE tickets_cache ADD COLUMN IF NOT EXISTS custom_fields JSONB DEFAULT '{}';
    CREATE INDEX IF NOT EXISTS idx_tc_created ON tickets_cache (created_datetime);
    CREATE INDEX IF NOT EXISTS idx_tc_closed ON tickets_cache (closed_datetime);
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
      event_date DATE NOT NULL, added_by TEXT DEFAULT 'anonymous',
      attachment_name TEXT, attachment_type TEXT, attachment_data TEXT,
      created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS sync_state (k TEXT PRIMARY KEY, v JSONB NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS returns_cache (
      redo_id TEXT PRIMARY KEY, order_name TEXT DEFAULT '', type TEXT DEFAULT '', status TEXT DEFAULT '',
      created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ,
      refund NUMERIC DEFAULT 0, exchange_value NUMERIC DEFAULT 0, store_credit NUMERIC DEFAULT 0,
      items JSONB DEFAULT '[]', return_tags JSONB DEFAULT '[]', synced_at TIMESTAMPTZ DEFAULT now());
    CREATE INDEX IF NOT EXISTS idx_rc_created ON returns_cache (created_at);
    CREATE TABLE IF NOT EXISTS campaigns_cache (
      klaviyo_id TEXT PRIMARY KEY, name TEXT DEFAULT '', channel TEXT DEFAULT '', status TEXT DEFAULT '',
      send_time TIMESTAMPTZ, recipients INT, opens INT, open_rate DOUBLE PRECISION,
      clicks INT, click_rate DOUBLE PRECISION, revenue NUMERIC, synced_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS unsub_rate DOUBLE PRECISION;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS spam_rate DOUBLE PRECISION;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS bounce_rate DOUBLE PRECISION;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS subject TEXT;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS preview TEXT;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS from_email TEXT;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS html TEXT;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS text_body TEXT;
    ALTER TABLE campaigns_cache ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS flows_cache (
      flow_id TEXT PRIMARY KEY, name TEXT DEFAULT '', status TEXT DEFAULT '', channel TEXT DEFAULT '',
      recipients INT, open_rate DOUBLE PRECISION, click_rate DOUBLE PRECISION, revenue NUMERIC, synced_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS uk_stock (
      sku TEXT PRIMARY KEY, name TEXT DEFAULT '', qty INT, raw JSONB, updated_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE uk_stock ADD COLUMN IF NOT EXISTS upc TEXT DEFAULT '';
    ALTER TABLE uk_stock ADD COLUMN IF NOT EXISTS brand_new INT;
    ALTER TABLE uk_stock ADD COLUMN IF NOT EXISTS non_pristine INT;
    ALTER TABLE uk_stock ADD COLUMN IF NOT EXISTS damaged INT;
    ALTER TABLE uk_stock ADD COLUMN IF NOT EXISTS founders INT;
    CREATE TABLE IF NOT EXISTS uk_stock_history (
      taken_at TIMESTAMPTZ DEFAULT now(), sku TEXT, qty INT);
    CREATE TABLE IF NOT EXISTS stock_sign_outs (
      id SERIAL PRIMARY KEY, po_number TEXT NOT NULL, destination TEXT DEFAULT '',
      notes TEXT DEFAULT '', created_by TEXT DEFAULT '', include_invoice BOOLEAN DEFAULT false,
      items JSONB DEFAULT '[]', created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS shipbob_stock (
      sku TEXT PRIMARY KEY, name TEXT DEFAULT '', upc TEXT DEFAULT '',
      on_hand INT, fulfillable INT, committed INT, by_fc JSONB DEFAULT '[]', updated_at TIMESTAMPTZ DEFAULT now());
    DROP TABLE IF EXISTS shipbob_inventory;
    CREATE TABLE IF NOT EXISTS floship_stock (
      sku TEXT PRIMARY KEY, description TEXT DEFAULT '', upc TEXT DEFAULT '',
      qty INT, on_hand INT, by_wh JSONB DEFAULT '[]', updated_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS manual_stock (
      sku TEXT, source TEXT, qty INT, description TEXT DEFAULT '', updated_at TIMESTAMPTZ DEFAULT now(),
      PRIMARY KEY (sku, source));
    CREATE TABLE IF NOT EXISTS inv_source_ord (source TEXT PRIMARY KEY, ord INT);
    CREATE TABLE IF NOT EXISTS inv_sku_ord (sku TEXT PRIMARY KEY, ord INT);
    CREATE TABLE IF NOT EXISTS freight_shipments (
      id SERIAL PRIMARY KEY, reference TEXT DEFAULT '', description TEXT DEFAULT '',
      units INT, origin TEXT DEFAULT '', destination TEXT DEFAULT '', carrier TEXT DEFAULT '',
      status TEXT DEFAULT 'Packed at factory', eta DATE, notes TEXT DEFAULT '',
      created_by TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS name TEXT DEFAULT '';
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS from_country TEXT DEFAULT '';
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS to_country TEXT DEFAULT '';
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS items JSONB DEFAULT '[]';
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS stages JSONB DEFAULT '[]';
    ALTER TABLE freight_shipments ADD COLUMN IF NOT EXISTS step INT DEFAULT 0;
    CREATE TABLE IF NOT EXISTS freight_docs (
      id SERIAL PRIMARY KEY, shipment_id INT, label TEXT DEFAULT '', filename TEXT DEFAULT '',
      mime TEXT DEFAULT '', data TEXT, uploaded_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS orders_cache (
      shopify_id BIGINT PRIMARY KEY, order_number TEXT DEFAULT '',
      created_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ,
      currency TEXT DEFAULT '', total_price NUMERIC DEFAULT 0,
      country TEXT DEFAULT '', financial_status TEXT DEFAULT '', fulfillment_status TEXT DEFAULT '',
      items JSONB DEFAULT '[]', updated_at TIMESTAMPTZ, synced_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS order_tags JSONB DEFAULT '[]';
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS fulfilled_at TIMESTAMPTZ;
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS cancel_reason TEXT DEFAULT '';
    CREATE INDEX IF NOT EXISTS idx_oc_created ON orders_cache (created_at);
    CREATE INDEX IF NOT EXISTS idx_oc_fulfilled ON orders_cache (fulfilled_at);
    CREATE TABLE IF NOT EXISTS product_images (
      sku TEXT PRIMARY KEY, title TEXT DEFAULT '', image_url TEXT, updated_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE product_images ADD COLUMN IF NOT EXISTS variant_title TEXT DEFAULT '';
    CREATE TABLE IF NOT EXISTS connector_types (
      slug TEXT PRIMARY KEY, label TEXT NOT NULL, fields JSONB NOT NULL,
      notes TEXT DEFAULT '', created_by TEXT DEFAULT 'assistant', created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'approved';
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approved_by TEXT;
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY, pass_hash TEXT, created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_token TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_expires TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS shipping BOOLEAN DEFAULT false;
    CREATE TABLE IF NOT EXISTS connection_requests (
      id SERIAL PRIMARY KEY, service TEXT NOT NULL, reason TEXT NOT NULL,
      requested_by TEXT DEFAULT 'anonymous', status TEXT DEFAULT 'pending',
      decided_by TEXT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now());
  `);
  // single flat knowledge base: ensure one "main" base, and fold any legacy bases in as sources (once)
  let mainKb = (await lockClient.query(`SELECT id FROM kb_suggestions WHERE is_main LIMIT 1`)).rows[0]?.id;
  if (!mainKb) {
    mainKb = (await lockClient.query(
      `INSERT INTO kb_suggestions (name, description, suggested_by, status, is_main)
       VALUES ('Clicks Knowledge Base', 'Links, docs and specs for Clicks', 'system', 'approved', true) RETURNING id`)).rows[0].id;
  }
  const legacy = (await lockClient.query(`SELECT id, name, description FROM kb_suggestions WHERE NOT is_main AND NOT migrated`)).rows;
  for (const b of legacy) {
    const desc = String(b.description || '').trim();
    const isUrl = /^(https?:\/\/|www\.)/i.test(desc);
    await lockClient.query(
      `INSERT INTO kb_pages (kb_id, title, content, link, added_by) VALUES ($1,$2,$3,$4,'migration')`,
      [mainKb, b.name, isUrl ? '' : desc, isUrl ? desc : '']);
    await lockClient.query(`UPDATE kb_pages SET kb_id=$1 WHERE kb_id=$2`, [mainKb, b.id]); // keep any real pages
    await lockClient.query(`UPDATE kb_suggestions SET migrated=true, status='archived' WHERE id=$1`, [b.id]);
  }
  for (const em of ['fran@clicks.tech', 'kp@clicks.tech']) {
    await lockClient.query(`INSERT INTO users (email, role) VALUES ($1, 'admin')
                      ON CONFLICT (email) DO UPDATE SET role='admin'`, [em]);
  }
  await lockClient.query(`INSERT INTO users (email, role) VALUES ('kevin@clicks.tech', 'member')
                    ON CONFLICT (email) DO NOTHING`);
  } finally {
    await lockClient.query('SELECT pg_advisory_unlock(728341)').catch(() => {});
    lockClient.release();
  }
}

async function isAdminReq(req) {
  if (!req.userEmail) return false;
  const { rows } = await pool.query('SELECT role FROM users WHERE email=$1', [req.userEmail]);
  return rows[0]?.role === 'admin';
}

// ---------- crypto ----------
const MASTER = process.env.ENCRYPTION_KEY || process.env.DATABASE_URL || 'dev-only-key';
const KEY = crypto.createHash('sha256').update(MASTER).digest();
function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), data].map(b => b.toString('base64')).join(':');
}
function decrypt(str) {
  const [iv, tag, data] = str.split(':').map(s => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString('utf8'));
}

const looksSecret = (t) =>
  /(api[_-]?key|secret|password|bearer\s+[a-z0-9]|sk-ant-|ghp_[A-Za-z0-9]{20,}|rnd_[A-Za-z0-9]{20,})/i.test(String(t || ''));

// ---------- connector registry ----------
const CONNECTOR_TYPES = {
  gorgias: {
    label: 'Gorgias helpdesk',
    fields: [
      { key: 'domain', label: 'Gorgias subdomain (e.g. "clicks" for clicks.gorgias.com)', secret: false },
      { key: 'email', label: 'Account email', secret: false },
      { key: 'api_key', label: 'REST API key (Settings → Account → REST API)', secret: true }
    ]
  },
  anthropic: {
    label: 'Claude assistant',
    fields: [{ key: 'api_key', label: 'Anthropic API key (console.anthropic.com)', secret: true }]
  },
  slack: {
    label: 'Slack bot (@clicksbot)',
    fields: [
      { key: 'bot_token', label: 'Bot User OAuth Token, starts with xoxb- (api.slack.com/apps → your app → OAuth & Permissions)', secret: true },
      { key: 'signing_secret', label: 'Signing Secret (api.slack.com/apps → your app → Basic Information)', secret: true },
      { key: 'alert_channel', label: 'Main alerts channel, e.g. #clicksbrain (invite @clicksbot to it first)', secret: false, optional: true },
      { key: 'freight_channel', label: 'Freight-only channel, e.g. #freight (optional — falls back to the main channel; invite @clicksbot)', secret: false, optional: true }
    ]
  },
  redo: {
    label: 'Redo (returns)',
    fields: [
      { key: 'store_id', label: 'Store ID (Redo Dashboard → Settings → Developer → General)', secret: false },
      { key: 'api_secret', label: 'API secret — create an API client with only the returns_read scope (Settings → Developer → Add API Client)', secret: true }
    ]
  },
  klaviyo: {
    label: 'Klaviyo (email/SMS campaigns)',
    fields: [
      { key: 'api_key', label: 'Private API key, read-only scopes: campaigns, metrics, flows (Klaviyo → Settings → API keys)', secret: true }
    ]
  },
  uk_stock: {
    label: 'UK stock (clicks-uk-returns)',
    fields: [
      { key: 'base_url', label: 'Stock endpoint URL, e.g. https://clicks-uk-returns.onrender.com/api/v1/stock', secret: false },
      { key: 'api_key', label: 'X-API-Key (rotate it first if it was ever shared in chat)', secret: true }
    ]
  },
  shopify: {
    label: 'Shopify store',
    fields: [
      { key: 'store_domain', label: 'Store subdomain, e.g. "clicks-tech" for clicks-tech.myshopify.com', secret: false },
      { key: 'client_id', label: 'App Client ID (dev.shopify.com → your app → Settings)', secret: false },
      { key: 'client_secret', label: 'App Client Secret (same page — rotate it first if it was ever shared in chat/email)', secret: true }
    ]
  },
  shipbob: {
    label: 'ShipBob (3PL fulfillment)',
    fields: [
      { key: 'token', label: 'Personal Access Token (ShipBob → Settings → API tokens)', secret: true },
      { key: 'channel_id', label: 'Channel ID (optional — leave blank to auto-detect)', secret: false, optional: true }
    ]
  },
  floship: {
    label: 'Floship (3PL fulfillment · HK)',
    fields: [
      { key: 'base_url', label: 'Inventory/stock API URL Floship gave you (full endpoint)', secret: false },
      { key: 'token', label: 'API token / key', secret: true }
    ]
  }
};

async function getAllConnectorTypes() {
  const dyn = (await pool.query('SELECT slug, label, fields, notes FROM connector_types ORDER BY created_at')).rows;
  const merged = { ...CONNECTOR_TYPES };
  for (const d of dyn) {
    if (!merged[d.slug]) merged[d.slug] = { label: d.label, fields: d.fields, notes: d.notes, dynamic: true };
  }
  return merged;
}

async function getConnector(type) {
  const { rows } = await pool.query(
    'SELECT * FROM connectors WHERE type=$1 AND active=true ORDER BY created_at DESC LIMIT 1', [type]);
  if (!rows[0]) return null;
  try { return { ...rows[0], config: decrypt(rows[0].config_encrypted) }; }
  catch { return null; }
}

app.get('/api/connector-types', async (_req, res) => res.json(await getAllConnectorTypes()));

// update just the Slack alert/freight channels in place (non-secret) — no need to re-enter the bot token
app.post('/api/slack/channels', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const row = (await pool.query(`SELECT id, config_encrypted, meta FROM connectors WHERE type='slack' AND active=true ORDER BY created_at DESC LIMIT 1`)).rows[0];
  if (!row) return res.status(404).json({ error: 'Slack is not connected yet — add it first.' });
  let cfg; try { cfg = decrypt(row.config_encrypted); } catch { return res.status(500).json({ error: 'could not read existing config' }); }
  const clean = v => String(v || '').trim().slice(0, 120);
  if (req.body.alert_channel !== undefined) cfg.alert_channel = clean(req.body.alert_channel);
  if (req.body.freight_channel !== undefined) cfg.freight_channel = clean(req.body.freight_channel);
  const meta = { ...(row.meta || {}), alert_channel: cfg.alert_channel || '', freight_channel: cfg.freight_channel || '' };
  await pool.query(`UPDATE connectors SET config_encrypted=$1, meta=$2 WHERE id=$3`, [encrypt(cfg), meta, row.id]);
  res.json({ ok: true, alert_channel: cfg.alert_channel || '', freight_channel: cfg.freight_channel || '' });
});
app.get('/api/slack/channels', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const conn = await getConnector('slack');
  if (!conn) return res.json({ configured: false });
  res.json({ configured: true, alert_channel: conn.config.alert_channel || '', freight_channel: conn.config.freight_channel || '' });
});

app.get('/api/connectors', async (_req, res) => {
  const { rows } = await pool.query(
    'SELECT id, type, name, meta, active, added_by, approval_status, approved_by, created_at, config_encrypted FROM connectors ORDER BY created_at DESC');
  res.json(rows.map(({ config_encrypted, ...r }) => {
    let decrypt_ok = true;
    try { decrypt(config_encrypted); } catch { decrypt_ok = false; }
    return { ...r, decrypt_ok }; // ciphertext itself is never returned
  }));
});

// ---------- pending integrations + admin approval ----------
const adminOk = (pw) => {
  const admin = process.env.ADMIN_PASSWORD;
  if (!admin || !pw) return false;
  const a = Buffer.from(String(pw)), b = Buffer.from(admin);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---------- connection requests (members propose, admins decide) ----------
app.get('/api/requests', async (_req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM connection_requests ORDER BY (status=\'pending\') DESC, created_at DESC LIMIT 100');
  res.json(rows);
});
app.post('/api/requests', async (req, res) => {
  const { service, reason } = req.body || {};
  if (!service || !reason) return res.status(400).json({ error: 'service and reason required' });
  if (looksSecret(service + ' ' + reason)) return res.status(400).json({ error: 'Requests must contain only the idea and the reason — never keys or passwords.' });
  const { rows } = await pool.query(
    'INSERT INTO connection_requests (service, reason, requested_by) VALUES ($1,$2,$3) RETURNING *',
    [String(service).slice(0, 200), String(reason).slice(0, 2000), req.userEmail || 'anonymous']);
  res.status(201).json(rows[0]);
});
app.post('/api/requests/:id/decision', async (req, res) => {
  const { decision, admin_password } = req.body || {};
  if (!(await isAdminReq(req)) && !adminOk(admin_password)) return res.status(403).json({ error: 'Only admins can decide requests.' });
  if (!['approved', 'rejected'].includes(decision)) return res.status(400).json({ error: 'decision must be approved or rejected' });
  const { rows } = await pool.query(
    `UPDATE connection_requests SET status=$1, decided_by=$2, decided_at=now()
     WHERE id=$3 AND status='pending' RETURNING *`,
    [decision, req.userEmail || 'admin', req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found or already decided' });
  res.json(rows[0]);
});

app.get('/api/integrations/pending', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, type, name, meta, added_by, created_at FROM connectors
     WHERE approval_status='pending' AND active=true ORDER BY created_at`);
  res.json(rows);
});

app.post('/api/connectors/:id/decision', async (req, res) => {
  const { decision, admin_password, decided_by } = req.body || {};
  if (!(await isAdminReq(req)) && !adminOk(admin_password))
    return res.status(403).json({ error: 'Only admins can approve or reject integrations.' });
  if (!['approved', 'rejected'].includes(decision))
    return res.status(400).json({ error: 'decision must be "approved" or "rejected"' });
  const { rows } = await pool.query(
    `UPDATE connectors SET approval_status=$1, approved_by=$2, approved_at=now(), active=(CASE WHEN $1='approved' THEN active ELSE false END)
     WHERE id=$3 AND approval_status='pending'
     RETURNING id, type, name, meta, approval_status, approved_by`,
    [decision, String(decided_by || 'admin').slice(0, 100), req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found or already decided' });
  res.json(rows[0]);
});

app.post('/api/connectors', async (req, res) => {
  const { type, name, config, added_by, admin_password } = req.body || {};
  if (!(await isAdminReq(req)) && !adminOk(admin_password)) {
    return res.status(403).json({ error: 'Only admins can add connectors. Members: request the connection in the chat above (idea + reason) — an admin will take it from there.' });
  }
  const types = await getAllConnectorTypes();
  const def = types[type];
  if (!def) return res.status(400).json({ error: 'unknown connector type' });
  for (const f of def.fields) {
    if (!config?.[f.key] && !f.optional) return res.status(400).json({ error: `missing field: ${f.key}` });
  }
  let meta = {};
  try {
    if (type === 'gorgias') {
      const test = await gorgiasRequest(config, '/api/account');
      meta = { domain: config.domain, account: test?.name || test?.domain || 'ok' };
    } else if (type === 'anthropic') {
      await anthropic(config.api_key, { messages: [{ role: 'user', content: 'ping' }], system: 'Reply "pong".', max_tokens: 8 });
      meta = { model: ASSISTANT_MODEL };
    } else if (type === 'slack') {
      const t = await (await fetch('https://slack.com/api/auth.test', {
        method: 'POST', headers: { Authorization: `Bearer ${config.bot_token}` }
      })).json();
      if (!t.ok) throw new Error(`Slack auth.test: ${t.error}`);
      meta = { team: t.team, bot: t.user };
    } else if (type === 'shopify') {
      const d = await shopifyGraphql(config, 'query { shop { name } }');
      meta = { store: d?.shop?.name || config.store_domain, domain: config.store_domain };
    } else if (type === 'redo') {
      const t = await redoRequest(config, `/stores/${config.store_id}/returns`, { 'X-Page-Size': '1' });
      meta = { returns_visible: (t.data.returns || []).length >= 0 ? 'ok' : 'none' };
    } else if (type === 'shipbob') {
      const chans = await shipbobRequest(config, '/1.0/channel');
      meta = { channels: Array.isArray(chans) ? chans.length : 'ok' };
    } else if (type === 'floship') {
      const p = await floshipProbe(config.base_url, config.token);
      if (!p.ok) throw new Error(`no auth style worked (last: ${p.auth || '?'} → ${p.status || p.error})`);
      meta = { endpoint: String(config.base_url).replace(/^https?:\/\//, '').split('/')[0], auth: p.auth, products_url: p.url };
    } else if (type === 'klaviyo') {
      const m = await klaviyoRequest(config, '/api/metrics/');
      meta = { metrics_visible: (m.data || []).length };
    } else if (type === 'uk_stock') {
      const j = await ukStockFetch(config);
      const items = extractStockItems(j);
      meta = { endpoint: config.base_url.replace(/^https?:\/\//, '').split('/')[0], items_seen: items ? items.length : 'unknown shape — will diagnose on sync' };
    } else {
      // dynamic connector: store credentials now, integration wired later.
      // Non-secret fields go into visible meta; secrets never do.
      for (const f of def.fields) if (!f.secret) meta[f.key] = config[f.key];
      meta.integration = 'pending';
    }
  } catch (e) {
    return res.status(400).json({ error: `Connection test failed: ${e.message}. Credentials were NOT saved.` });
  }
  await pool.query('UPDATE connectors SET active=false WHERE type=$1', [type]);
  const approval = 'approved'; // adding is admin-gated, so saving implies approval
  const { rows } = await pool.query(
    `INSERT INTO connectors (type, name, config_encrypted, meta, added_by, approval_status) VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, type, name, meta, active, added_by, approval_status, created_at`,
    [type, name || def.label, encrypt(config), meta, added_by || 'anonymous', approval]);
  if (type === 'gorgias') syncGorgias(15).catch(e => console.error('initial sync:', e.message));
  if (type === 'shopify') { syncShopify(30).catch(e => console.error('initial shopify sync:', e.message)); syncShopifyProducts().catch(e => console.error('initial product sync:', e.message)); }
  if (type === 'uk_stock') syncUkStock().catch(e => console.error('initial stock sync:', e.message));
  if (type === 'klaviyo') syncKlaviyo().catch(e => console.error('initial klaviyo sync:', e.message));
  if (type === 'redo') syncRedo(20).catch(e => console.error('initial redo sync:', e.message));
  if (type === 'shipbob') syncShipbob().catch(e => console.error('initial shipbob sync:', e.message));
  if (type === 'floship') syncFloship().catch(e => console.error('initial floship sync:', e.message));
  res.status(201).json(rows[0]);
});

// ---------- data endpoints (read + add-only) ----------
const rejectSecrets = (fields) => (req, res, next) => {
  const text = fields.map(f => req.body?.[f]).join(' ');
  if (looksSecret(text)) return res.status(400).json({ error: 'Submission looks like it contains a credential. Secrets belong in Connectors, not in content.' });
  next();
};

app.get('/api/products', async (_req, res) =>
  res.json((await pool.query('SELECT * FROM products ORDER BY name')).rows));
app.post('/api/products', rejectSecrets(['name', 'sku', 'specs', 'warranty', 'source']), async (req, res) => {
  const { name, sku, specs, warranty, source } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query(
    'INSERT INTO products (name, sku, specs, warranty, source) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [name, sku || '', specs || '', warranty || '', source || 'manual import']);
  res.status(201).json(rows[0]);
});
app.get('/api/dates', async (_req, res) =>
  res.json((await pool.query('SELECT * FROM key_dates ORDER BY date')).rows));
app.post('/api/dates', rejectSecrets(['event', 'source']), async (req, res) => {
  const { date, event, source } = req.body || {};
  if (!date || !event) return res.status(400).json({ error: 'date and event required' });
  const { rows } = await pool.query(
    'INSERT INTO key_dates (date, event, source) VALUES ($1,$2,$3) RETURNING *',
    [date, event, source || 'manual import']);
  res.status(201).json(rows[0]);
});
app.get('/api/kb', async (_req, res) =>
  res.json((await pool.query('SELECT * FROM kb_suggestions ORDER BY created_at DESC')).rows));
app.post('/api/kb', rejectSecrets(['name', 'description']), async (req, res) => {
  const { name, description, suggested_by } = req.body || {};
  if (!name || !description) return res.status(400).json({ error: 'name and description required' });
  const { rows } = await pool.query(
    'INSERT INTO kb_suggestions (name, description, suggested_by) VALUES ($1,$2,$3) RETURNING *',
    [name, description, suggested_by || 'anonymous']);
  res.status(201).json(rows[0]);
});

// ---------- single flat "Clicks Knowledge Base": a list of sources (links / files / notes) ----------
async function mainKbId() {
  return (await pool.query(`SELECT id FROM kb_suggestions WHERE is_main LIMIT 1`)).rows[0]?.id || null;
}
// everyone signed in sees the source titles; link/file access stays admin-only
app.get('/api/kb/sources', async (req, res) => {
  const id = await mainKbId();
  if (!id) return res.json({ can_open: false, sources: [] });
  const admin = await isAdminReq(req);
  const rows = (await pool.query(
    `SELECT id, title, updated_at, nullif(link,'') link, nullif(file_name,'') file_name
     FROM kb_pages WHERE kb_id=$1 ORDER BY lower(title)`, [id])).rows;
  res.json({ can_open: admin, sources: rows.map(r => admin ? r
    : { id: r.id, title: r.title, has_link: !!r.link, has_file: !!r.file_name }) });
});
// member submits a source (no bucket to pick — always the one Clicks KB)
app.post('/api/kb/submit', rejectSecrets(['title', 'notes', 'link']), async (req, res) => {
  const id = await mainKbId();
  if (!id) return res.status(500).json({ error: 'knowledge base not ready' });
  const b = req.body || {};
  const notes = String(b.notes || '').trim(), link = String(b.link || '').trim(), fileName = String(b.file_name || '').trim();
  if (!notes && !link && !b.file_data) return res.status(400).json({ error: 'add a link, a file, or some notes' });
  const title = (String(b.title || '').trim() || fileName || link || 'Untitled source').slice(0, 300);
  await pool.query(
    `INSERT INTO kb_submissions (kb_id, title, notes, link, file_data, file_name, file_mime, submitted_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, title, notes.slice(0, 100000), link.slice(0, 1000), b.file_data || null, fileName.slice(0, 200), String(b.file_mime || '').slice(0, 100), req.userEmail || 'anonymous']);
  res.status(201).json({ ok: true });
});
// admin adds a source directly (no review needed)
app.post('/api/kb/source', rejectSecrets(['title', 'notes', 'link']), async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const id = await mainKbId();
  if (!id) return res.status(500).json({ error: 'knowledge base not ready' });
  const b = req.body || {};
  const notes = String(b.notes || '').trim(), link = String(b.link || '').trim(), fileName = String(b.file_name || '').trim();
  if (!notes && !link && !b.file_data) return res.status(400).json({ error: 'add a link, a file, or some notes' });
  const title = (String(b.title || '').trim() || fileName || link || 'Untitled source').slice(0, 300);
  const content = [notes, link ? `Link: ${link}` : ''].filter(Boolean).join('\n\n');
  const { rows } = await pool.query(
    `INSERT INTO kb_pages (kb_id, title, content, link, file_data, file_name, file_mime, added_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [id, title, content.slice(0, 100000), link, b.file_data || null, fileName.slice(0, 200), String(b.file_mime || '').slice(0, 100), req.userEmail || 'admin']);
  res.status(201).json({ ok: true, id: rows[0].id });
});
app.post('/api/kb/pages/:id/delete', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  await pool.query('DELETE FROM kb_pages WHERE id=$1', [parseInt(req.params.id)]);
  res.json({ ok: true });
});

// ---------- KB pages (content, search, revisions) ----------
async function kbSearch(q, limit = 12) {
  const { rows } = await pool.query(
    `SELECT p.id, p.kb_id, s.name kb, p.title, p.updated_at,
       ts_headline('english', p.content, plainto_tsquery('english', $1),
         'MaxWords=35, MinWords=10, StartSel=**, StopSel=**') snippet,
       ts_rank(to_tsvector('english', p.title || ' ' || p.content), plainto_tsquery('english', $1)) rank
     FROM kb_pages p JOIN kb_suggestions s ON s.id = p.kb_id
     WHERE to_tsvector('english', p.title || ' ' || p.content) @@ plainto_tsquery('english', $1)
        OR p.title ILIKE '%' || $1 || '%'
     ORDER BY rank DESC NULLS LAST LIMIT $2`, [String(q).slice(0, 200), limit]);
  return rows;
}

// KB content (search, page lists, page bodies) is admin-only — members see the list of bases but not the docs
app.get('/api/kb/search', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const q = String(req.query.q || '').trim();
  if (!q) return res.json([]);
  try { res.json(await kbSearch(q)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/kb/:id/pages', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { rows } = await pool.query(
    `SELECT id, title, added_by, updated_by, updated_at, length(content)::int chars,
       nullif(link,'') link, nullif(file_name,'') file_name
     FROM kb_pages WHERE kb_id=$1 ORDER BY created_at`, [req.params.id]);
  res.json(rows);
});
app.get('/api/kb/pages/:pageId', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { rows } = await pool.query('SELECT id, kb_id, title, content, added_by, updated_by, created_at, updated_at, link, file_name, file_mime FROM kb_pages WHERE id=$1', [req.params.pageId]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});
app.get('/api/kb/pages/:pageId/file', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).send('admins only');
  const d = (await pool.query('SELECT file_data, file_name, file_mime FROM kb_pages WHERE id=$1', [parseInt(req.params.pageId)])).rows[0];
  if (!d?.file_data) return res.status(404).send('no file');
  res.set('Content-Type', d.file_mime || 'application/octet-stream');
  res.set('Content-Disposition', `inline; filename="${(d.file_name || 'file').replace(/"/g, '')}"`);
  res.send(Buffer.from(d.file_data, 'base64'));
});
app.post('/api/kb/:id/pages', rejectSecrets(['title', 'content']), async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only — members submit for approval instead' });
  const { title, content } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  const kb = (await pool.query('SELECT status FROM kb_suggestions WHERE id=$1', [req.params.id])).rows[0];
  if (!kb) return res.status(404).json({ error: 'knowledge base not found' });
  if (kb.status !== 'approved') return res.status(400).json({ error: 'Pages can only be added to approved knowledge bases.' });
  const { rows } = await pool.query(
    `INSERT INTO kb_pages (kb_id, title, content, added_by) VALUES ($1,$2,$3,$4)
     RETURNING id, title, added_by, updated_at`,
    [req.params.id, String(title).slice(0, 300), String(content || '').slice(0, 100000), req.userEmail || 'anonymous']);
  res.status(201).json(rows[0]);
});
app.put('/api/kb/pages/:pageId', rejectSecrets(['title', 'content']), async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { title, content } = req.body || {};
  const old = (await pool.query('SELECT * FROM kb_pages WHERE id=$1', [req.params.pageId])).rows[0];
  if (!old) return res.status(404).json({ error: 'not found' });
  await pool.query( // previous version is preserved, never lost
    'INSERT INTO kb_page_revisions (page_id, title, content, replaced_by) VALUES ($1,$2,$3,$4)',
    [old.id, old.title, old.content, req.userEmail || 'anonymous']);
  const { rows } = await pool.query(
    `UPDATE kb_pages SET title=$2, content=$3, updated_by=$4, updated_at=now() WHERE id=$1
     RETURNING id, title, updated_by, updated_at`,
    [old.id, String(title || old.title).slice(0, 300), String(content ?? old.content).slice(0, 100000), req.userEmail || 'anonymous']);
  res.json(rows[0]);
});

// ---------- KB submissions (members submit docs/links/files → admins approve into a page) ----------
// pull readable text out of a base64 file where we can (text-like formats); binaries stay for humans
function extractFileText(mime, filename, b64) {
  if (!b64) return '';
  const name = String(filename || '').toLowerCase();
  const textly = /^text\//i.test(mime || '') || /\.(txt|md|markdown|csv|tsv|json|html?|log|rtf)$/i.test(name);
  if (!textly) return ''; // PDFs/images/docx aren't text-extracted here
  try { return Buffer.from(b64, 'base64').toString('utf8').replace(/\u0000/g, '').slice(0, 60000); }
  catch { return ''; }
}
// member (any signed-in user) submits a doc/link/file to a knowledge base for review
app.post('/api/kb/:id/submit', rejectSecrets(['title', 'notes', 'link']), async (req, res) => {
  const b = req.body || {};
  const notes = String(b.notes || '').trim(), link = String(b.link || '').trim(), fileName = String(b.file_name || '').trim();
  if (!notes && !link && !b.file_data) return res.status(400).json({ error: 'add a link, a file, or some notes' });
  // title is optional — fall back to the file name, then the link, then a generic label
  const title = (String(b.title || '').trim() || fileName || link || 'Untitled submission').slice(0, 300);
  const kb = (await pool.query('SELECT status FROM kb_suggestions WHERE id=$1', [req.params.id])).rows[0];
  if (!kb) return res.status(404).json({ error: 'knowledge base not found' });
  if (kb.status !== 'approved') return res.status(400).json({ error: 'This knowledge base is not approved yet.' });
  await pool.query(
    `INSERT INTO kb_submissions (kb_id, title, notes, link, file_data, file_name, file_mime, submitted_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [req.params.id, title, notes.slice(0, 100000), link.slice(0, 1000),
     b.file_data || null, fileName.slice(0, 200), String(b.file_mime || '').slice(0, 100), req.userEmail || 'anonymous']);
  res.status(201).json({ ok: true });
});
// admin: list pending submissions (file metadata only, not the base64)
app.get('/api/kb/submissions', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { rows } = await pool.query(
    `SELECT sub.id, sub.kb_id, s.name kb, sub.title, sub.notes, nullif(sub.link,'') link,
       nullif(sub.file_name,'') file_name, sub.submitted_by, sub.created_at
     FROM kb_submissions sub JOIN kb_suggestions s ON s.id = sub.kb_id
     WHERE sub.status='pending' ORDER BY sub.created_at`);
  res.json(rows);
});
app.get('/api/kb/submission/:id/file', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).send('admins only');
  const d = (await pool.query('SELECT file_data, file_name, file_mime FROM kb_submissions WHERE id=$1', [parseInt(req.params.id)])).rows[0];
  if (!d?.file_data) return res.status(404).send('no file');
  res.set('Content-Type', d.file_mime || 'application/octet-stream');
  res.set('Content-Disposition', `inline; filename="${(d.file_name || 'file').replace(/"/g, '')}"`);
  res.send(Buffer.from(d.file_data, 'base64'));
});
// admin approves (→ becomes a KB page the assistant can use) or rejects a submission
app.post('/api/kb/submission/:id/decision', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const sub = (await pool.query('SELECT * FROM kb_submissions WHERE id=$1 AND status=$2', [parseInt(req.params.id), 'pending'])).rows[0];
  if (!sub) return res.status(404).json({ error: 'submission not found or already decided' });
  const decided = req.body?.decision === 'approved' ? 'approved' : 'rejected';
  if (decided === 'approved') {
    // build the page body the AI will read: notes + link + any extractable file text
    const fileText = extractFileText(sub.file_mime, sub.file_name, sub.file_data);
    const parts = [sub.notes, sub.link ? `Link: ${sub.link}` : '', fileText ? `\n[Attached file: ${sub.file_name}]\n${fileText}` : ''].filter(Boolean);
    await pool.query(
      `INSERT INTO kb_pages (kb_id, title, content, link, file_data, file_name, file_mime, added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [sub.kb_id, sub.title.slice(0, 300), parts.join('\n\n').slice(0, 100000), sub.link || '', sub.file_data || null, sub.file_name || '', sub.file_mime || '', sub.submitted_by]);
  }
  await pool.query('UPDATE kb_submissions SET status=$1, decided_by=$2, decided_at=now() WHERE id=$3',
    [decided, req.userEmail || 'admin', sub.id]);
  res.json({ ok: true, decision: decided });
});

// admin-triggered audit: cross-check knowledge bases against each other and live data
app.post('/api/kb/audit', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const conn = await getConnector('anthropic');
  const apiKey = conn?.config?.api_key || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'The Claude assistant connector is required for audits — add it on the ＋ page.' });
  try {
    const [kbs, stock, products, reasons, tags] = await Promise.all([
      pool.query(`SELECT s.name, s.description, s.status, s.suggested_by,
        coalesce((SELECT string_agg(p.title || ': ' || left(p.content, 800), E'\n---\n') FROM kb_pages p WHERE p.kb_id = s.id), '(no pages yet)') AS pages
        FROM kb_suggestions s WHERE s.status <> 'rejected' ORDER BY s.created_at`),
      pool.query(`SELECT sku, name, qty FROM uk_stock ORDER BY qty DESC LIMIT 40`),
      pool.query(`SELECT it->>'title' product, sum(coalesce((it->>'qty')::int,0))::int units FROM orders_cache, LATERAL jsonb_array_elements(items) it
                  WHERE created_at >= now()-interval '90 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 20`),
      pool.query(`SELECT coalesce(nullif(i->>'reason',''),'(none)') reason, count(*)::int c FROM returns_cache, LATERAL jsonb_array_elements(items) i
                  WHERE created_at >= now()-interval '90 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 12`),
      pool.query(`SELECT t.tag, count(*)::int c FROM tickets_cache, LATERAL jsonb_array_elements_text(tags) t(tag)
                  WHERE created_datetime >= now()-interval '90 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 15`)
    ]);
    if (!kbs.rows.length) return res.json({ findings: [], note: 'No knowledge bases to audit yet.' });
    const prompt = `Audit these internal knowledge base entries for a phone-keyboard company (Clicks Technology).
Cross-check them: (a) against each other for contradictions and overlaps, (b) against the live company data below for outdated or incorrect claims, (c) for vagueness, missing ownership, or entries too thin to be useful.

KNOWLEDGE BASES:
${JSON.stringify(kbs.rows, null, 1)}

LIVE DATA SNAPSHOT (from synced systems):
Current UK stock (top SKUs): ${JSON.stringify(stock.rows)}
Products sold last 90d: ${JSON.stringify(products.rows)}
Top return reasons 90d: ${JSON.stringify(reasons.rows)}
Top support ticket tags 90d: ${JSON.stringify(tags.rows)}

Respond with ONLY a JSON array (no prose), each element:
{"kb": "<kb name or 'cross-cutting'>", "severity": "high"|"medium"|"low", "issue": "<what is wrong or risky>", "suggestion": "<concrete fix>"}
Order by severity. If everything is genuinely fine, return [].`;
    const j = await anthropic(apiKey, { messages: [{ role: 'user', content: prompt }], max_tokens: 2000 });
    const text = (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
    let findings = [];
    try {
      const m = text.match(/\[[\s\S]*\]/);
      findings = m ? JSON.parse(m[0]) : [];
    } catch { findings = [{ kb: 'audit', severity: 'low', issue: 'Could not parse audit output', suggestion: text.slice(0, 500) }]; }
    const record = { at: new Date().toISOString(), by: req.userEmail || 'admin', findings };
    await pool.query(`INSERT INTO sync_state (k, v) VALUES ('kb_audit', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify(record)]);
    res.json(record);
  } catch (e) { res.status(502).json({ error: e.message }); }
});
app.get('/api/kb/audit', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='kb_audit'`)).rows[0]?.v || null;
  res.json(st || { findings: null });
});

app.post('/api/kb/:id/decision', async (req, res) => {
  const { decision } = req.body || {};
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'Only admins can approve or reject knowledge bases.' });
  if (!['approved', 'rejected'].includes(decision)) return res.status(400).json({ error: 'decision must be approved or rejected' });
  const { rows } = await pool.query(
    `UPDATE kb_suggestions SET status=$1 WHERE id=$2 AND status='pending' RETURNING *`,
    [decision, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found or already decided' });
  res.json(rows[0]);
});

// ---------- events (member-added, with optional attachment, pinned on charts) ----------
app.get('/api/events', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, title, description, event_date, added_by, attachment_name, created_at
     FROM events ORDER BY event_date DESC`);
  res.json(rows);
});
app.post('/api/events', rejectSecrets(['title', 'description']), async (req, res) => {
  const { title, description, event_date, added_by, attachment } = req.body || {};
  if (!title || !event_date) return res.status(400).json({ error: 'title and event_date required' });
  let aName = null, aType = null, aData = null;
  if (attachment?.data) {
    if (attachment.data.length > 7 * 1024 * 1024) return res.status(400).json({ error: 'attachment too large (max ~5MB)' });
    aName = String(attachment.name || 'attachment').slice(0, 200);
    aType = String(attachment.type || 'application/octet-stream').slice(0, 100);
    aData = attachment.data; // base64
  }
  const { rows } = await pool.query(
    `INSERT INTO events (title, description, event_date, added_by, attachment_name, attachment_type, attachment_data)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     RETURNING id, title, description, event_date, added_by, attachment_name, created_at`,
    [title, description || '', event_date, added_by || 'anonymous', aName, aType, aData]);
  res.status(201).json(rows[0]);
});
app.get('/api/events/:id/attachment', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT attachment_name, attachment_type, attachment_data FROM events WHERE id=$1', [req.params.id]);
  const a = rows[0];
  if (!a?.attachment_data) return res.status(404).send('no attachment');
  res.set('Content-Type', a.attachment_type || 'application/octet-stream');
  res.set('Content-Disposition', `inline; filename="${(a.attachment_name || 'file').replace(/"/g, '')}"`);
  res.send(Buffer.from(a.attachment_data, 'base64'));
});

// ---------- Gorgias ----------
async function gorgiasRequest(cfg, pathAndQuery, opts = {}) {
  const auth = Buffer.from(`${cfg.email}:${cfg.api_key}`).toString('base64');
  const r = await fetch(`https://${cfg.domain}.gorgias.com${pathAndQuery}`, {
    ...opts,
    headers: { Authorization: `Basic ${auth}`, Accept: 'application/json', 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
  if (!r.ok) throw new Error(`Gorgias ${pathAndQuery.split('?')[0]} → ${r.status}`);
  return r.json();
}

async function getGorgiasConfig() {
  const c = await getConnector('gorgias');
  if (c) return c.config;
  const { GORGIAS_DOMAIN, GORGIAS_EMAIL, GORGIAS_API_KEY } = process.env;
  if (GORGIAS_DOMAIN && GORGIAS_EMAIL && GORGIAS_API_KEY)
    return { domain: GORGIAS_DOMAIN, email: GORGIAS_EMAIL, api_key: GORGIAS_API_KEY };
  return null;
}

let syncRunning = false;
const BACKFILL_HORIZON_DAYS = 400; // keep ~13 months of history

// Gorgias custom-field IDs for this account (from /api/gorgias/debug). Values come through on each ticket
// as custom_fields[id].value. "Other"/blank is kept as-is; callers treat those as "not captured".
const GORGIAS_CF = { category: '235346', model: '235348', colour: '235351', country: '235350', solved_by: '235349', ai_intent: '229827' };
const cfVal = (cf, key) => String(cf?.[GORGIAS_CF[key]]?.value || '').slice(0, 200);
async function upsertTicket(x) {
  const cf = x.custom_fields || {};
  await pool.query(
    `INSERT INTO tickets_cache (gorgias_id, status, subject, channel, tags, created_datetime, closed_datetime, updated_datetime, spam, messages_count, customer_email, customer_name,
       cf_category, cf_model, cf_colour, cf_country, cf_solved_by, cf_ai_intent, custom_fields, synced_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,now())
     ON CONFLICT (gorgias_id) DO UPDATE SET status=$2, subject=$3, channel=$4, tags=$5,
       created_datetime=$6, closed_datetime=$7, updated_datetime=$8, spam=$9,
       messages_count=$10, customer_email=$11, customer_name=$12,
       cf_category=$13, cf_model=$14, cf_colour=$15, cf_country=$16, cf_solved_by=$17, cf_ai_intent=$18, custom_fields=$19, synced_at=now()`,
    [x.id, x.status || '', (x.subject || '').slice(0, 500), x.channel || '',
     JSON.stringify((x.tags || []).map(g => g?.name).filter(Boolean)),
     x.created_datetime || null, x.closed_datetime || null, x.updated_datetime || null, !!x.spam,
     Number.isFinite(x.messages_count) ? x.messages_count : null,
     (x.customer?.email || '').slice(0, 200), (x.customer?.name || '').slice(0, 200),
     cfVal(cf, 'category'), cfVal(cf, 'model'), cfVal(cf, 'colour'), cfVal(cf, 'country'), cfVal(cf, 'solved_by'), cfVal(cf, 'ai_intent'),
     JSON.stringify(cf)]);
}

// re-verify every ticket the cache still thinks is open against Gorgias, in batches of 100.
// Keeps "Open now" / backlog accurate immediately, without waiting for the full history re-sync.
let openRefreshRunning = false;
async function refreshOpenTickets() {
  if (openRefreshRunning) return { skipped: true };
  const cfg = await getGorgiasConfig();
  if (!cfg) return { configured: false };
  openRefreshRunning = true;
  let checked = 0, changed = 0, errors = null;
  try {
    const ids = (await pool.query(
      `SELECT gorgias_id FROM tickets_cache WHERE status='open' ORDER BY updated_datetime DESC NULLS LAST LIMIT 4000`
    )).rows.map(r => r.gorgias_id);
    for (let i = 0; i < ids.length; i += 100) {
      const batch = ids.slice(i, i + 100);
      const q = `/api/tickets?limit=100&trashed=false&${batch.map(id => `ticket_ids=${id}`).join('&')}`;
      const t = await gorgiasRequest(cfg, q);
      const returned = new Set();
      for (const x of t.data || []) { await upsertTicket(x); returned.add(String(x.id)); }
      // ids not returned = trashed/deleted in Gorgias → no longer open; mark closed so they leave the backlog
      const gone = batch.filter(id => !returned.has(String(id)));
      if (gone.length) {
        await pool.query(`UPDATE tickets_cache SET status='closed', synced_at=now() WHERE gorgias_id = ANY($1)`, [gone]);
        changed += gone.length;
      }
      checked += batch.length;
    }
  } catch (e) { errors = String(e.message); console.error('refreshOpenTickets:', errors); }
  finally { openRefreshRunning = false; overviewCache.clear(); }
  return { checked, changed, errors };
}

async function syncGorgias(maxPages = 8) {
  if (syncRunning) return { skipped: true };
  const cfg = await getGorgiasConfig();
  if (!cfg) return { configured: false };
  syncRunning = true;
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v || {};
  if (st.data_version !== 3) { // v3: re-backfill to populate custom fields (category/model/colour/country/solved_by/ai_intent)
    st.data_version = 3; st.backfill_cursor = null; st.backfill_done = false;
  }
  let pages = 0, upserts = 0, lastError = null;
  const horizon = Date.now() - BACKFILL_HORIZON_DAYS * 864e5;

  const fetchPage = async (cursor) =>
    gorgiasRequest(cfg, `/api/tickets?limit=100&order_by=updated_datetime:desc&trashed=false${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
  const upsertRows = async (rows) => {
    for (const x of rows) { await upsertTicket(x); upserts++; }
  };

  try {
    // phase 1 — incremental: catch everything updated since the last run
    if (st.last_updated) {
      const lastUpd = Date.parse(st.last_updated);
      let cursor = null, newest = null, done = false;
      while (pages < maxPages && !done) {
        const t = await fetchPage(cursor);
        const rows = t.data || [];
        if (!rows.length) break;
        await upsertRows(rows);
        if (!newest) newest = rows[0]?.updated_datetime || null;
        pages++;
        const oldest = rows[rows.length - 1]?.updated_datetime;
        cursor = t.meta?.next_cursor;
        if (!cursor || (oldest && Date.parse(oldest) < lastUpd)) done = true;
      }
      if (newest) st.last_updated = newest;
    }

    // phase 2 — backfill: keep descending through history until the horizon, resumable across runs
    while (!st.backfill_done && pages < maxPages) {
      const t = await fetchPage(st.backfill_cursor || null);
      const rows = t.data || [];
      if (!rows.length) { st.backfill_done = true; break; }
      await upsertRows(rows);
      pages++;
      if (!st.last_updated && rows[0]?.updated_datetime && !st.backfill_cursor) {
        st.last_updated = rows[0].updated_datetime; // first ever run
      }
      const oldest = rows[rows.length - 1]?.updated_datetime;
      st.backfill_oldest = oldest || st.backfill_oldest;
      st.backfill_cursor = t.meta?.next_cursor || null;
      if (!st.backfill_cursor || (oldest && Date.parse(oldest) < horizon)) st.backfill_done = true;
    }
  } catch (e) {
    lastError = String(e.message);
    console.error('gorgias sync error:', lastError);
  } finally {
    const cached = (await pool.query('SELECT count(*)::int c FROM tickets_cache')).rows[0].c;
    await pool.query(
      `INSERT INTO sync_state (k, v) VALUES ('gorgias', $1)
       ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ ...st, last_run: new Date().toISOString(), upserts, pages, cached, last_error: lastError })])
      .catch(e => console.error('sync_state write:', e.message));
    syncRunning = false;
    overviewCache.clear();
  }
  return { configured: true, pages, upserts, backfill_done: !!st.backfill_done, backfill_oldest: st.backfill_oldest || null, error: lastError };
}

async function maybeSync() {
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v;
  const stale = !st?.last_run || Date.now() - Date.parse(st.last_run) > 15 * 60 * 1000;
  if (stale) syncGorgias(5).catch(e => console.error('sync:', e.message));
  return st;
}

// background cadence: aggressive while backfilling history, hourly once caught up
setInterval(async () => {
  try {
    const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v;
    if (st && !st.backfill_done) {
      await syncGorgias(20); // ~2,000 tickets every 5 min until history is complete
    } else if (!st?.last_run || Date.now() - Date.parse(st.last_run) > 55 * 60 * 1000) {
      await syncGorgias(8);
    }
    // keep the open backlog accurate regardless of backfill progress
    if (await getGorgiasConfig()) await refreshOpenTickets();
  } catch (e) { console.error('interval sync:', e.message); }
  try {
    const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v;
    const hasConn = await getConnector('shopify');
    if (!hasConn) return;
    if (!ss || !ss.backfill_done) {
      await syncShopify(20);
    } else if (!ss.last_run || Date.now() - Date.parse(ss.last_run) > 55 * 60 * 1000) {
      await syncShopify(8);
    }
  } catch (e) { console.error('interval shopify sync:', e.message); }
  try {
    const ps = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify_products'`)).rows[0]?.v;
    if (await getConnector('shopify') && (!ps?.last_run || Date.now() - Date.parse(ps.last_run) > 24 * 3600 * 1000)) {
      await syncShopifyProducts(); // product images change rarely — daily is plenty
    }
  } catch (e) { console.error('interval product sync:', e.message); }
  // UK stock is now owned/edited inside clicks-brain — no auto-sync so admin edits aren't overwritten.
  // Admins can still trigger a one-time re-import from clicks_ruk via POST /api/stock/sync.
  try {
    const ks = (await pool.query(`SELECT v FROM sync_state WHERE k='klaviyo'`)).rows[0]?.v;
    if (await getConnector('klaviyo') && (!ks?.last_run || Date.now() - Date.parse(ks.last_run) > 55 * 60 * 1000)) {
      await syncKlaviyo();
      await notifyNewCampaigns();
    }
  } catch (e) { console.error('interval klaviyo sync:', e.message); }
  try {
    const rs = (await pool.query(`SELECT v FROM sync_state WHERE k='redo'`)).rows[0]?.v;
    if (await getConnector('redo')) {
      if (!rs || !rs.backfill_done) await syncRedo(10);
      else if (!rs.last_run || Date.now() - Date.parse(rs.last_run) > 55 * 60 * 1000) await syncRedo(6);
    }
  } catch (e) { console.error('interval redo sync:', e.message); }
  try {
    const sb = (await pool.query(`SELECT v FROM sync_state WHERE k='shipbob'`)).rows[0]?.v;
    if (await getConnector('shipbob') && (!sb?.last_run || Date.now() - Date.parse(sb.last_run) > 55 * 60 * 1000)) {
      await syncShipbob();
    }
  } catch (e) { console.error('interval shipbob sync:', e.message); }
  try {
    const fs = (await pool.query(`SELECT v FROM sync_state WHERE k='floship'`)).rows[0]?.v;
    if (await getConnector('floship') && (!fs?.last_run || Date.now() - Date.parse(fs.last_run) > 55 * 60 * 1000)) {
      await syncFloship();
    }
  } catch (e) { console.error('interval floship sync:', e.message); }
}, 5 * 60 * 1000);

async function bootSync() {
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v;
  const c = (await pool.query('SELECT count(*)::int c FROM tickets_cache')).rows[0].c;
  if (c === 0 || !st?.backfill_done) {
    console.log('starting sync (cache:', c, 'backfill_done:', !!st?.backfill_done, ')');
    const r = await syncGorgias(30);
    console.log('boot sync:', JSON.stringify(r));
  }
}

app.post('/api/gorgias/sync', async (_req, res) => {
  try {
    const r = await syncGorgias(50);
    const open = await refreshOpenTickets(); // re-verify open set right away
    res.json({ ...r, open_refresh: open });
  } catch (e) { res.status(502).json({ error: e.message }); }
});
// admin debug: dump a recent ticket's raw shape so we can locate custom fields (Model, Colour, etc.)
app.get('/api/gorgias/debug', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const cfg = await getGorgiasConfig();
  if (!cfg) return res.status(400).json({ error: 'Gorgias not connected' });
  try {
    const t = await gorgiasRequest(cfg, `/api/tickets?limit=3&order_by=updated_datetime:desc&trashed=false`);
    // strip the heavy bits so the custom-field structure is easy to read
    const slim = (x) => { const { messages, events, ...rest } = x || {}; return rest; };
    const sample = (t.data || []).map(slim);
    const keys = sample[0] ? Object.keys(sample[0]) : [];
    // also try the dedicated custom-fields endpoints if they exist on this plan
    let customFieldDefs = null, ticketFieldVals = null;
    try { customFieldDefs = await gorgiasRequest(cfg, `/api/custom-fields?limit=30`); } catch (e) { customFieldDefs = { error: e.message }; }
    try { if (sample[0]) ticketFieldVals = await gorgiasRequest(cfg, `/api/tickets/${sample[0].id}/custom-fields`); } catch (e) { ticketFieldVals = { error: e.message }; }
    res.json({ ticket_top_level_keys: keys, sample_tickets: sample, custom_field_defs: customFieldDefs, ticket_field_values: ticketFieldVals });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// cancellation & refund ticket tracker (from Gorgias custom fields), with timeframe + field-capture + resolution
app.get('/api/gorgias/cancel-refund', async (req, res) => {
  try {
    const win = resolveWindow(req.query);
    const p = [win.start.toISOString(), win.end.toISOString()];
    const captured = c => `count(*) FILTER (WHERE ${c} <> '' AND ${c} !~* 'other')::int`;
    const group = async (matchSql) => {
      const base = `FROM tickets_cache WHERE NOT spam AND created_datetime >= $1 AND created_datetime < $2 AND (${matchSql})`;
      const totals = (await pool.query(
        `SELECT count(*)::int total, ${captured('cf_model')} with_model, ${captured('cf_colour')} with_colour,
          ${captured('cf_category')} with_category, ${captured('cf_country')} with_country, ${captured('cf_solved_by')} with_solved ${base}`, p)).rows[0];
      const resolutions = (await pool.query(
        `SELECT coalesce(nullif(cf_solved_by,''),'(not set)') solved_by, count(*)::int c ${base} GROUP BY 1 ORDER BY 2 DESC`, p)).rows;
      const variants = (await pool.query(
        `SELECT cf_model model, count(*)::int c ${base} AND cf_model <> '' AND cf_model !~* 'other'
         GROUP BY 1 ORDER BY 2 DESC LIMIT 15`, p)).rows;
      return { ...totals, resolutions, variants };
    };
    // Category encodes the intent; AI Intent is the fallback signal
    const cancel = await group(`cf_category ILIKE '%cancellation%' OR cf_ai_intent ILIKE 'Order::Cancel%'`);
    const refund = await group(`cf_category ILIKE '%refund%' OR cf_ai_intent ILIKE 'Order::Refund%'`);
    res.json({ days: win.days, custom: win.custom, from: p[0], to: p[1], cancel, refund });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Redo (returns) ----------
async function redoRequest(cfg, pathAndQuery, pageHeaders = {}) {
  const r = await fetch(`https://api.getredo.com/v2.2${pathAndQuery}`, {
    headers: { Authorization: `Bearer ${cfg.api_secret}`, Accept: 'application/json', ...pageHeaders }
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Redo ${pathAndQuery.split('?')[0]} → ${r.status}: ${(j.detail || j.title || '').slice(0, 200)}`);
  return { data: j, next: r.headers.get('x-page-next') || null };
}
const moneyNum = (m) => { const v = parseFloat(m?.amount ?? m); return Number.isFinite(v) ? v : 0; };

async function upsertRedoReturn(x) {
  await pool.query(
    `INSERT INTO returns_cache (redo_id, order_name, type, status, created_at, updated_at, refund, exchange_value, store_credit, items, return_tags, synced_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
     ON CONFLICT (redo_id) DO UPDATE SET order_name=$2, type=$3, status=$4, created_at=$5, updated_at=$6,
       refund=$7, exchange_value=$8, store_credit=$9, items=$10, return_tags=$11, synced_at=now()`,
    [x.id, x.order?.name || '', x.type || 'return', x.status || '',
     x.createdAt || null, x.updatedAt || null,
     moneyNum(x.totals?.refund?.amount), moneyNum(x.totals?.exchange?.amount), moneyNum(x.totals?.storeCredit?.amount),
     JSON.stringify((x.items || []).map(i => ({ sku: i.sku || '', qty: i.quantity || 1, reason: i.reason || '', green: !!i.greenReturn }))),
     JSON.stringify((x.tags || []).map(t => t.name))]);
}

let redoSyncRunning = false;
async function syncRedo(maxPages = 6) {
  if (redoSyncRunning) return { skipped: true };
  const conn = await getConnector('redo');
  if (!conn) return { configured: false };
  const cfg = conn.config;
  redoSyncRunning = true;
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='redo'`)).rows[0]?.v || {};
  let pages = 0, upserts = 0, lastError = null;
  const horizon = Date.now() - BACKFILL_HORIZON_DAYS * 864e5;
  try {
    // incremental: everything updated since last run
    if (st.last_updated) {
      let cursor = null, newest = st.last_updated;
      while (pages < maxPages) {
        const { data, next } = await redoRequest(cfg,
          `/stores/${cfg.store_id}/returns?updated_at_min=${encodeURIComponent(st.last_updated)}`,
          { 'X-Page-Size': '100', ...(cursor ? { 'X-Page-Continue': cursor } : {}) });
        const rows = data.returns || [];
        if (!rows.length) break;
        for (const x of rows) { await upsertRedoReturn(x); upserts++; if (x.updatedAt > newest) newest = x.updatedAt; }
        pages++;
        cursor = next;
        if (!cursor) break;
      }
      st.last_updated = newest;
    }
    // backfill history to the horizon, resumable
    while (!st.backfill_done && pages < maxPages) {
      const { data, next } = await redoRequest(cfg, `/stores/${cfg.store_id}/returns`,
        { 'X-Page-Size': '100', ...(st.backfill_cursor ? { 'X-Page-Continue': st.backfill_cursor } : {}) });
      const rows = data.returns || [];
      if (!rows.length) { st.backfill_done = true; break; }
      for (const x of rows) { await upsertRedoReturn(x); upserts++; }
      pages++;
      if (!st.last_updated) st.last_updated = new Date().toISOString();
      const oldest = rows[rows.length - 1]?.createdAt;
      st.backfill_oldest = oldest || st.backfill_oldest;
      st.backfill_cursor = next;
      if (!next || (oldest && Date.parse(oldest) < horizon)) st.backfill_done = true;
    }
  } catch (e) {
    lastError = String(e.message);
    console.error('redo sync:', lastError);
  } finally {
    const cached = (await pool.query('SELECT count(*)::int c FROM returns_cache')).rows[0].c;
    await pool.query(`INSERT INTO sync_state (k, v) VALUES ('redo', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ ...st, last_run: new Date().toISOString(), upserts, pages, cached, last_error: lastError })])
      .catch(() => {});
    redoSyncRunning = false;
    overviewCache.clear();
  }
  return { configured: true, pages, upserts, backfill_done: !!st.backfill_done, error: lastError };
}

// Shopify product images (sku → featured image + title), refreshed daily
let productSyncRunning = false;
async function syncShopifyProducts() {
  if (productSyncRunning) return { skipped: true };
  const conn = await getConnector('shopify');
  if (!conn) return { configured: false };
  const cfg = conn.config;
  productSyncRunning = true;
  let cursor = null, pages = 0, upserts = 0, lastError = null;
  const Q = `query P($cursor:String){ products(first:50, after:$cursor){ pageInfo{hasNextPage endCursor}
    nodes{ title featuredImage{url} variants(first:100){ nodes{ sku title selectedOptions{ name value } } } } } }`;
  try {
    while (pages < 40) {
      const d = await shopifyGraphql(cfg, Q, { cursor });
      const nodes = d.products?.nodes || [];
      for (const p of nodes) {
        const img = p.featuredImage?.url || null;
        for (const v of p.variants?.nodes || []) {
          if (!v.sku) continue;
          // variant descriptor: prefer selectedOptions (e.g. "Blue", "Pro") skipping Shopify's default "Title";
          // fall back to the variant title unless it's the placeholder "Default Title"
          const opts = (v.selectedOptions || [])
            .filter(o => o.name && o.name.toLowerCase() !== 'title' && o.value && o.value.toLowerCase() !== 'default title')
            .map(o => o.value);
          let variant = opts.join(' · ');
          if (!variant && v.title && v.title.toLowerCase() !== 'default title') variant = v.title;
          await pool.query(
            `INSERT INTO product_images (sku, title, variant_title, image_url, updated_at) VALUES ($1,$2,$3,$4,now())
             ON CONFLICT (sku) DO UPDATE SET title=$2, variant_title=$3, image_url=$4, updated_at=now()`,
            [v.sku, (p.title || '').slice(0, 300), (variant || '').slice(0, 200), img]);
          upserts++;
        }
      }
      pages++;
      if (!d.products?.pageInfo?.hasNextPage) break;
      cursor = d.products.pageInfo.endCursor;
    }
  } catch (e) { lastError = String(e.message); console.error('product image sync:', lastError); }
  finally {
    await pool.query(`INSERT INTO sync_state (k, v) VALUES ('shopify_products', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ last_run: new Date().toISOString(), upserts, last_error: lastError })]).catch(() => {});
    productSyncRunning = false;
  }
  return { upserts, error: lastError };
}

// product picker: list of returned products + per-product return detail
app.get('/api/redo/products', async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT i->>'sku' sku, count(*)::int returns FROM returns_cache, LATERAL jsonb_array_elements(items) i
    WHERE created_at >= now()-interval '365 days' AND coalesce(i->>'sku','') <> '' GROUP BY 1 ORDER BY 2 DESC`);
  const skus = rows.map(r => r.sku);
  const names = skus.length ? (await pool.query(
    `SELECT sku, coalesce(us.name, pi.title) name, nullif(pi.variant_title,'') variant FROM unnest($1::text[]) sku
     LEFT JOIN product_images pi USING (sku) LEFT JOIN uk_stock us USING (sku)`, [skus])).rows : [];
  const nameMap = Object.fromEntries(names.map(n => [n.sku, n]));
  res.json(rows.map(r => ({ sku: r.sku, returns: r.returns,
    name: nameMap[r.sku]?.name || null, variant: nameMap[r.sku]?.variant || null })));
});
app.get('/api/redo/product', async (req, res) => {
  const sku = String(req.query.sku || '');
  if (!sku) return res.status(400).json({ error: 'sku required' });
  const [meta, reasons, total] = await Promise.all([
    pool.query(`SELECT pi.title p_title, nullif(pi.variant_title,'') variant, pi.image_url, us.name us_name FROM (SELECT $1::text sku) x
                LEFT JOIN product_images pi ON pi.sku=x.sku LEFT JOIN uk_stock us ON us.sku=x.sku`, [sku]),
    pool.query(`SELECT coalesce(nullif(i->>'reason',''),'(no reason)') reason, count(*)::int c
                FROM returns_cache, LATERAL jsonb_array_elements(items) i
                WHERE i->>'sku'=$1 AND created_at >= now()-interval '365 days' GROUP BY 1 ORDER BY 2 DESC`, [sku]),
    pool.query(`SELECT count(*)::int c FROM returns_cache, LATERAL jsonb_array_elements(items) i
                WHERE i->>'sku'=$1 AND created_at >= now()-interval '365 days'`, [sku])
  ]);
  const m = meta.rows[0] || {};
  res.json({ sku, name: m.us_name || m.p_title || sku, variant: m.variant || null, image: m.image_url || null,
    total: total.rows[0].c, reasons: reasons.rows });
});

app.get('/api/redo/summary', async (_req, res) => {
  try {
    const conn = await getConnector('redo');
    const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='redo'`)).rows[0]?.v || null;
    const has = (await pool.query('SELECT 1 FROM returns_cache LIMIT 1')).rows.length > 0;
    if (!has) return res.json({ configured: !!conn, empty: true, sync: ss });
    const [tot, reasons, statuses, recent] = await Promise.all([
      pool.query(`SELECT count(*)::int returns,
        count(*) FILTER (WHERE type='claim')::int claims,
        count(*) FILTER (WHERE type='warranty')::int warranties,
        round(coalesce(sum(refund),0))::int refund_total,
        round(coalesce(sum(exchange_value),0))::int exchange_total,
        round(coalesce(sum(store_credit),0))::int credit_total
        FROM returns_cache WHERE created_at >= now()-interval '30 days'`),
      pool.query(`SELECT coalesce(nullif(i->>'reason',''),'(no reason)') reason, count(*)::int c
        FROM returns_cache, LATERAL jsonb_array_elements(items) i
        WHERE created_at >= now()-interval '30 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 8`),
      pool.query(`SELECT status, count(*)::int c FROM returns_cache
        WHERE status NOT IN ('complete','rejected','deleted') GROUP BY 1 ORDER BY 2 DESC`),
      pool.query(`SELECT redo_id, order_name, type, status, created_at::date d, refund, exchange_value, store_credit, items, return_tags
        FROM returns_cache ORDER BY created_at DESC NULLS LAST LIMIT 12`)
    ]);

    // cross-source cards — isolated so a failure here never breaks the rest of the tab
    const hasSales = (await pool.query('SELECT 1 FROM orders_cache LIMIT 1')).rows.length > 0;
    let leakage = null, defects = null, extraError = null;
    if (hasSales) {
      try {
        const [rev, ref] = await Promise.all([
          pool.query(`SELECT to_char(date_trunc('month',created_at),'YYYY-MM') mon, round(sum(total_price))::int revenue
                      FROM orders_cache WHERE cancelled_at IS NULL AND created_at >= now()-interval '6 months' GROUP BY 1`),
          pool.query(`SELECT to_char(date_trunc('month',created_at),'YYYY-MM') mon, round(sum(refund))::int refunded
                      FROM returns_cache WHERE created_at >= now()-interval '6 months' GROUP BY 1`)
        ]);
        const revMap = Object.fromEntries(rev.rows.map(r => [r.mon, r.revenue]));
        const refMap = Object.fromEntries(ref.rows.map(r => [r.mon, r.refunded]));
        const months = [...new Set([...Object.keys(revMap), ...Object.keys(refMap)])].sort();
        leakage = months.map(mon => {
          const revenue = revMap[mon] || 0, refunded = refMap[mon] || 0;
          return { month: mon, revenue, refunded, pct: revenue > 0 ? Math.round(refunded / revenue * 1000) / 10 : null };
        });

        // return reason × product (90d): why each product comes back.
        // name resolves from UK stock catalog first (richest per-SKU detail), then Shopify title.
        var reasonByProduct = (await pool.query(`
          SELECT rr.sku, coalesce(s.name, sh.title) name, nullif(pi.variant_title,'') variant, rr.reason, rr.c FROM (
            SELECT coalesce(nullif(i->>'sku',''),'(no sku)') sku, coalesce(nullif(i->>'reason',''),'(no reason)') reason, count(*)::int c
            FROM returns_cache, LATERAL jsonb_array_elements(items) i
            WHERE created_at >= now()-interval '90 days' GROUP BY 1,2
          ) rr
          LEFT JOIN uk_stock s ON s.sku = rr.sku
          LEFT JOIN product_images pi ON pi.sku = rr.sku
          LEFT JOIN (SELECT it->>'sku' sku, max(it->>'title') title FROM orders_cache, LATERAL jsonb_array_elements(items) it
                     WHERE coalesce(it->>'sku','') <> '' GROUP BY 1) sh ON sh.sku = rr.sku
          ORDER BY rr.c DESC LIMIT 25`)).rows;

        defects = (await pool.query(`
          WITH sold AS (
            SELECT it->>'sku' sku, max(it->>'title') title, sum(coalesce((it->>'qty')::int,0))::int units
            FROM orders_cache, LATERAL jsonb_array_elements(items) it
            WHERE created_at >= now()-interval '90 days' AND cancelled_at IS NULL AND coalesce(it->>'sku','') <> ''
            GROUP BY 1),
          returned AS (
            SELECT i->>'sku' sku, sum(coalesce((i->>'qty')::int,1))::int units
            FROM returns_cache, LATERAL jsonb_array_elements(items) i
            WHERE created_at >= now()-interval '90 days' AND coalesce(i->>'sku','') <> ''
            GROUP BY 1)
          SELECT s.sku, coalesce(us.name, s.title) title, nullif(pi.variant_title,'') variant, s.units sold, coalesce(r.units,0) returned,
            round(coalesce(r.units,0)::numeric / nullif(s.units,0) * 1000)/10 return_pct
          FROM sold s
          LEFT JOIN returned r ON r.sku = s.sku
          LEFT JOIN uk_stock us ON us.sku = s.sku
          LEFT JOIN product_images pi ON pi.sku = s.sku
          WHERE s.units >= 20 ORDER BY return_pct DESC NULLS LAST LIMIT 15`)).rows;
      } catch (e) { extraError = String(e.message); console.error('redo cross-source:', extraError); }
    }

    const currency = (await pool.query(`SELECT max(currency) c FROM orders_cache WHERE currency <> ''`)).rows[0]?.c || 'USD';
    res.json({ configured: true, totals_30d: tot.rows[0], top_reasons: reasons.rows, open_by_status: statuses.rows,
      recent: recent.rows, leakage, defects, reason_by_product: (typeof reasonByProduct !== 'undefined' ? reasonByProduct : null),
      currency, extra_error: extraError, sync: ss });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/redo/sync', async (_req, res) => {
  try { res.json(await syncRedo(20)); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- Klaviyo (campaigns + attribution) ----------
const KLAVIYO_REVISION = process.env.KLAVIYO_REVISION || '2025-04-15';
async function klaviyoRequest(cfg, pathAndQuery, opts = {}) {
  let r, j;
  for (let attempt = 0; attempt < 4; attempt++) {
    r = await fetch(`https://a.klaviyo.com${pathAndQuery}`, {
      ...opts,
      headers: {
        Authorization: `Klaviyo-API-Key ${cfg.api_key}`,
        revision: KLAVIYO_REVISION,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(opts.headers || {})
      }
    });
    if (r.status !== 429) break;
    const wait = Math.min(parseInt(r.headers.get('retry-after')) || (attempt + 1) * 12, 60);
    await new Promise(res => setTimeout(res, wait * 1000)); // respect Klaviyo's throttle
  }
  j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Klaviyo ${pathAndQuery.split('?')[0]} → ${r.status}: ${(j.errors || []).map(e => e.detail).join('; ').slice(0, 200)}`);
  return j;
}

let klaviyoSyncRunning = false;
async function syncKlaviyo() {
  if (klaviyoSyncRunning) return { skipped: true };
  const conn = await getConnector('klaviyo');
  if (!conn) return { configured: false };
  klaviyoSyncRunning = true;
  const cfg = conn.config;
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='klaviyo'`)).rows[0]?.v || {};
  let campaigns = 0, statsApplied = 0;
  try {
    // conversion metric (Placed Order) for revenue attribution — resolved once
    if (!st.conversion_metric_id) {
      let url = '/api/metrics/';
      for (let p = 0; p < 5 && url; p++) {
        const m = await klaviyoRequest(cfg, url);
        const hit = (m.data || []).find(x => x.attributes?.name === 'Placed Order');
        if (hit) { st.conversion_metric_id = hit.id; break; }
        url = m.links?.next ? m.links.next.replace('https://a.klaviyo.com', '') : null;
      }
    }
    // campaigns per channel
    for (const channel of ['email', 'sms']) {
      let url = `/api/campaigns/?filter=equals(messages.channel,'${channel}')&sort=-scheduled_at`;
      for (let p = 0; p < 5 && url; p++) {
        const res = await klaviyoRequest(cfg, url);
        for (const c of res.data || []) {
          const a = c.attributes || {};
          await pool.query(
            `INSERT INTO campaigns_cache (klaviyo_id, name, channel, status, send_time, synced_at)
             VALUES ($1,$2,$3,$4,$5,now())
             ON CONFLICT (klaviyo_id) DO UPDATE SET name=$2, channel=$3, status=$4, send_time=$5, synced_at=now()`,
            [c.id, (a.name || '').slice(0, 300), channel, a.status || '', a.send_time || a.scheduled_at || null]);
          campaigns++;
        }
        url = res.links?.next ? res.links.next.replace('https://a.klaviyo.com', '') : null;
      }
    }
    // performance stats (best effort — requires the conversion metric).
    if (st.conversion_metric_id) {
      const stats = ['recipients', 'opens', 'open_rate', 'clicks', 'click_rate', 'conversion_value',
                     'unsubscribe_rate', 'spam_complaint_rate', 'bounce_rate'];
      const applyResults = async (results) => {
        // group_by default is campaign_id+campaign_message_id+send_channel, so a campaign can span
        // several rows (A/B variations, multi-message) — accumulate per campaign_id.
        // Rates come from Klaviyo directly (recipient-weighted), never recomputed from total opens.
        const byCampaign = {};
        for (const row of results || []) {
          const id = row.groupings?.campaign_id; if (!id) continue;
          const s = row.statistics || {};
          const rec = s.recipients || 0;
          const a = byCampaign[id] || (byCampaign[id] = { recipients: 0, opens: 0, clicks: 0, revenue: 0, orW: 0, crW: 0, unsW: 0, spamW: 0, bncW: 0 });
          a.recipients += rec; a.opens += s.opens || 0; a.clicks += s.clicks || 0; a.revenue += s.conversion_value || 0;
          a.orW += (s.open_rate || 0) * rec; a.crW += (s.click_rate || 0) * rec;
          a.unsW += (s.unsubscribe_rate || 0) * rec; a.spamW += (s.spam_complaint_rate || 0) * rec; a.bncW += (s.bounce_rate || 0) * rec;
        }
        for (const [id, a] of Object.entries(byCampaign)) {
          const w = (x) => a.recipients ? x / a.recipients : null;
          await pool.query(
            `UPDATE campaigns_cache SET recipients=$2, opens=$3, open_rate=$4, clicks=$5, click_rate=$6, revenue=$7,
               unsub_rate=$8, spam_rate=$9, bounce_rate=$10, synced_at=now() WHERE klaviyo_id=$1`,
            [id, a.recipients, a.opens, w(a.orW), a.clicks, w(a.crW), a.revenue, w(a.unsW), w(a.spamW), w(a.bncW)]);
          statsApplied++;
        }
        return Object.keys(byCampaign);
      };
      const runReport = async (filter) => {
        const rep = await klaviyoRequest(cfg, '/api/campaign-values-reports/', {
          method: 'POST',
          body: JSON.stringify({ data: { type: 'campaign-values-report', attributes: {
            timeframe: { key: 'last_365_days' }, conversion_metric_id: st.conversion_metric_id,
            statistics: stats, ...(filter ? { filter } : {}) } } })
        });
        await applyResults(rep.data?.attributes?.results);
      };
      await runReport(null); // single whole-account pass — the report returns every campaign in one page
    }
    // email content (subject/preview + template body) for recent campaigns, a few per run
    const need = await pool.query(
      `SELECT klaviyo_id FROM campaigns_cache WHERE subject IS NULL ORDER BY send_time DESC NULLS LAST LIMIT 10`);
    for (const row of need.rows) {
      try {
        const msgs = await klaviyoRequest(cfg, `/api/campaigns/${row.klaviyo_id}/campaign-messages`);
        const msg = msgs.data?.[0];
        const content = msg?.attributes?.definition?.content || msg?.attributes?.content || {};
        let html = null, textBody = null;
        if (msg) {
          try {
            const tpl = await klaviyoRequest(cfg, `/api/campaign-messages/${msg.id}/template`);
            html = tpl.data?.attributes?.html || null;
            textBody = tpl.data?.attributes?.text || null;
          } catch (e) { console.error('template fetch (need templates:read scope?):', e.message); }
        }
        await pool.query(
          `UPDATE campaigns_cache SET subject=$2, preview=$3, from_email=$4, html=$5, text_body=$6 WHERE klaviyo_id=$1`,
          [row.klaviyo_id, content.subject || '', content.preview_text || '', content.from_email || '', html, textBody]);
      } catch (e) { console.error('campaign content', row.klaviyo_id, e.message); }
    }
    // flows: automated series (welcome, abandoned cart, win-back...) — names + performance
    try {
      const names = {};
      let url = '/api/flows/';
      for (let p = 0; p < 5 && url; p++) {
        const f = await klaviyoRequest(cfg, url);
        for (const fl of f.data || []) names[fl.id] = { name: fl.attributes?.name || '', status: fl.attributes?.status || '' };
        url = f.links?.next ? f.links.next.replace('https://a.klaviyo.com', '') : null;
      }
      if (st.conversion_metric_id) {
        const rep = await klaviyoRequest(cfg, '/api/flow-values-reports/', {
          method: 'POST',
          body: JSON.stringify({ data: { type: 'flow-values-report', attributes: {
            timeframe: { key: 'last_365_days' }, conversion_metric_id: st.conversion_metric_id,
            statistics: ['recipients', 'open_rate', 'click_rate', 'conversion_value'] } } })
        });
        const byFlow = {};
        for (const row of rep.data?.attributes?.results || []) {
          const id = row.groupings?.flow_id; if (!id) continue;
          const s = row.statistics || {}; const rec = s.recipients || 0;
          const a = byFlow[id] || (byFlow[id] = { recipients: 0, revenue: 0, orW: 0, crW: 0, channel: row.groupings?.send_channel || '' });
          a.recipients += rec; a.revenue += s.conversion_value || 0;
          a.orW += (s.open_rate || 0) * rec; a.crW += (s.click_rate || 0) * rec;
        }
        for (const [id, a] of Object.entries(byFlow)) {
          await pool.query(
            `INSERT INTO flows_cache (flow_id, name, status, channel, recipients, open_rate, click_rate, revenue, synced_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
             ON CONFLICT (flow_id) DO UPDATE SET name=$2, status=$3, channel=$4, recipients=$5, open_rate=$6, click_rate=$7, revenue=$8, synced_at=now()`,
            [id, names[id]?.name || '', names[id]?.status || '', a.channel,
             a.recipients, a.recipients ? a.orW / a.recipients : null, a.recipients ? a.crW / a.recipients : null, a.revenue]);
        }
      }
    } catch (e) { console.error('klaviyo flows:', e.message); }

    st.last_error = null;
  } catch (e) {
    st.last_error = String(e.message);
    console.error('klaviyo sync:', st.last_error);
  }
  st.last_run = new Date().toISOString();
  st.campaigns = campaigns; st.stats_applied = statsApplied;
  await pool.query(`INSERT INTO sync_state (k, v) VALUES ('klaviyo', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
    [JSON.stringify(st)]).catch(() => {});
  overviewCache.clear();
  klaviyoSyncRunning = false;
  return { configured: true, campaigns, stats_applied: statsApplied, error: st.last_error };
}

app.get('/api/klaviyo/summary', async (_req, res) => {
  const conn = await getConnector('klaviyo');
  const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='klaviyo'`)).rows[0]?.v || null;
  const [totals, recent] = await Promise.all([
    pool.query(`SELECT count(*)::int campaigns,
      round(avg(open_rate) FILTER (WHERE open_rate IS NOT NULL) * 100)::int avg_open_pct,
      round(avg(click_rate) FILTER (WHERE click_rate IS NOT NULL) * 100)::int avg_click_pct,
      round(coalesce(sum(revenue),0))::int revenue
      FROM campaigns_cache WHERE send_time >= now()-interval '30 days'`),
    pool.query(`SELECT c.klaviyo_id, c.name, c.channel, c.status, c.send_time, c.recipients, c.open_rate, c.click_rate, c.revenue, c.unsub_rate,
      CASE WHEN length(coalesce(c.subject,'')) >= 6 THEN
        (SELECT count(*)::int FROM tickets_cache t
         WHERE strpos(lower(t.subject), lower(c.subject)) > 0
           AND t.created_datetime >= c.send_time AND t.created_datetime < c.send_time + interval '21 days')
      END tickets_created,
      CASE WHEN length(coalesce(c.subject,'')) >= 6 THEN
        (SELECT count(*)::int FROM tickets_cache t
         WHERE strpos(lower(t.subject), lower(c.subject)) > 0
           AND t.created_datetime >= c.send_time AND t.created_datetime < c.send_time + interval '21 days'
           AND t.status = 'closed')
      END tickets_closed
      FROM campaigns_cache c WHERE c.send_time IS NOT NULL ORDER BY c.send_time DESC LIMIT 20`)
  ]);
  // email's share of total revenue (Klaviyo attributed ÷ Shopify revenue, 30d)
  let revenue_share = null;
  try {
    const kv = totals.rows[0]?.revenue || 0;
    const shop = (await pool.query(`SELECT round(coalesce(sum(total_price),0))::int r FROM orders_cache
      WHERE cancelled_at IS NULL AND created_at >= now()-interval '30 days'`)).rows[0]?.r || 0;
    if (shop > 0) revenue_share = { klaviyo: kv, shopify: shop, pct: Math.round(kv / shop * 1000) / 10 };
  } catch {}
  const flows = (await pool.query(
    `SELECT name, status, channel, recipients, open_rate, click_rate, revenue FROM flows_cache
     WHERE coalesce(recipients,0) > 0 ORDER BY revenue DESC NULLS LAST LIMIT 15`)).rows;
  const currency = (await pool.query(`SELECT max(currency) c FROM orders_cache WHERE currency <> ''`)).rows[0]?.c || 'USD';
  res.json({ configured: !!conn, totals_30d: totals.rows[0], recent: recent.rows, revenue_share, flows, currency, sync: ss });
});
app.get('/api/klaviyo/campaign/:id', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT klaviyo_id, name, channel, send_time, subject, preview, from_email, html, text_body,
     recipients, open_rate, click_rate, revenue FROM campaigns_cache WHERE klaviyo_id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});
// diagnostic (admin): what does Klaviyo's report return for the campaigns still missing stats?
app.get('/api/klaviyo/debug', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  try {
    const conn = await getConnector('klaviyo');
    if (!conn) return res.json({ error: 'not connected' });
    const cfg = conn.config;
    const st = (await pool.query(`SELECT v FROM sync_state WHERE k='klaviyo'`)).rows[0]?.v || {};
    const blank = (await pool.query(
      `SELECT klaviyo_id, name FROM campaigns_cache WHERE recipients IS NULL AND send_time IS NOT NULL ORDER BY send_time DESC LIMIT 3`)).rows;
    const out = { conversion_metric_id: st.conversion_metric_id || null, blank_sample: blank };
    // single isolated report call using the EXACT sync request, then write the results directly.
    // If this populates the campaigns, the sync logic is correct and the failure was rate-limit competition.
    try {
      const rep = await klaviyoRequest(cfg, '/api/campaign-values-reports/', {
        method: 'POST',
        body: JSON.stringify({ data: { type: 'campaign-values-report', attributes: {
          timeframe: { key: 'last_12_months' }, conversion_metric_id: st.conversion_metric_id,
          statistics: ['recipients', 'opens', 'open_rate', 'clicks', 'click_rate', 'conversion_value'] } } })
      });
      const results = rep.data?.attributes?.results || [];
      const byCampaign = {};
      for (const row of results) {
        const id = row.groupings?.campaign_id; if (!id) continue;
        const s = row.statistics || {}; const rec = s.recipients || 0;
        const a = byCampaign[id] || (byCampaign[id] = { recipients: 0, opens: 0, clicks: 0, revenue: 0, orW: 0, crW: 0 });
        a.recipients += rec; a.opens += s.opens || 0; a.clicks += s.clicks || 0; a.revenue += s.conversion_value || 0;
        a.orW += (s.open_rate || 0) * rec; a.crW += (s.click_rate || 0) * rec;
      }
      let written = 0;
      for (const [id, a] of Object.entries(byCampaign)) {
        const r = await pool.query(
          `UPDATE campaigns_cache SET recipients=$2, opens=$3, open_rate=$4, clicks=$5, click_rate=$6, revenue=$7, synced_at=now() WHERE klaviyo_id=$1`,
          [id, a.recipients, a.opens, a.recipients ? a.orW / a.recipients : null, a.clicks, a.recipients ? a.crW / a.recipients : null, a.revenue]);
        written += r.rowCount;
      }
      overviewCache.clear();
      out.total_rows = results.length;
      out.rows_written = written;
      out.blank_now_filled = blank.map(c => ({ name: c.name, campaign_in_report: !!byCampaign[c.klaviyo_id] }));
    } catch (e) { out.error = String(e.message); }
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/klaviyo/sync', async (_req, res) => {
  try { const r = await syncKlaviyo(); res.json(r); notifyNewCampaigns(); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- UK stock (simple keyed JSON API) ----------
async function ukStockFetch(cfg) {
  let url;
  try { url = new URL(String(cfg.base_url).trim()); } catch { throw new Error(`invalid URL "${cfg.base_url}" — it must look like https://clicks-uk-returns.onrender.com/api/v1/stock`); }
  if (!/^https?:$/.test(url.protocol)) throw new Error('URL must start with https://');
  // the stock service sleeps on Render's free tier — retry through cold-start 502/503s and transient network errors
  let lastErr = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt) await new Promise(r => setTimeout(r, 8000));
    let r;
    try {
      r = await fetch(url, { headers: { 'X-API-Key': cfg.api_key, Accept: 'application/json' } });
    } catch (e) {
      const code = e.cause?.code || e.cause?.message || e.message;
      lastErr = `network error reaching ${url.hostname}: ${code}${code === 'ENOTFOUND' ? ' (domain not found — check the URL for typos)' : ''}`;
      continue; // transient network issues get retried too
    }
    if (r.ok) return r.json();
    lastErr = `UK stock API → ${r.status}${[502, 503, 504].includes(r.status) ? ' (service may be waking from sleep — try again in ~1 min)' : ''}`;
    if (![502, 503, 504].includes(r.status)) break; // real error (401/403/404) — don't retry
  }
  throw new Error(lastErr || 'unreachable');
}
const pickField = (o, keys) => { for (const k of keys) { if (o?.[k] != null) return o[k]; } return null; };
function extractStockItems(j) {
  if (Array.isArray(j)) return j;
  for (const k of ['items', 'stock', 'data', 'products', 'results', 'inventory']) {
    if (Array.isArray(j?.[k])) return j[k];
  }
  return null;
}

async function syncUkStock() {
  const conn = await getConnector('uk_stock');
  if (!conn) return { configured: false };
  const st = {};
  try {
    const j = await ukStockFetch(conn.config);
    const items = extractStockItems(j);
    if (!items) throw new Error(`unrecognized response shape — top-level keys: ${Object.keys(j || {}).slice(0, 10).join(', ')}`);
    let upserts = 0;
    const num = (v) => Number.isFinite(+v) ? Math.trunc(+v) : null;
    for (const it of items) {
      const sku = String(pickField(it, ['sku', 'SKU', 'code', 'product_code', 'id', 'product_id']) ?? '').slice(0, 100);
      if (!sku) continue;
      const name = String(pickField(it, ['description', 'name', 'title', 'product', 'product_name']) ?? '').slice(0, 300);
      const upc = String(pickField(it, ['upc', 'UPC', 'barcode', 'ean']) ?? '').slice(0, 50);
      const brandNew = num(pickField(it, ['brand_new', 'brandNew', 'brand new', 'new']));
      const nonPristine = num(pickField(it, ['non_pristine', 'nonPristine', 'non-pristine', 'non pristine']));
      const damaged = num(pickField(it, ['damaged']));
      const founders = num(pickField(it, ['founders', 'founder']));
      let qty = num(pickField(it, ['total', 'TOTAL', 'qty', 'quantity', 'stock', 'available', 'count', 'units', 'on_hand', 'level']));
      if (qty == null) {
        const parts = [brandNew, nonPristine, damaged, founders].filter(x => x != null);
        if (parts.length) qty = parts.reduce((a, b) => a + b, 0);
      }
      const prev = (await pool.query('SELECT qty FROM uk_stock WHERE sku=$1', [sku])).rows[0];
      await pool.query(
        `INSERT INTO uk_stock (sku, name, upc, qty, brand_new, non_pristine, damaged, founders, raw, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
         ON CONFLICT (sku) DO UPDATE SET name=$2, upc=$3, qty=$4, brand_new=$5, non_pristine=$6, damaged=$7, founders=$8, raw=$9, updated_at=now()`,
        [sku, name, upc, qty, brandNew, nonPristine, damaged, founders, JSON.stringify(it)]);
      if (!prev || prev.qty !== qty) {
        await pool.query('INSERT INTO uk_stock_history (sku, qty) VALUES ($1,$2)', [sku, qty]);
      }
      upserts++;
    }
    st.items = upserts;
  } catch (e) {
    st.last_error = String(e.message);
    console.error('uk stock sync:', st.last_error);
  }
  st.last_run = new Date().toISOString();
  await pool.query(`INSERT INTO sync_state (k, v) VALUES ('uk_stock', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
    [JSON.stringify(st)]).catch(() => {});
  return { configured: true, ...st };
}

app.get('/api/stock', async (_req, res) => {
  const conn = await getConnector('uk_stock');
  const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='uk_stock'`)).rows[0]?.v || null;
  const [items, totals, history] = await Promise.all([
    pool.query('SELECT sku, name, upc, qty, brand_new, non_pristine, damaged, founders, updated_at FROM uk_stock ORDER BY qty ASC NULLS LAST LIMIT 300'),
    pool.query(`SELECT count(*)::int skus, coalesce(sum(qty),0)::int units,
                coalesce(sum(brand_new),0)::int brand_new, coalesce(sum(non_pristine),0)::int non_pristine,
                coalesce(sum(damaged),0)::int damaged, coalesce(sum(founders),0)::int founders,
                count(*) FILTER (WHERE qty IS NOT NULL AND qty < 10 AND qty > 0)::int low,
                count(*) FILTER (WHERE qty = 0)::int out_of_stock FROM uk_stock`),
    pool.query(`SELECT h.taken_at, h.sku, h.qty, s.name FROM uk_stock_history h
                LEFT JOIN uk_stock s ON s.sku = h.sku ORDER BY h.taken_at DESC LIMIT 15`)
  ]);
  // diagnostic: expose one raw item so field-mapping problems are visible in the UI
  const sample = (await pool.query('SELECT raw FROM uk_stock LIMIT 1')).rows[0]?.raw || null;
  res.json({ configured: !!conn, items: items.rows, totals: totals.rows[0], history: history.rows, sync: ss, sample_raw: sample });
});
// one-time re-import from clicks_ruk (admin only) — overwrites, so it's opt-in now
app.post('/api/stock/sync', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  try { res.json(await syncUkStock()); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- UK stock management (clicks-brain is the source of truth; admins only) ----------
const stockInt = v => { const n = parseInt(v); return Number.isFinite(n) && n >= 0 ? n : 0; };
// add or update a stock item
app.post('/api/stock/item', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const b = req.body || {};
  const sku = String(b.sku || '').trim();
  if (!sku) return res.status(400).json({ error: 'SKU is required.' });
  const name = String(b.description ?? b.name ?? '').trim().slice(0, 300);
  const upc = String(b.upc || '').trim().slice(0, 50);
  const bn = stockInt(b.brand_new), np = stockInt(b.non_pristine), dm = stockInt(b.damaged), fd = stockInt(b.founders);
  const qty = bn + np + dm + fd;
  // if renaming an existing SKU, remove the old row
  const oldSku = String(b.old_sku || '').trim();
  if (oldSku && oldSku !== sku) await pool.query('DELETE FROM uk_stock WHERE sku=$1', [oldSku]);
  await pool.query(
    `INSERT INTO uk_stock (sku, name, upc, brand_new, non_pristine, damaged, founders, qty, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
     ON CONFLICT (sku) DO UPDATE SET name=$2, upc=$3, brand_new=$4, non_pristine=$5, damaged=$6, founders=$7, qty=$8, updated_at=now()`,
    [sku, name, upc, bn, np, dm, fd, qty]);
  await pool.query('INSERT INTO uk_stock_history (sku, qty) VALUES ($1,$2)', [sku, qty]).catch(() => {});
  res.json({ ok: true, sku });
});
// delete a stock item
app.post('/api/stock/item/delete', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const sku = String(req.body?.sku || '').trim();
  const r = await pool.query('DELETE FROM uk_stock WHERE sku=$1', [sku]);
  if (!r.rowCount) return res.status(404).json({ error: 'SKU not found.' });
  res.json({ ok: true });
});
// look up a single item by UPC (for the scanner)
app.get('/api/stock/by-upc', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const upc = String(req.query.upc || '').trim();
  if (!upc) return res.status(400).json({ error: 'upc required' });
  const row = (await pool.query('SELECT sku, name, upc, brand_new, non_pristine, damaged, founders, qty FROM uk_stock WHERE upc=$1 LIMIT 1', [upc])).rows[0] || null;
  res.json({ found: !!row, item: row });
});
// ---------- sign-out / PO cart (admins): deduct stock, keep a record, print docs ----------
const STOCK_CONDS = ['brand_new', 'non_pristine', 'damaged', 'founders'];
const CONDLABEL = { brand_new: 'Brand New', non_pristine: 'Non-Pristine', damaged: 'Damaged', founders: 'Founders' };
app.post('/api/stock/sign-out', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const b = req.body || {};
  const items = Array.isArray(b.items) ? b.items : [];
  if (!items.length) return res.status(400).json({ error: 'Cart is empty.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // validate availability with row locks, then deduct
    for (const it of items) {
      const sku = String(it.sku || '');
      const cond = STOCK_CONDS.includes(it.condition) ? it.condition : 'brand_new';
      const qty = Math.max(0, parseInt(it.qty) || 0);
      const row = (await client.query(`SELECT ${cond} AS c FROM uk_stock WHERE sku=$1 FOR UPDATE`, [sku])).rows[0];
      if (!row) throw new Error(`Unknown SKU ${sku}`);
      if ((row.c || 0) < qty) throw new Error(`Insufficient ${CONDLABEL[cond]} for ${sku} (have ${row.c || 0}, need ${qty})`);
    }
    for (const it of items) {
      const sku = String(it.sku || '');
      const cond = STOCK_CONDS.includes(it.condition) ? it.condition : 'brand_new';
      const qty = Math.max(0, parseInt(it.qty) || 0);
      await client.query(`UPDATE uk_stock SET ${cond}=GREATEST(0,coalesce(${cond},0)-$2), qty=GREATEST(0,coalesce(qty,0)-$2), updated_at=now() WHERE sku=$1`, [sku, qty]);
      await client.query(`INSERT INTO uk_stock_history (sku, qty) SELECT sku, qty FROM uk_stock WHERE sku=$1`, [sku]);
    }
    const po = String(b.po_number || '').trim() || ('PO-' + Date.now());
    const clean = items.map(it => ({ sku: String(it.sku || ''), description: String(it.description || ''), upc: String(it.upc || ''),
      condition: STOCK_CONDS.includes(it.condition) ? it.condition : 'brand_new', qty: Math.max(0, parseInt(it.qty) || 0) }));
    const ins = await client.query(
      `INSERT INTO stock_sign_outs (po_number, destination, notes, created_by, include_invoice, items)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [po, String(b.destination || ''), String(b.notes || ''), readSession(req) || '', !!b.include_invoice, JSON.stringify(clean)]);
    await client.query('COMMIT');
    res.json({ ok: true, id: ins.rows[0].id, po_number: po });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); res.status(400).json({ error: e.message }); }
  finally { client.release(); }
});
app.get('/api/stock/sign-outs', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const rows = (await pool.query(
    `SELECT id, po_number, destination, notes, created_by, include_invoice, items, created_at
     FROM stock_sign_outs ORDER BY id DESC LIMIT 50`)).rows;
  res.json(rows);
});
// printable packing list / commercial invoice
app.get('/api/stock/sign-out-doc', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).send('admins only');
  const id = parseInt(req.query.id);
  const type = req.query.type === 'invoice' ? 'invoice' : 'packing';
  const so = (await pool.query('SELECT * FROM stock_sign_outs WHERE id=$1', [id])).rows[0];
  if (!so) return res.status(404).send('Not found');
  const items = Array.isArray(so.items) ? so.items : [];
  const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const totalUnits = items.reduce((n, i) => n + (i.qty || 0), 0);
  const title = type === 'invoice' ? 'Commercial Invoice' : 'Packing List';
  const rows = items.map((i, n) => `<tr><td>${n + 1}</td><td><b>${esc(i.sku)}</b></td><td>${esc(i.description)}</td><td>${esc(i.upc)}</td><td>${esc(CONDLABEL[i.condition] || i.condition)}</td><td style="text-align:right">${i.qty}</td></tr>`).join('');
  res.set('Content-Type', 'text/html');
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>${title} · ${esc(so.po_number)}</title>
<style>body{font:13px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#111;max-width:820px;margin:28px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 2px}.muted{color:#666}.meta{margin:14px 0 18px;display:flex;flex-wrap:wrap;gap:6px 28px}
.meta div span{color:#666}table{width:100%;border-collapse:collapse;margin-top:8px}
th{background:#f3f4f6;text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.4px;border-bottom:2px solid #e5e7eb}
td{padding:8px 10px;border-bottom:1px solid #eee}tfoot td{font-weight:700;border-top:2px solid #e5e7eb}
.btn{margin:18px 0;padding:8px 16px;border:1px solid #ccc;border-radius:8px;background:#ffc800;font-weight:700;cursor:pointer}
@media print{.btn{display:none}}</style></head><body>
<button class="btn" onclick="window.print()">🖨 Print</button>
<h1>${title}</h1><div class="muted">Clicks Technology — UK stock sign-out</div>
<div class="meta">
  <div><span>PO number:</span> <b>${esc(so.po_number)}</b></div>
  <div><span>Destination:</span> ${esc(so.destination) || '—'}</div>
  <div><span>Date:</span> ${new Date(so.created_at).toLocaleString()}</div>
  <div><span>Signed out by:</span> ${esc(so.created_by) || '—'}</div>
  ${so.notes ? `<div><span>Notes:</span> ${esc(so.notes)}</div>` : ''}
</div>
<table><thead><tr><th>#</th><th>SKU</th><th>Description</th><th>UPC</th><th>Condition</th><th style="text-align:right">Qty</th></tr></thead>
<tbody>${rows}</tbody>
<tfoot><tr><td colspan="5">Total units</td><td style="text-align:right">${totalUnits}</td></tr></tfoot></table>
${type === 'invoice' ? '<p class="muted" style="margin-top:20px">This commercial invoice is issued for customs/shipping purposes. Goods described above are transferred as stated.</p>' : ''}
</body></html>`);
});

// CSV export of all stock (admins only)
app.get('/api/stock/export', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).send('admins only');
  const rows = (await pool.query('SELECT upc, sku, name, brand_new, non_pristine, damaged, founders, qty FROM uk_stock ORDER BY sku')).rows;
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['UPC', 'SKU', 'Description', 'Brand New', 'Non-Pristine', 'Damaged', 'Founders', 'Total'];
  const csv = [head.join(','), ...rows.map(r => [r.upc, r.sku, r.name, r.brand_new ?? 0, r.non_pristine ?? 0, r.damaged ?? 0, r.founders ?? 0, r.qty ?? 0].map(esc).join(','))].join('\r\n');
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', `attachment; filename="uk-stock-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(csv);
});

// ---------- ShipBob (3PL fulfillment inventory) ----------
async function shipbobRequest(cfg, path) {
  const headers = { Authorization: `Bearer ${cfg.token}`, Accept: 'application/json' };
  if (cfg.channel_id) headers['shipbob_channel_id'] = String(cfg.channel_id);
  const r = await fetch(`https://api.shipbob.com${path}`, { headers });
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  if (!r.ok) throw new Error(`ShipBob ${path} → ${r.status}: ${typeof body === 'string' ? body.slice(0, 200) : JSON.stringify(body).slice(0, 200)}`);
  return body;
}
// pull all pages of a 1.0 list endpoint (array responses, ?Page&Limit)
async function shipbobList(cfg, base, limit = 250, maxPages = 40) {
  const out = [];
  for (let page = 1; page <= maxPages; page++) {
    const sep = base.includes('?') ? '&' : '?';
    const rows = await shipbobRequest(cfg, `${base}${sep}Page=${page}&Limit=${limit}`);
    const arr = Array.isArray(rows) ? rows : (rows.data || rows.items || []);
    out.push(...arr);
    if (arr.length < limit) break;
  }
  return out;
}
let shipbobSyncRunning = false;
async function syncShipbob() {
  if (shipbobSyncRunning) return { skipped: true };
  const conn = await getConnector('shipbob');
  if (!conn) return { configured: false };
  const cfg = conn.config;
  shipbobSyncRunning = true;
  let upserts = 0, lastError = null;
  try {
    // products carry SKU + quantities + per-fulfillment-center breakdown — everything we need in one call
    const products = await shipbobList(cfg, '/1.0/product');
    const bySku = {};
    for (const p of products) {
      const sku = String(p.sku || '').trim();
      if (!sku || !/[A-Za-z]/.test(sku)) continue; // skip blank and all-numeric (barcode) SKUs
      const onHand = p.total_onhand_quantity ?? 0;
      if (bySku[sku] && (bySku[sku].on_hand ?? 0) >= onHand) continue; // dedupe channel copies, keep the richest
      bySku[sku] = { sku, name: String(p.name || '').slice(0, 300), upc: String(p.upc || p.barcode || ''),
        on_hand: onHand, fulfillable: p.total_fulfillable_quantity ?? 0, committed: p.total_committed_quantity ?? 0,
        by_fc: p.fulfillable_quantity_by_fulfillment_center || [] };
    }
    const skus = Object.keys(bySku);
    for (const sku of skus) {
      const r = bySku[sku];
      await pool.query(
        `INSERT INTO shipbob_stock (sku, name, upc, on_hand, fulfillable, committed, by_fc, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,now())
         ON CONFLICT (sku) DO UPDATE SET name=$2, upc=$3, on_hand=$4, fulfillable=$5, committed=$6, by_fc=$7, updated_at=now()`,
        [r.sku, r.name, r.upc, r.on_hand, r.fulfillable, r.committed, JSON.stringify(r.by_fc)]);
      upserts++;
    }
    if (skus.length) await pool.query('DELETE FROM shipbob_stock WHERE sku <> ALL($1)', [skus]); // drop SKUs no longer in ShipBob
  } catch (e) { lastError = String(e.message); console.error('shipbob sync:', lastError); }
  finally {
    await pool.query(`INSERT INTO sync_state (k, v) VALUES ('shipbob', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ last_run: new Date().toISOString(), upserts, last_error: lastError })]).catch(() => {});
    shipbobSyncRunning = false;
  }
  return { upserts, error: lastError };
}
// raw API peek so we can see the real response shape before trusting the parser (admin only)
app.get('/api/shipbob/debug', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const conn = await getConnector('shipbob');
  if (!conn) return res.status(400).json({ error: 'ShipBob not connected — add it on the ＋ page first.' });
  const out = {};
  for (const [k, path] of [['channels', '/1.0/channel'], ['inventory_sample', '/1.0/inventory?Page=1&Limit=2'], ['product_sample', '/1.0/product?Page=1&Limit=2']]) {
    try { out[k] = await shipbobRequest(conn.config, path); }
    catch (e) { out[k] = { error: e.message }; }
  }
  res.json(out);
});
app.get('/api/shipbob/summary', async (_req, res) => {
  const conn = await getConnector('shipbob');
  const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='shipbob'`)).rows[0]?.v || null;
  const items = (await pool.query(
    `SELECT sku, name, upc, on_hand, fulfillable, committed, by_fc FROM shipbob_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201') ORDER BY sku, name`)).rows;
  const totals = (await pool.query(
    `SELECT count(*)::int items, coalesce(sum(on_hand),0)::int on_hand, coalesce(sum(fulfillable),0)::int fulfillable,
            coalesce(sum(committed),0)::int committed FROM shipbob_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`)).rows[0];
  res.json({ configured: !!conn, items, totals, sync: ss });
});
app.post('/api/shipbob/sync', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  try { res.json(await syncShipbob()); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- Floship (3PL, shape unknown until we probe the live API) ----------
// auth-style variants to try against a given URL
function floshipAuthAttempts(url, token) {
  const q = (u, k) => u + (u.includes('?') ? '&' : '?') + k + '=' + encodeURIComponent(token);
  const basic = 'Basic ' + Buffer.from(token + ':').toString('base64');
  return [
    ['Bearer', url, { Authorization: `Bearer ${token}` }],
    ['Token', url, { Authorization: `Token ${token}` }],
    ['Token token=', url, { Authorization: `Token token=${token}` }],
    ['Api-Key', url, { Authorization: `Api-Key ${token}` }],
    ['raw Authorization', url, { Authorization: token }],
    ['X-API-Key', url, { 'X-API-Key': token }],
    ['api-token', url, { 'api-token': token }],
    ['api_key header', url, { api_key: token }],
    ['Basic key:', url, { Authorization: basic }],
    ['?api_key=', q(url, 'api_key'), {}],
    ['?token=', q(url, 'token'), {}]
  ];
}
// try many auth styles across common resource paths under the base; report the first 200 or a compact log
async function floshipProbe(baseUrl, token) {
  const b = String(baseUrl).replace(/\/+$/, '');
  const looksBase = /\/api(\/v\d+)?$/i.test(b) || String(baseUrl).endsWith('/');
  const paths = looksBase
    ? ['', '/inventory', '/inventories', '/inventory/summary', '/products', '/product', '/stock', '/stocks', '/sku', '/skus', '/warehouses', '/warehouse', '/orders']
    : [''];
  const log = [];
  for (const p of paths) {
    const url = b + p;
    let pathAlive = false;
    for (const [desc, u, hdrs] of floshipAuthAttempts(url, token)) {
      try {
        const r = await fetch(u, { headers: { ...hdrs, Accept: 'application/json' } });
        const text = await r.text();
        let body; try { body = JSON.parse(text); } catch { body = text; }
        if (r.ok) return { ok: true, url: u, auth: desc, status: r.status, body };
        log.push({ url, auth: desc, status: r.status });
        if (r.status !== 404) pathAlive = true;
        if (desc === 'Bearer' && r.status === 404) break; // path doesn't exist → don't try more auth on it
      } catch (e) { log.push({ url, auth: desc, error: e.message }); break; }
    }
  }
  return { ok: false, tried: log.slice(0, 80) };
}
app.get('/api/floship/debug', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const conn = await getConnector('floship');
  if (!conn) return res.status(400).json({ error: 'Floship not connected — add it on the ＋ page first.' });
  res.json(await floshipProbe(conn.config.base_url, conn.config.token));
});
// probe an arbitrary URL+token without saving a connector — for figuring out the right endpoint/auth
app.post('/api/floship/probe', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { base_url, token } = req.body || {};
  if (!base_url) return res.status(400).json({ error: 'base_url required' });
  res.json(await floshipProbe(String(base_url).trim(), String(token || '')));
});
// apply a discovered auth style (by its probe label) to a url
function floshipAuthApply(auth, url, token) {
  const qp = (u, k) => u + (u.includes('?') ? '&' : '?') + k + '=' + encodeURIComponent(token);
  const map = {
    'Bearer': [url, { Authorization: `Bearer ${token}` }],
    'Token': [url, { Authorization: `Token ${token}` }],
    'Token token=': [url, { Authorization: `Token token=${token}` }],
    'Api-Key': [url, { Authorization: `Api-Key ${token}` }],
    'raw Authorization': [url, { Authorization: token }],
    'X-API-Key': [url, { 'X-API-Key': token }],
    'api-token': [url, { 'api-token': token }],
    'api_key header': [url, { api_key: token }],
    'Basic key:': [url, { Authorization: 'Basic ' + Buffer.from(token + ':').toString('base64') }],
    '?api_key=': [qp(url, 'api_key'), {}],
    '?token=': [qp(url, 'token'), {}]
  };
  return map[auth] || [url, { Authorization: `Token ${token}` }];
}
let floshipSyncRunning = false;
async function syncFloship() {
  if (floshipSyncRunning) return { skipped: true };
  const conn = await getConnector('floship');
  if (!conn) return { configured: false };
  const cfg = conn.config;
  const auth = conn.meta?.auth || 'Token';
  const first = conn.meta?.products_url || (String(cfg.base_url).replace(/\/+$/, '') + '/products');
  floshipSyncRunning = true;
  let upserts = 0, lastError = null;
  try {
    const skusSeen = [];
    let page = first, guard = 0;
    while (page && guard++ < 200) {
      const [u, hdrs] = floshipAuthApply(auth, page, cfg.token);
      const r = await fetch(u, { headers: { ...hdrs, Accept: 'application/json' } });
      if (!r.ok) throw new Error(`Floship ${r.status} at ${page}`);
      const body = await r.json();
      const results = Array.isArray(body) ? body : (body.results || []);
      for (const p of results) {
        const sku = String(p.sku || '').trim();
        if (!sku || !/[A-Za-z]/.test(sku)) continue; // skip blank and all-numeric (barcode) SKUs
        const wh = p.warehouses_stock || [];
        const qty = wh.reduce((s, w) => s + (w.qty || 0), 0);
        const onHand = wh.reduce((s, w) => s + (w.qty_on_hand || 0), 0);
        await pool.query(
          `INSERT INTO floship_stock (sku, description, upc, qty, on_hand, by_wh, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,now())
           ON CONFLICT (sku) DO UPDATE SET description=$2, upc=$3, qty=$4, on_hand=$5, by_wh=$6, updated_at=now()`,
          [sku, String(p.description || '').slice(0, 300), String(p.upc || ''), qty, onHand, JSON.stringify(wh)]);
        skusSeen.push(sku); upserts++;
      }
      page = (body && typeof body === 'object' && body.next) ? body.next : null;
    }
    if (skusSeen.length) await pool.query('DELETE FROM floship_stock WHERE sku <> ALL($1)', [skusSeen]);
  } catch (e) { lastError = String(e.message); console.error('floship sync:', lastError); }
  finally {
    await pool.query(`INSERT INTO sync_state (k, v) VALUES ('floship', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ last_run: new Date().toISOString(), upserts, last_error: lastError })]).catch(() => {});
    floshipSyncRunning = false;
  }
  return { upserts, error: lastError };
}
app.get('/api/floship/summary', async (_req, res) => {
  const conn = await getConnector('floship');
  const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='floship'`)).rows[0]?.v || null;
  const items = (await pool.query(
    `SELECT sku, description, upc, qty, on_hand, by_wh FROM floship_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201') ORDER BY sku`)).rows;
  const totals = (await pool.query(
    `SELECT count(*)::int items, coalesce(sum(qty),0)::int qty, coalesce(sum(on_hand),0)::int on_hand FROM floship_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`)).rows[0];
  res.json({ configured: !!conn, items, totals, sync: ss });
});
app.post('/api/floship/sync', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  try { res.json(await syncFloship()); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- Freight tracker (shipment builder: fields, items, documents, configurable stage stepper) ----------
const FREIGHT_STAGES = ['Shipment booked', 'Picked up / dropped off', 'En route to destination country',
  'Arrived at destination country', 'Customs clearance', 'En route to final warehouse', 'Arrived at warehouse'];
app.get('/api/freight', async (req, res) => {
  const rows = (await pool.query(
    `SELECT id, name, reference, from_country, to_country, carrier, to_char(eta,'YYYY-MM-DD') eta,
       notes, items, stages, step, created_by, updated_at
     FROM freight_shipments ORDER BY eta ASC NULLS LAST, id DESC`)).rows;
  // documents are only exposed to admins and members with the "shipping" sub-role
  const canDocs = await canSeeFreightDocs(req);
  if (canDocs) {
    const docs = (await pool.query(`SELECT id, shipment_id, label, filename, mime FROM freight_docs ORDER BY id`)).rows;
    const byShip = {}; docs.forEach(d => (byShip[d.shipment_id] = byShip[d.shipment_id] || []).push(d));
    rows.forEach(r => { r.docs = byShip[r.id] || []; });
  } else {
    rows.forEach(r => { r.docs = []; });
  }
  res.json({ default_stages: FREIGHT_STAGES, shipments: rows, can_docs: canDocs });
});
app.post('/api/freight', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const b = req.body || {};
  const notify = b.notify !== false; // default on; frontend can opt out to avoid Slack spam on repeated edits
  const eta = b.eta ? String(b.eta).slice(0, 10) : null;
  const items = Array.isArray(b.items) ? b.items.map(i => ({ sku: String(i.sku || '').slice(0, 60), qty: parseInt(i.qty) || 0 })).filter(i => i.sku) : [];
  const stages = Array.isArray(b.stages) ? b.stages.map(s => String(s).slice(0, 80)).filter(Boolean) : [];
  const step = Math.max(0, Math.min(parseInt(b.step) || 0, stages.length));
  const f = [String(b.name || '').slice(0, 160), String(b.from_country || '').slice(0, 80), String(b.to_country || '').slice(0, 80),
    String(b.carrier || '').slice(0, 120), eta, String(b.notes || '').slice(0, 1000),
    JSON.stringify(items), JSON.stringify(stages), step];
  if (b.id) {
    const r = await pool.query(
      `UPDATE freight_shipments SET name=$1, from_country=$2, to_country=$3, carrier=$4, eta=$5, notes=$6,
         items=$7, stages=$8, step=$9, updated_at=now() WHERE id=$10 RETURNING id`, [...f, parseInt(b.id)]);
    if (!r.rowCount) return res.status(404).json({ error: 'shipment not found' });
    res.json({ ok: true, id: r.rows[0].id });
    if (notify) notifyFreight('edited', { id: parseInt(b.id), name: b.name, from_country: b.from_country, to_country: b.to_country,
      carrier: b.carrier, eta, notes: b.notes, items, stages, step });
    return;
  }
  const r = await pool.query(
    `INSERT INTO freight_shipments (name, from_country, to_country, carrier, eta, notes, items, stages, step, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, [...f, readSession(req) || '']);
  res.json({ ok: true, id: r.rows[0].id });
  if (notify) notifyFreight('created', { id: r.rows[0].id, name: b.name, from_country: b.from_country, to_country: b.to_country,
    carrier: b.carrier, eta, notes: b.notes, items, stages, step }); // best-effort Slack post, after responding
});
// quick stage advance (click a step on the progress bar) — does NOT post to Slack (use the Post button for that)
app.post('/api/freight/step', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const r = await pool.query(`UPDATE freight_shipments SET step=$2, updated_at=now() WHERE id=$1 RETURNING id`,
    [parseInt(req.body?.id), Math.max(0, parseInt(req.body?.step) || 0)]);
  if (!r.rowCount) return res.status(404).json({ error: 'shipment not found' });
  res.json({ ok: true });
});
// manual "Post to Slack" button — announces the shipment's current stage/status
app.post('/api/freight/announce', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const row = (await pool.query(
    `SELECT name, from_country, to_country, carrier, to_char(eta,'YYYY-MM-DD') eta, notes, items, stages, step FROM freight_shipments WHERE id=$1`,
    [parseInt(req.body?.id)])).rows[0];
  if (!row) return res.status(404).json({ error: 'shipment not found' });
  res.json({ ok: true });
  notifyFreight('update', { ...row, id: parseInt(req.body?.id) });
});
// mark a shipment complete (all stages done) — posts a Slack "completed" alert
app.post('/api/freight/complete', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const id = parseInt(req.body?.id);
  const row = (await pool.query(
    `SELECT name, from_country, to_country, carrier, to_char(eta,'YYYY-MM-DD') eta, notes, items, stages FROM freight_shipments WHERE id=$1`, [id])).rows[0];
  if (!row) return res.status(404).json({ error: 'shipment not found' });
  const n = (Array.isArray(row.stages) ? row.stages.length : 0) + 1; // step past the last stage = all done
  await pool.query(`UPDATE freight_shipments SET step=$2, updated_at=now() WHERE id=$1`, [id, n]);
  res.json({ ok: true });
  if (req.body?.notify !== false) notifyFreight('completed', { ...row, id });
});
app.post('/api/freight/delete', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const id = parseInt(req.body?.id);
  const row = (await pool.query(
    `SELECT name, from_country, to_country, carrier, to_char(eta,'YYYY-MM-DD') eta, items FROM freight_shipments WHERE id=$1`, [id])).rows[0];
  await pool.query('DELETE FROM freight_docs WHERE shipment_id=$1', [id]);
  const r = await pool.query('DELETE FROM freight_shipments WHERE id=$1', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'shipment not found' });
  res.json({ ok: true });
  if (row) notifyFreight('deleted', { ...row, id });
});
// documents: upload (base64), download, delete
app.post('/api/freight/doc', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const b = req.body || {};
  const sid = parseInt(b.shipment_id);
  if (!sid || !b.data) return res.status(400).json({ error: 'shipment_id and file required' });
  const r = await pool.query(
    `INSERT INTO freight_docs (shipment_id, label, filename, mime, data) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [sid, String(b.label || 'Document').slice(0, 80), String(b.filename || 'file').slice(0, 200), String(b.mime || 'application/octet-stream').slice(0, 100), String(b.data || '')]);
  res.json({ ok: true, id: r.rows[0].id });
});
app.get('/api/freight/doc/:id', async (req, res) => {
  if (!(await canSeeFreightDocs(req))) return res.status(403).send('not authorised — freight documents are for admins and the shipping role');
  const d = (await pool.query('SELECT filename, mime, data FROM freight_docs WHERE id=$1', [parseInt(req.params.id)])).rows[0];
  if (!d) return res.status(404).send('not found');
  res.set('Content-Type', d.mime || 'application/octet-stream');
  res.set('Content-Disposition', `inline; filename="${(d.filename || 'file').replace(/"/g, '')}"`);
  res.send(Buffer.from(d.data || '', 'base64'));
});
app.post('/api/freight/doc/delete', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  await pool.query('DELETE FROM freight_docs WHERE id=$1', [parseInt(req.body?.id)]);
  res.json({ ok: true });
});

// combined inventory grid: one row per SKU, one column per source (ShipBob + Floship live from API, plus any imported sheet columns)
const GRID_PALETTE = ['#db2777', '#ea580c', '#7c3aed', '#0891b2', '#65a30d', '#9333ea', '#0d9488', '#c026d3', '#dc2626', '#ca8a04'];
app.get('/api/fulfillment/grid', async (_req, res) => {
  const [sb, fl, man, srcOrd, skuOrd] = await Promise.all([
    pool.query(`SELECT sku, name, fulfillable, by_fc FROM shipbob_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(`SELECT sku, description, qty, by_wh FROM floship_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(`SELECT sku, source, qty, description FROM manual_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(`SELECT source, ord FROM inv_source_ord`),
    pool.query(`SELECT sku, ord FROM inv_sku_ord`)
  ]);
  const srcOrdMap = {}; srcOrd.rows.forEach(r => srcOrdMap[r.source] = r.ord);
  const skuOrdMap = {}; skuOrd.rows.forEach(r => skuOrdMap[r.sku] = r.ord);
  const bySku = {};
  const ensure = s => (bySku[s] = bySku[s] || { sku: s, name: '', vals: {}, loc: {} });
  sb.rows.forEach(r => {
    const x = ensure(r.sku); x.name = x.name || r.name || ''; x.vals.shipbob = r.fulfillable || 0;
    x.loc.shipbob = (r.by_fc || []).filter(f => (f.fulfillable_quantity ?? 0) > 0).map(f => ({ name: f.name, qty: f.fulfillable_quantity }));
  });
  fl.rows.forEach(r => {
    const x = ensure(r.sku); x.name = x.name || r.description || ''; x.vals.floship = r.qty || 0;
    x.loc.floship = (r.by_wh || []).filter(w => (w.qty ?? 0) > 0).map(w => ({ name: String(w.warehouse_name || '').replace('Floship ', ''), qty: w.qty }));
  });
  const manualSources = {}; // key -> label
  man.rows.forEach(r => {
    const key = 'm_' + String(r.source).toLowerCase().replace(/[^a-z0-9]+/g, '_');
    manualSources[key] = r.source;
    const x = ensure(r.sku); x.name = x.name || r.description || '';
    x.vals[key] = (x.vals[key] || 0) + (r.qty || 0);
  });
  const sources = [
    { key: 'shipbob', label: 'ShipBob', color: '#059669', api: true },
    { key: 'floship', label: 'Floship', color: '#2563eb', api: true },
    ...Object.entries(manualSources).map(([key, label], i) =>
      ({ key, label, color: GRID_PALETTE[i % GRID_PALETTE.length], api: false }))
  ];
  // resolve product names the same way the UK stock tab does: UK-stock name first, then Shopify title (+ variant),
  // falling back to the source description only if neither exists
  const gskus = Object.keys(bySku);
  if (gskus.length) {
    const nm = (await pool.query(
      `SELECT sku, us.name us_name, pi.title p_title, nullif(pi.variant_title, '') variant FROM unnest($1::text[]) sku
       LEFT JOIN product_images pi USING (sku) LEFT JOIN uk_stock us USING (sku)`, [gskus])).rows;
    nm.forEach(r => {
      if (r.us_name) bySku[r.sku].name = r.us_name;                                    // UK-stock name as-is (already has model + colour), matches the UK Stock tab
      else if (r.p_title) bySku[r.sku].name = r.variant ? `${r.p_title} — ${r.variant}` : r.p_title; // Shopify fallback: base title + colour
    });
  }
  // order columns to match the imported sheet's layout (ShipBob→'shipbob', Floship→'floship', others by label);
  // anything not in the sheet falls to the end
  const ordOf = s => srcOrdMap[s.api ? s.key : s.label] ?? (900 + sources.indexOf(s));
  sources.sort((a, b) => ordOf(a) - ordOf(b));
  const rows = Object.values(bySku).map(x => { x.total = sources.reduce((s, src) => s + (x.vals[src.key] || 0), 0); return x; })
    .sort((a, b) => (skuOrdMap[a.sku] ?? 1e9) - (skuOrdMap[b.sku] ?? 1e9) || b.total - a.total || a.sku.localeCompare(b.sku));
  const totals = { total: 0 }; sources.forEach(s => totals[s.key] = 0);
  rows.forEach(x => { sources.forEach(s => totals[s.key] += x.vals[s.key] || 0); totals.total += x.total; });
  res.json({ sources, rows, totals, connected: { shipbob: !!(await getConnector('shipbob')), floship: !!(await getConnector('floship')), manual: man.rows.length > 0 } });
});

// stock forecast: current Global Inventory total per SKU, drawn down by recent Shopify sales velocity.
// projected stock at 7/14/30/90 days = current − (avg daily units sold over the chosen window × horizon)
async function forecastRows(win) {
  const [sb, fl, man, sales] = await Promise.all([
    pool.query(`SELECT sku, name, fulfillable FROM shipbob_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(`SELECT sku, description, qty FROM floship_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(`SELECT sku, qty, description FROM manual_stock WHERE sku ~ '[A-Za-z]' AND sku !~* '-top$' AND lower(sku) NOT IN ('x-redo','quarantine - returns','ck-reserve','ck-request','ck-5100','ck-5101','ck-5200','ck-5201')`),
    pool.query(
      `SELECT it->>'sku' sku, sum(coalesce((it->>'qty')::int, 0))::int units
       FROM orders_cache, LATERAL jsonb_array_elements(items) it
       WHERE cancelled_at IS NULL AND created_at >= now() - make_interval(days => $1::int)
       GROUP BY 1`, [win])
  ]);
  const stock = {}, rawName = {};
  const add = (s, q, n) => { if (!s) return; stock[s] = (stock[s] || 0) + (q || 0); if (n && !rawName[s]) rawName[s] = n; };
  sb.rows.forEach(r => add(r.sku, r.fulfillable, r.name));
  fl.rows.forEach(r => add(r.sku, r.qty, r.description));
  man.rows.forEach(r => add(r.sku, r.qty, r.description));
  const sold = {}; sales.rows.forEach(r => { if (r.sku) sold[r.sku] = (sold[r.sku] || 0) + (r.units || 0); });

  const skus = Object.keys(stock);
  const nameMap = {};
  if (skus.length) {
    const nm = (await pool.query(
      `SELECT sku, coalesce(us.name, pi.title) nm, nullif(pi.variant_title, '') variant FROM unnest($1::text[]) sku
       LEFT JOIN product_images pi USING (sku) LEFT JOIN uk_stock us USING (sku)`, [skus])).rows;
    nm.forEach(r => { if (r.nm) nameMap[r.sku] = r.variant ? `${r.nm} — ${r.variant}` : r.nm; });
  }

  const horizons = [7, 14, 30, 90];
  const rows = skus.map(sku => {
    const cur = stock[sku] || 0;
    const rate = (sold[sku] || 0) / win; // units per day
    const cover = rate > 0 ? cur / rate : null; // days until stockout
    const proj = {}; horizons.forEach(h => proj[h] = Math.round(cur - rate * h));
    return { sku, name: nameMap[sku] || rawName[sku] || sku, stock: cur, sold: sold[sku] || 0,
      rate: Math.round(rate * 100) / 100, cover: cover == null ? null : Math.round(cover * 10) / 10, proj };
  });
  // soonest stockout first; SKUs with no sales (no depletion) sink to the bottom
  rows.sort((a, b) => (a.cover == null ? Infinity : a.cover) - (b.cover == null ? Infinity : b.cover)
    || b.sold - a.sold || a.sku.localeCompare(b.sku));
  return { window: win, horizons, rows, hasSales: sales.rows.length > 0 };
}
app.get('/api/forecast', async (req, res) => {
  const win = Math.max(1, Math.min(parseInt(req.query.window) || 14, 90));
  res.json(await forecastRows(win));
});

// resolve product names (UK-stock name, else Shopify title + variant) for a list of SKUs
async function resolveNames(skus) {
  const map = {};
  if (!skus.length) return map;
  const rows = (await pool.query(
    `SELECT sku, us.name us_name, pi.title p_title, nullif(pi.variant_title,'') variant FROM unnest($1::text[]) sku
     LEFT JOIN product_images pi USING (sku) LEFT JOIN uk_stock us USING (sku)`, [skus])).rows;
  rows.forEach(r => {
    if (r.us_name) map[r.sku] = r.us_name;
    else if (r.p_title) map[r.sku] = r.variant ? `${r.p_title} — ${r.variant}` : r.p_title;
  });
  return map;
}

// variant quality score: per SKU over the window, returns + refunds + cancellations, each normalised
// per units sold, summed into one score (higher = worse). Return reasons come from Redo.
app.get('/api/quality/variants', async (req, res) => {
  try {
    const win = Math.max(7, Math.min(parseInt(req.query.window) || 90, 366));
    const iv = `now() - make_interval(days => ${win})`;
    const [sold, returns, refunds, cancels, reasons] = await Promise.all([
      pool.query(`SELECT it->>'sku' sku, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE cancelled_at IS NULL AND created_at >= ${iv} AND coalesce(it->>'sku','') <> '' GROUP BY 1`),
      pool.query(`SELECT i->>'sku' sku, count(*)::int c
        FROM returns_cache, LATERAL jsonb_array_elements(items) i
        WHERE created_at >= ${iv} AND coalesce(i->>'sku','') <> '' GROUP BY 1`),
      pool.query(`SELECT it->>'sku' sku, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE financial_status IN ('refunded','partially_refunded') AND created_at >= ${iv} AND coalesce(it->>'sku','') <> '' GROUP BY 1`),
      pool.query(`SELECT it->>'sku' sku, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv} AND coalesce(it->>'sku','') <> '' GROUP BY 1`),
      pool.query(`SELECT i->>'sku' sku, coalesce(nullif(i->>'reason',''),'(none)') reason, count(*)::int c
        FROM returns_cache, LATERAL jsonb_array_elements(items) i
        WHERE created_at >= ${iv} AND coalesce(i->>'sku','') <> '' GROUP BY 1,2`)
    ]);
    const soldM = {}; sold.rows.forEach(r => soldM[r.sku] = r.u);
    const retM = {}; returns.rows.forEach(r => retM[r.sku] = r.c);
    const refM = {}; refunds.rows.forEach(r => refM[r.sku] = r.u);
    const canM = {}; cancels.rows.forEach(r => canM[r.sku] = r.u);
    const reasonM = {}; reasons.rows.forEach(r => (reasonM[r.sku] = reasonM[r.sku] || []).push({ reason: r.reason, c: r.c }));
    // only score SKUs with enough sales to be meaningful
    const MIN_SOLD = 10;
    const skus = Object.keys(soldM).filter(s => soldM[s] >= MIN_SOLD);
    const names = await resolveNames(skus);
    const pct = (n, d) => d > 0 ? Math.round((n / d) * 1000) / 10 : 0;
    const rows = skus.map(sku => {
      const u = soldM[sku];
      const returnRate = pct(retM[sku] || 0, u), refundRate = pct(refM[sku] || 0, u), cancelRate = pct(canM[sku] || 0, u);
      const score = Math.round((returnRate + refundRate + cancelRate) * 10) / 10;
      return { sku, name: names[sku] || sku, sold: u, returns: retM[sku] || 0, refunds: refM[sku] || 0, cancels: canM[sku] || 0,
        returnRate, refundRate, cancelRate, score, reasons: (reasonM[sku] || []).sort((a, b) => b.c - a.c).slice(0, 4) };
    }).filter(r => r.score > 0).sort((a, b) => b.score - a.score);
    res.json({ window: win, min_sold: MIN_SOLD, rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// normalise any product name OR Gorgias model value to one canonical model label so the two data
// worlds (SKU-keyed Shopify/returns vs Model-keyed Gorgias tickets) can be joined. Best-effort.
function canonicalModel(s) {
  let t = String(s || '').toLowerCase();
  if (!t) return null;
  // Gorgias values are hierarchical ("iPhone::iPhone 15::15 Pro") — collapse to brand + leaf so the
  // leaf's variant (15 Pro) isn't lost and it lines up with Shopify names ("15 Pro - Royal Ink")
  if (t.includes('::')) { const seg = t.split('::').map(x => x.trim()); t = seg[0] + ' ' + seg[seg.length - 1]; }
  if (/power keyboard/.test(t)) return 'Power Keyboard';
  if (/communicator/.test(t)) return 'Communicator';
  if (/lanyard/.test(t)) return 'Lanyard';
  if (/razr.*ultra|ultra onyx|60 ultra/.test(t)) return 'Razr Ultra 2025';
  if (/razr.*(plus|\+).*(2025|60)|razr.*60\+/.test(t)) return 'Razr Plus 2025';
  if (/razr.*(2025|\b60\b)/.test(t)) return 'Razr 2025';
  if (/razr.*(plus|\+).*(2024|50)|razr.*50\+/.test(t)) return 'Razr Plus 2024';
  if (/razr.*(2024|\b50\b)/.test(t)) return 'Razr 2024';
  if (/razr|top cover/.test(t)) return 'Razr';
  let m = t.match(/pixel\s*(10|9|8)\s*(pro xl|pro)?/);
  if (m) return `Pixel ${m[1]}${m[2] ? ' ' + m[2].replace(/\b\w/g, c => c.toUpperCase()) : ''}`;
  if (/flip\s*7/.test(t)) return 'Samsung Flip 7';
  if (/flip\s*6/.test(t)) return 'Samsung Flip 6';
  m = t.match(/\bs(25|24|23)\s*(ultra|plus|\+)?/);
  if (m) return `Samsung S${m[1]}${m[2] ? ' ' + (m[2] === '+' ? 'Plus' : m[2].replace(/\b\w/g, c => c.toUpperCase())) : ''}`;
  m = t.match(/\b(17|16|15|14|13)\s*(pro max|pro|plus|air|mini|e)?/);
  if (m) return `iPhone ${m[1]}${m[2] ? ' ' + m[2].replace(/\b\w/g, c => c.toUpperCase()) : ''}`;
  return null;
}
// per-model quality: joins Shopify (units/cancels/refunds), Redo (returns + reasons) via SKU→model,
// and Gorgias tickets (cancel / defect / warranty) via the model custom field.
app.get('/api/quality/models', async (req, res) => {
  try {
    const win = Math.max(7, Math.min(parseInt(req.query.window) || 90, 366));
    const iv = `now() - make_interval(days => ${win})`;
    const skuField = `it->>'sku'`;
    const [sold, cancels, refunds, returns, reasons, tickets] = await Promise.all([
      pool.query(`SELECT ${skuField} sku, max(it->>'title') title, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE cancelled_at IS NULL AND created_at >= ${iv} AND coalesce(${skuField},'') <> '' GROUP BY 1`),
      pool.query(`SELECT ${skuField} sku, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv} AND coalesce(${skuField},'') <> '' GROUP BY 1`),
      pool.query(`SELECT ${skuField} sku, sum(coalesce((it->>'qty')::int,0))::int u
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE financial_status IN ('refunded','partially_refunded') AND created_at >= ${iv} AND coalesce(${skuField},'') <> '' GROUP BY 1`),
      pool.query(`SELECT i->>'sku' sku, max(i->>'title') title, count(*)::int c
        FROM returns_cache, LATERAL jsonb_array_elements(items) i
        WHERE created_at >= ${iv} AND coalesce(i->>'sku','') <> '' GROUP BY 1`),
      pool.query(`SELECT i->>'sku' sku, coalesce(nullif(i->>'reason',''),'(none)') reason, count(*)::int c
        FROM returns_cache, LATERAL jsonb_array_elements(items) i
        WHERE created_at >= ${iv} AND coalesce(i->>'sku','') <> '' GROUP BY 1,2`),
      pool.query(`SELECT cf_model,
          count(*) FILTER (WHERE cf_category ILIKE '%cancellation%' OR cf_ai_intent ILIKE 'Order::Cancel%')::int cancel_t,
          count(*) FILTER (WHERE cf_category ILIKE '%technical support%' OR cf_category ILIKE '%hardware%' OR cf_category ILIKE '%software%')::int defect_t,
          count(*) FILTER (WHERE cf_category ILIKE '%warranty%' OR cf_solved_by ILIKE '%replacement%')::int warranty_t
        FROM tickets_cache WHERE NOT spam AND created_datetime >= ${iv} AND cf_model <> '' GROUP BY 1`)
    ]);
    // resolve names for all SKUs so we can map SKU→model
    const allSkus = [...new Set([...sold.rows, ...cancels.rows, ...refunds.rows, ...returns.rows].map(r => r.sku))];
    const nameMap = await resolveNames(allSkus);
    const M = {}; // canonical model → aggregates
    const ensure = k => (M[k] = M[k] || { model: k, sold: 0, cancels: 0, refunds: 0, returns: 0, cancel_t: 0, defect_t: 0, warranty_t: 0, reasons: {} });
    const skuModel = sku => canonicalModel(nameMap[sku] || sku) || 'Other / unmapped';
    sold.rows.forEach(r => { ensure(canonicalModel(nameMap[r.sku] || r.title || r.sku) || 'Other / unmapped').sold += r.u; });
    cancels.rows.forEach(r => { ensure(skuModel(r.sku)).cancels += r.u; });
    refunds.rows.forEach(r => { ensure(skuModel(r.sku)).refunds += r.u; });
    returns.rows.forEach(r => { ensure(canonicalModel(nameMap[r.sku] || r.title || r.sku) || 'Other / unmapped').returns += r.c; });
    reasons.rows.forEach(r => { const k = canonicalModel(nameMap[r.sku] || r.sku) || 'Other / unmapped'; const m = ensure(k); m.reasons[r.reason] = (m.reasons[r.reason] || 0) + r.c; });
    tickets.rows.forEach(r => { const k = canonicalModel(r.cf_model) || 'Other / unmapped'; const m = ensure(k); m.cancel_t += r.cancel_t; m.defect_t += r.defect_t; m.warranty_t += r.warranty_t; });
    const rows = Object.values(M).map(m => ({
      ...m, reasons: Object.entries(m.reasons).map(([reason, c]) => ({ reason, c })).sort((a, b) => b.c - a.c).slice(0, 3),
      problems: m.cancels + m.refunds + m.returns + m.cancel_t + m.defect_t + m.warranty_t
    })).sort((a, b) => b.problems - a.problems);
    res.json({ window: win, rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// product cancellation explorer: cancelled units + reasons per product; ?sku= drills into one product
app.get('/api/shopify/cancellations', async (req, res) => {
  try {
    const win = Math.max(1, Math.min(parseInt(req.query.window) || 90, 366));
    const iv = `now() - make_interval(days => ${win})`;
    const conn = await getConnector('shopify');
    const adminBase = shopifyAdminOrderBase(conn?.config?.store_domain);
    const reasonLabel = `coalesce(nullif(cancel_reason,''),'(unknown)')`;
    if (req.query.sku) {
      const sku = String(req.query.sku);
      const [orders, byReason] = await Promise.all([
        pool.query(`SELECT shopify_id, order_number, to_char(cancelled_at,'YYYY-MM-DD') d, ${reasonLabel} reason,
            (SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it WHERE it->>'sku'=$1)::int qty
          FROM orders_cache
          WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv}
            AND EXISTS (SELECT 1 FROM jsonb_array_elements(items) it WHERE it->>'sku'=$1)
          ORDER BY cancelled_at DESC LIMIT 200`, [sku]),
        pool.query(`SELECT ${reasonLabel} reason, count(*)::int orders,
            sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it WHERE it->>'sku'=$1))::int units
          FROM orders_cache
          WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv}
            AND EXISTS (SELECT 1 FROM jsonb_array_elements(items) it WHERE it->>'sku'=$1)
          GROUP BY 1 ORDER BY 2 DESC`, [sku])
      ]);
      const nm = await resolveNames([sku]);
      return res.json({ sku, name: nm[sku] || sku, admin_base: adminBase, reasons: byReason.rows, orders: orders.rows });
    }
    const [products, reasons] = await Promise.all([
      pool.query(`SELECT it->>'sku' sku, max(it->>'title') title,
          sum(coalesce((it->>'qty')::int,0))::int units, count(distinct shopify_id)::int orders
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv} AND coalesce(it->>'sku','') <> ''
        GROUP BY 1 ORDER BY 3 DESC`),
      pool.query(`SELECT ${reasonLabel} reason, count(*)::int orders FROM orders_cache
        WHERE cancelled_at IS NOT NULL AND cancelled_at >= ${iv} GROUP BY 1 ORDER BY 2 DESC`)
    ]);
    const names = await resolveNames(products.rows.map(r => r.sku));
    const rows = products.rows.map(r => ({ sku: r.sku, name: names[r.sku] || r.title || r.sku, units: r.units, orders: r.orders }));
    res.json({ window: win, admin_base: adminBase, rows, reasons: reasons.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// import a spreadsheet (CSV): rows = products, columns = inventory sources. ShipBob/Floship columns are ignored (API is source of truth).
function parseCsv(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) { if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; }
    else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; }
    else if (ch === '\r') { /* skip */ }
    else cell += ch;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows.filter(r => r.some(c => String(c).trim() !== ''));
}
app.post('/api/inventory/import', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const all = parseCsv(String(req.body?.csv || ''));
  // find the real header row (the one with a "SKU" cell) so preamble rows like "Updated / Inventory" are skipped
  let hIdx = all.findIndex(r => r.some(c => /^\s*sku\s*$/i.test(String(c))));
  if (hIdx < 0) hIdx = 0;
  const header = all[hIdx].map(h => String(h).trim());
  const rows = all.slice(hIdx); // header + data (loop starts at r=1 below)
  if (rows.length < 2) return res.status(400).json({ error: 'Need a header row (with a SKU column) plus at least one data row.' });
  const idxSku = header.findIndex(h => /^sku$/i.test(h)) >= 0 ? header.findIndex(h => /^sku$/i.test(h)) : 0;
  const idxDesc = header.findIndex(h => /desc|name|product|title/i.test(h));
  const apiRe = /shipbob|floship|flowship/i;         // API-owned: don't import values, but remember their column position
  const dropRe = /available|^total$|^units$/i;        // computed columns: ignore entirely
  const sourceCols = header.map((h, i) => ({ label: h, i }))
    .filter(c => c.i !== idxSku && c.i !== idxDesc && c.label && !apiRe.test(c.label) && !dropRe.test(c.label));
  if (!sourceCols.length) return res.status(400).json({ error: 'No importable source columns found (ShipBob/Floship columns are ignored on purpose).' });
  const sourcesPresent = sourceCols.map(c => c.label);
  const skipped = header.filter(h => apiRe.test(h));
  const client = await pool.connect();
  let imported = 0, skus = 0;
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM manual_stock WHERE source = ANY($1)', [sourcesPresent]); // refresh these columns
    // record column order (so the grid matches the sheet's left-to-right layout, incl. where ShipBob/Floship sit)
    for (let i = 0; i < header.length; i++) {
      const h = header[i];
      if (i === idxSku || i === idxDesc || dropRe.test(h) || !h) continue;
      const key = apiRe.test(h) ? (/floship|flowship/i.test(h) ? 'floship' : 'shipbob') : h;
      await client.query(`INSERT INTO inv_source_ord (source, ord) VALUES ($1,$2) ON CONFLICT (source) DO UPDATE SET ord=$2`, [key, i]);
    }
    let ord = 0;
    for (let r = 1; r < rows.length; r++) {
      const cells = rows[r];
      const sku = String(cells[idxSku] || '').trim();
      if (!sku || !/[A-Za-z]/.test(sku) || /-top$/i.test(sku)) continue; // skip blank, all-numeric, and -TOP SKUs
      const desc = idxDesc >= 0 ? String(cells[idxDesc] || '').trim().slice(0, 300) : '';
      await client.query(`INSERT INTO inv_sku_ord (sku, ord) VALUES ($1,$2) ON CONFLICT (sku) DO UPDATE SET ord=$2`, [sku, ord++]);
      let any = false;
      for (const c of sourceCols) {
        const raw = String(cells[c.i] ?? '').replace(/[, ]/g, '').trim();
        if (raw === '') continue;
        const qty = parseInt(raw, 10);
        if (!Number.isFinite(qty)) continue;
        await client.query(
          `INSERT INTO manual_stock (sku, source, qty, description, updated_at) VALUES ($1,$2,$3,$4,now())
           ON CONFLICT (sku, source) DO UPDATE SET qty=$3, description=$4, updated_at=now()`,
          [sku, c.label, qty, desc]);
        imported++; any = true;
      }
      if (any) skus++;
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); return res.status(400).json({ error: e.message }); }
  finally { client.release(); }
  res.json({ ok: true, imported, skus, sources: sourcesPresent, skipped });
});
// list the imported (manual) sources so admins can clear one
app.get('/api/inventory/manual-sources', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const rows = (await pool.query(`SELECT source, count(*)::int rows, max(updated_at) updated FROM manual_stock GROUP BY 1 ORDER BY 1`)).rows;
  res.json(rows);
});
app.post('/api/inventory/clear-source', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const src = String(req.body?.source || '');
  const r = await pool.query('DELETE FROM manual_stock WHERE source=$1', [src]);
  await pool.query('DELETE FROM inv_source_ord WHERE source=$1', [src]).catch(() => {});
  res.json({ ok: true, removed: r.rowCount });
});

// ---------- Shopify (orders sync, same pattern as Gorgias) ----------
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2026-01';

// 2026 flow: apps are created in the Dev Dashboard; the server exchanges client_id/client_secret
// for a 24h access token (client credentials grant) and refreshes it automatically.
const shopifyTokenCache = {};
async function getShopifyToken(cfg) {
  if (cfg.admin_token) return cfg.admin_token; // legacy custom-app tokens still honored
  const k = `${cfg.store_domain}:${cfg.client_id}`;
  const c = shopifyTokenCache[k];
  if (c && Date.now() < c.exp - 5 * 60 * 1000) return c.token;
  const r = await fetch(`https://${cfg.store_domain}.myshopify.com/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: cfg.client_id, client_secret: cfg.client_secret })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    throw new Error(`Shopify token exchange failed (${r.status}): ${j.error_description || j.error || 'check client ID/secret and that the app is installed on this store'}`);
  }
  shopifyTokenCache[k] = { token: j.access_token, exp: Date.now() + (j.expires_in || 86399) * 1000, scope: j.scope || '' };
  return j.access_token;
}

// GraphQL Admin API — REST is unavailable to apps created after Shopify's 2025/2026 cutoff
async function shopifyGraphql(cfg, query, variables = {}) {
  const token = await getShopifyToken(cfg);
  const r = await fetch(`https://${cfg.store_domain}.myshopify.com/admin/api/${SHOPIFY_API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Shopify GraphQL → ${r.status}`);
  if (j.errors?.length) {
    const msg = j.errors.map(e => e.message).join('; ').slice(0, 300);
    if (/access denied/i.test(msg)) {
      // scopes may have just changed — drop the cached token so the next call gets a fresh one
      delete shopifyTokenCache[`${cfg.store_domain}:${cfg.client_id}`];
    }
    throw new Error(`Shopify GraphQL: ${msg}`);
  }
  return j.data;
}

const ORDERS_QUERY = `
query Orders($cursor: String, $q: String, $sortKey: OrderSortKeys!) {
  orders(first: 50, after: $cursor, query: $q, sortKey: $sortKey, reverse: true) {
    pageInfo { hasNextPage endCursor }
    nodes {
      legacyResourceId name createdAt updatedAt cancelledAt cancelReason closedAt tags
      currencyCode
      totalPriceSet { shopMoney { amount } }
      displayFinancialStatus displayFulfillmentStatus
      fulfillments(first: 20) { createdAt }
      shippingAddress { countryCodeV2 }
      lineItems(first: 20) { nodes { title sku quantity } }
    }
  }
}`;

function normalizeOrder(n) {
  return {
    id: Number(n.legacyResourceId),
    name: n.name || '',
    created_at: n.createdAt || null,
    cancelled_at: n.cancelledAt || null,
    cancel_reason: n.cancelReason || '', // Shopify enum: CUSTOMER, INVENTORY, FRAUD, DECLINED, STAFF, OTHER
    archived_at: n.closedAt || null, // Shopify "archived" = order closed
    updated_at: n.updatedAt || null,
    currency: n.currencyCode || '',
    total_price: n.totalPriceSet?.shopMoney?.amount || 0,
    country: n.shippingAddress?.countryCodeV2 || '',
    financial_status: (n.displayFinancialStatus || '').toLowerCase(),
    fulfillment_status: (n.displayFulfillmentStatus || 'unfulfilled').toLowerCase(),
    // actual fulfillment date = latest fulfillment's createdAt (null if never fulfilled).
    // this is the real date goods shipped — distinct from the order's createdAt.
    fulfilled_at: (() => {
      const ds = (n.fulfillments || []).map(f => f.createdAt).filter(Boolean).sort();
      return ds.length ? ds[ds.length - 1] : null;
    })(),
    tags: Array.isArray(n.tags) ? n.tags : [],
    line_items: (n.lineItems?.nodes || []).map(li => ({ title: li.title, sku: li.sku, quantity: li.quantity }))
  };
}

async function fetchOrdersPage(cfg, { cursor = null, q = null, sortKey = 'UPDATED_AT' } = {}) {
  const d = await shopifyGraphql(cfg, ORDERS_QUERY, { cursor, q, sortKey });
  return {
    orders: (d.orders?.nodes || []).map(normalizeOrder),
    next: d.orders?.pageInfo?.hasNextPage ? d.orders.pageInfo.endCursor : null
  };
}

let shopifySyncRunning = false;
async function syncShopify(maxPages = 8) {
  if (shopifySyncRunning) return { skipped: true };
  const conn = await getConnector('shopify');
  if (!conn) return { configured: false };
  const cfg = conn.config;
  shopifySyncRunning = true;
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v || {};
  if (st.engine !== 'graphql-v5') { // v5: re-backfill to capture cancelReason; v4 archived; v3 fulfillment dates
    st.engine = 'graphql-v5'; st.backfill_cursor = null; st.backfill_done = false; st.last_error = null;
  }
  let pages = 0, upserts = 0, lastError = null;
  const horizonIso = new Date(Date.now() - BACKFILL_HORIZON_DAYS * 864e5).toISOString();

  const upsertOrders = async (orders) => {
    for (const o of orders) {
      await pool.query(
        `INSERT INTO orders_cache (shopify_id, order_number, created_at, cancelled_at, currency, total_price, country, financial_status, fulfillment_status, items, order_tags, updated_at, fulfilled_at, archived_at, cancel_reason, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now())
         ON CONFLICT (shopify_id) DO UPDATE SET order_number=$2, created_at=$3, cancelled_at=$4, currency=$5,
           total_price=$6, country=$7, financial_status=$8, fulfillment_status=$9, items=$10, order_tags=$11, updated_at=$12, fulfilled_at=$13, archived_at=$14, cancel_reason=$15, synced_at=now()`,
        [o.id, o.name || '', o.created_at || null, o.cancelled_at || null, o.currency || '',
         Number(o.total_price) || 0,
         o.country || '',
         o.financial_status || '', o.fulfillment_status || 'unfulfilled',
         JSON.stringify((o.line_items || []).map(li => ({ title: li.title, sku: li.sku, qty: li.quantity }))),
         JSON.stringify(o.tags || []),
         o.updated_at || null, o.fulfilled_at || null, o.archived_at || null, o.cancel_reason || '']);
      upserts++;
    }
  };

  try {
    // incremental: everything updated since last run (UPDATED_AT desc, stop when older than last sync)
    if (st.last_updated) {
      const lastUpd = Date.parse(st.last_updated);
      let cursor = null, newest = null, done = false;
      while (pages < maxPages && !done) {
        const { orders, next } = await fetchOrdersPage(cfg, { cursor, sortKey: 'UPDATED_AT' });
        if (!orders.length) break;
        await upsertOrders(orders);
        if (!newest) newest = orders[0]?.updated_at || null;
        pages++;
        const oldest = orders[orders.length - 1]?.updated_at;
        cursor = next;
        if (!cursor || (oldest && Date.parse(oldest) < lastUpd)) done = true;
      }
      if (newest) st.last_updated = newest;
    }
    // backfill: CREATED_AT desc within the horizon, resumable across runs
    while (!st.backfill_done && pages < maxPages) {
      const { orders, next } = await fetchOrdersPage(cfg, {
        cursor: st.backfill_cursor || null,
        q: `created_at:>='${horizonIso}'`,
        sortKey: 'CREATED_AT'
      });
      if (!orders.length) { st.backfill_done = true; break; }
      await upsertOrders(orders);
      pages++;
      if (!st.last_updated) st.last_updated = new Date().toISOString();
      st.backfill_oldest = orders[orders.length - 1]?.created_at || st.backfill_oldest;
      st.backfill_cursor = next;
      if (!next) st.backfill_done = true;
    }
  } catch (e) {
    lastError = String(e.message);
    console.error('shopify sync error:', lastError);
  } finally {
    const cached = (await pool.query('SELECT count(*)::int c FROM orders_cache')).rows[0].c;
    await pool.query(
      `INSERT INTO sync_state (k, v) VALUES ('shopify', $1) ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ ...st, last_run: new Date().toISOString(), upserts, pages, cached, last_error: lastError })])
      .catch(e => console.error('shopify sync_state write:', e.message));
    shopifySyncRunning = false;
    overviewCache.clear();
  }
  return { configured: true, pages, upserts, backfill_done: !!st.backfill_done, error: lastError };
}

// build the new-style Shopify admin order link base: https://admin.shopify.com/store/<handle>/orders/
// store_domain may be "clickstech.myshopify.com" or "clickstech" → handle = "clickstech"
function shopifyAdminOrderBase(storeDomain) {
  const handle = String(storeDomain || '').trim().replace(/^https?:\/\//, '').split('.')[0];
  return handle ? `https://admin.shopify.com/store/${handle}/orders/` : null;
}

app.get('/api/shopify/summary', async (_req, res) => {
  try {
    const conn = await getConnector('shopify');
    const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v || null;
    const has = (await pool.query('SELECT 1 FROM orders_cache LIMIT 1')).rows.length > 0;
    let granted_scopes = null;
    if (conn) {
      try { await getShopifyToken(conn.config); granted_scopes = shopifyTokenCache[`${conn.config.store_domain}:${conn.config.client_id}`]?.scope ?? null; }
      catch (e) { granted_scopes = `token error: ${e.message}`; }
    }
    if (!has) return res.json({ configured: !!conn, empty: true, sync: ss, granted_scopes });
    // ---- filters: window (?days / ?from&to) + product / country / tag ----
    const win = resolveWindow(_req.query);
    const p = [win.start.toISOString(), win.end.toISOString()];
    const cond = ['created_at >= $1', 'created_at < $2'];
    // all-time awaiting list: honors product/country/tag but not the date window — its own param array
    const xp = [], xcond = [];
    const { product, country, tag } = _req.query;
    if (country) { p.push(country); cond.push(`country = $${p.length}`); xp.push(country); xcond.push(`country = $${xp.length}`); }
    if (tag) { p.push(tag); cond.push(`order_tags ? $${p.length}`); xp.push(tag); xcond.push(`order_tags ? $${xp.length}`); }
    if (product) {
      p.push(product); cond.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(items) it WHERE it->>'title' = $${p.length})`);
      xp.push(product); xcond.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(items) it WHERE it->>'title' = $${xp.length})`);
    }
    const W = cond.join(' AND ');
    const WX = xcond.length ? xcond.join(' AND ') : 'true';
    const [tot, countries, products, recent] = await Promise.all([
      pool.query(`SELECT count(*) FILTER (WHERE cancelled_at IS NULL)::int orders,
        round(sum(total_price) FILTER (WHERE cancelled_at IS NULL))::int revenue,
        count(*) FILTER (WHERE cancelled_at IS NOT NULL)::int cancelled,
        count(*) FILTER (WHERE financial_status IN ('refunded','partially_refunded'))::int refunded,
        count(*) FILTER (WHERE fulfillment_status='fulfilled' AND cancelled_at IS NULL)::int fulfilled,
        count(*) FILTER (WHERE fulfillment_status<>'fulfilled' AND cancelled_at IS NULL)::int unfulfilled,
        max(currency) currency
        FROM orders_cache WHERE ${W}`, p),
      pool.query(`SELECT country, round(sum(total_price))::int revenue, count(*)::int orders
        FROM orders_cache WHERE ${W} AND cancelled_at IS NULL AND country <> ''
        GROUP BY 1 ORDER BY 2 DESC LIMIT 6`, p),
      pool.query(`SELECT it->>'title' product, max(nullif(it->>'sku','')) sku, sum(coalesce((it->>'qty')::int,0))::int qty
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE ${W} AND cancelled_at IS NULL
        GROUP BY 1 ORDER BY 3 DESC LIMIT 6`, p),
      pool.query(`SELECT order_number, created_at::date d, country, total_price, currency, financial_status, fulfillment_status,
        order_tags, (cancelled_at IS NOT NULL) cancelled FROM orders_cache WHERE ${W} ORDER BY created_at DESC LIMIT 12`, p)
    ]);
    const orderTags = (await pool.query(
      `SELECT t.tag, count(*)::int c FROM orders_cache, LATERAL jsonb_array_elements_text(order_tags) t(tag)
       WHERE ${W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8`, p)).rows;
    // fulfillment breakdown + orders still awaiting fulfillment, oldest first (actionable)
    const fulfil = (await pool.query(
      `SELECT lower(coalesce(nullif(fulfillment_status,''),'unfulfilled')) status, count(*)::int c
       FROM orders_cache WHERE ${W} AND cancelled_at IS NULL
       GROUP BY 1 ORDER BY 2 DESC`, p)).rows;
    // "awaiting" = genuinely actionable open orders. Exclude cancelled, archived (closed),
    // refunded/voided, and anything older than our sync horizon (data we can't keep fresh → likely a stale artifact).
    const awaiting = (await pool.query(
      `SELECT shopify_id, order_number, created_at::date d, country, total_price, currency, financial_status, fulfillment_status,
       floor(extract(epoch from now()-created_at)/86400)::int age_days
       FROM orders_cache
       WHERE ${WX} AND cancelled_at IS NULL AND archived_at IS NULL
         AND financial_status NOT IN ('refunded','voided')
         AND fulfillment_status NOT IN ('fulfilled','restocked')
         AND created_at >= now() - interval '${BACKFILL_HORIZON_DAYS} days'
       ORDER BY created_at ASC LIMIT 30`, xp)).rows;
    // filter option lists (over last 365d, independent of active filters, so dropdowns stay stable)
    const [optCountries, optTags, optProducts] = await Promise.all([
      pool.query(`SELECT country, count(*)::int c FROM orders_cache
        WHERE created_at >= now()-interval '365 days' AND country <> '' GROUP BY 1 ORDER BY 2 DESC LIMIT 100`),
      pool.query(`SELECT t.tag, count(*)::int c FROM orders_cache, LATERAL jsonb_array_elements_text(order_tags) t(tag)
        WHERE created_at >= now()-interval '365 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 100`),
      pool.query(`SELECT it->>'title' product, max(nullif(it->>'sku','')) sku, sum(coalesce((it->>'qty')::int,0))::int qty
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE created_at >= now()-interval '365 days' AND it->>'title' <> ''
        GROUP BY 1 ORDER BY 3 DESC LIMIT 200`)
    ]);
    const adminBase = shopifyAdminOrderBase(conn?.config?.store_domain);
    res.json({ configured: true, totals_30d: tot.rows[0], top_countries: countries.rows, top_products: products.rows,
      top_order_tags: orderTags, fulfillment: fulfil, awaiting, recent: recent.rows, sync: ss, admin_base: adminBase,
      days: win.days, custom: win.custom, from: p[0], to: p[1],
      filters: { active: { product: product || null, country: country || null, tag: tag || null },
        countries: optCountries.rows.map(r => r.country),
        tags: optTags.rows.map(r => r.tag),
        products: optProducts.rows.map(r => ({ product: r.product, sku: r.sku })) } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Fulfillments keyed to the ACTUAL fulfillment date (fulfilled_at), not order creation.
// ?days=N → per-day counts; ?date=YYYY-MM-DD → the specific orders fulfilled that day (for spot-checking in Shopify).
app.get('/api/shopify/fulfillments', async (req, res) => {
  try {
    const conn = await getConnector('shopify');
    const adminBase = shopifyAdminOrderBase(conn?.config?.store_domain);
    const backfillDone = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v?.backfill_done ?? null;

    // optional filters shared with the Shopify card (product / country / tag)
    const { product, country, tag } = req.query;
    const addFilters = (p, cond) => {
      if (country) { p.push(country); cond.push(`country = $${p.length}`); }
      if (tag) { p.push(tag); cond.push(`order_tags ? $${p.length}`); }
      if (product) { p.push(product); cond.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(items) it WHERE it->>'title' = $${p.length})`); }
    };

    if (req.query.date) {
      const day = String(req.query.date).slice(0, 10);
      const p = [day], cond = [`fulfilled_at >= $1::date`, `fulfilled_at < ($1::date + interval '1 day')`];
      addFilters(p, cond);
      const orders = (await pool.query(
        `SELECT shopify_id, order_number, created_at, fulfilled_at, country, total_price, currency, fulfillment_status, items,
           floor(extract(epoch from (fulfilled_at - created_at))/86400)::int days_to_fulfill
         FROM orders_cache
         WHERE ${cond.join(' AND ')}
         ORDER BY fulfilled_at ASC LIMIT 500`, p)).rows;
      return res.json({ date: day, admin_base: adminBase, backfill_done: backfillDone, count: orders.length, orders });
    }

    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 366);
    const start = new Date(Date.now() - days * 864e5).toISOString();
    const p = [start], cond = [`fulfilled_at >= $1`, `cancelled_at IS NULL`];
    addFilters(p, cond);
    const byDay = (await pool.query(
      `SELECT to_char(fulfilled_at::date,'YYYY-MM-DD') d, count(*)::int orders,
         coalesce(sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it)),0)::int units
       FROM orders_cache
       WHERE ${cond.join(' AND ')}
       GROUP BY 1 ORDER BY 1 DESC`, p)).rows;
    res.json({ days, admin_base: adminBase, backfill_done: backfillDone, by_day: byDay });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/shopify/sync', async (_req, res) => {
  try {
    const r = await syncShopify(30);
    syncShopifyProducts().catch(e => console.error('product resync:', e.message)); // refresh titles/variants in background
    res.json(r);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- overview stats (from local cache → any period) ----------
const CANCEL_RX = 'cancel|refund|return|chargeback';
// ≤31d daily, otherwise weekly
const bucketFor = days => days <= 31 ? 'day' : 'week';
// resolve a time window from query params: ?days=N (preset) or ?from=ISO&to=ISO (custom)
function resolveWindow(query) {
  const from = query.from ? new Date(query.from) : null;
  const to = query.to ? new Date(query.to) : null;
  if (from && to && !isNaN(from) && !isNaN(to) && from < to) {
    const days = Math.max(1, Math.round((to - from) / 864e5));
    return { start: from, end: to, days, bucket: bucketFor(days), custom: true };
  }
  const days = Math.min(Math.max(parseInt(query.days) || 7, 1), 366);
  return { start: new Date(Date.now() - days * 864e5), end: new Date(), days, bucket: bucketFor(days), custom: false };
}

async function overviewStats(win) {
  if (typeof win !== 'object') win = resolveWindow({ days: win }); // back-compat for callers passing days
  const { bucket } = win;
  const params = [win.start.toISOString(), win.end.toISOString()];
  const days = win.days;
  const CATS = {
    cancel_refund: "subject ~* 'cancel|refund|chargeback' OR tags::text ~* 'cancel|refund|chargeback'",
    troubleshoot: "subject ~* 'trouble|not work|broken|defect|faulty|error|bug|stopped|repair' OR tags::text ~* 'troubleshoot|defect|bug'",
    shipping: "subject ~* 'ship|deliver|tracking|arriv|customs|where.*order' OR tags::text ~* 'shipping|delivery|wismo'",
    returns_warranty: "subject ~* 'return|warranty|replac|exchange' OR tags::text ~* 'return|warranty|exchange'",
    product_question: "subject ~* 'compatib|fit|work with|which model|pre.?order|available' OR tags::text ~* 'presales|product'"
  };
  const catSelects = Object.entries(CATS)
    .map(([k, cond]) => `count(*) FILTER (WHERE ${cond})::int ${k}`).join(', ');
  // spam and trashed tickets are excluded everywhere to match Gorgias's "All" view / reporting
  const mkCount = (col, extra = '') =>
    `SELECT date_trunc('${bucket}', ${col})::date d, count(*)::int c FROM tickets_cache
     WHERE ${col} >= $1 AND ${col} < $2 AND NOT spam ${extra} GROUP BY 1 ORDER BY 1`;
  const mkCats = (col, extra = '') =>
    `SELECT date_trunc('${bucket}', ${col})::date d, ${catSelects} FROM tickets_cache
     WHERE ${col} >= $1 AND ${col} < $2 AND NOT spam ${extra} GROUP BY 1 ORDER BY 1`;
  const mkTags = (col, extra = '') =>
    `SELECT date_trunc('${bucket}', ${col})::date d, t.tag, count(*)::int c
     FROM tickets_cache, LATERAL jsonb_array_elements_text(tags) t(tag)
     WHERE ${col} >= $1 AND ${col} < $2 AND NOT spam ${extra} GROUP BY 1, 2 ORDER BY 1, 3 DESC`;
  // "tickets to solve" = open backlog at the END of each bucket: created by then and not yet closed by then
  const backlogQuery =
    `SELECT to_char(g.b::date,'YYYY-MM-DD') d,
       (SELECT count(*)::int FROM tickets_cache t
        WHERE NOT t.spam AND t.created_datetime < g.b + interval '1 ${bucket}'
          AND (t.closed_datetime IS NULL OR t.closed_datetime >= g.b + interval '1 ${bucket}')) c
     FROM generate_series(date_trunc('${bucket}', $1::timestamptz), date_trunc('${bucket}', $2::timestamptz), interval '1 ${bucket}') g(b)
     ORDER BY 1`;
  const [created, opened, closed,
         createdCats, openCats, closedCats,
         createdTags, openTags, closedTags,
         totals, events, st] = await Promise.all([
    pool.query(mkCount('created_datetime'), params),
    pool.query(backlogQuery, params),
    pool.query(mkCount('closed_datetime'), params),
    pool.query(mkCats('created_datetime'), params),
    pool.query(mkCats('created_datetime', "AND status='open'"), params),
    pool.query(mkCats('closed_datetime'), params),
    pool.query(mkTags('created_datetime'), params),
    pool.query(mkTags('created_datetime', "AND status='open'"), params),
    pool.query(mkTags('closed_datetime'), params),
    pool.query(`SELECT count(*)::int total,
                count(*) FILTER (WHERE status='open')::int open,
                count(*) FILTER (WHERE created_datetime >= $1 AND created_datetime < $2)::int created,
                count(*) FILTER (WHERE closed_datetime >= $1 AND closed_datetime < $2)::int closed,
                count(*) FILTER (WHERE created_datetime >= $1 AND created_datetime < $2 AND (subject ~* '${CANCEL_RX}' OR tags::text ~* '${CANCEL_RX}'))::int cancel_refund
                FROM tickets_cache WHERE NOT spam`, params),
    pool.query(`SELECT id, title, description, event_date, added_by, attachment_name FROM events
                WHERE event_date >= $1::date AND event_date <= ($2::date + interval '30 days')
                ORDER BY event_date`, params),
    pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)
  ]);
  const [salesSeries, cancelSeries, fulfilledSeries, salesTotals, shopifySt] = await Promise.all([
    pool.query(`SELECT date_trunc('${bucket}', created_at)::date d, count(*)::int orders, round(sum(total_price))::int revenue,
                count(*) FILTER (WHERE financial_status IN ('refunded','partially_refunded'))::int refunded
                FROM orders_cache WHERE created_at >= $1 AND created_at < $2 AND cancelled_at IS NULL GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT date_trunc('${bucket}', cancelled_at)::date d, count(*)::int c
                FROM orders_cache WHERE cancelled_at >= $1 AND cancelled_at < $2 GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT date_trunc('${bucket}', fulfilled_at)::date d,
                coalesce(sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it)),0)::int units
                FROM orders_cache WHERE fulfilled_at >= $1 AND fulfilled_at < $2 AND cancelled_at IS NULL
                GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT count(*) FILTER (WHERE cancelled_at IS NULL)::int orders,
                round(sum(total_price) FILTER (WHERE cancelled_at IS NULL))::int revenue,
                count(*) FILTER (WHERE cancelled_at IS NOT NULL)::int cancelled,
                count(*) FILTER (WHERE financial_status IN ('refunded','partially_refunded'))::int refunded,
                count(*) FILTER (WHERE fulfillment_status='fulfilled' AND cancelled_at IS NULL)::int delivered,
                max(currency) currency
                FROM orders_cache WHERE created_at >= $1 AND created_at < $2`, params),
    pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)
  ]);
  const hasSales = (await pool.query('SELECT 1 FROM orders_cache LIMIT 1')).rows.length > 0;
  const campaigns = (await pool.query(
    `SELECT klaviyo_id, name, channel, to_char(send_time::date,'YYYY-MM-DD') d, recipients, open_rate, click_rate, revenue
     FROM campaigns_cache WHERE send_time >= $1 AND send_time <= $2 ORDER BY send_time`, params)).rows;
  return {
    days, bucket, custom: win.custom, from: params[0], to: params[1],
    tickets: {
      series: { created: created.rows, still_open: opened.rows, closed: closed.rows },
      breakdowns: {
        created: { cats: createdCats.rows, tags: createdTags.rows },
        still_open: { cats: [], tags: [] }, // point-in-time backlog: no per-day category split
        closed: { cats: closedCats.rows, tags: closedTags.rows }
      },
      totals: totals.rows[0]
    },
    sales: hasSales ? { series: salesSeries.rows, cancel_series: cancelSeries.rows, fulfilled_series: fulfilledSeries.rows, totals: salesTotals.rows[0], sync: shopifySt.rows[0]?.v || null } : null,
    events: events.rows,
    campaigns,
    last_sync: st.rows[0]?.v?.last_run || null,
    sync: st.rows[0]?.v || null
  };
}

const overviewCache = new Map(); // key → {t, v}; cleared after every sync
app.get('/api/stats/overview', async (req, res) => {
  try {
    maybeSync().catch(() => {}); // fire-and-forget, never blocks the response
    const win = resolveWindow(req.query);
    const key = win.custom ? `${req.query.from}|${req.query.to}` : `d${win.days}`;
    const hit = overviewCache.get(key);
    if (hit && Date.now() - hit.t < 5 * 60 * 1000) return res.json(hit.v); // cleared early whenever a sync lands
    const v = await overviewStats(win);
    overviewCache.set(key, { t: Date.now(), v });
    res.json(v);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- impact analyzer: how a metric moved around an event ----------
// metric registry — agg strings are fixed (never user input), so no injection risk
const IMPACT_METRICS = {
  orders:          { table: 'orders_cache', col: 'created_at',        agg: 'count(*)',                                                                                         where: 'cancelled_at IS NULL', label: 'Orders' },
  revenue:         { table: 'orders_cache', col: 'created_at',        agg: 'round(coalesce(sum(total_price),0))',                                                               where: 'cancelled_at IS NULL', label: 'Revenue', money: true },
  units_fulfilled: { table: 'orders_cache', col: 'fulfilled_at',      agg: "coalesce(sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it)),0)",   where: 'cancelled_at IS NULL', label: 'Units fulfilled' },
  cancelled:       { table: 'orders_cache', col: 'cancelled_at',      agg: 'count(*)',                                                                                         where: 'true', label: 'Cancelled orders' },
  returns:         { table: 'returns_cache', col: 'created_at',       agg: 'count(*)',                                                                                         where: 'true', label: 'Returns' },
  tickets_created: { table: 'tickets_cache', col: 'created_datetime', agg: 'count(*)',                                                                                         where: 'NOT spam', label: 'Tickets created' },
  tickets_closed:  { table: 'tickets_cache', col: 'closed_datetime',  agg: 'count(*)',                                                                                         where: 'NOT spam', label: 'Tickets closed' }
};
async function metricDailyMap(mkey, startISO, endISO) {
  const m = IMPACT_METRICS[mkey];
  const rows = (await pool.query(
    `SELECT to_char(date_trunc('day', ${m.col})::date,'YYYY-MM-DD') d, (${m.agg})::numeric v
     FROM ${m.table} WHERE ${m.col} >= $1 AND ${m.col} < $2 AND (${m.where}) GROUP BY 1`, [startISO, endISO])).rows;
  const map = {}; rows.forEach(r => { map[r.d] = Number(r.v) || 0; });
  return map;
}
// list of selectable events: Klaviyo sends + team-logged events
app.get('/api/impact/events', async (_req, res) => {
  try {
    const cmps = (await pool.query(
      `SELECT klaviyo_id, name, channel, to_char(send_time::date,'YYYY-MM-DD') d FROM campaigns_cache
       WHERE send_time IS NOT NULL ORDER BY send_time DESC LIMIT 300`)).rows
      .map(c => ({ id: 'kv' + c.klaviyo_id, label: c.name || '(campaign)', date: c.d, kind: 'campaign', sub: c.channel }));
    const evs = (await pool.query(
      `SELECT id, title, to_char(event_date,'YYYY-MM-DD') d FROM events ORDER BY event_date DESC LIMIT 300`)).rows
      .map(e => ({ id: 'ev' + e.id, label: e.title, date: e.d, kind: 'event', sub: 'team event' }));
    res.json([...cmps, ...evs].sort((a, b) => a.date < b.date ? 1 : -1));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/impact', async (req, res) => {
  try {
    const mkey = String(req.query.metric || 'orders');
    const m = IMPACT_METRICS[mkey];
    if (!m) return res.status(400).json({ error: 'unknown metric' });
    const window = Math.min(Math.max(parseInt(req.query.window) || 3, 1), 30);
    const dateStr = String(req.query.date || '').slice(0, 10);
    const D = new Date(dateStr + 'T00:00:00Z');
    if (isNaN(D)) return res.status(400).json({ error: 'bad date' });
    const addDays = (dt, n) => new Date(dt.getTime() + n * 864e5);
    const key = dt => dt.toISOString().slice(0, 10);
    const map = await metricDailyMap(mkey, addDays(D, -(window + 7)).toISOString(), addDays(D, window).toISOString());
    const sumRange = (from, days) => { let t = 0; for (let i = 0; i < days; i++) t += map[key(addDays(from, i))] || 0; return t; };
    const before = sumRange(addDays(D, -window), window);
    const after = sumRange(D, window);          // event day counts as day 0 of "after"
    const prevWeek = sumRange(addDays(D, -7), window);
    const series = [];
    for (let i = -window; i < window; i++) { const k = key(addDays(D, i)); series.push({ d: k, v: map[k] || 0 }); }
    // other events inside the window (confounders)
    const wStart = key(addDays(D, -window)), wEnd = key(addDays(D, window));
    const [evs, cmps] = await Promise.all([
      pool.query(`SELECT title label, to_char(event_date,'YYYY-MM-DD') d FROM events WHERE event_date >= $1::date AND event_date < $2::date`, [wStart, wEnd]),
      pool.query(`SELECT name label, to_char(send_time::date,'YYYY-MM-DD') d FROM campaigns_cache WHERE send_time >= $1 AND send_time < $2`, [addDays(D, -window).toISOString(), addDays(D, window).toISOString()])
    ]);
    const confounders = [...evs.rows.map(r => ({ ...r, kind: 'event' })), ...cmps.rows.map(r => ({ ...r, kind: 'campaign' }))];
    const currency = m.money ? ((await pool.query(`SELECT max(currency) c FROM orders_cache WHERE currency <> ''`)).rows[0]?.c || 'USD') : null;
    res.json({
      metric: mkey, label: m.label, money: !!m.money, currency, date: dateStr, window,
      before, after, prev_week: prevWeek,
      change_abs: after - before,
      change_pct: before > 0 ? Math.round((after - before) / before * 1000) / 10 : null,
      vs_prev_week_pct: prevWeek > 0 ? Math.round((after - prevWeek) / prevWeek * 1000) / 10 : null,
      series, confounders
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gorgias tab: synced-cache stats always; live extras (CSAT, FRT, all-time total) when the connector is available
app.get('/api/gorgias/stats', async (req, res) => {
  const cfg = await getGorgiasConfig();
  const win = resolveWindow(req.query);
  const { bucket, days } = win;
  const w = [win.start.toISOString(), win.end.toISOString()];
  const out = { configured: !!cfg, days, bucket, custom: win.custom, fetched_at: new Date().toISOString(), errors: [] };
  try {
    const c = await pool.query(`SELECT
      count(*)::int cached_total,
      count(*) FILTER (WHERE status='open')::int open_total,
      count(*) FILTER (WHERE created_datetime >= $1 AND created_datetime < $2)::int created_period,
      count(*) FILTER (WHERE closed_datetime >= $1 AND closed_datetime < $2)::int closed_period
      FROM tickets_cache WHERE NOT spam`, w);
    Object.assign(out, {
      cached_total: c.rows[0].cached_total,
      open_total: c.rows[0].open_total,
      created_last_7d: c.rows[0].created_period,
      closed_last_7d: c.rows[0].closed_period
    });
    const [perDay, perDayClosed] = await Promise.all([
      pool.query(`SELECT to_char(date_trunc('${bucket}', created_datetime)::date, 'YYYY-MM-DD') d, count(*)::int c FROM tickets_cache
                  WHERE created_datetime >= $1 AND created_datetime < $2 AND NOT spam GROUP BY 1 ORDER BY 1`, w),
      pool.query(`SELECT to_char(date_trunc('${bucket}', closed_datetime)::date, 'YYYY-MM-DD') d, count(*)::int c FROM tickets_cache
                  WHERE closed_datetime >= $1 AND closed_datetime < $2 AND NOT spam GROUP BY 1 ORDER BY 1`, w)
    ]);
    const daysMap = {}, closedMap = {};
    perDay.rows.forEach(r => { daysMap[r.d] = r.c; });
    perDayClosed.rows.forEach(r => { closedMap[r.d] = r.c; });
    out.created_per_day = daysMap;
    out.closed_per_day = closedMap;
    const [tags, channels, recent] = await Promise.all([
      pool.query(`SELECT t.tag, count(*)::int c FROM tickets_cache, LATERAL jsonb_array_elements_text(tags) t(tag)
                  WHERE created_datetime >= now()-interval '30 days' AND NOT spam GROUP BY 1 ORDER BY 2 DESC LIMIT 8`),
      pool.query(`SELECT coalesce(nullif(channel,''),'unknown') channel, count(*)::int c FROM tickets_cache
                  WHERE created_datetime >= now()-interval '30 days' AND NOT spam GROUP BY 1 ORDER BY 2 DESC LIMIT 8`),
      pool.query(`SELECT subject, status, channel, created_datetime::date d FROM tickets_cache
                  WHERE NOT spam ORDER BY created_datetime DESC LIMIT 10`)
    ]);
    out.top_tags = tags.rows;
    out.channels = channels.rows;
    out.recent = recent.rows;
    out.gorgias_domain = cfg?.domain || null;
    const [difficult, oldest] = await Promise.all([
      pool.query(`SELECT gorgias_id, subject, messages_count, status, created_datetime::date d FROM tickets_cache
                  WHERE NOT spam AND status='open' AND messages_count >= 10 ORDER BY messages_count DESC, created_datetime DESC LIMIT 10`),
      pool.query(`SELECT gorgias_id, subject, channel, created_datetime::date d,
                  floor(extract(epoch from now()-created_datetime)/86400)::int age_days FROM tickets_cache
                  WHERE status='open' AND NOT spam ORDER BY created_datetime ASC LIMIT 5`)
    ]);
    out.difficult_tickets = difficult.rows;
    out.oldest_open = oldest.rows;
    if (await isAdminReq(req)) { // customer emails are PII → admins only
      // exclude automated / business / vendor senders (no-reply, notifications, review apps, etc.)
      const EXCLUDE = ['%no-reply%', '%noreply%', '%no_reply%', '%do-not-reply%', '%donotreply%',
        '%notification%', '%notifications%', '%mailer%', '%mailer-daemon%', '%@stamped.io', '%@klaviyo%',
        '%@shopify%', '%@gorgias%', '%@redo%', '%@getredo%', '%support@%', '%billing@%', '%invoices@%',
        '%receipts@%', '%team@%', '%hello@%', '%info@%', '%accounts@%', '%postmaster@%', '%bounce%',
        '%service@paypal%', '%@paypal.%', '%@gmass.co', '%get@aiadssolutions.com', '%@aiadssolutions.com',
        '%@mg.postscriptapp.com', '%@postscriptapp.com', '%edm.feedback@tiktok.com', '%@tiktok.com',
        '%notify@%', '%@mail.%', '%@e.%', '%@email.%', 'kp@clicks.tech'];
      const notLike = EXCLUDE.map((_, i) => `customer_email NOT ILIKE $${i + 1}`).join(' AND ');
      const rc = await pool.query(
        `SELECT customer_email, customer_name, count(*)::int tickets FROM tickets_cache
         WHERE NOT spam AND customer_email <> '' AND created_datetime >= now()-interval '90 days'
           AND ${notLike}
         GROUP BY 1,2 HAVING count(*) > 1 ORDER BY tickets DESC LIMIT 10`, EXCLUDE);
      out.repeat_customers = rc.rows;
    }
  } catch (e) { out.errors.push(String(e.message)); }
  if (cfg) {
    try {
      const t = await gorgiasRequest(cfg, '/api/tickets?limit=1&trashed=false');
      out.total_tickets = t.meta?.total_resources ?? null;
    } catch (e) { out.errors.push(String(e.message)); }
    try {
      const s = await gorgiasRequest(cfg, '/api/satisfaction-surveys?limit=100');
      const scored = (s.data || []).filter(x => typeof x.score === 'number');
      out.csat_responses = scored.length;
      out.csat_avg_5 = scored.length ? +(scored.reduce((a, x) => a + x.score, 0) / scored.length).toFixed(2) : null;
    } catch (e) { out.errors.push(String(e.message)); }
    try {
      const frt = await gorgiasRequest(cfg, '/api/reporting/stats?limit=1', {
        method: 'POST',
        body: JSON.stringify({ scope: 'first-response-time', measures: ['averageFirstResponseTime'], filters: [], timezone: 'UTC' })
      });
      const row = frt?.data?.[0] || frt?.data || {};
      const v = row.averageFirstResponseTime ?? row['FirstResponseTime.averageFirstResponseTime'] ?? null;
      out.avg_first_response_seconds = typeof v === 'number' ? v : (v ? Number(v) : null);
    } catch (e) { console.error('gorgias FRT (best-effort):', e.message); } // quiet — metric shows "—"
  } else {
    out.message = 'Live Gorgias metrics unavailable — the connector needs re-adding on the ＋ page. Showing locally synced data.';
  }
  res.json(out);
});

// ---------- embedded Claude assistant (with data tools) ----------
const ASSISTANT_MODEL = process.env.ASSISTANT_MODEL || 'claude-haiku-4-5-20251001';

async function anthropic(apiKey, body) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: ASSISTANT_MODEL, max_tokens: 1000, ...body })
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j?.error?.message || `Anthropic API → ${r.status}`);
  return j;
}

const TOOLS = [
  {
    name: 'query_tickets',
    description: 'Search/count helpdesk tickets in the local synced Gorgias cache. Returns counts and up to 10 sample subjects. Use text_match (regex, case-insensitive) against subject and tags, e.g. "cancel|refund", "japan", "product y".',
    input_schema: {
      type: 'object',
      properties: {
        text_match: { type: 'string', description: 'case-insensitive regex matched against subject and tags' },
        status: { type: 'string', enum: ['open', 'closed'] },
        created_after: { type: 'string', description: 'ISO date' },
        created_before: { type: 'string', description: 'ISO date' },
        closed_after: { type: 'string', description: 'ISO date' },
        closed_before: { type: 'string', description: 'ISO date' }
      }
    }
  },
  {
    name: 'get_overview_stats',
    description: 'Ticket stats (created/closed/cancel-refund) plus team events for the last N days.',
    input_schema: { type: 'object', properties: { days: { type: 'integer', description: '7, 30, 90, 180 or 365' } }, required: ['days'] }
  },
  {
    name: 'list_events',
    description: 'List team-logged events (campaigns, launches...) with dates and who added them.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'query_sales',
    description: 'Search/aggregate Shopify orders from the local synced cache: revenue, order counts, cancellations, refunds, delivery status — filterable by country (ISO-2 like AU, JP), product text, fulfillment/financial status, and date range. Returns totals plus up to 10 sample orders.',
    input_schema: {
      type: 'object',
      properties: {
        product_match: { type: 'string', description: 'case-insensitive regex matched against line item titles/SKUs' },
        country: { type: 'string', description: 'ISO-2 country code, e.g. AU, JP, US' },
        fulfillment_status: { type: 'string', enum: ['fulfilled', 'unfulfilled', 'partial'], description: 'fulfilled = delivered/shipped; unfulfilled = not yet' },
        financial_status: { type: 'string', description: 'e.g. paid, refunded, partially_refunded' },
        cancelled: { type: 'boolean', description: 'true = only cancelled orders' },
        created_after: { type: 'string', description: 'ISO date' },
        created_before: { type: 'string', description: 'ISO date' }
      }
    }
  },
  {
    name: 'search_knowledge',
    description: 'Full-text search the team knowledge base pages (policies, product info, FAQs, processes). Use this FIRST for any question about company policy, procedures, or documented knowledge.',
    input_schema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] }
  },
  {
    name: 'query_returns_redo',
    description: 'Redo returns/claims/warranties from the local sync: counts, refund vs exchange vs store-credit amounts, reasons, statuses. Filterable by type, status, reason regex, sku regex, and recency.',
    input_schema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['return', 'claim', 'warranty'] },
        status: { type: 'string', description: 'open, in_transit, delivered, needs_review, in_review, complete, rejected, flagged, pre_shipment' },
        reason_match: { type: 'string', description: 'case-insensitive regex against item return reasons' },
        sku_match: { type: 'string', description: 'case-insensitive regex against returned item SKUs' },
        days: { type: 'integer', description: 'only returns created in the last N days' }
      }
    }
  },
  {
    name: 'query_campaigns',
    description: 'Klaviyo email/SMS campaign performance from the local sync: send date, recipients, open/click rates, attributed revenue. Filter by name regex and/or recency.',
    input_schema: {
      type: 'object',
      properties: {
        text_match: { type: 'string', description: 'case-insensitive regex against campaign name' },
        days: { type: 'integer', description: 'only campaigns sent in the last N days' }
      }
    }
  },
  {
    name: 'query_uk_stock',
    description: 'Current UK warehouse stock levels from the clicks-uk-returns API (synced hourly). Optionally filter by product name/SKU regex.',
    input_schema: { type: 'object', properties: { text_match: { type: 'string', description: 'case-insensitive regex against sku and name' } } }
  },
  {
    name: 'create_connection_request',
    description: 'Log a member\'s request to connect a new data source. Use once you know WHAT service they want and WHY (what data/benefit). Admins review requests on the ＋ page. Never include credentials.',
    input_schema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'the service/source they want connected, e.g. "Klaviyo", "DHL tracking API"' },
        reason: { type: 'string', description: 'what data they want and why it helps the team' }
      },
      required: ['service', 'reason']
    }
  },
  {
    name: 'list_pending_integrations',
    description: 'List connection requests (pending/approved/rejected) and connectors awaiting wiring. Use when someone asks about the status of requests or integrations.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'create_connector_type',
    description: 'Create a new connector type so a member can securely submit credentials for a service via the Connectors form (never via chat). Use after you understand what service they want to connect and what its API needs (base URL, key, account id, etc). The form appears immediately in the "New connector" type dropdown. Mark every credential-like field secret:true.',
    input_schema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'lowercase identifier, e.g. "shopify", "klaviyo", "custom-erp"' },
        label: { type: 'string', description: 'human name shown in the dropdown, e.g. "Shopify store"' },
        fields: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              key: { type: 'string', description: 'lowercase field id, e.g. "api_key"' },
              label: { type: 'string', description: 'help text incl. where to find it' },
              secret: { type: 'boolean' }
            },
            required: ['key', 'label', 'secret']
          }
        },
        notes: { type: 'string', description: 'what data this will provide and any integration notes' }
      },
      required: ['slug', 'label', 'fields']
    }
  }
];

async function runTool(name, input, ctx) {
  if (name === 'query_tickets') {
    const conds = [], params = [];
    const add = (v, sqlFn) => { params.push(v); conds.push(sqlFn(`$${params.length}`)); };
    if (input.text_match) add(String(input.text_match).slice(0, 200), p => `(subject ~* ${p} OR tags::text ~* ${p})`);
    if (input.status) add(input.status, p => `status = ${p}`);
    if (input.created_after) add(input.created_after, p => `created_datetime >= ${p}`);
    if (input.created_before) add(input.created_before, p => `created_datetime < ${p}`);
    if (input.closed_after) add(input.closed_after, p => `closed_datetime >= ${p}`);
    if (input.closed_before) add(input.closed_before, p => `closed_datetime < ${p}`);
    conds.push('NOT spam'); // exclude spam to match Gorgias views
    const where = 'WHERE ' + conds.join(' AND ');
    const count = await pool.query(
      `SELECT count(*)::int total, count(*) FILTER (WHERE status='open')::int open,
       count(*) FILTER (WHERE status='closed')::int closed FROM tickets_cache ${where}`, params);
    const sample = await pool.query(
      `SELECT subject, status, channel, tags, created_datetime::date created, closed_datetime::date closed
       FROM tickets_cache ${where} ORDER BY created_datetime DESC LIMIT 10`, params);
    const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v;
    return { ...count.rows[0], sample: sample.rows, note: `Cache synced from Gorgias; last sync: ${st?.last_run || 'never'}. Only synced tickets are counted.` };
  }
  if (name === 'get_overview_stats') return overviewStats(input.days);
  if (name === 'list_events') {
    return (await pool.query('SELECT id, title, description, event_date, added_by, attachment_name FROM events ORDER BY event_date DESC LIMIT 50')).rows;
  }
  if (name === 'query_sales') {
    const hasSales = (await pool.query('SELECT 1 FROM orders_cache LIMIT 1')).rows.length > 0;
    if (!hasSales) {
      const conn = await getConnector('shopify');
      return { error: conn
        ? 'Shopify is connected but no orders have synced yet — the backfill may still be running. Try again in a few minutes or press Sync now.'
        : 'No sales source connected yet. A built-in "Shopify store" connector exists in the New connector dropdown on the ＋ page — it needs the store subdomain and an Admin API token (shpat_) with read_orders scope.' };
    }
    const conds = [], p = [];
    const add = (v, fn) => { p.push(v); conds.push(fn(`$${p.length}`)); };
    if (input.product_match) add(String(input.product_match).slice(0, 200), x => `items::text ~* ${x}`);
    if (input.country) add(String(input.country).toUpperCase().slice(0, 2), x => `country = ${x}`);
    if (input.fulfillment_status) add(input.fulfillment_status, x => `fulfillment_status = ${x}`);
    if (input.financial_status) add(input.financial_status, x => `financial_status = ${x}`);
    if (input.cancelled === true) conds.push('cancelled_at IS NOT NULL');
    if (input.cancelled === false) conds.push('cancelled_at IS NULL');
    if (input.created_after) add(input.created_after, x => `created_at >= ${x}`);
    if (input.created_before) add(input.created_before, x => `created_at < ${x}`);
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const agg = await pool.query(
      `SELECT count(*)::int orders, round(coalesce(sum(total_price),0))::int revenue, max(currency) currency,
       count(*) FILTER (WHERE fulfillment_status='fulfilled')::int fulfilled,
       count(*) FILTER (WHERE cancelled_at IS NOT NULL)::int cancelled,
       count(*) FILTER (WHERE financial_status IN ('refunded','partially_refunded'))::int refunded
       FROM orders_cache ${where}`, p);
    const sample = await pool.query(
      `SELECT order_number, created_at::date created, country, total_price, currency, financial_status, fulfillment_status,
       cancelled_at IS NOT NULL AS cancelled, items
       FROM orders_cache ${where} ORDER BY created_at DESC LIMIT 10`, p);
    const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v;
    return { ...agg.rows[0], sample: sample.rows,
      note: `From the local Shopify sync. Last sync: ${ss?.last_run || 'unknown'}${ss?.backfill_done ? '' : ' (history backfill still in progress — older orders may be missing)'}.` };
  }
  if (name === 'search_knowledge') {
    const hits = await kbSearch(String(input.query || ''), 5);
    if (!hits.length) return { results: [], note: 'No knowledge base pages matched. The KB may not cover this yet — suggest the member proposes it.' };
    const detailed = [];
    for (const h of hits.slice(0, 3)) {
      const page = (await pool.query('SELECT content FROM kb_pages WHERE id=$1', [h.id])).rows[0];
      detailed.push({ kb: h.kb, title: h.title, updated_at: h.updated_at, content: (page?.content || '').slice(0, 2000) });
    }
    return { results: detailed, note: 'Answer from this content and cite the KB/page name. If content seems outdated vs live data, say so.' };
  }
  if (name === 'query_returns_redo') {
    const conn = await getConnector('redo');
    if (!conn) return { error: 'Redo is not connected yet — an admin can add it on the ＋ page.' };
    const conds = [], p = [];
    const add = (v, fn) => { p.push(v); conds.push(fn(`$${p.length}`)); };
    if (input.type) add(input.type, x => `type = ${x}`);
    if (input.status) add(input.status, x => `status = ${x}`);
    if (input.reason_match) add(String(input.reason_match).slice(0, 200), x => `items::text ~* ${x}`);
    if (input.sku_match) add(String(input.sku_match).slice(0, 200), x => `items::text ~* ${x}`);
    if (input.days) add(`${Math.min(+input.days || 30, 400)} days`, x => `created_at >= now()-${x}::interval`);
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const agg = await pool.query(
      `SELECT count(*)::int returns, round(coalesce(sum(refund),0))::int refund_total,
       round(coalesce(sum(exchange_value),0))::int exchange_total, round(coalesce(sum(store_credit),0))::int store_credit_total
       FROM returns_cache ${where}`, p);
    const sample = await pool.query(
      `SELECT order_name, type, status, created_at::date created, refund, items FROM returns_cache ${where}
       ORDER BY created_at DESC LIMIT 10`, p);
    return { ...agg.rows[0], sample: sample.rows, note: 'exchange_total = value kept as exchanges instead of refunded.' };
  }
  if (name === 'query_campaigns') {
    const conn = await getConnector('klaviyo');
    if (!conn) return { error: 'Klaviyo is not connected yet — an admin can add it on the ＋ page.' };
    const conds = [], p = [];
    if (input.text_match) { p.push(String(input.text_match).slice(0, 200)); conds.push(`name ~* $${p.length}`); }
    if (input.days) { p.push(`${Math.min(+input.days || 30, 400)} days`); conds.push(`send_time >= now()-$${p.length}::interval`); }
    const { rows } = await pool.query(
      `SELECT name, channel, status, send_time::date sent, recipients,
       round(open_rate*100)::int open_pct, round(click_rate*100)::int click_pct, round(coalesce(revenue,0))::int revenue
       FROM campaigns_cache ${conds.length ? 'WHERE ' + conds.join(' AND ') : ''} ORDER BY send_time DESC NULLS LAST LIMIT 25`, p);
    return { campaigns: rows, note: 'revenue = Klaviyo-attributed conversion value (Placed Order).' };
  }
  if (name === 'query_uk_stock') {
    const conn = await getConnector('uk_stock');
    if (!conn) return { error: 'UK stock is not connected yet — an admin can add the "UK stock" connector on the ＋ page.' };
    const conds = [], p = [];
    if (input.text_match) { p.push(String(input.text_match).slice(0, 200)); conds.push(`(sku ~* $1 OR name ~* $1)`); }
    const { rows } = await pool.query(
      `SELECT sku, name, qty, updated_at::date updated FROM uk_stock ${conds.length ? 'WHERE ' + conds.join(' AND ') : ''}
       ORDER BY qty ASC NULLS LAST LIMIT 50`, p);
    const ss = (await pool.query(`SELECT v FROM sync_state WHERE k='uk_stock'`)).rows[0]?.v;
    return { items: rows, last_sync: ss?.last_run || null, note: 'qty = units in UK stock; sorted lowest first.' };
  }
  if (name === 'create_connection_request') {
    const service = String(input.service || '').slice(0, 200);
    const reason = String(input.reason || '').slice(0, 2000);
    if (!service || !reason) return { error: 'service and reason required' };
    if (looksSecret(service + ' ' + reason)) return { error: 'The request seems to contain a credential — refuse it and remind the member: idea and reason only.' };
    const { rows } = await pool.query(
      'INSERT INTO connection_requests (service, reason, requested_by) VALUES ($1,$2,$3) RETURNING id',
      [service, reason, ctx?.userEmail || 'anonymous']);
    return { ok: true, id: rows[0].id, message: 'Request logged. Tell the member an admin will review it on this page and they\'ll see the decision in the Requests list.' };
  }
  if (name === 'list_pending_integrations') {
    const reqs = await pool.query(
      `SELECT id, service, reason, requested_by, status, decided_by, created_at FROM connection_requests ORDER BY created_at DESC LIMIT 30`);
    const { rows } = await pool.query(
      `SELECT id, type, name, meta, added_by, approval_status, created_at FROM connectors
       WHERE meta->>'integration'='pending' AND active=true ORDER BY created_at DESC LIMIT 50`);
    return { connection_requests: reqs.rows, connectors_awaiting_wiring: rows,
      note: 'connection_requests: member proposals awaiting admin decision on the ＋ page. connectors_awaiting_wiring: credentials saved by an admin, sync code still being built.' };
  }
  if (name === 'create_connector_type') {
    const slug = String(input.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 40);
    const label = String(input.label || '').slice(0, 80);
    const fields = (Array.isArray(input.fields) ? input.fields : []).slice(0, 12).map(f => ({
      key: String(f.key || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 40),
      label: String(f.label || '').slice(0, 200),
      secret: !!f.secret
    })).filter(f => f.key && f.label);
    if (!slug || !label || !fields.length) return { error: 'slug, label and at least one field are required' };
    if (CONNECTOR_TYPES[slug]) return { error: `"${slug}" is a built-in connector type — it already exists in the dropdown` };
    await pool.query(
      `INSERT INTO connector_types (slug, label, fields, notes) VALUES ($1,$2,$3,$4)
       ON CONFLICT (slug) DO UPDATE SET label=$2, fields=$3, notes=$4`,
      [slug, label, JSON.stringify(fields), String(input.notes || '').slice(0, 1000)]);
    return { ok: true, slug, label, fields, message: `Connector form "${label}" created. Tell the user to pick "${label}" in the New connector form on this page and fill it in — credentials go into the form, never into this chat. Data sync for this source will be wired by the dev team once credentials are saved.` };
  }
  return { error: 'unknown tool' };
}

async function runAssistant(inputMessages, opts = {}) {
  const conn = await getConnector('anthropic');
  const apiKey = conn?.config?.api_key || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { configured: false, reply: 'The assistant isn\'t connected yet. Go to Connectors (＋) → "Claude assistant" and add an Anthropic API key from console.anthropic.com.' };
  }
  let messages = inputMessages.slice(-12)
    .filter(m => ['user', 'assistant'].includes(m.role) && typeof m.content === 'string')
    .map(m => ({ role: m.role, content: m.content }));
  if (!messages.length) throw new Error('messages required');

  const conns = await pool.query('SELECT type, name, meta, active FROM connectors WHERE active=true');
  const knownTypes = await getAllConnectorTypes();
  const system = `You are the built-in assistant of "clicks brain", an internal team dashboard. Today is ${new Date().toISOString().slice(0, 10)}. Current user: ${opts.userEmail || 'unknown'}.
Tabs: Overview (period stats 7d/1m/3m/6m/1y with event markers), Sales & Dates, Gorgias Stats, Knowledge Bases, Connectors (the ＋ button in the nav).
Product specs are not shown yet — they will be captured automatically from sources (Shopify product list, website) once those connectors are added.
House rules:
- Data flows in from sources; nothing is deletable/editable here. Wrong data → fix at the source, re-import.
- Credentials go ONLY into the New connector form on the ＋ page (encrypted, write-only). NEVER ask for or accept credentials in chat; if a user posts one, tell them to rotate it immediately and use the form instead.
- Connector types currently in the dropdown: ${JSON.stringify(Object.fromEntries(Object.entries(knownTypes).map(([k, v]) => [k, { label: v.label, fields: v.fields.map(f => f.key), dynamic: !!v.dynamic }])))}.
- Active connectors right now: ${JSON.stringify(conns.rows)}.
- Team events (campaigns, launches) are logged on the Overview tab with optional attachments and appear as 📌 markers on charts to show their influence.
CONNECTION REQUESTS are a core part of your job. Members cannot add connectors — only ADMINS can (the New connector form requires the admin password). The member flow is:
0. Remind them briefly: share only the IDEA and the REASON in chat — never keys, tokens or passwords. If they post a credential, tell them to rotate it immediately.
1. Ask what service they want connected and what data/benefit they expect.
2. Once you have service + reason, call create_connection_request to log it.
3. Tell them: an admin reviews it in the Requests list on this page; if approved, the admin sets up the credentials and the dev team wires the sync.
For ADMINS preparing an approved request, you may call create_connector_type to add a tailored credentials form to the dropdown (clear field labels saying where to find each value; every credential secret:true).
gorgias, anthropic, slack, shopify, klaviyo, redo and uk_stock connectors are fully wired: they test the connection and work immediately once an admin saves them. redo unlocks returns/claims/warranties data (query_returns_redo). Shopify sync unlocks sales/order/delivery data (query_sales) and the sales line on Overview. klaviyo unlocks campaign performance (query_campaigns) and auto-marks campaign sends as ✉️ on the Overview chart. uk_stock unlocks UK warehouse stock levels (query_uk_stock).
Use list_pending_integrations to report request/wiring status. You cannot approve anything yourself.
Use your tools to answer data questions with real numbers. If a question needs sales/order/delivery data, use query_sales and relay its guidance. Be concise. Answer in the user's language.${opts.slack ? '\nYou are replying inside Slack: use Slack formatting (*bold*, bullet lines with •), keep replies short, no markdown headers or tables.' : ''}`;

  let reply = '';
  for (let round = 0; round < 5; round++) {
    const j = await anthropic(apiKey, { system, messages, tools: TOOLS });
    const toolUses = (j.content || []).filter(b => b.type === 'tool_use');
    const text = (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
    if (j.stop_reason !== 'tool_use') { reply = text; break; }
    messages = [...messages, { role: 'assistant', content: j.content }, {
      role: 'user',
      content: await Promise.all(toolUses.map(async tu => ({
        type: 'tool_result', tool_use_id: tu.id,
        content: JSON.stringify(await runTool(tu.name, tu.input || {}, opts)).slice(0, 8000)
      })))
    }];
    reply = text; // fallback if rounds exhausted
  }
  return { configured: true, reply: reply || '(no reply)' };
}

app.post('/api/assistant', async (req, res) => {
  try {
    res.json(await runAssistant(req.body?.messages || [], { userEmail: req.userEmail }));
  } catch (e) {
    res.status(502).json({ error: `Assistant error: ${e.message}` });
  }
});

// ---------- Slack bot (@clicksbot) ----------
function slackSigValid(cfg, req) {
  const ts = req.headers['x-slack-request-timestamp'];
  const sig = req.headers['x-slack-signature'];
  if (!ts || !sig || Math.abs(Date.now() / 1000 - ts) > 300) return false;
  const base = `v0:${ts}:${req.rawBody}`;
  const mine = 'v0=' + crypto.createHmac('sha256', cfg.signing_secret).update(base).digest('hex');
  const a = Buffer.from(mine), b = Buffer.from(String(sig));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function slackPost(token, channel, text, thread_ts, blocks) {
  const r = await (await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ channel, text, thread_ts, ...(blocks ? { blocks } : {}) })
  })).json();
  if (!r.ok) console.error('slack post failed:', r.error);
}
// escape for Slack mrkdwn AND defeat Slack's automatic colour-swatch: a "#" followed by 3/6 hex digits
// (e.g. a reference like #983680) would otherwise render an unwanted colour square. A zero-width space
// after the "#" keeps the text visible but stops Slack treating it as a hex colour.
const slackEsc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/#(?=[0-9a-fA-F])/g, '#​');
// stable per-shipment colour square (emoji) so each freight is distinguishable in Slack without a hex code.
// keyed off a stable string (the shipment ID) → same square every time for that freight.
const FREIGHT_SQUARES = ['🟥', '🟧', '🟨', '🟩', '🟦', '🟪', '🟫', '⬛', '⬜'];
function freightSquare(key) {
  let h = 5381;
  for (const ch of String(key || 'freight')) h = ((h << 5) + h + ch.charCodeAt(0)) >>> 0;
  return FREIGHT_SQUARES[h % FREIGHT_SQUARES.length];
}
// post a freight shipment update to the configured alerts channel (best-effort, never blocks the request)
const FREIGHT_HEADERS = {
  created: '🚢 New freight shipment',
  edited: '✏️ Freight shipment updated',
  deleted: '🗑️ Freight shipment deleted',
  completed: '✅ Freight shipment completed',
  stage: '🔄 Freight stage updated',
  update: '📣 Freight status update'
};
// name of the stage a shipment is currently sitting on, based on its step counter
function freightCurrentStage(sh) {
  const stages = Array.isArray(sh.stages) ? sh.stages : [];
  const step = parseInt(sh.step) || 0;
  if (!stages.length) return 'No stages set';
  if (step <= 0) return 'Not started';
  if (step > stages.length) return '✅ All stages complete';
  return stages[step - 1];
}
async function notifyFreight(action, sh, extra) {
  try {
    const conn = await getConnector('slack');
    if (!conn?.config?.bot_token) return;
    const channel = (conn.config.freight_channel || conn.config.alert_channel || '#clicksbrain').trim();
    const name = sh.name || 'Untitled shipment';
    const items = (sh.items || []).map(i => `${i.sku} ×${i.qty}`).join(', ') || '—';
    const stages = (sh.stages || []).length ? (sh.stages || []).join('  →  ') : 'none set';
    const eta = sh.eta ? new Date(sh.eta + 'T00:00:00').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const header = FREIGHT_HEADERS[action] || '🚢 Freight update';
    const current = action === 'completed' ? '✅ All stages complete' : freightCurrentStage(sh);

    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: header, emoji: true } },
      { type: 'section', text: { type: 'mrkdwn', text: `${freightSquare(sh.id != null ? 'F' + sh.id : name)}  *${slackEsc(name)}*` } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Route*\n${slackEsc(sh.from_country || '?')}  →  ${slackEsc(sh.to_country || '?')}` },
        { type: 'mrkdwn', text: `*ETA*\n${eta}` },
        { type: 'mrkdwn', text: `*Carrier*\n${slackEsc(sh.carrier || '—')}` },
        { type: 'mrkdwn', text: `*Contents*\n${slackEsc(items)}` }
      ] }
    ];
    if (action !== 'deleted') {
      // stage move: show where it came from and where it went; otherwise show the current stage
      if (action === 'stage' && extra && extra.fromStage != null) {
        blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Stage moved*\n${slackEsc(extra.fromStage)}  →  *${slackEsc(extra.toStage)}*` } });
      } else {
        blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Current stage*\n*${slackEsc(current)}*` } });
      }
      // all-stages list with the current stage bolded
      const list = (sh.stages || []);
      const step = action === 'completed' ? list.length + 1 : (parseInt(sh.step) || 0);
      const stageList = list.length
        ? list.map((s, i) => (i + 1 === step) ? `📍*${slackEsc(s)}*` : slackEsc(s)).join('  →  ')
        : 'none set';
      blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `All stages: ${stageList}` }] });
    }
    if (sh.notes && action !== 'deleted') blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `📝 ${slackEsc(sh.notes)}` }] });
    const appUrl = (process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || 'https://clicks-brain.onrender.com').replace(/\/$/, '');
    if (action !== 'deleted') blocks.push({ type: 'actions', elements: [
      { type: 'button', text: { type: 'plain_text', text: '🚢 Open Freight Tracker', emoji: true }, url: `${appUrl}/#freight` }
    ] });
    blocks.push({ type: 'divider' });

    // plain-text fallback (shown in notifications / clients that don't render blocks)
    const stageText = action === 'stage' && extra ? `${extra.fromStage} → ${extra.toStage}` : current;
    const fallback = `${header} — ${name} · ${sh.from_country || '?'} → ${sh.to_country || '?'} · Stage: ${stageText}`;
    await slackPost(conn.config.bot_token, channel, fallback, undefined, blocks);
  } catch (e) { console.error('freight slack notify failed:', e.message); }
}

// post a Slack alert for each newly-sent Klaviyo campaign (called after every Klaviyo sync).
// Only campaigns sent in the last few hours are posted; older un-notified ones are marked silently
// so a first run (or downtime) never floods the channel with history.
async function postCampaignAlert(conn, channel, appUrl, c) {
  const icon = (c.channel || '').toLowerCase() === 'sms' ? '📱' : '📧';
  const fields = [
    { type: 'mrkdwn', text: `*Subject*\n${slackEsc(c.subject || '—')}` },
    { type: 'mrkdwn', text: `*Channel*\n${slackEsc((c.channel || 'email').toUpperCase())}` },
    { type: 'mrkdwn', text: `*Sent*\n${c.sent || '—'}` },
    { type: 'mrkdwn', text: `*Recipients*\n${c.recipients != null ? c.recipients.toLocaleString() : 'counting…'}` }
  ];
  if (c.from_email) fields.push({ type: 'mrkdwn', text: `*From*\n${slackEsc(c.from_email)}` });
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `${icon} Klaviyo email sent`, emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: `*${slackEsc(c.name || 'Campaign')}*` } },
    { type: 'section', fields },
    { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '👀 View email', emoji: true }, url: `${appUrl}/#klaviyo/mail/${encodeURIComponent(c.klaviyo_id)}` }] },
    { type: 'divider' }
  ];
  await slackPost(conn.config.bot_token, channel, `${icon} Klaviyo email sent — ${c.name || 'Campaign'} · ${c.subject || ''}`, undefined, blocks);
}
async function notifyNewCampaigns() {
  try {
    const conn = await getConnector('slack');
    if (!conn?.config?.bot_token) return;
    const channel = (conn.config.alert_channel || '#clicksbrain').trim();
    const appUrl = (process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || 'https://clicks-brain.onrender.com').replace(/\/$/, '');
    // silently mark anything older than the window so we never post stale campaigns
    await pool.query(`UPDATE campaigns_cache SET notified_at=now()
                      WHERE notified_at IS NULL AND (send_time IS NULL OR send_time < now() - interval '6 hours')`);
    const fresh = (await pool.query(
      `SELECT klaviyo_id, name, channel, to_char(send_time,'DD Mon YYYY, HH24:MI') sent, recipients, subject, from_email
       FROM campaigns_cache
       WHERE notified_at IS NULL AND send_time IS NOT NULL AND send_time >= now() - interval '6 hours'
       ORDER BY send_time ASC`)).rows;
    for (const c of fresh) {
      await postCampaignAlert(conn, channel, appUrl, c);
      await pool.query(`UPDATE campaigns_cache SET notified_at=now() WHERE klaviyo_id=$1`, [c.klaviyo_id]);
    }
  } catch (e) { console.error('klaviyo campaign notify failed:', e.message); }
}
// admin test: re-post the most recent campaign as a sample notification (does NOT send any email)
app.post('/api/klaviyo/test-notify', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const conn = await getConnector('slack');
  if (!conn?.config?.bot_token) return res.status(400).json({ error: 'Slack bot not connected' });
  const c = (await pool.query(
    `SELECT klaviyo_id, name, channel, to_char(send_time,'DD Mon YYYY, HH24:MI') sent, recipients, subject, from_email
     FROM campaigns_cache ORDER BY send_time DESC NULLS LAST LIMIT 1`)).rows[0];
  if (!c) return res.status(404).json({ error: 'No campaigns cached yet — run a Klaviyo sync first.' });
  const channel = (conn.config.alert_channel || '#clicksbrain').trim();
  const appUrl = (process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || 'https://clicks-brain.onrender.com').replace(/\/$/, '');
  try { await postCampaignAlert(conn, channel, appUrl, c); res.json({ ok: true, name: c.name }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- daily report (Slack, 18:00 Europe/London) ----------
const REPORT_TZ = 'Europe/London';
function londonNow() {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: REPORT_TZ,
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    .formatToParts(new Date()).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, hour: parseInt(p.hour), minute: parseInt(p.minute) };
}
async function refreshForReport() {
  const jobs = [];
  try { if (await getConnector('shopify')) jobs.push(syncShopify(8)); } catch {}
  try { if (await getGorgiasConfig()) jobs.push(refreshOpenTickets()); } catch {}
  try { if (await getConnector('redo')) jobs.push(syncRedo(6)); } catch {}
  try { if (await getConnector('klaviyo')) jobs.push(syncKlaviyo()); } catch {}
  await Promise.allSettled(jobs);
}
async function buildDailyReport() {
  await refreshForReport();
  const sym = c => c === 'GBP' ? '£' : c === 'EUR' ? '€' : c === 'USD' ? '$' : '';
  const money = (n, c) => `${sym(c)}${Math.round(n || 0).toLocaleString()}`;
  const delta = (a, b) => b > 0 ? `${a >= b ? '▲' : '▼'}${Math.round(Math.abs(a - b) / b * 100)}%` : (a > 0 ? '▲ new' : '–');
  const DAY = `(created_at AT TIME ZONE 'Europe/London')::date`, TODAY = `(now() AT TIME ZONE 'Europe/London')::date`;

  const s = (await pool.query(`
    SELECT count(*) FILTER (WHERE d=t) o0, count(*) FILTER (WHERE d=t-1) o1, count(*) FILTER (WHERE d=t-7) o7,
      coalesce(sum(total_price) FILTER (WHERE d=t),0)::numeric r0,
      coalesce(sum(total_price) FILTER (WHERE d=t-1),0)::numeric r1,
      coalesce(sum(total_price) FILTER (WHERE d=t-7),0)::numeric r7, max(currency) cur
    FROM (SELECT total_price, currency, ${DAY} d, ${TODAY} t FROM orders_cache
          WHERE cancelled_at IS NULL AND created_at >= now() - interval '9 days') x`)).rows[0] || {};
  const units0 = (await pool.query(`SELECT coalesce(sum((it->>'qty')::int),0)::int u
    FROM orders_cache, LATERAL jsonb_array_elements(items) it
    WHERE cancelled_at IS NULL AND ${DAY} = ${TODAY}`)).rows[0]?.u || 0;
  const fdt = (await pool.query(`SELECT count(*)::int c FROM orders_cache
    WHERE (fulfilled_at AT TIME ZONE 'Europe/London')::date = ${TODAY}`)).rows[0]?.c || 0;
  const cur = s.cur || 'USD';

  const g = (await pool.query(`SELECT
      count(*) FILTER (WHERE (created_datetime AT TIME ZONE 'Europe/London')::date = ${TODAY} AND coalesce(spam,false)=false) new_today,
      count(*) FILTER (WHERE status='open') open_now,
      count(*) FILTER (WHERE status='open' AND messages_count>=10) difficult
    FROM tickets_cache`)).rows[0] || {};
  const ret = (await pool.query(`SELECT
      count(*) FILTER (WHERE ${DAY} = ${TODAY}) today,
      count(*) FILTER (WHERE created_at >= now()-interval '7 days') last7 FROM returns_cache`)).rows[0] || {};
  const kv = (await pool.query(`SELECT count(*) sent, coalesce(sum(revenue),0)::numeric rev FROM campaigns_cache
    WHERE (send_time AT TIME ZONE 'Europe/London')::date = ${TODAY}`)).rows[0] || {};

  // 90-day forecast: only SKUs projected to fall below 0 within the next 90 days (soonest first)
  const fc = await forecastRows(90);
  const belowZero = fc.rows.filter(r => r.proj[90] < 0);
  const fcList = belowZero.slice(0, 10).map(r => `• *${slackEsc(r.sku)}*${r.name && r.name !== r.sku ? ` ${slackEsc(r.name)}` : ''} — out in ~${r.cover}d → short *${Math.abs(r.proj[90]).toLocaleString()} units* by day 90`).join('\n')
    + (belowZero.length > 10 ? `\n…and ${belowZero.length - 10} more` : '');
  const fcText = belowZero.length ? fcList : '_none forecast to run out in the next 90 days_';

  const fr = (await pool.query(`SELECT name, to_char(eta,'DD Mon') eta,
      (eta < ${TODAY}) overdue, (eta BETWEEN ${TODAY} AND ${TODAY} + 7) soon,
      (jsonb_array_length(coalesce(stages,'[]'::jsonb)) > 0 AND step >= jsonb_array_length(coalesce(stages,'[]'::jsonb))) done
    FROM freight_shipments WHERE eta IS NOT NULL`)).rows;
  const frSoon = fr.filter(x => x.soon && !x.done), frOverdue = fr.filter(x => x.overdue && !x.done);
  const freightLine = [
    frSoon.length ? `📦 Arriving ≤7d: ${frSoon.map(x => `${slackEsc(x.name)} (${x.eta})`).join(', ')}` : '',
    frOverdue.length ? `⚠️ Overdue: ${frOverdue.map(x => `${slackEsc(x.name)} (${x.eta})`).join(', ')}` : ''
  ].filter(Boolean).join('\n') || '_no shipments arriving in the next 7 days_';

  const today = new Date().toLocaleDateString('en-GB', { timeZone: REPORT_TZ, weekday: 'long', day: 'numeric', month: 'long' });
  const appUrl = (process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || 'https://clicks-brain.onrender.com').replace(/\/$/, '');
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `📊 Daily report — ${today}`, emoji: true } },
    { type: 'context', elements: [{ type: 'mrkdwn', text: '*💰 Sales*' }] },
    { type: 'section', fields: [
      { type: 'mrkdwn', text: `*🛒 Orders today*\n${s.o0 || 0}  _(${delta(+s.o0, +s.o1)} vs yday · ${delta(+s.o0, +s.o7)} vs last wk)_` },
      { type: 'mrkdwn', text: `*💷 Revenue today*\n${money(+s.r0, cur)}  _(${delta(+s.r0, +s.r7)} vs last wk)_` },
      { type: 'mrkdwn', text: `*📦 Units today*\n${units0.toLocaleString()}` },
      { type: 'mrkdwn', text: `*✅ Fulfilled today*\n${fdt.toLocaleString()}` }
    ] },
    { type: 'divider' },
    { type: 'context', elements: [{ type: 'mrkdwn', text: '*🎧 Support & marketing*' }] },
    { type: 'section', fields: [
      { type: 'mrkdwn', text: `*🎧 New tickets*\n${g.new_today || 0}` },
      { type: 'mrkdwn', text: `*🔴 Difficult (open, 10+ msgs)*\n${g.difficult || 0}` },
      { type: 'mrkdwn', text: `*✉️ Campaigns today*\n${kv.sent || 0}${(+kv.rev) > 0 ? ` · ${money(+kv.rev, cur)}` : ''}` }
    ] },
    { type: 'divider' },
    { type: 'context', elements: [{ type: 'mrkdwn', text: '*📦 Inventory & returns*' }] },
    { type: 'section', text: { type: 'mrkdwn', text: `*↩️ Returns today:* ${ret.today || 0}  _(7d: ${ret.last7 || 0})_` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*📉 Forecast to run out within 90 days (${belowZero.length}):*\n${fcText}` } },
    { type: 'divider' },
    { type: 'context', elements: [{ type: 'mrkdwn', text: '*🚢 Freight*' }] },
    { type: 'section', text: { type: 'mrkdwn', text: freightLine } },
    { type: 'divider' },
    { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '📊 Open dashboard', emoji: true }, url: appUrl + '/' }] },
    { type: 'context', elements: [{ type: 'mrkdwn', text: `Data refreshed just before posting · ${new Date().toLocaleString('en-GB', { timeZone: REPORT_TZ })}` }] }
  ];
  const fallback = `Daily report ${today}: ${s.o0 || 0} orders, ${money(+s.r0, cur)}, ${g.open_now || 0} open tickets.`;
  return { blocks, fallback };
}
async function postDailyReport() {
  const conn = await getConnector('slack');
  if (!conn?.config?.bot_token) throw new Error('Slack bot not connected');
  const channel = (conn.config.alert_channel || '#clicksbrain').trim();
  const { blocks, fallback } = await buildDailyReport();
  await slackPost(conn.config.bot_token, channel, fallback, undefined, blocks);
}
app.post('/api/report/daily', async (req, res) => {
  const token = req.query.token || req.body?.token;
  const ok = (process.env.REPORT_TOKEN && token === process.env.REPORT_TOKEN) || (await isAdminReq(req));
  if (!ok) return res.status(403).json({ error: 'forbidden' });
  try { await postDailyReport(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// in-app scheduler: post once when the Europe/London clock reaches 18:00 (reliable on an always-on plan)
let lastReportDay = null;
setInterval(async () => {
  try {
    const { date, hour, minute } = londonNow();
    if (hour === 18 && minute < 5 && lastReportDay !== date) {
      lastReportDay = date;
      if (await getConnector('slack')) await postDailyReport();
    }
  } catch (e) { console.error('daily report scheduler:', e.message); }
}, 60 * 1000);

const seenSlackEvents = new Set();
app.post('/api/slack/events', async (req, res) => {
  if (req.body?.type === 'url_verification') return res.json({ challenge: req.body.challenge });
  const conn = await getConnector('slack');
  if (!conn) return res.sendStatus(200);
  if (!slackSigValid(conn.config, req)) return res.sendStatus(401);
  res.sendStatus(200); // ack within 3s; process async
  // retries are processed too (service may have been asleep on first delivery); seenSlackEvents dedupes
  const ev = req.body?.event;
  if (!ev || ev.bot_id) return;
  const isMention = ev.type === 'app_mention';
  const isDm = ev.type === 'message' && ev.channel_type === 'im' && !ev.subtype;
  if (!isMention && !isDm) return;
  if (seenSlackEvents.has(ev.ts)) return;
  seenSlackEvents.add(ev.ts);
  if (seenSlackEvents.size > 500) seenSlackEvents.clear();
  const text = String(ev.text || '').replace(/<@[^>]+>/g, '').trim();
  if (!text) return;
  try {
    const { reply } = await runAssistant([{ role: 'user', content: text }], { slack: true, userEmail: `slack:${ev.user || 'unknown'}` });
    await slackPost(conn.config.bot_token, ev.channel, reply, ev.thread_ts || ev.ts);
  } catch (e) {
    console.error('slack assistant error:', e.message);
    await slackPost(conn.config.bot_token, ev.channel, `⚠️ Couldn't answer that: ${e.message}`, ev.thread_ts || ev.ts);
  }
});

// admin: per-source sync health / logs
app.get('/api/health/connectors', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const labels = { gorgias: '🎧 Gorgias', shopify: '🛒 Shopify', klaviyo: '✉️ Klaviyo', redo: '↩️ Redo', uk_stock: '📦 UK stock' };
  const rows = (await pool.query(`SELECT k, v FROM sync_state WHERE k = ANY($1)`, [Object.keys(labels)])).rows;
  const byKey = Object.fromEntries(rows.map(r => [r.k, r.v]));
  const active = (await pool.query(`SELECT type FROM connectors WHERE active=true`)).rows.map(r => r.type);
  const out = Object.keys(labels).map(k => {
    const v = byKey[k] || {};
    const connected = active.includes(k) || (k === 'gorgias' && !!process.env.GORGIAS_DOMAIN);
    return {
      source: k, label: labels[k], connected,
      last_run: v.last_run || null,
      last_error: v.last_error || null,
      backfill_done: v.backfill_done ?? null,
      cached: v.cached ?? v.items ?? v.upserts ?? null,
      stale: v.last_run ? (Date.now() - Date.parse(v.last_run) > 90 * 60 * 1000) : true
    };
  });
  res.json(out);
});

// admin: pending-item counts for nav badges
app.get('/api/pending-counts', async (req, res) => {
  if (!(await isAdminReq(req))) return res.json({ requests: 0, kb: 0 });
  const [reqs, conns, kb] = await Promise.all([
    pool.query(`SELECT count(*)::int c FROM connection_requests WHERE status='pending'`),
    pool.query(`SELECT count(*)::int c FROM connectors WHERE approval_status='pending' AND active=true`),
    pool.query(`SELECT count(*)::int c FROM kb_suggestions WHERE status='pending'`)
  ]);
  res.json({ requests: reqs.rows[0].c + conns.rows[0].c, kb: kb.rows[0].c });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`clicks brain on :${PORT}`);
      console.log('env check — ADMIN_PASSWORD set:', !!process.env.ADMIN_PASSWORD,
        '| DASHBOARD_PASSWORD set:', !!process.env.DASHBOARD_PASSWORD,
        '| ENCRYPTION_KEY set:', !!process.env.ENCRYPTION_KEY);
    });
    bootSync().catch(e => console.error('boot sync:', e.message));
  })
  .catch((e) => { console.error('DB init failed:', e); process.exit(1); });
