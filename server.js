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
  p.startsWith('/api/slack/') || p === '/api/health' || p === '/login.html' || p.startsWith('/api/auth/');

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
  if (AUTH_EXEMPT(req.path)) return next();
  const email = readSession(req);
  if (email) { req.userEmail = email; return next(); }
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

app.post('/api/auth/setup', async (req, res) => {
  const { email, password, invite_code } = req.body || {};
  const invite = process.env.ADMIN_PASSWORD || process.env.DASHBOARD_PASSWORD;
  if (!invite) return res.status(400).json({ error: 'No ADMIN_PASSWORD set on the server — set it in Render → Environment first.' });
  if (invite_code !== invite) return res.status(403).json({ error: 'Wrong invite code.' });
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

app.post('/api/auth/login', async (req, res) => {
  const em = String(req.body?.email || '').toLowerCase().trim();
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [em])).rows[0];
  if (!u?.pass_hash) return res.status(403).json({ error: u ? 'No password set yet — use First time? below.' : 'Unknown email.' });
  const [salt, hash] = u.pass_hash.split(':');
  const a = Buffer.from(hashPw(String(req.body?.password || ''), salt)), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: 'Wrong password.' });
  setSessionCookie(res, em);
  res.json({ ok: true, email: em });
});

app.post('/api/auth/logout', (_req, res) => {
  res.set('Set-Cookie', 'cb_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ---------- member management (admins only) ----------
app.get('/api/users', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const { rows } = await pool.query(
    `SELECT email, role, (pass_hash IS NOT NULL) AS activated, created_at FROM users ORDER BY created_at`);
  res.json(rows);
});
app.post('/api/users', async (req, res) => {
  if (!(await isAdminReq(req))) return res.status(403).json({ error: 'admins only' });
  const em = String(req.body?.email || '').toLowerCase().trim();
  const role = req.body?.role === 'admin' ? 'admin' : 'member';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ error: 'valid email required' });
  const { rows } = await pool.query(
    `INSERT INTO users (email, role) VALUES ($1,$2)
     ON CONFLICT (email) DO UPDATE SET role=$2
     RETURNING email, role, (pass_hash IS NOT NULL) AS activated`, [em, role]);
  res.status(201).json(rows[0]);
});

app.get('/api/auth/me', async (req, res) => {
  const email = readSession(req);
  if (!email) return res.json({ email: null });
  const { rows } = await pool.query('SELECT role FROM users WHERE email=$1', [email]);
  res.json({ email, role: rows[0]?.role || 'member' });
});

// ---------- Postgres ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false
});

async function initDb() {
  await pool.query(`
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
    CREATE TABLE IF NOT EXISTS orders_cache (
      shopify_id BIGINT PRIMARY KEY, order_number TEXT DEFAULT '',
      created_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ,
      currency TEXT DEFAULT '', total_price NUMERIC DEFAULT 0,
      country TEXT DEFAULT '', financial_status TEXT DEFAULT '', fulfillment_status TEXT DEFAULT '',
      items JSONB DEFAULT '[]', updated_at TIMESTAMPTZ, synced_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS order_tags JSONB DEFAULT '[]';
    ALTER TABLE orders_cache ADD COLUMN IF NOT EXISTS fulfilled_at TIMESTAMPTZ;
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
    CREATE TABLE IF NOT EXISTS connection_requests (
      id SERIAL PRIMARY KEY, service TEXT NOT NULL, reason TEXT NOT NULL,
      requested_by TEXT DEFAULT 'anonymous', status TEXT DEFAULT 'pending',
      decided_by TEXT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now());
  `);
  for (const em of ['fran@clicks.tech', 'kp@clicks.tech']) {
    await pool.query(`INSERT INTO users (email, role) VALUES ($1, 'admin')
                      ON CONFLICT (email) DO UPDATE SET role='admin'`, [em]);
  }
  await pool.query(`INSERT INTO users (email, role) VALUES ('kevin@clicks.tech', 'member')
                    ON CONFLICT (email) DO NOTHING`);
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
      { key: 'signing_secret', label: 'Signing Secret (api.slack.com/apps → your app → Basic Information)', secret: true }
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

app.get('/api/kb/search', async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q) return res.json([]);
  try { res.json(await kbSearch(q)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/kb/:id/pages', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, title, added_by, updated_by, updated_at, length(content)::int chars
     FROM kb_pages WHERE kb_id=$1 ORDER BY created_at`, [req.params.id]);
  res.json(rows);
});
app.get('/api/kb/pages/:pageId', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM kb_pages WHERE id=$1', [req.params.pageId]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});
app.post('/api/kb/:id/pages', rejectSecrets(['title', 'content']), async (req, res) => {
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

async function upsertTicket(x) {
  await pool.query(
    `INSERT INTO tickets_cache (gorgias_id, status, subject, channel, tags, created_datetime, closed_datetime, updated_datetime, spam, messages_count, customer_email, customer_name, synced_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
     ON CONFLICT (gorgias_id) DO UPDATE SET status=$2, subject=$3, channel=$4, tags=$5,
       created_datetime=$6, closed_datetime=$7, updated_datetime=$8, spam=$9,
       messages_count=$10, customer_email=$11, customer_name=$12, synced_at=now()`,
    [x.id, x.status || '', (x.subject || '').slice(0, 500), x.channel || '',
     JSON.stringify((x.tags || []).map(g => g?.name).filter(Boolean)),
     x.created_datetime || null, x.closed_datetime || null, x.updated_datetime || null, !!x.spam,
     Number.isFinite(x.messages_count) ? x.messages_count : null,
     (x.customer?.email || '').slice(0, 200), (x.customer?.name || '').slice(0, 200)]);
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
  if (st.data_version !== 2) { // re-backfill to populate spam + messages_count + customer on existing rows
    st.data_version = 2; st.backfill_cursor = null; st.backfill_done = false;
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
  try {
    const us = (await pool.query(`SELECT v FROM sync_state WHERE k='uk_stock'`)).rows[0]?.v;
    if (await getConnector('uk_stock') && (!us?.last_run || Date.now() - Date.parse(us.last_run) > 55 * 60 * 1000)) {
      await syncUkStock();
    }
  } catch (e) { console.error('interval stock sync:', e.message); }
  try {
    const ks = (await pool.query(`SELECT v FROM sync_state WHERE k='klaviyo'`)).rows[0]?.v;
    if (await getConnector('klaviyo') && (!ks?.last_run || Date.now() - Date.parse(ks.last_run) > 55 * 60 * 1000)) {
      await syncKlaviyo();
    }
  } catch (e) { console.error('interval klaviyo sync:', e.message); }
  try {
    const rs = (await pool.query(`SELECT v FROM sync_state WHERE k='redo'`)).rows[0]?.v;
    if (await getConnector('redo')) {
      if (!rs || !rs.backfill_done) await syncRedo(10);
      else if (!rs.last_run || Date.now() - Date.parse(rs.last_run) > 55 * 60 * 1000) await syncRedo(6);
    }
  } catch (e) { console.error('interval redo sync:', e.message); }
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

    res.json({ configured: true, totals_30d: tot.rows[0], top_reasons: reasons.rows, open_by_status: statuses.rows,
      recent: recent.rows, leakage, defects, reason_by_product: (typeof reasonByProduct !== 'undefined' ? reasonByProduct : null),
      extra_error: extraError, sync: ss });
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
  res.json({ configured: !!conn, totals_30d: totals.rows[0], recent: recent.rows, revenue_share, flows, sync: ss });
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
  try { res.json(await syncKlaviyo()); }
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
app.post('/api/stock/sync', async (_req, res) => {
  try { res.json(await syncUkStock()); }
  catch (e) { res.status(502).json({ error: e.message }); }
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
      legacyResourceId name createdAt updatedAt cancelledAt tags
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
  if (st.engine !== 'graphql-v3') { // v3: re-backfill to pick up fulfillment dates (and order tags)
    st.engine = 'graphql-v3'; st.backfill_cursor = null; st.backfill_done = false; st.last_error = null;
  }
  let pages = 0, upserts = 0, lastError = null;
  const horizonIso = new Date(Date.now() - BACKFILL_HORIZON_DAYS * 864e5).toISOString();

  const upsertOrders = async (orders) => {
    for (const o of orders) {
      await pool.query(
        `INSERT INTO orders_cache (shopify_id, order_number, created_at, cancelled_at, currency, total_price, country, financial_status, fulfillment_status, items, order_tags, updated_at, fulfilled_at, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
         ON CONFLICT (shopify_id) DO UPDATE SET order_number=$2, created_at=$3, cancelled_at=$4, currency=$5,
           total_price=$6, country=$7, financial_status=$8, fulfillment_status=$9, items=$10, order_tags=$11, updated_at=$12, fulfilled_at=$13, synced_at=now()`,
        [o.id, o.name || '', o.created_at || null, o.cancelled_at || null, o.currency || '',
         Number(o.total_price) || 0,
         o.country || '',
         o.financial_status || '', o.fulfillment_status || 'unfulfilled',
         JSON.stringify((o.line_items || []).map(li => ({ title: li.title, sku: li.sku, qty: li.quantity }))),
         JSON.stringify(o.tags || []),
         o.updated_at || null, o.fulfilled_at || null]);
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
      pool.query(`SELECT it->>'title' product, sum(coalesce((it->>'qty')::int,0))::int qty
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE ${W} AND cancelled_at IS NULL
        GROUP BY 1 ORDER BY 2 DESC LIMIT 6`, p),
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
    const awaiting = (await pool.query(
      `SELECT order_number, created_at::date d, country, total_price, currency,
       floor(extract(epoch from now()-created_at)/86400)::int age_days
       FROM orders_cache
       WHERE ${WX} AND cancelled_at IS NULL AND fulfillment_status NOT IN ('fulfilled','restocked')
       ORDER BY created_at ASC LIMIT 20`, xp)).rows;
    // filter option lists (over last 365d, independent of active filters, so dropdowns stay stable)
    const [optCountries, optTags, optProducts] = await Promise.all([
      pool.query(`SELECT country, count(*)::int c FROM orders_cache
        WHERE created_at >= now()-interval '365 days' AND country <> '' GROUP BY 1 ORDER BY 2 DESC LIMIT 100`),
      pool.query(`SELECT t.tag, count(*)::int c FROM orders_cache, LATERAL jsonb_array_elements_text(order_tags) t(tag)
        WHERE created_at >= now()-interval '365 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 100`),
      pool.query(`SELECT it->>'title' product, sum(coalesce((it->>'qty')::int,0))::int qty
        FROM orders_cache, LATERAL jsonb_array_elements(items) it
        WHERE created_at >= now()-interval '365 days' AND it->>'title' <> ''
        GROUP BY 1 ORDER BY 2 DESC LIMIT 200`)
    ]);
    res.json({ configured: true, totals_30d: tot.rows[0], top_countries: countries.rows, top_products: products.rows,
      top_order_tags: orderTags, fulfillment: fulfil, awaiting, recent: recent.rows, sync: ss,
      days: win.days, custom: win.custom, from: p[0], to: p[1],
      filters: { active: { product: product || null, country: country || null, tag: tag || null },
        countries: optCountries.rows.map(r => r.country),
        tags: optTags.rows.map(r => r.tag),
        products: optProducts.rows.map(r => r.product) } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Fulfillments keyed to the ACTUAL fulfillment date (fulfilled_at), not order creation.
// ?days=N → per-day counts; ?date=YYYY-MM-DD → the specific orders fulfilled that day (for spot-checking in Shopify).
app.get('/api/shopify/fulfillments', async (req, res) => {
  try {
    const conn = await getConnector('shopify');
    const storeDomain = conn?.config?.store_domain || '';
    const adminBase = storeDomain ? `https://${storeDomain}/admin/orders/` : null;
    const backfillDone = (await pool.query(`SELECT v FROM sync_state WHERE k='shopify'`)).rows[0]?.v?.backfill_done ?? null;

    if (req.query.date) {
      const day = String(req.query.date).slice(0, 10);
      const orders = (await pool.query(
        `SELECT shopify_id, order_number, created_at, fulfilled_at, country, total_price, currency, fulfillment_status, items,
           floor(extract(epoch from (fulfilled_at - created_at))/86400)::int days_to_fulfill
         FROM orders_cache
         WHERE fulfilled_at >= $1::date AND fulfilled_at < ($1::date + interval '1 day')
         ORDER BY fulfilled_at ASC LIMIT 500`, [day])).rows;
      return res.json({ date: day, admin_base: adminBase, backfill_done: backfillDone, count: orders.length, orders });
    }

    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 366);
    const start = new Date(Date.now() - days * 864e5).toISOString();
    const byDay = (await pool.query(
      `SELECT to_char(fulfilled_at::date,'YYYY-MM-DD') d, count(*)::int orders,
         coalesce(sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it)),0)::int units
       FROM orders_cache
       WHERE fulfilled_at >= $1 AND cancelled_at IS NULL
       GROUP BY 1 ORDER BY 1 DESC`, [start])).rows;
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
// resolve a time window from query params: ?days=N (preset) or ?from=ISO&to=ISO (custom)
function resolveWindow(query) {
  const from = query.from ? new Date(query.from) : null;
  const to = query.to ? new Date(query.to) : null;
  if (from && to && !isNaN(from) && !isNaN(to) && from < to) {
    const days = Math.max(1, Math.round((to - from) / 864e5));
    return { start: from, end: to, days, bucket: days <= 31 ? 'day' : 'week', custom: true };
  }
  const days = Math.min(Math.max(parseInt(query.days) || 7, 1), 366);
  return { start: new Date(Date.now() - days * 864e5), end: new Date(), days, bucket: days <= 31 ? 'day' : 'week', custom: false };
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
    pool.query(`SELECT date_trunc('${bucket}', created_at)::date d,
                coalesce(sum((SELECT sum(coalesce((it->>'qty')::int,0)) FROM jsonb_array_elements(items) it)),0)::int units
                FROM orders_cache WHERE created_at >= $1 AND created_at < $2 AND fulfillment_status='fulfilled' AND cancelled_at IS NULL
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
                  WHERE NOT spam AND messages_count >= 10 ORDER BY messages_count DESC, created_datetime DESC LIMIT 10`),
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
        '%notify@%', '%@mail.%', '%@e.%', '%@email.%'];
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

async function slackPost(token, channel, text, thread_ts) {
  const r = await (await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ channel, text, thread_ts })
  })).json();
  if (!r.ok) console.error('slack post failed:', r.error);
}

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
