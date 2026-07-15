/**
 * clicks brain — internal knowledge dashboard
 * - Data flows IN from sources; nothing is deletable from the dashboard.
 * - Connectors (Gorgias, Claude assistant) are added from the UI. Credentials are
 *   encrypted at rest (AES-256-GCM), write-only: no API response ever returns them.
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------- optional site-wide protection ----------
const SITE_PW = process.env.DASHBOARD_PASSWORD;
if (SITE_PW) {
  app.use((req, res, next) => {
    const [, b64] = (req.headers.authorization || '').split(' ');
    const pw = b64 ? Buffer.from(b64, 'base64').toString().split(':').slice(1).join(':') : '';
    if (pw === SITE_PW) return next();
    res.set('WWW-Authenticate', 'Basic realm="clicks brain"').status(401).send('Auth required');
  });
}
app.use(express.static(path.join(__dirname, 'public')));

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
    CREATE TABLE IF NOT EXISTS connectors (
      id SERIAL PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
      config_encrypted TEXT NOT NULL, meta JSONB DEFAULT '{}',
      active BOOLEAN DEFAULT true, added_by TEXT DEFAULT 'anonymous', created_at TIMESTAMPTZ DEFAULT now());
  `);
}

// ---------- crypto (credentials never stored or returned in plain text) ----------
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
  /(api[_-]?key|secret|password|token|bearer\s+[a-z0-9]|sk-[a-z0-9]{8,}|ghp_[a-z0-9]+|rnd_[a-z0-9]+)/i.test(String(t || ''));
const rejectSecrets = (req, res, next) => {
  if (looksSecret(JSON.stringify(req.body))) {
    return res.status(400).json({ error: 'Submission looks like it contains a credential. Secrets belong in Connectors, not in content.' });
  }
  next();
};

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
    fields: [
      { key: 'api_key', label: 'Anthropic API key (console.anthropic.com)', secret: true }
    ]
  }
};

async function getConnector(type) {
  const { rows } = await pool.query(
    'SELECT * FROM connectors WHERE type=$1 AND active=true ORDER BY created_at DESC LIMIT 1', [type]);
  if (!rows[0]) return null;
  try { return { ...rows[0], config: decrypt(rows[0].config_encrypted) }; }
  catch { return null; }
}

app.get('/api/connector-types', (_req, res) => res.json(CONNECTOR_TYPES));

app.get('/api/connectors', async (_req, res) => {
  const { rows } = await pool.query(
    'SELECT id, type, name, meta, active, added_by, created_at FROM connectors ORDER BY created_at DESC');
  res.json(rows); // note: config_encrypted intentionally never selected
});

app.post('/api/connectors', async (req, res) => {
  const { type, name, config, added_by } = req.body || {};
  const def = CONNECTOR_TYPES[type];
  if (!def) return res.status(400).json({ error: 'unknown connector type' });
  for (const f of def.fields) {
    if (!config?.[f.key]) return res.status(400).json({ error: `missing field: ${f.key}` });
  }
  // test the connection before saving
  let meta = {};
  try {
    if (type === 'gorgias') {
      const test = await gorgiasRequest(config, '/api/account');
      meta = { domain: config.domain, account: test?.name || test?.domain || 'ok' };
    } else if (type === 'anthropic') {
      await anthropicRequest(config.api_key, [{ role: 'user', content: 'ping' }], 'Reply with "pong".', 8);
      meta = { model: ASSISTANT_MODEL };
    }
  } catch (e) {
    return res.status(400).json({ error: `Connection test failed: ${e.message}. Credentials were NOT saved.` });
  }
  // supersede previous connector of same type (no hard delete, per design)
  await pool.query('UPDATE connectors SET active=false WHERE type=$1', [type]);
  const { rows } = await pool.query(
    `INSERT INTO connectors (type, name, config_encrypted, meta, added_by) VALUES ($1,$2,$3,$4,$5)
     RETURNING id, type, name, meta, active, added_by, created_at`,
    [type, name || def.label, encrypt(config), meta, added_by || 'anonymous']);
  res.status(201).json(rows[0]);
});

// ---------- data endpoints (read + add-only) ----------
app.get('/api/products', async (_req, res) => {
  res.json((await pool.query('SELECT * FROM products ORDER BY name')).rows);
});
app.post('/api/products', rejectSecrets, async (req, res) => {
  const { name, sku, specs, warranty, source } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query(
    'INSERT INTO products (name, sku, specs, warranty, source) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [name, sku || '', specs || '', warranty || '', source || 'manual import']);
  res.status(201).json(rows[0]);
});
app.get('/api/dates', async (_req, res) => {
  res.json((await pool.query('SELECT * FROM key_dates ORDER BY date')).rows);
});
app.post('/api/dates', rejectSecrets, async (req, res) => {
  const { date, event, source } = req.body || {};
  if (!date || !event) return res.status(400).json({ error: 'date and event required' });
  const { rows } = await pool.query(
    'INSERT INTO key_dates (date, event, source) VALUES ($1,$2,$3) RETURNING *',
    [date, event, source || 'manual import']);
  res.status(201).json(rows[0]);
});
app.get('/api/kb', async (_req, res) => {
  res.json((await pool.query('SELECT * FROM kb_suggestions ORDER BY created_at DESC')).rows);
});
app.post('/api/kb', rejectSecrets, async (req, res) => {
  const { name, description, suggested_by } = req.body || {};
  if (!name || !description) return res.status(400).json({ error: 'name and description required' });
  const { rows } = await pool.query(
    'INSERT INTO kb_suggestions (name, description, suggested_by) VALUES ($1,$2,$3) RETURNING *',
    [name, description, suggested_by || 'anonymous']);
  res.status(201).json(rows[0]);
});

// ---------- Gorgias (credentials from connector, env as fallback) ----------
async function gorgiasRequest(cfg, pathAndQuery, opts = {}) {
  const auth = Buffer.from(`${cfg.email}:${cfg.api_key}`).toString('base64');
  const r = await fetch(`https://${cfg.domain}.gorgias.com${pathAndQuery}`, {
    ...opts,
    headers: { Authorization: `Basic ${auth}`, Accept: 'application/json', 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
  if (!r.ok) throw new Error(`Gorgias ${pathAndQuery} → ${r.status}`);
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

app.get('/api/gorgias/stats', async (_req, res) => {
  const cfg = await getGorgiasConfig();
  if (!cfg) {
    return res.json({ configured: false, message: 'Gorgias not connected — add it from the Connectors tab (+).' });
  }
  const out = { configured: true, fetched_at: new Date().toISOString(), errors: [] };
  const now = Date.now();
  const weekAgo = now - 7 * 864e5;
  try {
    const t = await gorgiasRequest(cfg, '/api/tickets?limit=100&order_by=created_datetime:desc&trashed=false');
    const tickets = t.data || [];
    out.total_tickets = t.meta?.total_resources ?? null;
    out.sample_size = tickets.length;
    out.open_in_recent = tickets.filter(x => x.status === 'open').length;
    out.created_last_7d = tickets.filter(x => Date.parse(x.created_datetime) >= weekAgo).length;
    out.closed_last_7d = tickets.filter(x => x.closed_datetime && Date.parse(x.closed_datetime) >= weekAgo).length;
    const days = {};
    for (let i = 6; i >= 0; i--) days[new Date(now - i * 864e5).toISOString().slice(0, 10)] = 0;
    tickets.forEach(x => { const d = (x.created_datetime || '').slice(0, 10); if (d in days) days[d]++; });
    out.created_per_day = days;
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
  } catch (e) { out.errors.push(String(e.message)); }
  res.json(out);
});

// ---------- embedded Claude assistant ----------
const ASSISTANT_MODEL = process.env.ASSISTANT_MODEL || 'claude-haiku-4-5-20251001';

async function anthropicRequest(apiKey, messages, system, maxTokens = 800) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: ASSISTANT_MODEL, max_tokens: maxTokens, system, messages })
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j?.error?.message || `Anthropic API → ${r.status}`);
  return j;
}

app.post('/api/assistant', async (req, res) => {
  const conn = await getConnector('anthropic');
  const apiKey = conn?.config?.api_key || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.json({ configured: false, reply: 'The assistant isn\'t connected yet. Go to the Connectors tab, click "+ Add connector", choose "Claude assistant" and paste an Anthropic API key from console.anthropic.com.' });
  }
  const messages = (req.body?.messages || []).slice(-12)
    .filter(m => ['user', 'assistant'].includes(m.role) && typeof m.content === 'string');
  if (!messages.length) return res.status(400).json({ error: 'messages required' });

  // context for the assistant — names and counts only, never credentials
  const [conns, p, d, k] = await Promise.all([
    pool.query('SELECT type, name, meta, active, created_at FROM connectors ORDER BY created_at DESC'),
    pool.query('SELECT count(*) FROM products'),
    pool.query('SELECT count(*) FROM key_dates'),
    pool.query('SELECT name, status, suggested_by FROM kb_suggestions ORDER BY created_at DESC LIMIT 20')
  ]);
  const system = `You are the built-in assistant of "clicks brain", an internal team dashboard with tabs: Product Specs, Sales & Dates, Gorgias Stats, Knowledge Bases, Connectors.
House rules you must follow and explain when relevant:
- Data flows in from sources. Nothing can be deleted or edited in the dashboard; wrong data must be fixed at the source and re-imported.
- Credentials are entered ONLY via Connectors tab → "+ Add connector". They are encrypted at rest and write-only. NEVER ask users to paste credentials into this chat, and never reveal anything about stored credentials.
- Available connector types: ${Object.entries(CONNECTOR_TYPES).map(([k, v]) => `${k} (${v.label}: fields ${v.fields.map(f => f.key).join(', ')})`).join('; ')}.
- To add Gorgias: Connectors tab → + → Gorgias helpdesk → subdomain, account email, and REST API key from Gorgias Settings → Account → REST API.
Current state: connectors: ${JSON.stringify(conns.rows)}; products: ${p.rows[0].count}; key dates: ${d.rows[0].count}; recent KB suggestions: ${JSON.stringify(k.rows)}.
Help members use the dashboard, add connectors, and suggest knowledge bases. Be concise and friendly.`;
  try {
    const j = await anthropicRequest(apiKey, messages, system);
    res.json({ configured: true, reply: j.content?.[0]?.text || '(no reply)' });
  } catch (e) {
    res.status(502).json({ error: `Assistant error: ${e.message}` });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`clicks brain on :${PORT}`)))
  .catch((e) => { console.error('DB init failed:', e); process.exit(1); });
