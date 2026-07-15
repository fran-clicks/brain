/**
 * clicks brain — internal knowledge dashboard
 * Data flows IN from sources (Gorgias API, member imports). Nothing is deletable
 * from the dashboard by design: wrong info gets fixed at the source.
 * Credentials live ONLY in environment variables and are never sent to the browser.
 */
const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------- optional site-wide protection (set DASHBOARD_PASSWORD on Render) ----------
const SITE_PW = process.env.DASHBOARD_PASSWORD;
if (SITE_PW) {
  app.use((req, res, next) => {
    const hdr = req.headers.authorization || '';
    const [, b64] = hdr.split(' ');
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
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      sku TEXT DEFAULT '',
      specs TEXT DEFAULT '',
      warranty TEXT DEFAULT '',
      source TEXT DEFAULT 'manual import',
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS key_dates (
      id SERIAL PRIMARY KEY,
      date DATE NOT NULL,
      event TEXT NOT NULL,
      source TEXT DEFAULT 'manual import',
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS kb_suggestions (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      suggested_by TEXT DEFAULT 'anonymous',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
}

// crude guard: refuse payloads that look like credentials
const looksSecret = (t) =>
  /(api[_-]?key|secret|password|token|bearer\s+[a-z0-9]|sk-[a-z0-9]{8,})/i.test(String(t || ''));

const rejectSecrets = (req, res, next) => {
  if (looksSecret(JSON.stringify(req.body))) {
    return res.status(400).json({ error: 'Submission looks like it contains a credential (API key/token/password). Secrets are never stored in the brain.' });
  }
  next();
};

// ---------- read + add-only endpoints (NO delete/update by design) ----------
app.get('/api/products', async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM products ORDER BY name');
  res.json(rows);
});
app.post('/api/products', rejectSecrets, async (req, res) => {
  const { name, sku, specs, warranty, source } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query(
    'INSERT INTO products (name, sku, specs, warranty, source) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [name, sku || '', specs || '', warranty || '', source || 'manual import']
  );
  res.status(201).json(rows[0]);
});

app.get('/api/dates', async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM key_dates ORDER BY date');
  res.json(rows);
});
app.post('/api/dates', rejectSecrets, async (req, res) => {
  const { date, event, source } = req.body || {};
  if (!date || !event) return res.status(400).json({ error: 'date and event required' });
  const { rows } = await pool.query(
    'INSERT INTO key_dates (date, event, source) VALUES ($1,$2,$3) RETURNING *',
    [date, event, source || 'manual import']
  );
  res.status(201).json(rows[0]);
});

app.get('/api/kb', async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM kb_suggestions ORDER BY created_at DESC');
  res.json(rows);
});
app.post('/api/kb', rejectSecrets, async (req, res) => {
  const { name, description, suggested_by } = req.body || {};
  if (!name || !description) return res.status(400).json({ error: 'name and description required' });
  const { rows } = await pool.query(
    'INSERT INTO kb_suggestions (name, description, suggested_by) VALUES ($1,$2,$3) RETURNING *',
    [name, description, suggested_by || 'anonymous']
  );
  res.status(201).json(rows[0]);
});

// ---------- Gorgias proxy (credentials stay server-side) ----------
const G = {
  domain: process.env.GORGIAS_DOMAIN, // e.g. "clicks" for clicks.gorgias.com
  email: process.env.GORGIAS_EMAIL,
  key: process.env.GORGIAS_API_KEY
};

async function gorgias(pathAndQuery, opts = {}) {
  const auth = Buffer.from(`${G.email}:${G.key}`).toString('base64');
  const r = await fetch(`https://${G.domain}.gorgias.com${pathAndQuery}`, {
    ...opts,
    headers: {
      Authorization: `Basic ${auth}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(opts.headers || {})
    }
  });
  if (!r.ok) throw new Error(`Gorgias ${pathAndQuery} → ${r.status}`);
  return r.json();
}

app.get('/api/gorgias/stats', async (_req, res) => {
  if (!G.domain || !G.email || !G.key) {
    return res.json({
      configured: false,
      message: 'Gorgias not connected. Set GORGIAS_DOMAIN, GORGIAS_EMAIL and GORGIAS_API_KEY in the Render environment.'
    });
  }
  const out = { configured: true, fetched_at: new Date().toISOString(), errors: [] };
  const now = Date.now();
  const weekAgo = now - 7 * 864e5;

  // Recent tickets → open/closed counts, weekly activity, total volume
  try {
    const t = await gorgias('/api/tickets?limit=100&order_by=created_datetime:desc&trashed=false');
    const tickets = t.data || [];
    out.total_tickets = t.meta?.total_resources ?? null;
    out.sample_size = tickets.length;
    out.open_in_recent = tickets.filter(x => x.status === 'open').length;
    out.created_last_7d = tickets.filter(x => Date.parse(x.created_datetime) >= weekAgo).length;
    out.closed_last_7d = tickets.filter(x => x.closed_datetime && Date.parse(x.closed_datetime) >= weekAgo).length;
    // per-day created counts for chart (last 7 days)
    const days = {};
    for (let i = 6; i >= 0; i--) days[new Date(now - i * 864e5).toISOString().slice(0, 10)] = 0;
    tickets.forEach(x => {
      const d = (x.created_datetime || '').slice(0, 10);
      if (d in days) days[d]++;
    });
    out.created_per_day = days;
  } catch (e) { out.errors.push(String(e.message)); }

  // CSAT from recent satisfaction surveys (scores are 1-5)
  try {
    const s = await gorgias('/api/satisfaction-surveys?limit=100');
    const scored = (s.data || []).filter(x => typeof x.score === 'number');
    out.csat_responses = scored.length;
    out.csat_avg_5 = scored.length
      ? +(scored.reduce((a, x) => a + x.score, 0) / scored.length).toFixed(2)
      : null;
  } catch (e) { out.errors.push(String(e.message)); }

  // Average first response time (best effort — reporting stats API)
  try {
    const frt = await gorgias('/api/reporting/stats?limit=1', {
      method: 'POST',
      body: JSON.stringify({
        scope: 'first-response-time',
        measures: ['averageFirstResponseTime'],
        filters: [],
        timezone: 'UTC'
      })
    });
    const row = frt?.data?.[0] || frt?.data || {};
    const v = row.averageFirstResponseTime ?? row['FirstResponseTime.averageFirstResponseTime'] ?? null;
    out.avg_first_response_seconds = typeof v === 'number' ? v : (v ? Number(v) : null);
  } catch (e) { out.errors.push(String(e.message)); }

  res.json(out);
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`clicks brain on :${PORT}`)))
  .catch((e) => { console.error('DB init failed:', e); process.exit(1); });
