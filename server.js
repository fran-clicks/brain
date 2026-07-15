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

// ---------- optional site-wide protection ----------
// /api/slack/* is exempt (Slack signs its own requests); /api/health is exempt for Render's health checker.
const SITE_PW = process.env.DASHBOARD_PASSWORD;
if (SITE_PW) {
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/slack/') || req.path === '/api/health') return next();
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
    CREATE TABLE IF NOT EXISTS tickets_cache (
      gorgias_id BIGINT PRIMARY KEY, status TEXT, subject TEXT DEFAULT '', channel TEXT DEFAULT '',
      tags JSONB DEFAULT '[]', created_datetime TIMESTAMPTZ, closed_datetime TIMESTAMPTZ,
      updated_datetime TIMESTAMPTZ, synced_at TIMESTAMPTZ DEFAULT now());
    CREATE INDEX IF NOT EXISTS idx_tc_created ON tickets_cache (created_datetime);
    CREATE INDEX IF NOT EXISTS idx_tc_closed ON tickets_cache (closed_datetime);
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
      event_date DATE NOT NULL, added_by TEXT DEFAULT 'anonymous',
      attachment_name TEXT, attachment_type TEXT, attachment_data TEXT,
      created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS sync_state (k TEXT PRIMARY KEY, v JSONB NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS connector_types (
      slug TEXT PRIMARY KEY, label TEXT NOT NULL, fields JSONB NOT NULL,
      notes TEXT DEFAULT '', created_by TEXT DEFAULT 'assistant', created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'approved';
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approved_by TEXT;
    ALTER TABLE connectors ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
  `);
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
    'SELECT id, type, name, meta, active, added_by, approval_status, approved_by, created_at FROM connectors ORDER BY created_at DESC');
  res.json(rows);
});

// ---------- pending integrations + admin approval ----------
const adminOk = (pw) => {
  const admin = process.env.ADMIN_PASSWORD;
  if (!admin || !pw) return false;
  const a = Buffer.from(String(pw)), b = Buffer.from(admin);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

app.get('/api/integrations/pending', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, type, name, meta, added_by, created_at FROM connectors
     WHERE approval_status='pending' AND active=true ORDER BY created_at`);
  res.json(rows);
});

app.post('/api/connectors/:id/decision', async (req, res) => {
  const { decision, admin_password, decided_by } = req.body || {};
  if (!process.env.ADMIN_PASSWORD)
    return res.status(400).json({ error: 'No ADMIN_PASSWORD is set on the server. Set it in Render → Environment to enable approvals.' });
  if (!adminOk(admin_password))
    return res.status(403).json({ error: 'Wrong admin password. Only authorized members can approve or reject integrations.' });
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
  const { type, name, config, added_by } = req.body || {};
  const types = await getAllConnectorTypes();
  const def = types[type];
  if (!def) return res.status(400).json({ error: 'unknown connector type' });
  for (const f of def.fields) {
    if (!config?.[f.key]) return res.status(400).json({ error: `missing field: ${f.key}` });
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
  const approval = CONNECTOR_TYPES[type] ? 'approved' : 'pending'; // built-ins auto-approved; dynamic need admin sign-off
  const { rows } = await pool.query(
    `INSERT INTO connectors (type, name, config_encrypted, meta, added_by, approval_status) VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, type, name, meta, active, added_by, approval_status, created_at`,
    [type, name || def.label, encrypt(config), meta, added_by || 'anonymous', approval]);
  if (type === 'gorgias') syncGorgias(15).catch(e => console.error('initial sync:', e.message));
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
async function syncGorgias(maxPages = 5) {
  if (syncRunning) return { skipped: true };
  const cfg = await getGorgiasConfig();
  if (!cfg) return { configured: false };
  syncRunning = true;
  try {
    const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v || {};
    const lastSync = st.last_updated ? Date.parse(st.last_updated) : 0;
    let cursor = null, pages = 0, upserts = 0, done = false, newest = st.last_updated || null;
    while (pages < maxPages && !done) {
      const q = `/api/tickets?limit=100&order_by=updated_datetime:desc&trashed=false${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
      const t = await gorgiasRequest(cfg, q);
      const rows = t.data || [];
      if (!rows.length) break;
      for (const x of rows) {
        await pool.query(
          `INSERT INTO tickets_cache (gorgias_id, status, subject, channel, tags, created_datetime, closed_datetime, updated_datetime, synced_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
           ON CONFLICT (gorgias_id) DO UPDATE SET status=$2, subject=$3, channel=$4, tags=$5,
             created_datetime=$6, closed_datetime=$7, updated_datetime=$8, synced_at=now()`,
          [x.id, x.status || '', (x.subject || '').slice(0, 500), x.channel || '',
           JSON.stringify((x.tags || []).map(g => g.name)),
           x.created_datetime || null, x.closed_datetime || null, x.updated_datetime || null]);
        upserts++;
      }
      if (!newest && rows[0]?.updated_datetime) newest = rows[0].updated_datetime;
      const oldest = rows[rows.length - 1]?.updated_datetime;
      if (lastSync && oldest && Date.parse(oldest) < lastSync) done = true;
      cursor = t.meta?.next_cursor;
      if (!cursor) done = true;
      pages++;
    }
    await pool.query(
      `INSERT INTO sync_state (k, v) VALUES ('gorgias', $1)
       ON CONFLICT (k) DO UPDATE SET v=$1`,
      [JSON.stringify({ last_updated: newest || new Date().toISOString(), last_run: new Date().toISOString(), upserts })]);
    return { configured: true, pages, upserts };
  } finally { syncRunning = false; }
}

async function maybeSync() {
  const st = (await pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)).rows[0]?.v;
  const stale = !st?.last_run || Date.now() - Date.parse(st.last_run) > 15 * 60 * 1000;
  if (stale) syncGorgias(5).catch(e => console.error('sync:', e.message));
  return st;
}

app.post('/api/gorgias/sync', async (_req, res) => {
  try { res.json(await syncGorgias(20)); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ---------- overview stats (from local cache → any period) ----------
const CANCEL_RX = 'cancel|refund|return|chargeback';
async function overviewStats(days) {
  days = Math.min(Math.max(parseInt(days) || 7, 1), 366);
  const bucket = days <= 31 ? 'day' : 'week';
  const params = [`${days} days`];
  const [created, closed, cancels, totals, events, st] = await Promise.all([
    pool.query(`SELECT date_trunc('${bucket}', created_datetime)::date d, count(*)::int c FROM tickets_cache
                WHERE created_datetime >= now()-$1::interval GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT date_trunc('${bucket}', closed_datetime)::date d, count(*)::int c FROM tickets_cache
                WHERE closed_datetime >= now()-$1::interval GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT date_trunc('${bucket}', created_datetime)::date d, count(*)::int c FROM tickets_cache
                WHERE created_datetime >= now()-$1::interval AND (subject ~* '${CANCEL_RX}' OR tags::text ~* '${CANCEL_RX}')
                GROUP BY 1 ORDER BY 1`, params),
    pool.query(`SELECT count(*)::int total,
                count(*) FILTER (WHERE status='open')::int open,
                count(*) FILTER (WHERE created_datetime >= now()-$1::interval)::int created,
                count(*) FILTER (WHERE closed_datetime >= now()-$1::interval)::int closed,
                count(*) FILTER (WHERE created_datetime >= now()-$1::interval AND (subject ~* '${CANCEL_RX}' OR tags::text ~* '${CANCEL_RX}'))::int cancel_refund
                FROM tickets_cache`, params),
    pool.query(`SELECT id, title, event_date, added_by, attachment_name FROM events
                WHERE event_date >= (now()-$1::interval)::date ORDER BY event_date`, params),
    pool.query(`SELECT v FROM sync_state WHERE k='gorgias'`)
  ]);
  return {
    days, bucket,
    tickets: { series: { created: created.rows, closed: closed.rows, cancel_refund: cancels.rows }, totals: totals.rows[0] },
    sales: null, // no sales source connected yet
    events: events.rows,
    last_sync: st.rows[0]?.v?.last_run || null
  };
}

app.get('/api/stats/overview', async (req, res) => {
  try {
    await maybeSync();
    res.json(await overviewStats(req.query.days));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// legacy endpoint kept for the Gorgias tab (live snapshot)
app.get('/api/gorgias/stats', async (_req, res) => {
  const cfg = await getGorgiasConfig();
  if (!cfg) return res.json({ configured: false, message: 'Gorgias not connected — add it from the Connectors tab (+).' });
  const out = { configured: true, fetched_at: new Date().toISOString(), errors: [] };
  const now = Date.now(), weekAgo = now - 7 * 864e5;
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
    description: 'Sales/orders data (deliveries, revenue by country/product, etc).',
    input_schema: { type: 'object', properties: { question: { type: 'string' } } }
  },
  {
    name: 'list_pending_integrations',
    description: 'List connector integrations that are pending admin approval, rejected, or approved but not yet wired. Use when someone asks about pending integrations or the status of a connector they added.',
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

async function runTool(name, input) {
  if (name === 'query_tickets') {
    const conds = [], params = [];
    const add = (v, sqlFn) => { params.push(v); conds.push(sqlFn(`$${params.length}`)); };
    if (input.text_match) add(String(input.text_match).slice(0, 200), p => `(subject ~* ${p} OR tags::text ~* ${p})`);
    if (input.status) add(input.status, p => `status = ${p}`);
    if (input.created_after) add(input.created_after, p => `created_datetime >= ${p}`);
    if (input.created_before) add(input.created_before, p => `created_datetime < ${p}`);
    if (input.closed_after) add(input.closed_after, p => `closed_datetime >= ${p}`);
    if (input.closed_before) add(input.closed_before, p => `closed_datetime < ${p}`);
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
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
    return { error: 'No sales source is connected to the brain yet. Sales, delivery and order data (by country, product, delivery status) will become available once a store/sales connector is added. Offer to set one up right now: ask which platform they use, then use create_connector_type to build the credentials form.' };
  }
  if (name === 'list_pending_integrations') {
    const { rows } = await pool.query(
      `SELECT id, type, name, meta, added_by, approval_status, approved_by, created_at FROM connectors
       WHERE approval_status IN ('pending','rejected') OR (approval_status='approved' AND meta->>'integration'='pending')
       ORDER BY created_at DESC LIMIT 50`);
    return { integrations: rows, note: 'pending = waiting for an authorized member to approve/reject on the ＋ page. approved with integration:pending = authorized, sync code still being wired by the dev team.' };
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
  const system = `You are the built-in assistant of "clicks brain", an internal team dashboard. Today is ${new Date().toISOString().slice(0, 10)}.
Tabs: Overview (period stats 7d/1m/3m/6m/1y with event markers), Sales & Dates, Gorgias Stats, Knowledge Bases, Connectors (the ＋ button in the nav).
Product specs are not shown yet — they will be captured automatically from sources (Shopify product list, website) once those connectors are added.
House rules:
- Data flows in from sources; nothing is deletable/editable here. Wrong data → fix at the source, re-import.
- Credentials go ONLY into the New connector form on the ＋ page (encrypted, write-only). NEVER ask for or accept credentials in chat; if a user posts one, tell them to rotate it immediately and use the form instead.
- Connector types currently in the dropdown: ${JSON.stringify(Object.fromEntries(Object.entries(knownTypes).map(([k, v]) => [k, { label: v.label, fields: v.fields.map(f => f.key), dynamic: !!v.dynamic }])))}.
- Active connectors right now: ${JSON.stringify(conns.rows)}.
- Team events (campaigns, launches) are logged on the Overview tab with optional attachments and appear as 📌 markers on charts to show their influence.
Adding NEW kinds of connectors is a core part of your job. When a member wants to connect something not in the dropdown (Shopify, Klaviyo, a shipping provider, a custom internal API...):
1. Ask what service it is and what data they want from it.
2. Work out what its API needs for server-to-server auth (base URL/store domain, API key/token, account id...). Ask if unsure — the member may need to check with whoever admins that service.
3. Call create_connector_type with clear field labels that say exactly where to find each value. Mark every credential secret:true.
4. Tell them the form is now in the dropdown on this page; after they save, an AUTHORIZED member must approve it in the "Pending integrations" list on this page (requires the admin password, entered in that list — never in chat). Once approved, the dev team wires the data sync.
gorgias, anthropic and slack connectors are fully wired and auto-approved: they test the connection and work immediately.
Use list_pending_integrations to report what's waiting for approval or wiring. You cannot approve anything yourself.
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
        content: JSON.stringify(await runTool(tu.name, tu.input || {})).slice(0, 8000)
      })))
    }];
    reply = text; // fallback if rounds exhausted
  }
  return { configured: true, reply: reply || '(no reply)' };
}

app.post('/api/assistant', async (req, res) => {
  try {
    res.json(await runAssistant(req.body?.messages || []));
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
    const { reply } = await runAssistant([{ role: 'user', content: text }], { slack: true });
    await slackPost(conn.config.bot_token, ev.channel, reply, ev.thread_ts || ev.ts);
  } catch (e) {
    console.error('slack assistant error:', e.message);
    await slackPost(conn.config.bot_token, ev.channel, `⚠️ Couldn't answer that: ${e.message}`, ev.thread_ts || ev.ts);
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`clicks brain on :${PORT}`)))
  .catch((e) => { console.error('DB init failed:', e); process.exit(1); });
