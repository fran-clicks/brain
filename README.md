# clicks brain

Internal knowledge dashboard: product specs, key dates, live Gorgias stats, and member-suggested knowledge bases.

Design principles: data flows **in** from sources; nothing is deletable from the dashboard (fix errors at the source). Credentials live only in environment variables — never in the database, the UI, or API responses.

## Deploy to Render (via GitHub)

1. Push this folder to a new GitHub repo.
2. In Render: **New → Blueprint**, pick the repo. `render.yaml` creates the web service + Postgres automatically.
3. When prompted, set `DASHBOARD_PASSWORD` (recommended — protects the whole site; any username works). `ENCRYPTION_KEY` is generated automatically.
4. Deploy. Your dashboard will be at `https://clicks-brain.onrender.com` (or similar).

## Connectors (added inside the dashboard, not in Render)

Open the **Connectors** tab → **＋ Add connector**:

- **Gorgias helpdesk** — subdomain (e.g. `clicks`), account email, REST API key (Gorgias: Settings → Account → REST API). Powers the Gorgias Stats tab.
- **Claude assistant** — an Anthropic API key from console.anthropic.com. Powers the 🧠 chat bubble that helps members add connectors and answer questions.

Credentials are AES-256-GCM encrypted at rest and write-only — no API response ever includes them. The connection is tested before saving. Adding a connector of the same type replaces (deactivates, never deletes) the previous one. Env vars `GORGIAS_*` / `ANTHROPIC_API_KEY` still work as fallbacks if you prefer them.

Notes: Render's free web services sleep after inactivity (first load takes ~30s), and free Postgres instances expire after a period — check Render's current terms or upgrade the DB plan for permanence.

## Gorgias metrics shown

- Total tickets, open among latest 100, created/closed last 7 days (from `GET /api/tickets`)
- CSAT average from the latest 100 satisfaction surveys
- Average first response time (from `POST /api/reporting/stats`, best effort)

## Local run

```
npm install
DATABASE_URL=postgres://... node server.js
```
