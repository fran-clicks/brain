# clicks brain

Internal knowledge dashboard: product specs, key dates, live Gorgias stats, and member-suggested knowledge bases.

Design principles: data flows **in** from sources; nothing is deletable from the dashboard (fix errors at the source). Credentials live only in environment variables — never in the database, the UI, or API responses.

## Deploy to Render (via GitHub)

1. Push this folder to a new GitHub repo.
2. In Render: **New → Blueprint**, pick the repo. `render.yaml` creates the web service + Postgres automatically.
3. When prompted, set these environment variables:
   - `GORGIAS_DOMAIN` — your subdomain only, e.g. `clicks` for `clicks.gorgias.com`
   - `GORGIAS_EMAIL` — the Gorgias account email
   - `GORGIAS_API_KEY` — from Gorgias: Settings → Account → REST API
   - `DASHBOARD_PASSWORD` — optional but recommended; protects the whole site with a password (any username)
4. Deploy. Your dashboard will be at `https://clicks-brain.onrender.com` (or similar).

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
