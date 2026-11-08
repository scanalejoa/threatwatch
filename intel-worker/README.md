# ThreatWatch intel worker

Cloudflare Worker that gives the dashboard an **early-warning feed**:

| Job | Schedule | What it does |
|-----|----------|--------------|
| `ingestCveOrg` | every 15 min | Reads the newest part of CVE.org's `cvelistV5/cves/deltaLog.json` (HTTP Range, ~256 KB ≈ 5 h), fetches up to 40 new or updated CVE records per run, keeps CNA CVSS and **CISA SSVC** (exploitation `none/poc/active`, automatable, impact) in KV, sharded by day, for 14 days. New CVEs appear here minutes after publication, often days before NVD scores them. |
| `refreshAdvisories` | hourly at :07 | Node.js security releases (incl. **pre-announcements** with date and severity), the OpenSSH security page, and PHP's GitHub security advisories. Keeps the last good data per source when one fails. |

Endpoints (CORS for the dashboard origins only):

- `GET /v1/recent?days=7` — compact CVE.org records published in the last N days (max 14)
- `GET /v1/advisories` — upstream advisories and upcoming security releases
- `GET /v1/health` — cursor, last run, last error, pending queue, `gap` (true if deltas were missed)

Designed for the **Workers free plan**: ≤ 41 subrequests per run, small KV shards, ~200 KV writes a day.

## Deploy (one time)

```bash
cd intel-worker
npx wrangler login                       # opens the browser
npx wrangler kv namespace create INTEL   # copy the "id" it prints
# paste the id into wrangler.toml → [[kv_namespaces]] id = "…"
npx wrangler deploy
```

The dashboard expects `https://threatwatch-intel.<your-subdomain>.workers.dev`; if your subdomain is not
`scanalejoa`, change `INTEL_API` in `js/app.js`.

The first run only sees the last ~5 hours of CVE.org; the 14-day window fills up as the cron runs
(NVD and the other feeds cover older CVEs meanwhile). Trigger a run right away instead of waiting:
open the Worker in the Cloudflare dashboard → Settings → Triggers → Cron → "Trigger".

## Local development

```bash
cd intel-worker
npx wrangler dev --test-scheduled --port 8787
curl "http://localhost:8787/__scheduled?cron=*/15+*+*+*+*"   # ingest
curl "http://localhost:8787/__scheduled?cron=7+*+*+*+*"      # advisories
```

Point a local dashboard at it from the browser console: `localStorage.setItem('tw_intel_url', 'http://localhost:8787')`
(remove the key to go back to production).

## Files

- `worker.js` — entry point (handlers only; the Workers runtime rejects other exports)
- `lib.js` — ingestion, advisories and HTTP helpers (tested in `tests/intel-worker.test.js`)
- `../js/feeds.js` — parsers shared with the browser fallback
