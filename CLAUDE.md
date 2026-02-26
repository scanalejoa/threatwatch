# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ThreatWatch — Project Context

Single-page cybersecurity dashboard (`index.html`) that aggregates vulnerability data from 4 sources into a unified real-time feed. Deployed via GitHub Pages / Cloudflare Pages.

## Commands

```bash
# Local dev server (serves index.html at http://localhost:3000)
npm run dev

# Deploy CORS proxy to Cloudflare Workers
cd cors-proxy
npx wrangler login    # one-time auth
npx wrangler deploy
```

No build step. There are no tests.

## Architecture

- **Single file**: All HTML, CSS, and JavaScript in `index.html` (~2600 lines). The `<script>` block starts at line 1583.
- **No build step**: Pure vanilla JS, no frameworks
- **CORS Proxy**: Cloudflare Worker at `cors-proxy/worker.js` — proxies requests via `?url=<encoded-target>`, enforces an origin allowlist and a domain allowlist

## Data Sources

| Source | API Endpoint | CORS Proxy? |
|--------|-------------|-------------|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | No |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Yes |
| GitHub Advisories | `api.github.com/advisories` | No |
| Palo Alto PSIRT | `security.paloaltonetworks.com/json` | Yes (fallback) |

## Key Global State

```js
let allCves = [];            // unified CVE array — all sources merged here
let kevData = [];            // raw KEV catalog for cross-reference
let currentFilter = 'ALL';       // severity filter: ALL/CRITICAL/HIGH/MEDIUM
let currentSourceFilter = 'ALL'; // source filter: ALL/NVD/KEV/GITHUB/PALOALTO
let currentRangeDays = 7;        // active date range; -1 = custom range
let _nvdCancelFlag = false;      // cancels in-progress paginated NVD loads
```

## Key Functions (line references)

| Function | Line | Purpose |
|----------|------|---------|
| `loadNVD()` | ~1656 | Paginated NVD fetch; uses `_nvdCancelFlag` to abort stale loads |
| `loadKEV()` | ~1780 | Fetches CISA KEV; sets `_kevExploited: true`; calls `mergeExternalCves()` |
| `loadGitHub()` | ~1866 | Fetches GitHub Advisories; normalises to NVD-like shape |
| `loadPaloAlto()` | ~1934 | Fetches Palo Alto PSIRT with proxy fallback |
| `mergeExternalCves()` | ~1987 | Deduplicates and merges external entries into `allCves[]` by CVE ID |
| `getCvss()` | ~2001 | v4.0→v3.1→v3.0→v2.0; Primary (NVD) preferred over Secondary (CNA) |
| `renderCves()` | ~2066 | Main list renderer; reads `allCves[]`, `currentFilter`, `currentSourceFilter` |
| `renderStats()` | ~2150 | Updates stat cards and severity counts |
| `runSearch()` | ~2534 | Searches local cache + NVD API; enriches zero-score entries via batch NVD fetch |
| `proxyUrl()` | ~1860 | Wraps a target URL for the CORS proxy |
| `loadDemoData()` | ~2333 | Fallback when NVD is unreachable |

## Key Data Flow

1. `loadNVD()` paginates NVD (2000 results/page, 6.5 s between pages due to rate limit) → stored in `allCves[]` with `_source: 'nvd'`
2. External loaders convert to NVD-like shape and merge via `mergeExternalCves()` (deduplicates by `.cve.id`)
3. KEV entries get `_kevExploited: true`; they lack CVSS natively — scores are enriched lazily during search
4. All rendering reads `allCves[]` filtered by `currentFilter` / `currentSourceFilter`

## CVSS Scoring (`getCvss()`)

- Checks v4.0 → v3.1 → v3.0 → v2.0 in order
- Prefers **Primary** (NVD) scores, falls back to **Secondary** (CNA vendor scores like Fortinet, Cisco)
- Returns `0` if no score; UI renders `"N/A"` for score `0`

## CVSS Enrichment

- KEV entries have score 0 until enriched
- During search, entries with score 0 are batch-fetched from NVD by CVE ID (up to 10 parallel)
- Enriched scores persist in `allCves[]` for the session

## API Rate Limits

- NVD: 5 requests / 30 s without API key → `NVD_RATE_DELAY_MS = 6500` between paginated requests
- NVD keyword search requires **full words** — partial terms like `"forti"` return 404; use `"fortinet"`

## Common Gotchas

- `loadNVD()` preserves external source entries on refresh (filters `allCves` by `_source !== 'nvd'` before replacing)
- Loading order matters: NVD loads first, then external sources merge sequentially
- `_nvdCancelFlag` is set to `true` at the start of each `loadNVD()` call to abort any previous in-progress paginated fetch
- Browser caching can serve stale JS — hard-refresh (`Ctrl+Shift+R`) after editing `index.html`
- The CORS proxy `worker.js` has two allowlists that must be kept in sync: `ALLOWED_ORIGINS` (caller domains) and the `allowed` domain array (proxy targets)

## Deployment

- **Dashboard**: push to `main` → GitHub Pages / Cloudflare Pages auto-deploys `index.html`
- **CORS proxy**: `cd cors-proxy && npx wrangler deploy`
- Live URL: `https://threatwatch-7du.pages.dev/`
- Proxy URL: `https://threatwatch-cors-proxy.scanalejoa.workers.dev`
