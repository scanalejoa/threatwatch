# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ThreatWatch — Project Context

Single-page cybersecurity dashboard (`index.html`) that aggregates vulnerability data from 8 sources into a unified real-time feed. Deployed via Cloudflare Pages.

## Commands

```bash
# Local dev server (serves index.html at http://localhost:3000)
npm run dev

# Deploy CORS proxy to Cloudflare Workers
cd cors-proxy
npx wrangler deploy
# If OAuth login fails, use API token instead:
# $env:CLOUDFLARE_API_TOKEN="<token>" && npx wrangler deploy
```

No build step. There are no tests.

## Architecture

- **Single file**: All HTML, CSS, and JavaScript in `index.html` (~3400 lines). The `<script>` block starts at line 1718.
- **No build step**: Pure vanilla JS, no frameworks
- **CORS Proxy**: Cloudflare Worker at `cors-proxy/worker.js` — proxies requests via `?url=<encoded-target>`, enforces an origin allowlist and a domain allowlist. Supports GET and POST (body forwarding).

## Data Sources

| Source | API Endpoint | CORS Proxy? |
|--------|-------------|-------------|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | No |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Yes |
| GitHub Advisories | `api.github.com/advisories` | No |
| Palo Alto PSIRT | `security.paloaltonetworks.com/json` | Yes (fallback) |
| OSV | `api.osv.dev/v1/querybatch` (POST) | Yes (CORS blocks browser POST) |
| Ubuntu | `ubuntu.com/security/notices.json` | Yes (fallback) |
| MSRC | `api.msrc.microsoft.com/cvrf/v3.0/...` | Yes |
| Red Hat | `access.redhat.com/hydra/rest/securitydata/cve.json` | Yes (fallback) |

## Key Global State

```js
let allCves = [];             // unified CVE array — all sources merged here
let kevData = [];             // raw KEV catalog for cross-reference
let currentFilter = 'ALL';        // severity filter: ALL/CRITICAL/HIGH/MEDIUM
let currentSourceFilter = 'ALL';  // source filter: ALL/NVD/KEV/GITHUB/PALOALTO/OSV/UBUNTU/MSRC/REDHAT
let currentRangeDays = 7;         // active date range; -1 = custom range
let _nvdCancelFlag = false;       // cancels in-progress paginated NVD loads
let _currentLoadKeyword = '';     // active keyword for long/custom range searches
```

## Key Functions (line references)

| Function | Line | Purpose |
|----------|------|---------|
| `setRange()` | ~1758 | Switches date range tab; reloads external sources if switching away from a keyword view |
| `loadCustomRange()` | ~1809 | Validates custom date inputs, sets `_currentLoadKeyword`, calls `loadNVD()` then reloads external sources |
| `loadNVD()` | ~1842 | Paginated NVD fetch with CVE ID detection, pre-filtering, chunking, and cancel support |
| `loadKEV()` | ~2072 | Fetches CISA KEV; sets `_kevExploited: true`; calls `mergeExternalCves()` |
| `loadGitHub()` | ~2158 | Fetches GitHub Advisories; normalises to NVD-like shape |
| `loadPaloAlto()` | ~2226 | Fetches Palo Alto PSIRT with proxy fallback |
| `loadOSV()` | ~2459 | POST querybatch to OSV for 26 popular packages across 6 ecosystems; proxy fallback |
| `loadUbuntu()` | ~2554 | Fetches Ubuntu Security Notices (4 pages × limit=20); extracts CVE IDs from description text |
| `loadMSRC()` | ~2610 | Fetches latest Microsoft MSRC CVRF document via proxy |
| `loadRedHat()` | ~2337 | Fetches Red Hat CVE data; direct-first with proxy fallback |
| `classifyOwaspApi()` | ~2433 | Client-side OWASP API Top 10 classifier; keyword-matches CVE descriptions |
| `mergeExternalCves()` | ~2279 | Deduplicates and merges external entries into `allCves[]`; applies keyword filter when active |
| `getCvss()` | ~2303 | v4.0→v3.1→v3.0→v2.0; Primary (NVD) preferred over Secondary (CNA) |
| `renderCves()` | ~2368 | Main list renderer; reads `allCves[]`, `currentFilter`, `currentSourceFilter` |
| `renderStats()` | ~2462 | Updates stat cards and severity counts |
| `_getPanelCves()` | ~2826 | Returns filtered + sorted panel CVEs for export |
| `exportPanelCSV()` | ~2833 | Exports current panel view as CSV download |
| `exportPanelPDF()` | ~2861 | Prints / saves current panel view as PDF |
| `runSearch()` | ~3018 | Searches local cache + NVD API; enriches zero-score entries via batch NVD fetch |
| `proxyUrl()` | ~2152 | Wraps a target URL for the CORS proxy |
| `loadDemoData()` | ~2647 | Fallback when NVD is unreachable (skipped when keyword is active) |
| `setSourceStatus()` | — | Sets source pill green (ok=true) or yellow (ok=false) with entry count |

## Key Data Flow

1. `loadNVD()` paginates NVD (2000 results/page, 6.5 s between pages due to rate limit) → stored in `allCves[]` with `_source: 'nvd'`
2. External loaders convert to NVD-like shape and merge via `mergeExternalCves()` (deduplicates by `.cve.id`)
3. KEV entries get `_kevExploited: true`; they lack CVSS natively — scores are enriched lazily during search
4. All rendering reads `allCves[]` filtered by `currentFilter` / `currentSourceFilter`
5. On custom range load: `loadNVD()` completes → `.then()` reloads all external sources so they re-filter through `mergeExternalCves()` with the active keyword

## `loadNVD()` internals

The function handles several cases in this order inside its `try` block:

1. **Pre-filter**: if `_currentLoadKeyword` is set, strips all non-NVD entries from `allCves[]` that don't match the keyword (removes unrelated KEV/GitHub/PaloAlto entries loaded at page init)
2. **CVE ID direct lookup**: if keyword matches `CVE-2021-23017`, `cve-2021-23017`, or bare `2021-23017` — uses `?cveId=` parameter for an instant single-request lookup; skips all date range/chunking logic
3. **Chunking**: ranges > 119 days are split into sequential 119-day chunks (NVD API max: 120 days/request); chunk dates use actual UTC timestamps (`.toISOString().split('.')[0] + '.000'`) — forced midnight/end-of-day breaks pagination
4. **Incremental render**: updates panel on every page so user sees results arriving live
5. **Progress**: button shows global `%` across ALL chunks combined (not per-chunk, which would falsely hit 100% repeatedly)
6. **`finally` block**: always resets the REFRESH button regardless of success, error, or early return

## CVSS Scoring (`getCvss()`)

- Checks v4.0 → v3.1 → v3.0 → v2.0 in order
- Prefers **Primary** (NVD) scores, falls back to **Secondary** (CNA vendor scores like Fortinet, Cisco)
- Returns `0` if no score; UI renders `"N/A"` for score `0`

## CVSS Enrichment

- KEV entries have score 0 until enriched
- During search, entries with score 0 are batch-fetched from NVD by CVE ID (up to 10 parallel)
- Enriched scores persist in `allCves[]` for the session

## API Rate Limits & Quirks

- NVD: 5 requests / 30 s without API key → `NVD_RATE_DELAY_MS = 6500` between paginated requests
- NVD `keywordSearch` requires **full words** — partial terms like `"forti"` return 404; use `"fortinet"`
- NVD `keywordSearch` with `keywordExactMatch` enforces exact phrase matching — prevents single-word AND-matching that returns unrelated CVEs
- For exact CVE ID lookups use `?cveId=CVE-YYYY-NNNNN` — do NOT use `keywordSearch` for IDs
- **OSV**: ecosystem names are exact — `crates.io` (NOT `cargo`), `PyPI`, `npm`, `Go`, `Maven`, `RubyGems`. An invalid ecosystem name causes HTTP 400 for the **entire** batch.
- **Ubuntu**: max `limit` is **20** (higher values return HTTP 422). The `order=` param is also invalid (422). Paginate with offset. CVE IDs are in `description`/`summary` text — extract with `/CVE-\d{4}-\d+/g`.
- **Red Hat**: correct endpoint is `/hydra/rest/securitydata/cve.json`. Top-level fields: `cvss3_score`, `bugzilla_description` (not nested). Occasional 503 outages — not a code issue.
- **MSRC**: fetch CVRF Updates list first, then the latest document by ID.

## Custom Date Range Behaviour

- Ranges ≤ 90 days: no keyword required; external sources reload after NVD via `.then()`
- Ranges > 90 days: keyword required (UI enforces this); keyword is passed as `keywordSearch` + `keywordExactMatch` to NVD
- Date inputs are capped to today — future dates are clamped automatically
- If keyword matches a CVE ID pattern, the entire date range is ignored and a direct `cveId` lookup is performed instead

## Auto-refresh

- Fires every 5 minutes to keep the standard date-range views current
- **Skipped** when `currentRangeDays === -1` (custom range) or `_currentLoadKeyword` is non-empty — prevents wiping user-initiated custom searches

## Common Gotchas

- `loadNVD()` preserves external source entries on refresh (filters `allCves` by `_source !== 'nvd'` before replacing)
- `_nvdCancelFlag` is set to `true` at the start of each `loadNVD()` call to abort any previous in-progress paginated fetch
- External sources are loaded once at page init without keyword. When a keyword search starts, `loadNVD()` pre-filters `allCves` to remove non-matching external entries immediately, then reloads them via `.then()` so they re-merge through the keyword filter
- `loadDemoData()` is skipped when `_currentLoadKeyword` is set — it would inject 80 unrelated fake CVEs
- When switching from a keyword view back to a standard range tab (`setRange()`), `hadKeyword` is checked and external sources are reloaded to restore full unfiltered data
- Browser caching can serve stale JS — hard-refresh (`Ctrl+Shift+R`) after editing `index.html`
- The CORS proxy `worker.js` has two allowlists that must be kept in sync: `ALLOWED_ORIGINS` (caller domains) and the `allowed` domain array (proxy targets)
- Chunk dates must use actual UTC timestamps — using `T00:00:00.000`/`T23:59:59.000` makes `pubEndDate` land in the future, which causes NVD to reject paginated requests (`startIndex > 0`)
- If Cloudflare Pages deployments get stuck in "Queued", push an empty commit to force a new build: `git commit --allow-empty -m "Trigger redeploy" && git push`

## Deployment

- **Dashboard**: push to `main` → Cloudflare Pages auto-deploys `index.html`
- **CORS proxy**: `cd cors-proxy && npx wrangler deploy` (deployed separately — not auto-deployed)
- Live URL: `https://threatwatch-7du.pages.dev/`
- Proxy URL: `https://threatwatch-cors-proxy.scanalejoa.workers.dev`
