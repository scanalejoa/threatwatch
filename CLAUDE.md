# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ThreatWatch — Project Context

Single-page cybersecurity dashboard (`index.html`) that aggregates vulnerability data from 8 sources into a unified real-time feed, **plus an integrated AI-native Cloudflare console (formerly the standalone CLOUDCTL project)**. Deployed via Cloudflare Pages.

The merged app combines:
- **Threat Intelligence**: live CVE feed from NVD, CISA KEV, GitHub, Palo Alto PSIRT, OSV, Ubuntu, MSRC, Red Hat. (Original ThreatWatch.)
- **Cloudflare Operations**: Claude tool-use over the Cloudflare REST API for DNS / WAF / firewall / Workers / Pages / analytics / cache / bot-mgmt. (Ported from CLOUDCTL v1.0.)
- **WAF Coverage**: cross-feature that joins critical/KEV CVEs against the zone's deployed WAF rules using a keyword heuristic.

The standalone CLOUDCTL project (v1.0) is frozen and lives outside this repo; all development happens here.

## Commands

```bash
# Local dev server (serves the site at http://localhost:3000 — the CORS proxy only allows this port)
npm run dev

# Unit tests (node:test, no dependencies): js/core.js + cors-proxy/worker.js
npm test

# Deploy CORS proxy to Cloudflare Workers
cd cors-proxy
npx wrangler deploy
# If OAuth login fails, use API token instead:
# $env:CLOUDFLARE_API_TOKEN="<token>" && npx wrangler deploy
```

No build step. Tests cover the pure helpers in `js/core.js` and the proxy worker; UI changes still need a manual check in the browser (desktop and ~390px wide).

## Architecture

- **Files** (no framework, no bundler — classic `<script>` tags share one global scope, so inline `onclick` handlers and cross-file globals work):
  - `index.html` — markup only (~600 lines).
  - `css/app.css` — all styles. Colour tokens live on `:root`; the review-fix block at the end overrides older rules.
  - `js/core.js` — **pure helpers, no DOM**: `escapeHtml`, `safeUrl`, `getCvss`, `getCvssDetail`, `getSeverity`, `getVendor`, `getChartVendor`, `mergeCves`, `sortCves`, `toCsv`, `parseHashState`/`buildHashState`, `dailyCounts`, `parseFeedDate`, `isNewSince`. Also `module.exports` for Node tests. Put new testable logic here.
  - `js/app.js` — threat-intel dashboard: loaders, rendering, detail panel, EPSS, search, exports, profile/watchlist.
  - `js/cloudctl.js` — Cloudflare console + Claude agent loop (ported from CLOUDCTL).
  - `js/main.js` — start-up: delegated listeners, URL state, first load, auto-refresh. Loaded last.
  - Load order matters: `core.js` → `app.js` → `cloudctl.js` → `main.js`.
- **Two optional Workers**:
  - `cors-proxy/worker.js` — ThreatWatch's CVE feed proxy. Routes via `?url=<encoded-target>`, origin + host allowlists, HTTPS targets only. Tested in `tests/worker.test.js`.
  - **CF API Bridge** (separate, optional) — when set in Setup as `CF_BRIDGE_URL`, the browser routes Cloudflare REST calls through this Worker (token sent as `X-CF-Token`). Required when direct browser → `api.cloudflare.com` calls are CORS-blocked. The reference Worker lives in the frozen CLOUDCTL project, not in this repo. The two Workers are **NOT merged** — different roles, different allowlists.

### Layout shell (post-merge)

```
<setup-overlay>            ← CF + Anthropic key configuration (sessionStorage)
<header>                   ← logo, profile banner, search, CF zone selector, AI/CF buttons
<div class="app-layout">
  <nav class="sidebar">    ← THREAT INTEL · CLOUDFLARE · CONFIG groups
  <div class="main-area">
    <div class="command-bar"> ← AI input + view-aware suggestion chips
    <div class="view-area">
      <div class="view active" id="view-threat-intel">  ← original dashboard
      <div class="view"        id="view-cf-overview">
      <div class="view"        id="view-cf-dns">
      <div class="view"        id="view-cf-waf">
      <div class="view"        id="view-cf-firewall">
      <div class="view"        id="view-cf-workers">
      <div class="view"        id="view-cf-pages">
      <div class="view"        id="view-cf-analytics">
      <div class="view"        id="view-waf-coverage">    ← cross-feature
<aside class="ai-drawer">  ← collapsible right panel; toggled by header [⚡ AI] button
<aside class="cve-detail">  ← CVE detail panel (openCveDetail / closeCveDetail)
```

Below 900px the sidebar becomes an off-canvas menu (`toggleSidebar()`, header ☰ button).

`showView(name, navEl)` toggles `.view.active`, updates the sidebar's active item, swaps suggestion chips via `setSuggestionsForView(name)`, closes the mobile menu, syncs the URL hash, and lazy-loads CF data when entering an empty CF view (if connected).

## Data Sources

| Source | API Endpoint | CORS Proxy? |
|--------|-------------|-------------|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | No |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Yes (always) |
| GitHub Advisories | `api.github.com/advisories` | No |
| Palo Alto PSIRT | `security.paloaltonetworks.com/json` | Yes (always — no CORS headers) |
| OSV | `api.osv.dev/v1/querybatch` (POST) | Fallback |
| Ubuntu | `ubuntu.com/security/notices.json` | Yes (always — no CORS headers) |
| MSRC | `api.msrc.microsoft.com/cvrf/v3.0/...` | Yes |
| Red Hat | `access.redhat.com/hydra/rest/securitydata/cve.json` | Fallback |
| EPSS (FIRST) | `api.first.org/data/v1/epss?cve=…` (≤100 IDs/call) | Fallback (sends `Access-Control-Allow-Origin: *`) |

## Key Global State

### ThreatWatch (js/app.js)
```js
let allCves = [];                 // unified CVE array — all sources merged here (mergeCves dedupes by id)
let kevData = [];                 // KEV records added inside the selected range (for the KEV card/search)
let currentFilter = 'ALL';        // ALL | CRITICAL | HIGH | MEDIUM | LOW | UNSCORED
let currentSourceFilter = 'ALL';  // ALL | nvd | kev | github | paloalto | osv | ubuntu | msrc | redhat
let currentSort = 'cvss';         // cvss | date | epss | kev
let currentPage = 1;              // feed paging, PAGE_SIZE = 50
let newOnly, watchOnly;           // feed toggles
let currentRangeDays = 7;         // 7 | 30 | 90; -1 = custom range
let _currentLoadKeyword = '';     // keyword for long custom ranges
let _loadGen = 0;                 // refresh generation — a superseded loadNVD stops writing state
const epssCache = new Map();      // CVE id -> { epss, percentile } | null
let companyTechStack, companyModeActive, watchlist, notifyEnabled; // localStorage: tw_company_profile
const PREV_VISIT_MS;              // localStorage tw_last_visit, read once → NEW badges
```

Each entry may carry `_source`, `_kevExploited`, `_kev` (KEV record: dateAdded, dueDate, requiredAction…), `_alsoIn` (other sources that reported the same CVE) and `_demo`.

### CLOUDCTL integration (sessionStorage; cleared on tab close)
```js
let CF_TOKEN, CF_ACCOUNT_ID, ANTHROPIC_KEY, CF_BRIDGE_URL = '';
let AI_MODEL;                  // localStorage tw_ai_model — claude-sonnet-5-5 (default) | claude-opus-5-5 | claude-haiku-5-5
let _lastWafRules;             // last WAF rules fetched by WAF Coverage; reused by the CVE detail panel
let currentZoneId = '', currentZoneName = '';
let chatHistory = [];          // API-shaped messages for Claude tool-use loop
let zoneData = {};
let currentView = 'threat-intel';
const CF_API = 'https://api.cloudflare.com/client/v4';
```

## Key Functions

Line numbers drift; search by name.

| Function | File | Purpose |
|----------|------|---------|
| `refreshAll()` | app.js | Bumps `_loadGen`, resets source pills, `loadNVD()` then `loadExternalSources()`. Use this, not `loadNVD()` directly |
| `loadNVD()` | app.js | Paginated NVD fetch with CVE-ID detection, chunking, cancel and supersede checks |
| `loadExternalSources()` | app.js | All 7 feed loaders in parallel, then range info, EPSS background fetch, alerts, `markVisit()` |
| `loadKEV()` … `loadMSRC()` | app.js | One loader per feed; each normalises to the NVD shape and calls `mergeExternalCves(list, src, fetched)` |
| `mergeExternalCves()` | app.js | Wraps `mergeCves()` with the keyword + date-range filters and updates the source pill |
| `getSelectedRange()` / `inSelectedRange()` | app.js | The dashboard's date range; external entries outside it are dropped |
| `fetchViaProxy()` | app.js | CORS proxy fetch with one retry on network error / 5xx |
| `renderAll()` | app.js | Coalesced re-render of every panel (use instead of calling render* one by one) |
| `getActiveCves()` / `getFilteredCves()` | app.js | Company-mode set (charts/cards) / feed set incl. filters + sort (also what exports use) |
| `openCveDetail(id)` / `renderCveDetail(id)` | app.js | Detail panel; fetches from NVD when the id isn't loaded |
| `queueEpssFor()` / `flushEpss()` | app.js | Batched EPSS lookups (visible page, then KEV/critical/high in background) |
| `checkAlerts()` | app.js | Real activity-log events + browser notifications for new KEV entries matching stack/watchlist |
| `syncHash()` / `applyHashState()` | app.js | Shareable URL state (`#range=30&sev=CRITICAL&sort=epss&cve=…`) |
| `runSearch()` | app.js | Local data + NVD keyword/ID search (+ Palo Alto PSIRT); results open in the detail panel |
| `getCvss()` | core.js | v4.0→v3.1→v3.0→v2.0; Primary (NVD) preferred over Secondary (CNA); 0 = unscored |
| `mergeCves()` | core.js | Dedupe by id; duplicates enrich the existing entry (CVSS, KEV, `_alsoIn`) |
| `classifyOwaspApi()` | app.js | Client-side OWASP API Top 10 classifier |
| `renderWafCoverage()` | cloudctl.js | CVE × WAF keyword join |

## Key Data Flow

1. `refreshAll()` → `loadNVD()` paginates NVD (2000/page, 6.5 s between pages) → `allCves` with `_source: 'nvd'`. Each page re-merges the existing external entries with `mergeCves()` so an NVD entry absorbs KEV status instead of being duplicated.
2. `loadExternalSources()` runs the feed loaders; each calls `mergeExternalCves()`, which drops entries dated outside the selected range (KEV uses `dateAdded`), dedupes, and records `_alsoIn`.
3. Changing the range clears external entries and calls `refreshAll()`; a load that has been superseded (`gen !== _loadGen`) returns without writing.
4. All rendering reads `getActiveCves()` (company mode) / `getFilteredCves()` (feed filters, sort, paging) via `renderAll()`.
5. Every value from a feed is untrusted: it goes through `escapeHtml()` (text/attributes) or `safeUrl()` (hrefs). Never build `onclick="fn('${value}')"` from feed data — use `data-*` attributes and a delegated listener (see `main.js`).

## `loadNVD()` internals

The function handles several cases in this order inside its `try` block:

1. **Pre-filter**: if `_currentLoadKeyword` is set, strips all non-NVD entries from `allCves[]` that don't match the keyword (removes unrelated KEV/GitHub/PaloAlto entries loaded at page init)
2. **CVE ID direct lookup**: if keyword matches `CVE-2021-23017`, `cve-2021-23017`, or bare `2021-23017` — uses `?cveId=` parameter for an instant single-request lookup; skips all date range/chunking logic
3. **Chunking**: ranges > 119 days are split into sequential 119-day chunks (NVD API max: 120 days/request); chunk dates use actual UTC timestamps (`.toISOString().split('.')[0] + '.000'`) — forced midnight/end-of-day breaks pagination
4. **Incremental render**: updates panel on every page so user sees results arriving live
5. **Progress**: button shows global `%` across ALL chunks combined (not per-chunk, which would falsely hit 100% repeatedly)
6. **`finally` block**: resets the REFRESH button unless the load was superseded by a newer `refreshAll()`
7. **Errors**: an NVD failure shows a notice banner with RETRY / LOAD DEMO DATA and keeps the other sources. Demo data is never loaded automatically and is marked `_demo` with `DEMO-` IDs

## CVSS Scoring (`getCvss()`)

- Checks v4.0 → v3.1 → v3.0 → v2.0 in order
- Prefers **Primary** (NVD) scores, falls back to **Secondary** (CNA vendor scores like Fortinet, Cisco)
- Returns `0` if no score; the UI calls that **UNSCORED** (its own card, filter and chart colour) — never "low"

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

- Fires every 5 minutes (`main.js`) via `refreshAll()` to keep the standard date-range views current
- **Skipped** when `currentRangeDays === -1` (custom range) or `_currentLoadKeyword` is non-empty — prevents wiping user-initiated custom searches

## Common Gotchas

- `loadNVD()` preserves external source entries on refresh (filters `allCves` by `_source !== 'nvd'` before replacing)
- A new `refreshAll()` supersedes any in-progress load via `_loadGen`; `_nvdCancelFlag` is only the user's CANCEL button
- External sources are loaded once at page init without keyword. When a keyword search starts, `loadNVD()` pre-filters `allCves` to remove non-matching external entries immediately, then reloads them via `.then()` so they re-merge through the keyword filter
- Demo data only loads when the user clicks LOAD DEMO DATA on the NVD-outage banner
- When switching from a keyword view back to a standard range tab (`setRange()`), `hadKeyword` is checked and external sources are reloaded to restore full unfiltered data
- Browser caching can serve stale JS/CSS — hard-refresh (`Ctrl+Shift+R`) after editing
- NVD timestamps have no zone suffix but are UTC — parse with `parseFeedDate()`, never `Date.parse()` directly
- Ubuntu notices list many older CVEs (mostly unscored); they dominate the UNSCORED count and timeline spikes on notice days. That is real data, not a bug
- CSV export goes through `toCsv()`, which prefixes cells starting with `= + - @` to stop spreadsheet formula injection
- The CORS proxy `worker.js` has two allowlists: `ALLOWED_ORIGINS` (caller domains) and `ALLOWED_HOSTS` (proxy targets, matched exactly or as a subdomain by `isAllowedHost()`). Adding a feed that needs the proxy means adding its host there **and redeploying the worker**
- Chunk dates must use actual UTC timestamps — using `T00:00:00.000`/`T23:59:59.000` makes `pubEndDate` land in the future, which causes NVD to reject paginated requests (`startIndex > 0`)
- If Cloudflare Pages deployments get stuck in "Queued", push an empty commit to force a new build: `git commit --allow-empty -m "Trigger redeploy" && git push`

## CLOUDCTL Integration — Operational Notes

### Function naming convention (avoid collisions)
The CF helpers are renamed from CLOUDCTL's originals so they don't clash with anything in ThreatWatch's existing code:

| CLOUDCTL (frozen) | Merged ThreatWatch |
|---|---|
| `cfGet/Post/Put/Patch/Delete` | `cloudflareCfGet/Post/Put/Patch/Delete` |
| `cfFetch` | `cloudflareCfFetch` |
| `TOOLS` (tool registry) | `CF_TOOLS` |
| `showSection` | `showView` (different shape — toggles full views, not just panels) |
| `renderSection` | `renderCfSection` |
| `loadOverview` | `loadCfOverview` |
| `initApp` | `initCfApp` |

When porting changes from CLOUDCTL v1.0, apply the same rename to the new code.

### AI command flow
1. User types in `#cmd-input`, presses Enter → `sendCommand()`.
2. Query pushed to `chatHistory` (API-shaped). Drawer opens automatically.
3. `runAgentLoop()` POSTs to `https://api.anthropic.com/v1/messages` with:
   - `model: AI_MODEL` (Setup → AI MODEL; default `claude-sonnet-5-5`), `max_tokens: 16000` (current models think first)
   - `system: buildUnifiedSystem()` — dynamically rebuilt every turn; injects current CVE counts, KEV count, active filters, company stack, CF account, current zone, and current view.
   - `tools: Object.values(CF_TOOLS).map(t => t.schema)`
   - Browser-side header: `anthropic-dangerous-direct-browser-access: true`
4. For each `tool_use` block: `read` runs immediately; `write` and `destructive` go through `confirmToolCall()` (renders an inline confirm card in the chat with CONFIRM / CANCEL buttons). **The confirm gate is load-bearing** — the CF token has Edit scope and auto-executing writes would be destructive.
5. Tool results (or cancellations) are pushed as `tool_result` blocks in the next turn. Loop until `stop_reason !== 'tool_use'` or `MAX_TURNS = 8`. `refusal` and `max_tokens` stop reasons show a system message. The full `data.content` (including thinking blocks) is appended unchanged — keep the history append-only.
6. Side effect: when a tool returns array data, `renderDataInPanelByKind()` also fills the matching `#cf-<kind>-body` so the chat result is mirrored in the CF view body.

### Adding a new Cloudflare tool
Append an entry to `CF_TOOLS`. That's the entire extension point — the schema teaches Claude what's available, `run()` does the call, `class` selects the confirmation gate, `panelKind` selects the renderer in `formatCfResultByKind` / `renderCfSection`.

### WAF Coverage cross-feature (`renderWafCoverage`)
Joins `allCves[]` against deployed WAF rules using a keyword heuristic:
1. **Candidates**: `c._kevExploited || getCvss(c) >= 9.0`. If `companyModeActive`, additionally restrict to entries whose JSON contains a tech-stack keyword. Capped at 80 rows.
2. **Per-CVE keywords**: vendor + product from `cve.containers.cna.affected[]` if present, else regex out a known-product list (Apache, Log4j, Fortinet, Citrix, Microsoft, etc.) from the description.
3. **Rule searchable surface**: `rule.filter.expression + rule.description + rule.action`, lowercased.
4. **Match**: case-insensitive `includes()` of any keyword against any rule's surface. ≥1 match = covered, 0 = uncovered.
5. **Suggest action**: per-uncovered-row button injects `Draft a Cloudflare WAF rule that mitigates likely exploitation of CVE-XXX (target keyword: "...")` into `#cmd-input` and opens the AI drawer.

This is a **triage signal, not a vulnerability scanner**. The view shows a permanent disclaimer.

### Setup modal
Auto-prefills sessionStorage values when reopened. Requires CF token + account ID together (not just one), but Anthropic key is independent. Threat-Intel works with no keys configured. The 5-minute auto-refresh continues regardless of which view is active.

### Things to watch when editing
- Threat-intel code goes in `js/app.js` (pure logic in `js/core.js` with a test); CF code in `js/cloudctl.js`; start-up wiring in `js/main.js`.
- `chatHistory` is intentionally not reset on view switch — cross-view continuity beats stale-zone risk.
- `escapeHtml()` and `safeUrl()` are defined in `js/core.js` and available everywhere.
- The security-warning hook flags `innerHTML =` patterns. The code uses `innerHTML` with `escapeHtml()` on every dynamic value; don't refactor wholesale just to silence the hook, but never interpolate an unescaped feed value.

## Deployment

- **Dashboard**: push to `main` → Cloudflare Pages auto-deploys the repo root (`index.html`, `css/`, `js/`, `favicon.svg`).
- **CVE CORS proxy**: `cd cors-proxy && npx wrangler deploy` (deployed separately — not auto-deployed). Same allowlists as before.
- **CF API Bridge** (optional): if direct browser → CF API is CORS-blocked, deploy the CLOUDCTL bridge worker separately and paste its URL into Setup → "CF API BRIDGE URL".
- Live URL: `https://threatwatch-7du.pages.dev/`
- CVE Proxy URL: `https://threatwatch-cors-proxy.scanalejoa.workers.dev`

## Git push
after a change in the application or a fix ask me if i want you to push it directly to git repository
