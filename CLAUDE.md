# ThreatWatch — Project Context

## Overview
Single-page cybersecurity dashboard (`index.html`) that aggregates vulnerability data from 4 sources into a unified real-time feed. Deployed via GitHub Pages.

## Architecture
- **Single file**: All HTML, CSS, and JavaScript in `index.html` (~2600 lines)
- **No build step**: Pure vanilla JS, no frameworks
- **CORS Proxy**: Cloudflare Worker at `cors-proxy/worker.js` for APIs that block browser requests

## Data Sources
| Source | API Endpoint | CORS Proxy? |
|--------|-------------|-------------|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | No |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Yes |
| GitHub Advisories | `api.github.com/advisories` | No |
| Palo Alto PSIRT | `security.paloaltonetworks.com/json` | Yes (fallback) |

## Key Data Flow
1. `loadNVD()` fetches CVEs by date range → stored in `allCves[]` with `_source: 'nvd'`
2. External sources (KEV, GitHub, Palo Alto) convert to NVD-like format and merge via `mergeExternalCves()`
3. KEV entries get `_kevExploited: true` flag and inherit CVSS from NVD matches
4. All rendering uses the unified `allCves[]` array

## CVSS Scoring (`getCvss()`)
- Checks CVSS v4.0 → v3.1 → v3.0 → v2.0 in order
- Prefers **Primary** (NVD) scores, falls back to **Secondary** (CNA vendor scores like Fortinet, Cisco)
- Returns 0 if no score exists; UI shows "N/A" for score 0

## CVSS Enrichment
- KEV entries lack CVSS scores natively
- During search, entries with score 0 are batch-fetched from NVD by `cveId` (up to 10 parallel)
- Enriched scores persist in `allCves[]` for the session

## Filtering
- **Severity**: ALL / CRITICAL / HIGH / MEDIUM (via `currentFilter`)
- **Source**: ALL / NVD / KEV / GITHUB / PALOALTO (via `currentSourceFilter`)

## API Rate Limits
- NVD: 5 requests per 30 seconds without API key, `resultsPerPage` max 2000
- NVD keyword search requires **full words** (partial like "forti" returns 404)

## Deployment
- Push to `main` branch → GitHub Pages serves `index.html`
- CORS proxy: `cd cors-proxy && npx wrangler deploy`

## Common Gotchas
- `loadNVD()` preserves external source entries when refreshing (filters by `_source !== 'nvd'`)
- Loading order matters: NVD first, then external sources merge in sequentially
- Browser caching can serve stale JS — always hard-refresh (`Ctrl+Shift+R`) after deploys
