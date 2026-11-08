# 🛡️ THREATWATCH — Real-Time Security Dashboard

A live security dashboard that merges vulnerability data from **8 feeds** into one view, scores exploit likelihood with **EPSS**, and includes an **AI-driven Cloudflare console** that can check your WAF rules against the CVEs that matter.

**Live:** [threatwatch-7du.pages.dev](https://threatwatch-7du.pages.dev/)

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Stack](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-orange)

---

## ✨ Features

### Fix First — remediation priority (default view)
A ranked to-do list for a security lead: which recent vulnerabilities to fix first, in order.

| Tier | Rule | Suggested SLA |
|------|------|---------------|
| **P1 · FIX NOW** | Exploited in the wild (CISA KEV, or CISA SSVC "active") | Immediately (shows the CISA due date and overdue days) |
| **P2 · THIS WEEK** | EPSS ≥ 10%, a **public exploit** (Nuclei template, CISA proof of concept, NVD exploit reference), or a **remote no-login bug in core software** | 7 days |
| **P3 · THIS MONTH** | CVSS ≥ 9.0, no exploitation signal | 30 days |
| **P4 · NEXT CYCLE** | CVSS 7.0–8.9, or core software with no score yet (triage) | Next patch cycle |

Inside a tier: known ransomware use first, then early warnings, then exploit strength, EPSS, CVSS and newest. Every row says **why** it is there. Medium/low CVEs with no exploitation signal are left out. Every CVE FIRST scores above 10% is bulk-loaded, so an unscored or medium-severity CVE that attackers are likely to use still lands in P2. Click a tier to filter, a row for full details; export the queue as CSV (rank, SLA, KEV due date, EPSS, CVSS) or PDF. Company mode narrows it to your stack.

### Early warning for core software
AI-assisted research and exploitation shrink the time from disclosure to attack; EPSS and KEV need days to react. So the dashboard also watches:

- **Core software watch** — OpenSSH, Linux kernel, PHP, Node.js, OpenSSL, glibc, sudo, nginx, Apache httpd, curl, xz, systemd (editable in Company Profile, plus your own). Matching is narrow: a WordPress plugin that "requires PHP" is not a PHP bug.
- **Early warnings** — remote, no-login bugs in core software published in the last 72 h, shown in a banner above the tiers.
- **Upstream advisories** — Node.js security releases (including pre-announcements: "release on Nov 11, highest severity HIGH"), the OpenSSH security page and PHP's GitHub advisories, often ahead of NVD.
- **CVE.org feed** — new CVEs minutes after publication with the CNA's score and CISA's SSVC assessment, via the [intel worker](intel-worker/README.md). Unscored Linux kernel CVEs are kept for triage instead of disappearing (distro patch bundles excluded).
- **Public exploits** — 4,500+ CVEs with a ProjectDiscovery Nuclei template.

### Threat intelligence
- **8 live feeds** — NVD, CISA KEV, GitHub Security Advisories, Palo Alto PSIRT, OSV, Ubuntu, Microsoft MSRC, Red Hat. Duplicates are merged: if GitHub or KEV reports a CVE NVD already has, the entry shows both sources and gains any score or KEV status the other feed had.
- **Honest date ranges** — 7D / 30D / 90D / custom. Every feed is filtered to the selected range (KEV by the date CISA added the entry); the source pills show "in range / fetched".
- **Severity cards** — Critical, High, Medium, Low, **Unscored** (no CVSS yet) and CISA KEV. Unscored is never counted as Low.
- **CVE detail panel** — click any row: CVSS with vector, EPSS probability and percentile, KEV due date and required action, CWE, affected products, references, matching Cloudflare WAF rules, and buttons to ask the AI, copy the ID or watch the vendor.
- **Feed tools** — sort by CVSS, newest, EPSS or KEV first; paging (50 per page); filters for severity, source, **NEW since your last visit** and **watchlist**.
- **Timeline** — new CVEs per day (per week for long ranges), stacked by severity, with hover details.
- **Charts** — top vendors (distro/package feeds excluded), severity donut, attack categories and threat themes (keyword matches; click a tile to see its CVEs).
- **Company profile** — tech-stack filter (company mode), inventory import from CSV/XLSX, a highlight-only **watchlist**, and optional **browser alerts** when a newly exploited (KEV) CVE matches your stack or watchlist.
- **Search** — CVE ID, vendor or keyword across loaded data and the NVD API (plus Palo Alto PSIRT for PAN-SA IDs).
- **Shareable views** — filters, range, sort, page, open CVE and current view live in the URL (`#range=30&sev=CRITICAL&sort=epss&cve=CVE-…`).
- **Exports** — CSV (all matching rows, spreadsheet-safe) and print/PDF.
- **Activity log** — real events only: feed loads and errors, new critical CVEs since the last refresh, new KEV entries since your last visit.

### Cloudflare console (optional)
- Connect a Cloudflare API token + account ID and an Anthropic API key in **Setup** (keys stay in `sessionStorage`).
- Views for DNS, WAF rules, IP firewall rules, Workers, Pages and analytics.
- **AI command bar** — Claude (Sonnet 5.5 by default; Opus 5.5 or Haiku 5.5 selectable) runs Cloudflare operations through tool use. Every write or delete asks for confirmation first.
- **WAF Coverage** — joins critical/KEV CVEs against your deployed WAF rules by keyword and offers to draft a rule for uncovered ones. A triage signal, not a scanner.

### Works everywhere
- Responsive down to phone width (off-canvas navigation below 900px).
- Keyboard accessible: rows, cards, tiles and bars open with Enter; Esc closes panels.
- Text colours meet WCAG AA contrast; chart colours are checked for colour-blind separation.

---

## 🚀 Quick start

Requires [Node.js](https://nodejs.org/) 18+ (only for the dev server and tests — the site itself has no build step).

```bash
git clone https://github.com/scanalejoa/threatwatch.git
cd threatwatch
npm run dev     # http://localhost:3000
npm test        # unit tests (node:test, no dependencies)
```

Use port 3000: the CORS proxy only accepts requests from `localhost:3000` and the production domains.

---

## 📁 Project structure

```
threatwatch/
├── index.html          # Markup
├── css/app.css         # Styles (colour tokens on :root)
├── js/
│   ├── core.js         # Pure helpers: scoring, priority tiers, core-software watch, merging, CSV, URL state (unit-tested)
│   ├── feeds.js        # Parsers for CVE.org, Node.js, OpenSSH, PHP, Nuclei (shared with the intel worker)
│   ├── app.js          # Threat-intel dashboard: feeds, rendering, detail panel, EPSS, search, exports
│   ├── cloudctl.js     # Cloudflare console + Claude agent loop
│   └── main.js         # Start-up wiring (loaded last)
├── favicon.svg
├── intel-worker/       # Cloudflare Worker: CVE.org early feed + upstream advisories (cron + KV)
├── cors-proxy/
│   ├── worker.js       # Cloudflare Worker CORS proxy (host allowlist)
│   └── wrangler.toml
├── tests/              # node:test suites for core.js and the proxy
└── package.json
```

---

## 🔌 Data sources

| Source | API | Via proxy |
|--------|-----|-----------|
| [NVD](https://nvd.nist.gov/) | `services.nvd.nist.gov/rest/json/cves/2.0` | No |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `www.cisa.gov/.../known_exploited_vulnerabilities.json` | Yes |
| [GitHub Advisories](https://github.com/advisories) | `api.github.com/advisories` | No |
| [Palo Alto PSIRT](https://security.paloaltonetworks.com/) | `security.paloaltonetworks.com/json` | Yes |
| [OSV](https://osv.dev/) | `api.osv.dev/v1/querybatch` | Fallback |
| [Ubuntu](https://ubuntu.com/security/notices) | `ubuntu.com/security/notices.json` | Yes |
| [Microsoft MSRC](https://msrc.microsoft.com/) | `api.msrc.microsoft.com/cvrf/v3.0` | Yes |
| [Red Hat](https://access.redhat.com/security/data) | `access.redhat.com/hydra/rest/securitydata` | Fallback |
| [EPSS (FIRST)](https://www.first.org/epss/) | `api.first.org/data/v1/epss` | Fallback |
| [CVE.org](https://www.cve.org/) (cvelistV5) | intel worker `/v1/recent` | Intel worker |
| Node.js / OpenSSH / PHP advisories | intel worker `/v1/advisories` | Intel worker, then proxy / direct |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | `raw.githubusercontent.com/…/cves.json` | No (cached 12 h) |

> The NVD API allows 5 requests per 30 seconds without a key, so long ranges load page by page. If NVD is unreachable, the dashboard shows the other feeds and offers clearly labelled demo data.

---

## 🌐 CORS proxy

`cors-proxy/worker.js` proxies the feeds that don't send CORS headers. It only accepts HTTPS targets on an allowlist of API hosts (exact host or subdomain — look-alike domains are rejected) and only answers the allowed origins.

```bash
cd cors-proxy
npx wrangler login    # one-time
npx wrangler deploy
```

**Deployed at:** `threatwatch-cors-proxy.scanalejoa.workers.dev`. Redeploy after changing the allowlist (EPSS needs `api.first.org`; the advisory fallback needs `nodejs.org` and `openssh.com`).

## 🛰️ Intel worker

`intel-worker/` runs on a cron and stores an early-warning feed in Workers KV — see [intel-worker/README.md](intel-worker/README.md) for the one-time deploy (`wrangler kv namespace create INTEL`, then `wrangler deploy`). Without it the dashboard still works: the CVE.ORG pill shows ERR and upstream advisories are fetched from the browser.

---

## 🛠️ Tech stack

Vanilla HTML, CSS and JavaScript · Cloudflare Pages (hosting) · Cloudflare Workers (proxy) · [SheetJS](https://sheetjs.com/) for inventory import · Fonts: Bebas Neue, Barlow Condensed, JetBrains Mono.

## 📝 License

MIT — free for personal and commercial use.
