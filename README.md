# 🛡️ THREATWATCH — Real-Time Security Dashboard

A live cybersecurity dashboard that aggregates vulnerability data from **4 independent sources** into a single, dark-themed command-center interface.

**Live:** [threatwatch-7du.pages.dev](https://threatwatch-7du.pages.dev/)

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Stack](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-orange)

---

## ✨ Features

### Live Data Feeds (4 Sources)
- **NVD CVE Feed** — Latest vulnerabilities from NIST, with CVE IDs, severity badges, and CVSS scores
- **CISA KEV Catalog** — Actively exploited vulnerabilities tracked by CISA
- **GitHub Security Advisories** — Reviewed security advisories from the GitHub ecosystem
- **Palo Alto PSIRT** — Vendor-specific advisories from Palo Alto Networks
- **Auto-refresh** every 5 minutes
- **Source status pills** — Green = live, Yellow = fallback/error

### Interactive Dashboard
- **Stat Cards** — Click CRITICAL / HIGH / MEDIUM / LOW cards to view detailed CVE lists with affected products
- **Top Vendors Chart** — Click any vendor bar to see all their vulnerabilities
- **Severity Donut Chart** — Visual breakdown of CVE severity distribution
- **Threat Activity Grid** — Animated global threat visualization

### 🔍 Live Search
- Search for any **CVE ID**, **vendor**, **software**, or **keyword**
- Searches both local cache **and** the NVD API in real-time
- Results sorted by criticality (CRITICAL first)

### 📅 Date Range Selector
- **7D** (default) — Fast load, focused on latest threats
- **30D / 90D** — Broader historical view
- **CUSTOM** — Pick any start/end date range

### CVE Details
- Clickable CVE IDs linked to NVD detail pages
- CVSS scores with color-coded severity
- Affected vendor/product information extracted from CPE data
- Vulnerability descriptions

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) (v14+)

### Install & Run
```bash
# Clone or download the project
cd security_dashboard

# Install dependencies
npm install

# Start the local dev server
npm run dev
```

The dashboard will be available at **http://localhost:3000**

---

## 📁 Project Structure

```
security_dashboard/
├── index.html          # Single-file dashboard (HTML + CSS + JS)
├── cors-proxy/
│   ├── worker.js       # Cloudflare Worker CORS proxy
│   └── wrangler.toml   # Worker deployment config
├── package.json        # Project config & dev server script
└── README.md           # This file
```

---

## 🔌 Data Sources

| Source | API | Data | CORS Proxy |
|--------|-----|------|------------|
| [NVD](https://nvd.nist.gov/) | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE vulnerabilities, CVSS scores, CPE data | No (CORS-friendly) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `www.cisa.gov/.../known_exploited_vulnerabilities.json` | Actively exploited vulnerabilities | **Yes** |
| [GitHub Advisories](https://github.com/advisories) | `api.github.com/advisories` | Reviewed security advisories | No (CORS-friendly) |
| [Palo Alto PSIRT](https://security.paloaltonetworks.com/) | `security.paloaltonetworks.com/json` | Palo Alto Networks advisories | Fallback |

> **Note:** The NVD API has rate limits (5 requests per 30 seconds without an API key). If requests fail, the dashboard falls back to demo data.

---

## 🌐 CORS Proxy

A lightweight Cloudflare Worker (`cors-proxy/worker.js`) proxies requests to APIs that block browser CORS. It:

- Allowlists specific origins (`threatwatch-7du.pages.dev`, `localhost:3000`)
- Allowlists specific target domains (CISA, Palo Alto, Red Hat, etc.)
- Adds proper `Access-Control-Allow-Origin` headers

**Deployed at:** `threatwatch-cors-proxy.scanalejoa.workers.dev`

### Deploying the Worker
```bash
cd cors-proxy
npx wrangler login    # One-time auth
npx wrangler deploy   # Deploy to Cloudflare
```

---

## 🎨 Design

- **Dark theme** with neon accent colors
- Fonts: [Orbitron](https://fonts.google.com/specimen/Orbitron) (headings), [Share Tech Mono](https://fonts.google.com/specimen/Share+Tech+Mono) (data)
- Glassmorphism panels with subtle glow effects
- Responsive layout
- CSS animations for threat activity grid

---

## 🛠️ Tech Stack

- **HTML5** — Structure
- **CSS3** — Styling (vanilla, no frameworks)
- **JavaScript** — Logic (vanilla, no frameworks)
- **Cloudflare Pages** — Static hosting
- **Cloudflare Workers** — CORS proxy
- **serve** — Local dev server

No build step required. The dashboard is a single HTML file.

---

## 📝 License

MIT — free for personal and commercial use.
