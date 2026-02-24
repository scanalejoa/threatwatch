# 🛡️ THREATWATCH — Real-Time Security Dashboard

A live cybersecurity dashboard that aggregates vulnerability data from the **NVD (National Vulnerability Database)** and the **CISA KEV (Known Exploited Vulnerabilities)** catalog into a single, dark-themed command-center interface.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Stack](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-orange)

---

## ✨ Features

### Live Data Feeds
- **NVD CVE Feed** — Latest vulnerabilities from NIST, with linked CVE IDs, severity badges, and CVSS scores
- **CISA KEV Catalog** — Actively exploited vulnerabilities tracked by CISA
- **Auto-refresh** every 5 minutes

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
├── index.html      # Single-file dashboard (HTML + CSS + JS)
├── package.json    # Project config & dev server script
└── README.md       # This file
```

---

## 🔌 Data Sources

| Source | API | Data |
|--------|-----|------|
| [NVD](https://nvd.nist.gov/) | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE vulnerabilities, CVSS scores, CPE data |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Actively exploited vulnerabilities |

> **Note:** The NVD API has rate limits (5 requests per 30 seconds without an API key). If requests fail, the dashboard falls back to demo data.

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
- **serve** — Local dev server

No build step required. It's a single HTML file.

---

## 📝 License

MIT — free for personal and commercial use.
