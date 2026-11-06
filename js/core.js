// ═══════════════════════════════════════════════════════════════
//  THREATWATCH — core helpers (pure functions, no DOM access)
//  Loaded as a classic <script> in the browser, so every top-level
//  function becomes a global. Also exported for Node tests
//  (`npm test`) via module.exports at the bottom.
// ═══════════════════════════════════════════════════════════════

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];

// Feeds whose CPE "vendor" slot holds a distro or package ecosystem rather
// than a real vendor. They are excluded from the Top Vendors chart.
const PSEUDO_VENDORS = new Set([
  'unknown', '*', '', 'ubuntu', 'redhat', 'npm', 'pip', 'pypi', 'go', 'maven',
  'rubygems', 'crates.io', 'crates_io', 'nuget', 'composer', 'packagist',
  'hex', 'pub', 'swift', 'erlang', 'actions', 'github_actions', 'other',
]);

/** Escape a value for safe interpolation into HTML text or a quoted attribute. */
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/** Only allow http(s) URLs in href attributes; anything else becomes '#'. */
function safeUrl(u) {
  try {
    const parsed = new URL(String(u));
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') ? parsed.href : '#';
  } catch { return '#'; }
}

/**
 * Parse a feed timestamp to epoch ms. NVD sends UTC timestamps without a zone
 * suffix ("2026-11-01T22:00:00.000"), which Date.parse would read as local time.
 */
function parseFeedDate(s) {
  if (!s) return 0;
  let str = String(s);
  if (/T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(str)) str += 'Z';
  return Date.parse(str) || 0;
}

function getDescription(vuln) {
  const d = vuln?.cve?.descriptions;
  if (!Array.isArray(d) || !d.length) return '';
  return (d.find(x => x.lang === 'en') || d[0]).value || '';
}

/** Best CVSS base score: v4.0 → v3.1 → v3.0 → v2.0, Primary (NVD) preferred over CNA. */
function getCvss(vuln) {
  const m = vuln?.cve?.metrics;
  if (!m) return 0;
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const pool = m[key];
    if (!Array.isArray(pool)) continue;
    const primary = pool.find(e => e.type === 'Primary');
    if (primary?.cvssData?.baseScore > 0) return primary.cvssData.baseScore;
    let best = 0;
    for (const e of pool) {
      const s = e?.cvssData?.baseScore || 0;
      if (s > best) best = s;
    }
    if (best > 0) return best;
  }
  return 0;
}

/** Details of the metric getCvss() picked: { score, version, vector }. */
function getCvssDetail(vuln) {
  const m = vuln?.cve?.metrics;
  const score = getCvss(vuln);
  if (!m || !score) return { score: 0, version: '', vector: '' };
  for (const [key, version] of [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']]) {
    const hit = (m[key] || []).find(e => e?.cvssData?.baseScore === score);
    if (hit) return { score, version: hit.cvssData.version || version, vector: hit.cvssData.vectorString || '' };
  }
  return { score, version: '', vector: '' };
}

/** CVSS → severity bucket. Score 0 means "not scored yet", not "low". */
function getSeverity(score) {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNSCORED';
}

function getCpeParts(vuln) {
  const out = [];
  (vuln?.cve?.configurations || []).forEach(c =>
    (c.nodes || []).forEach(n =>
      (n.cpeMatch || []).forEach(m => {
        const p = String(m.criteria || '').split(':');
        out.push({ vendor: p[3] || '', product: p[4] || '' });
      })));
  return out;
}

/** Raw CPE vendor of the first configuration (used for search and keyword matching). */
function getVendor(vuln) {
  const first = getCpeParts(vuln)[0];
  return (first && first.vendor) || 'unknown';
}

/** Vendor for the Top Vendors chart, or null for distro/ecosystem feeds and unknowns. */
function getChartVendor(vuln) {
  const v = getVendor(vuln).toLowerCase();
  return PSEUDO_VENDORS.has(v) ? null : v;
}

function getAffectedProducts(vuln, limit = 3) {
  const products = [];
  getCpeParts(vuln).forEach(({ vendor, product }) => {
    if (vendor && vendor !== '*' && product && product !== '*') products.push(vendor + ' ' + product.replace(/_/g, ' '));
    else if (vendor && vendor !== '*') products.push(vendor);
  });
  const unique = [...new Set(products)];
  return limit ? unique.slice(0, limit) : unique;
}

function matchesKeyword(vuln, kw) {
  if (!kw) return true;
  const k = kw.toLowerCase();
  return (vuln.cve.id || '').toLowerCase().includes(k)
    || getDescription(vuln).toLowerCase().includes(k)
    || getVendor(vuln).toLowerCase().includes(k);
}

/** Lowercased text a tech-stack / watchlist keyword is matched against. */
function searchableText(vuln) {
  const cpe = getCpeParts(vuln).map(p => p.vendor + ':' + p.product).join(' ');
  return (getDescription(vuln) + ' ' + cpe + ' ' + JSON.stringify(vuln.cve.affected || '')).toLowerCase();
}

function matchesAnyKeyword(vuln, keywords) {
  if (!keywords || !keywords.length) return false;
  const text = searchableText(vuln);
  return keywords.some(k => k && text.includes(String(k).toLowerCase()));
}

/**
 * Merge feed entries into the existing list, deduplicating by CVE ID.
 * Duplicates are not dropped silently: the existing entry records the extra
 * source in `_alsoIn`, inherits a CVSS score if it had none, and inherits KEV
 * status. Returns { list, added, enriched }.
 */
function mergeCves(existing, incoming, options = {}) {
  const { keyword = '', inRange = null } = options;
  const byId = new Map(existing.map(v => [v.cve.id, v]));
  const added = [];
  let enriched = 0;
  for (const v of incoming) {
    if (!v?.cve?.id) continue;
    const cur = byId.get(v.cve.id);
    if (cur) {
      const src = v._source || 'nvd';
      if (src !== (cur._source || 'nvd')) {
        cur._alsoIn = cur._alsoIn || [];
        if (!cur._alsoIn.includes(src)) cur._alsoIn.push(src);
      }
      if (getCvss(cur) === 0 && getCvss(v) > 0) { cur.cve.metrics = v.cve.metrics; enriched++; }
      if (v._kevExploited) { cur._kevExploited = true; if (v._kev) cur._kev = v._kev; }
      continue;
    }
    if (keyword && !matchesKeyword(v, keyword)) continue;
    if (inRange && !inRange(v)) continue;
    byId.set(v.cve.id, v);
    added.push(v);
  }
  return { list: added.length ? existing.concat(added) : existing, added, enriched };
}

function countsBySeverity(cves) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNSCORED: 0 };
  cves.forEach(v => { counts[getSeverity(getCvss(v))]++; });
  return counts;
}

/**
 * Sort a copy of `cves`. Modes: 'cvss' (score desc, unscored last, newest first
 * within ties), 'date' (newest first), 'epss' (EPSS desc, then CVSS), 'kev'
 * (KEV first, then CVSS). `epssLookup(id)` returns a number or undefined.
 */
function sortCves(cves, mode = 'cvss', epssLookup = () => undefined) {
  const date = v => parseFeedDate(v.cve.published);
  const byCvss = (a, b) => (getCvss(b) - getCvss(a)) || (date(b) - date(a));
  const cmp = {
    cvss: byCvss,
    date: (a, b) => (date(b) - date(a)) || byCvss(a, b),
    epss: (a, b) => ((epssLookup(b.cve.id) ?? -1) - (epssLookup(a.cve.id) ?? -1)) || byCvss(a, b),
    kev: (a, b) => ((b._kevExploited ? 1 : 0) - (a._kevExploited ? 1 : 0)) || byCvss(a, b),
  }[mode] || byCvss;
  return cves.slice().sort(cmp);
}

/** Excel/Sheets formula-injection guard + RFC 4180 quoting. */
function csvCell(value) {
  let s = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

function toCsv(rows) {
  return rows.map(r => r.map(csvCell).join(',')).join('\r\n');
}

// ── URL hash state (shareable views) ──────────────────────────
const HASH_DEFAULTS = { range: '7', sev: 'ALL', src: 'ALL', sort: 'cvss', page: 1, new: false, watch: false, view: 'threat-intel' };
const HASH_ALLOWED = {
  range: ['7', '30', '90', 'custom'],
  sev: ['ALL', ...SEVERITIES],
  src: ['ALL', 'nvd', 'kev', 'github', 'paloalto', 'osv', 'ubuntu', 'msrc', 'redhat'],
  sort: ['cvss', 'date', 'epss', 'kev'],
};
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CVE_RE = /^[A-Z0-9][A-Z0-9-]{2,40}$/i;

function parseHashState(hash) {
  const p = new URLSearchParams(String(hash || '').replace(/^#/, ''));
  const s = { ...HASH_DEFAULTS };
  for (const k of ['range', 'sev', 'src', 'sort']) {
    const v = p.get(k);
    if (v && HASH_ALLOWED[k].includes(v)) s[k] = v;
  }
  const page = parseInt(p.get('page'), 10);
  if (page > 0 && page < 10000) s.page = page;
  s.new = p.get('new') === '1';
  s.watch = p.get('watch') === '1';
  const view = p.get('view');
  if (view && /^[a-z-]{2,30}$/.test(view)) s.view = view;
  const cve = p.get('cve');
  if (cve && CVE_RE.test(cve)) s.cve = cve.toUpperCase();
  if (s.range === 'custom') {
    const from = p.get('from'), to = p.get('to');
    if (DATE_RE.test(from || '') && DATE_RE.test(to || '')) {
      s.from = from; s.to = to;
      const kw = (p.get('kw') || '').slice(0, 80);
      if (kw) s.kw = kw;
    } else {
      s.range = '7';
    }
  }
  return s;
}

function buildHashState(s) {
  const p = new URLSearchParams();
  for (const k of ['range', 'sev', 'src', 'sort', 'view']) {
    if (s[k] !== undefined && String(s[k]) !== String(HASH_DEFAULTS[k])) p.set(k, s[k]);
  }
  if (s.range === 'custom' && s.from && s.to) {
    p.set('from', s.from); p.set('to', s.to);
    if (s.kw) p.set('kw', s.kw);
  }
  if (s.page > 1) p.set('page', s.page);
  if (s.new) p.set('new', '1');
  if (s.watch) p.set('watch', '1');
  if (s.cve) p.set('cve', s.cve);
  const str = p.toString();
  return str ? '#' + str : '';
}

/**
 * Bucket CVEs by publication day between start and end (inclusive), split by
 * severity. Ranges longer than 92 days are bucketed by ISO week (Monday start).
 */
function dailyCounts(cves, start, end) {
  const day = d => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const s = day(start), e = day(end);
  const spanDays = Math.round((e - s) / 86400000) + 1;
  const weekly = spanDays > 92;
  const keyOf = d => {
    let k = day(d);
    if (weekly) k = new Date(k - ((k.getUTCDay() + 6) % 7) * 86400000);
    return k.toISOString().slice(0, 10);
  };
  const buckets = new Map();
  const step = weekly ? 7 : 1;
  let cur = weekly ? new Date(keyOf(s) + 'T00:00:00Z') : s;
  while (cur <= e) {
    buckets.set(cur.toISOString().slice(0, 10), { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNSCORED: 0 });
    cur = new Date(cur.getTime() + step * 86400000);
  }
  for (const v of cves) {
    const t = parseFeedDate(v.cve.published);
    if (!t) continue;
    const b = buckets.get(keyOf(new Date(t)));
    if (b) b[getSeverity(getCvss(v))]++;
  }
  return { weekly, buckets: [...buckets].map(([key, counts]) => ({ key, counts, total: SEVERITIES.reduce((n, k) => n + counts[k], 0) })) };
}

/** True when a CVE was published after the user's previous visit. */
function isNewSince(vuln, sinceMs) {
  if (!sinceMs) return false;
  const t = parseFeedDate(vuln?._kev?.dateAdded || vuln?.cve?.published);
  return !!t && t > sinceMs;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SEVERITIES, PSEUDO_VENDORS, parseFeedDate, escapeHtml, safeUrl, getDescription, getCvss, getCvssDetail,
    getSeverity, getVendor, getChartVendor, getAffectedProducts, matchesKeyword,
    matchesAnyKeyword, searchableText, mergeCves, countsBySeverity, sortCves, csvCell, toCsv,
    parseHashState, buildHashState, dailyCounts, isNewSince,
  };
}
