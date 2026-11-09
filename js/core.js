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
  if (!products.length) (vuln?.cve?._affected || []).forEach(a => products.push(String(a)));
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
  return (getDescription(vuln) + ' ' + cpe + ' ' + JSON.stringify(vuln.cve.affected || '') + ' ' + (vuln.cve._affected || []).join(' ')).toLowerCase();
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
      if (v._kevExploited) { cur._kevExploited = true; if (v._kev && !cur._kev?.dueDate) cur._kev = { ...(cur._kev || {}), ...v._kev }; }
      if (v._ssvc && !cur._ssvc) cur._ssvc = v._ssvc;
      if (v._upstream && !cur._upstream) cur._upstream = v._upstream;
      if (v.cve._affected && !cur.cve._affected) cur.cve._affected = v.cve._affected;
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
const HASH_DEFAULTS = { range: '7', sev: 'ALL', src: 'ALL', sort: 'cvss', page: 1, new: false, watch: false, view: 'priority', pt: 'ALL' };
const HASH_ALLOWED = {
  range: ['7', '30', '90', 'custom'],
  sev: ['ALL', ...SEVERITIES],
  src: ['ALL', 'nvd', 'kev', 'github', 'paloalto', 'osv', 'ubuntu', 'msrc', 'redhat', 'cveorg', 'upstream'],
  sort: ['cvss', 'date', 'epss', 'kev'],
  pt: ['ALL', '1', '2', '3', '4', 'early'],
};
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CVE_RE = /^[A-Z0-9][A-Z0-9-]{2,40}$/i;

function parseHashState(hash) {
  const p = new URLSearchParams(String(hash || '').replace(/^#/, ''));
  const s = { ...HASH_DEFAULTS };
  for (const k of ['range', 'sev', 'src', 'sort', 'pt']) {
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
  for (const k of ['range', 'sev', 'src', 'sort', 'view', 'pt']) {
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

// ── Core software watch ───────────────────────────────────────
// Software that runs almost everywhere, so a remote bug in it is a fleet-wide
// problem. Matching is deliberately narrow (CPE vendor:product, package name or
// a phrase like "in OpenSSH before 9.8") so that, e.g., a WordPress plugin that
// "requires PHP 7" is not tagged as a PHP interpreter bug.
const CORE_SOFTWARE = [
  { key: 'openssh', label: 'OpenSSH', cpe: ['openbsd:openssh'], pkg: ['openssh'], re: /\bOpenSSH\b/i },
  { key: 'linux-kernel', label: 'Linux kernel', cpe: ['linux:linux_kernel'], pkg: ['linux', 'linux-kernel', 'kernel'], re: /\b(?:in the )?Linux kernel\b/i },
  { key: 'php', label: 'PHP', cpe: ['php:php'], pkg: ['php', 'php-src', 'php8.3', 'php8.2', 'php8.1', 'php7.4'], re: /\b(?:in|affects?) PHP (?:versions? )?(?:before|prior to|\d+\.\d+)|\bphp-src\b|\bPHP-FPM\b|\bPHP interpreter\b/i },
  { key: 'nodejs', label: 'Node.js', cpe: ['nodejs:node.js', 'nodejs:nodejs'], pkg: ['nodejs', 'node.js'], re: /\b(?:in|affects?) Node\.js (?:versions? )?(?:before|prior to|v?\d+(?:\.\d+|\.x))|\bNode\.js runtime\b|^Node\.js: /i },
  { key: 'openssl', label: 'OpenSSL', cpe: ['openssl:openssl'], pkg: ['openssl'], re: /\b(?:in|affects?) OpenSSL\b|^Issue summary:/i },
  { key: 'glibc', label: 'glibc', cpe: ['gnu:glibc'], pkg: ['glibc', 'libc6', 'eglibc'], re: /\b(?:glibc|GNU C Library)\b/i },
  { key: 'sudo', label: 'sudo', cpe: ['sudo_project:sudo', 'todd_miller:sudo'], pkg: ['sudo'], re: /\bsudo (?:before|versions?|\d+\.\d+)/i },
  { key: 'nginx', label: 'nginx', cpe: ['f5:nginx', 'nginx:nginx', 'f5:nginx_open_source'], pkg: ['nginx'], re: /\bnginx (?:before|versions?|open source|\d+\.\d+)|\bin nginx\b/i },
  { key: 'httpd', label: 'Apache httpd', cpe: ['apache:http_server'], pkg: ['apache2', 'httpd'], re: /\bApache HTTP Server\b/i },
  { key: 'curl', label: 'curl', cpe: ['haxx:curl', 'haxx:libcurl'], pkg: ['curl', 'libcurl'], re: /\blibcurl\b|\bcurl (?:before|versions?|\d+\.\d+)/i },
  { key: 'xz', label: 'xz / liblzma', cpe: ['tukaani:xz'], pkg: ['xz-utils', 'xz', 'liblzma'], re: /\bxz[- ]utils\b|\bliblzma\b/i },
  { key: 'systemd', label: 'systemd', cpe: ['systemd_project:systemd'], pkg: ['systemd'], re: /\bsystemd\b/ },
];

/**
 * Which core package a CVE belongs to, or null.
 * `disabled` = built-in keys switched off; `extra` = user keywords (substring match).
 */
function coreSoftwareOf(vuln, disabled = [], extra = []) {
  const cpes = getCpeParts(vuln).map(p => (p.vendor + ':' + p.product).toLowerCase());
  const products = new Set(getCpeParts(vuln).map(p => p.product.toLowerCase()).concat((vuln?.cve?._affected || []).map(a => String(a).toLowerCase())));
  const desc = getDescription(vuln).slice(0, 400);
  const upstream = String(vuln?._upstream?.product || '').toLowerCase();
  for (const d of CORE_SOFTWARE) {
    if (disabled.includes(d.key)) continue;
    if (upstream && upstream === d.label.toLowerCase()) return d.label;
    if (d.cpe.some(c => cpes.includes(c))) return d.label;
    if (d.pkg.some(p => products.has(p))) return d.label;
    if (d.re.test(desc)) return d.label;
  }
  if (extra.length) {
    const text = searchableText(vuln);
    const hit = extra.find(k => k && text.includes(String(k).toLowerCase()));
    if (hit) return hit;
  }
  return null;
}

// ── Exploitation signals ─────────────────────────────────────

/** CVSS vector says network-reachable with no privileges (v3 or v4). */
function isRemoteNoAuth(vuln) {
  const vec = getCvssDetail(vuln).vector || '';
  return /AV:N/.test(vec) && /PR:N/.test(vec);
}

/** CISA SSVC (CVE.org ADP) — 'active' | 'poc' | 'none' | ''. */
/**
 * CISA SSVC decision as { e, a, t } (exploitation, automatable, technical impact),
 * from the CVE.org record (_ssvc) or NVD's copy (metrics.ssvcV203); null when absent.
 */
function ssvcOf(vuln) {
  if (vuln?._ssvc) return vuln._ssvc;
  const m = (vuln?.cve?.metrics?.ssvcV203 || [])[0];
  if (!m) return null;
  const o = Object.assign({}, ...(m.ssvcData?.options || []));
  const low = x => String(x || '').toLowerCase();
  return { e: low(o.exploitation ?? o.Exploitation), a: low(o.automatable ?? o.Automatable), t: low(o.technicalImpact ?? o['Technical Impact']) };
}
function ssvcExploitation(vuln) { return String(ssvcOf(vuln)?.e || ''); }

/**
 * Where a public exploit is known: 'nuclei' (ready-made scanner template),
 * 'ssvc' (CISA says PoC exists), 'nvd' (reference tagged Exploit), or ''.
 */
function publicExploitSource(vuln, exploitIds) {
  if (exploitIds && exploitIds.has && exploitIds.has(vuln.cve.id)) return 'nuclei';
  if (ssvcExploitation(vuln) === 'poc') return 'ssvc';
  if ((vuln.cve.references || []).some(r => (r.tags || []).some(t => /^exploit$/i.test(t)))) return 'nvd';
  return '';
}

// Distro feeds publish patch bundles: one Ubuntu kernel notice re-lists hundreds
// of CVEs. They are not new disclosures, so they never trigger "core, unscored".
const DISTRO_FEEDS = new Set(['ubuntu', 'redhat']);
function isDistroOnly(vuln) {
  return DISTRO_FEEDS.has(vuln?._source) && !(vuln._alsoIn || []).some(s => !DISTRO_FEEDS.has(s));
}
const EXPLOIT_STRENGTH = { nuclei: 3, ssvc: 2, nvd: 1 };

// ── Remediation priority (the "Fix First" dashboard) ─────────
// Exploitation evidence beats exploitation likelihood beats severity:
// a CVSS 7.5 bug attackers are using today outranks an unexploited 9.8.
const EPSS_URGENT = 0.1;          // ≥10% chance of exploitation in the next 30 days (≈ top 4% of all CVEs)
const EARLY_WARNING_HOURS = 72;   // EPSS and KEV lag new disclosures by days; AI shortens time-to-exploit
const PRIORITY_TIERS = [
  { tier: 1, key: 'P1', label: 'FIX NOW',    sla: 'Patch or mitigate immediately', rule: 'Exploited in the wild (CISA KEV or CISA SSVC "active")' },
  { tier: 2, key: 'P2', label: 'THIS WEEK',  sla: 'Patch within 7 days',          rule: 'EPSS ≥ 10%, a public exploit, or a remote no-auth bug in core software' },
  { tier: 3, key: 'P3', label: 'THIS MONTH', sla: 'Patch within 30 days',         rule: 'CVSS ≥ 9.0, no exploitation signal yet' },
  { tier: 4, key: 'P4', label: 'NEXT CYCLE', sla: 'Next patch cycle / triage',    rule: 'CVSS 7.0–8.9, or core software with no score yet' },
];

/**
 * Signals for one CVE. ctx = { epss, exploitIds:Set, core:(v)=>label|null, now }.
 * Returns { tier, reasons[], core, exploit, remote, early }.
 */
function prioritySignals(vuln, ctx = {}) {
  const epss = typeof ctx.epss === 'number' ? ctx.epss : undefined;
  const cvss = getCvss(vuln);
  const core = ctx.core ? ctx.core(vuln) : null;
  const exploit = publicExploitSource(vuln, ctx.exploitIds);
  const ssvc = ssvcExploitation(vuln);
  const remote = isRemoteNoAuth(vuln) || ssvcOf(vuln)?.a === 'yes';
  const ageH = ((ctx.now || Date.now()) - parseFeedDate(vuln?.cve?.published)) / 3600000;
  const early = !!core && remote && ageH >= 0 && ageH <= EARLY_WARNING_HOURS;
  const reasons = [];
  let tier = 0;
  if (vuln?._kevExploited) { tier = 1; reasons.push('In CISA KEV'); }
  if (ssvc === 'active') { tier = tier || 1; reasons.push('CISA: actively exploited'); }
  if (!tier) {
    if (epss !== undefined && epss >= EPSS_URGENT) reasons.push(`EPSS ${(epss * 100).toFixed(0)}%`);
    if (exploit) reasons.push({ nuclei: 'Public exploit (Nuclei template)', ssvc: 'CISA: proof of concept public', nvd: 'Exploit referenced by NVD' }[exploit]);
    if (core && remote) reasons.push(`Remote, no auth, in ${core}`);
    if (reasons.length) tier = 2;
  }
  if (!tier && cvss >= 9) { tier = 3; reasons.push(`CVSS ${cvss.toFixed(1)}`); }
  if (!tier && cvss >= 7) { tier = 4; reasons.push(`CVSS ${cvss.toFixed(1)}`); }
  if (!tier && core && cvss === 0 && !isDistroOnly(vuln)) { tier = 4; reasons.push(`${core}, not scored yet — triage`); }
  return { tier, reasons, core, exploit, remote, early };
}

/** 1 (most urgent) … 4, or 0 when the CVE needs no scheduled action. */
function priorityTier(vuln, epss, ctx = {}) {
  return prioritySignals(vuln, { ...ctx, epss }).tier;
}

/**
 * Remediation order. Within a tier: known ransomware use, early warning,
 * exploit strength (Nuclei > CISA PoC > NVD reference), EPSS, CVSS, then newest (KEV date added, else published). Returns
 * [{ v, tier, epss, cvss, ransomware, early, core, exploit, reasons, t }].
 */
function rankByPriority(cves, epssLookup = () => undefined, ctx = {}) {
  const rows = [];
  for (const v of cves) {
    const e = epssLookup(v.cve.id);
    const epss = typeof e === 'number' ? e : undefined;
    const sig = prioritySignals(v, { ...ctx, epss });
    if (!sig.tier) continue;
    rows.push({
      v, epss, cvss: getCvss(v), ...sig,
      ransomware: v._kev?.knownRansomwareCampaignUse === 'Known',
      t: parseFeedDate(v._kev?.dateAdded || v.cve.published),
    });
  }
  return rows.sort((a, b) => (a.tier - b.tier)
    || (Number(b.ransomware) - Number(a.ransomware))
    || (Number(b.early) - Number(a.early))
    || ((EXPLOIT_STRENGTH[b.exploit] || 0) - (EXPLOIT_STRENGTH[a.exploit] || 0))
    || ((b.epss ?? -1) - (a.epss ?? -1))
    || (b.cvss - a.cvss)
    || (b.t - a.t));
}

/** Whole days from `now` until a KEV due date (negative = overdue), or null. */
function daysUntil(dateStr, now = Date.now()) {
  const t = parseFeedDate(dateStr);
  if (!t) return null;
  const today = Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), new Date(now).getUTCDate());
  return Math.round((t - today) / 86400000);
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SEVERITIES, PSEUDO_VENDORS, parseFeedDate, escapeHtml, safeUrl, getDescription, getCvss, getCvssDetail,
    getSeverity, getVendor, getChartVendor, getAffectedProducts, matchesKeyword,
    matchesAnyKeyword, searchableText, mergeCves, countsBySeverity, sortCves, csvCell, toCsv,
    parseHashState, buildHashState, dailyCounts, isNewSince,
    EPSS_URGENT, EARLY_WARNING_HOURS, PRIORITY_TIERS, priorityTier, prioritySignals, rankByPriority, daysUntil,
    CORE_SOFTWARE, coreSoftwareOf, isDistroOnly, isRemoteNoAuth, publicExploitSource, ssvcExploitation, ssvcOf,
  };
}
