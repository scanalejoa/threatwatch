// ═══════════════════════════════════════════════════════════════
//  THREATWATCH — early-warning feed parsers.
//  Pure functions shared by the browser (classic <script>, globals),
//  the intel Worker (intel-worker/worker.js imports this file) and
//  the node:test suites (module.exports at the bottom).
//  No DOM, no fetch, no dependencies.
// ═══════════════════════════════════════════════════════════════

const FEED_CVE_RE = /CVE-\d{4}-\d{4,}/g;

function feedDecode(s) {
  return String(s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
}

/** HTML fragment → single-spaced plain text. */
function feedText(html) {
  return feedDecode(String(html || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function feedIsoDate(s) {
  const t = Date.parse(String(s || '').trim());
  return Number.isFinite(t) ? new Date(t).toISOString() : '';
}

// ── CVE.org (cvelistV5) ───────────────────────────────────────

/**
 * Parse the head of cvelistV5's deltaLog.json, read with an HTTP Range
 * request, so the text is usually cut off mid-array. The log is newest
 * first; we stop at the first delta at or before `sinceFetchTime`.
 * Returns { latest, newIds, updatedIds } (ids de-duplicated, newest first).
 */
function parseDeltaLogPrefix(text, sinceFetchTime = '') {
  const newIds = [], updatedIds = [];
  const seen = new Set();
  let latest = '';
  // Split on each delta object's fetchTime; the last chunk may be truncated, which is fine.
  const parts = String(text || '').split(/"fetchTime"\s*:\s*"/).slice(1);
  for (const part of parts) {
    const ft = part.slice(0, part.indexOf('"'));
    if (!ft) continue;
    if (!latest) latest = ft;
    if (sinceFetchTime && ft <= sinceFetchTime) break;
    const updIdx = part.search(/"updated"\s*:/);
    const errIdx = part.search(/"error"\s*:/);
    const newPart = updIdx >= 0 ? part.slice(0, updIdx) : part;
    const updPart = updIdx >= 0 ? part.slice(updIdx, errIdx > updIdx ? errIdx : undefined) : '';
    for (const [chunk, out] of [[newPart, newIds], [updPart, updatedIds]]) {
      for (const m of chunk.matchAll(/"cveId"\s*:\s*"(CVE-\d{4}-\d{4,})"/g)) {
        if (!seen.has(m[1])) { seen.add(m[1]); out.push(m[1]); }
      }
    }
  }
  return { latest, newIds, updatedIds };
}

/** Raw GitHub URL of a CVE record in cvelistV5. */
function cveRecordUrl(id) {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(id);
  if (!m) return '';
  const bucket = m[2].length <= 3 ? '0xxx' : m[2].slice(0, -3) + 'xxx';
  return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${m[1]}/${bucket}/${id}.json`;
}

function pickCvss(metrics) {
  for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
    const m = (metrics || []).find(x => x && x[key] && typeof x[key].baseScore === 'number');
    if (m) return { score: m[key].baseScore, vector: m[key].vectorString || '', version: m[key].version || key.replace('cvssV', '').replace('_', '.') };
  }
  return null;
}

/** Distinct "vendor product" strings, package names first (distro CNAs list many product variants). */
function trimAffected(list) {
  const ok = x => x && !/^n\/?a$/i.test(String(x).trim());
  const out = new Set();
  for (const a of list || []) if (ok(a.packageName)) out.add(String(a.packageName).trim());
  for (const a of list || []) {
    const s = [a.vendor, a.product].filter(ok).join(' ').trim();
    if (s) out.add(s);
  }
  return [...out].slice(0, 6);
}

/**
 * CVE JSON 5 record → compact record (≈0.5 KB) for the intel Worker's store.
 * Pulls CNA data plus CISA's ADP enrichment (SSVC exploitation/automatable,
 * KEV marker, CVSS when the CNA gave none).
 */
function trimCveRecord(rec) {
  const meta = rec?.cveMetadata || {};
  if (!meta.cveId || meta.state !== 'PUBLISHED') return null;
  const cna = rec.containers?.cna || {};
  const adps = rec.containers?.adp || [];
  const cisa = adps.find(a => /CISA-ADP/i.test(a?.providerMetadata?.shortName || '')) || {};
  const en = d => (d || []).find(x => /^en/i.test(x.lang)) || (d || [])[0];
  let ssvc = null, kev = null;
  for (const m of cisa.metrics || []) {
    const o = m?.other;
    if (o?.type === 'ssvc') {
      const opts = Object.assign({}, ...(o.content?.options || []));
      ssvc = {
        e: String(opts.Exploitation || '').toLowerCase(),
        a: String(opts.Automatable || '').toLowerCase(),
        t: String(opts['Technical Impact'] || '').toLowerCase(),
      };
    } else if (o?.type === 'kev') {
      kev = { dateAdded: o.content?.dateAdded || '' };
    }
  }
  const cvss = pickCvss(cna.metrics) || pickCvss(cisa.metrics);
  const cwe = [...new Set([...(cna.problemTypes || []), ...(cisa.problemTypes || [])]
    .flatMap(p => (p.descriptions || []).map(d => d.cweId)).filter(Boolean))].slice(0, 3);
  const refs = (cna.references || []).map(r => ({ url: r.url, tags: (r.tags || []).filter(t => /exploit|patch|vendor-advisory/i.test(t)) }));
  refs.sort((a, b) => Number(b.tags.some(t => /exploit/i.test(t))) - Number(a.tags.some(t => /exploit/i.test(t))));
  return {
    id: meta.cveId,
    pub: meta.datePublished || '',
    upd: meta.dateUpdated || '',
    cna: meta.assignerShortName || '',
    title: String(cna.title || '').slice(0, 160),
    desc: String(en(cna.descriptions)?.value || '').slice(0, 500),
    cvss,
    cwe,
    affected: trimAffected(cna.affected),
    refs: refs.slice(0, 5),
    ssvc,
    kev,
  };
}

// ── Upstream project advisories ───────────────────────────────

/** Node.js vulnerability RSS → [{ title, link, date }] newest first. */
function parseNodeRss(xml) {
  return [...String(xml || '').matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => {
    const tag = n => feedDecode((m[1].match(new RegExp(`<${n}>([\\s\\S]*?)</${n}>`)) || [])[1] || '').trim();
    return { title: tag('title'), link: tag('link'), date: feedIsoDate(tag('pubDate')) };
  }).filter(i => i.link);
}

/**
 * A Node.js security-release post. Released posts list each issue as
 * "<h2>Title (CVE-…) - (high)</h2><p>…</p>". Pre-announcements have no
 * CVE ids yet: they return `upcoming` with the release date and severity.
 */
function parseNodePost(html, item = {}) {
  const src = String(html || '');
  const cves = [];
  const re = /<h[23][^>]*>([\s\S]*?)<\/h[23]>([\s\S]*?)(?=<h[1-3][\s>]|$)/g;
  for (const m of src.matchAll(re)) {
    const head = feedText(m[1]);
    const hm = /^(.*?)\s*\((CVE-\d{4}-\d{4,})\)\s*-\s*\((critical|high|medium|low)\)/i.exec(head);
    if (!hm) continue;
    const body = feedText((m[2].match(/<p>[\s\S]*?<\/p>/) || [''])[0]);
    cves.push({ id: hm[2], title: hm[1], severity: hm[3].toUpperCase(), desc: body.slice(0, 500) });
  }
  let upcoming = null;
  if (!cves.length) {
    const text = feedText(src);
    const when = /release new versions of the ([\dx., ]+?)\s*releases? lines? on or shortly after,?\s*([A-Z][a-z]+day,\s*[A-Z][a-z]+ \d{1,2},\s*\d{4})/i.exec(text);
    const sev = /highest severity issue fixed in this release is (CRITICAL|HIGH|MEDIUM|LOW)/i.exec(text);
    if (when) {
      upcoming = {
        product: 'Node.js',
        releaseDate: feedIsoDate(when[2]).slice(0, 10),
        lines: when[1].split(/,\s*/).map(s => s.trim()).filter(Boolean),
        severity: sev ? sev[1].toUpperCase() : '',
        link: item.link || '',
        announced: item.date || '',
      };
    }
  }
  return { cves, upcoming };
}

/** openssh.com/security.html → [{ date, versions, title, text, cves, link }] newest first. */
function parseOpensshSecurity(html) {
  const out = [];
  for (const m of String(html || '').matchAll(/<li><p><b>([^<]+)<\/b><br>([\s\S]*?)(?=<li><p><b>|<\/ul>|$)/g)) {
    const date = feedIsoDate(m[1]);
    if (!date) continue;
    const parts = m[2].split(/<br\s*\/?>/i).map(feedText);
    const rel = (m[2].match(/href="(txt\/release-[^"]+)"/) || [])[1];
    out.push({
      date,
      versions: parts[0] || '',
      title: parts[1] || '',
      text: (parts[2] || '').slice(0, 500),
      cves: [...new Set(m[2].match(FEED_CVE_RE) || [])],
      link: rel ? 'https://www.openssh.com/' + rel : 'https://www.openssh.com/security.html',
    });
  }
  return out;
}

/** GitHub repository security advisories (php/php-src) → compact entries. */
function parsePhpAdvisories(list) {
  return (Array.isArray(list) ? list : []).filter(a => a && a.cve_id && a.state !== 'withdrawn').map(a => {
    const c = a.cvss_severities?.cvss_v4?.score ? a.cvss_severities.cvss_v4 : (a.cvss_severities?.cvss_v3 || a.cvss || {});
    return {
      id: a.cve_id,
      title: String(a.summary || '').slice(0, 160),
      desc: String(a.description || a.summary || '').replace(/\s+/g, ' ').slice(0, 500),
      severity: String(a.severity || '').toUpperCase(),
      cvss: typeof c.score === 'number' ? { score: c.score, vector: c.vector_string || '' } : null,
      date: a.published_at || '',
      link: a.html_url || '',
    };
  });
}

/** ProjectDiscovery nuclei-templates cves.json (NDJSON) → array of CVE ids with a ready-made exploit check. */
function parseNucleiIds(ndjson) {
  return [...new Set(String(ndjson || '').match(/"ID"\s*:\s*"(CVE-\d{4}-\d{4,})"/g)?.map(s => s.match(/CVE-\d{4}-\d{4,}/)[0]) || [])];
}

// ── Normalise to the dashboard's NVD-like entry shape ─────────

function cvssMetricsFrom(cvss, type = 'Secondary') {
  if (!cvss || typeof cvss.score !== 'number' || !(cvss.score > 0)) return {};
  const v = String(cvss.version || (/^CVSS:4/.test(cvss.vector) ? '4.0' : /^CVSS:3\.0/.test(cvss.vector) ? '3.0' : '3.1'));
  const key = v.startsWith('4') ? 'cvssMetricV40' : v === '3.0' ? 'cvssMetricV30' : v.startsWith('2') ? 'cvssMetricV2' : 'cvssMetricV31';
  return { [key]: [{ type, cvssData: { baseScore: cvss.score, vectorString: cvss.vector || '', version: v } }] };
}

/** Compact CVE.org record → dashboard entry (`_source: 'cveorg'`). */
function cveOrgToEntry(r) {
  return {
    _source: 'cveorg',
    ...(r.ssvc ? { _ssvc: r.ssvc } : {}),
    ...(r.kev ? { _kevExploited: true, _kev: { dateAdded: r.kev.dateAdded } } : {}),
    cve: {
      id: r.id,
      published: r.pub,
      lastModified: r.upd,
      descriptions: [{ lang: 'en', value: r.desc || r.title || '' }],
      metrics: cvssMetricsFrom(r.cvss),
      weaknesses: r.cwe?.length ? [{ description: r.cwe.map(value => ({ lang: 'en', value })) }] : [],
      references: (r.refs || []).map(x => ({ url: x.url, tags: (x.tags || []).map(t => t.replace(/^\w/, c => c.toUpperCase())) })),
      configurations: [],
      _affected: r.affected || [],
      _cna: r.cna || '',
    },
  };
}

/** Upstream advisory → dashboard entry (`_source: 'upstream'`). Vendor severity is kept separately, never turned into a fake CVSS. */
function upstreamToEntry(a, product) {
  return {
    _source: 'upstream',
    _upstream: { product, severity: a.severity || '', link: a.link || '', title: a.title || '' },
    cve: {
      id: a.id,
      published: a.date || '',
      descriptions: [{ lang: 'en', value: `${product}: ${a.title ? a.title + '. ' : ''}${a.desc || ''}`.trim() }],
      metrics: cvssMetricsFrom(a.cvss),
      references: a.link ? [{ url: a.link, tags: ['Vendor Advisory'] }] : [],
      configurations: [],
      _affected: [product],
    },
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    feedDecode, feedText, feedIsoDate, parseDeltaLogPrefix, cveRecordUrl, trimCveRecord,
    parseNodeRss, parseNodePost, parseOpensshSecurity, parsePhpAdvisories, parseNucleiIds,
    cvssMetricsFrom, cveOrgToEntry, upstreamToEntry,
  };
}
