const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../js/core.js');

const cve = (id, { score, published = '2026-11-01T10:00:00.000', source = 'nvd', desc = 'desc', cpe, type, kev } = {}) => ({
  _source: source,
  ...(kev ? { _kevExploited: true } : {}),
  cve: {
    id, published,
    descriptions: [{ lang: 'en', value: desc }],
    metrics: score === undefined ? {} : { cvssMetricV31: [{ type, cvssData: { baseScore: score, version: '3.1', vectorString: 'CVSS:3.1/AV:N' } }] },
    configurations: cpe ? [{ nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${cpe}:*:*:*` }] }] }] : [],
  },
});

test('escapeHtml neutralises markup, quotes and nullish values', () => {
  assert.equal(core.escapeHtml('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  assert.equal(core.escapeHtml("it's"), 'it&#39;s');
  assert.equal(core.escapeHtml(undefined), '');
  assert.equal(core.escapeHtml(null), '');
  assert.equal(core.escapeHtml(9.8), '9.8');
});

test('safeUrl only passes http(s)', () => {
  assert.equal(core.safeUrl('https://nvd.nist.gov/x'), 'https://nvd.nist.gov/x');
  assert.equal(core.safeUrl('javascript:alert(1)'), '#');
  assert.equal(core.safeUrl('not a url'), '#');
});

test('getCvss prefers Primary, newest version, and returns 0 when unscored', () => {
  const v = { cve: { metrics: {
    cvssMetricV40: [{ type: 'Secondary', cvssData: { baseScore: 8.7 } }],
    cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 9.8 } }],
  } } };
  assert.equal(core.getCvss(v), 8.7, 'v4.0 secondary beats v3.1 because versions are checked newest first');
  const p = { cve: { metrics: { cvssMetricV31: [
    { type: 'Secondary', cvssData: { baseScore: 9.1 } },
    { type: 'Primary', cvssData: { baseScore: 7.5 } },
  ] } } };
  assert.equal(core.getCvss(p), 7.5, 'Primary wins within a version');
  assert.equal(core.getCvss(cve('CVE-1')), 0);
  assert.equal(core.getCvss({ cve: {} }), 0);
});

test('getCvssDetail returns version and vector of the chosen metric', () => {
  assert.deepEqual(core.getCvssDetail(cve('CVE-1', { score: 9.8 })), { score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N' });
  assert.deepEqual(core.getCvssDetail(cve('CVE-2')), { score: 0, version: '', vector: '' });
});

test('getSeverity buckets, with 0 meaning UNSCORED (not LOW)', () => {
  assert.equal(core.getSeverity(9), 'CRITICAL');
  assert.equal(core.getSeverity(8.9), 'HIGH');
  assert.equal(core.getSeverity(4), 'MEDIUM');
  assert.equal(core.getSeverity(0.1), 'LOW');
  assert.equal(core.getSeverity(0), 'UNSCORED');
});

test('getChartVendor drops distro and ecosystem pseudo-vendors', () => {
  assert.equal(core.getChartVendor(cve('A', { cpe: 'ubuntu:linux' })), null);
  assert.equal(core.getChartVendor(cve('B', { cpe: 'npm:lodash' })), null);
  assert.equal(core.getChartVendor(cve('C')), null);
  assert.equal(core.getChartVendor(cve('D', { cpe: 'fortinet:fortios' })), 'fortinet');
});

test('mergeCves dedupes, records extra sources and enriches missing CVSS/KEV', () => {
  const existing = [cve('CVE-1', { source: 'nvd' })];
  const kevEntry = { ...cve('CVE-1', { source: 'kev', kev: true }), _kev: { dateAdded: '2026-11-02' } };
  const scored = cve('CVE-1', { source: 'github', score: 9.1 });
  const fresh = cve('CVE-2', { source: 'github', score: 5 });
  const r = core.mergeCves(existing, [kevEntry, scored, fresh]);
  assert.equal(r.list.length, 2);
  assert.deepEqual(r.added.map(v => v.cve.id), ['CVE-2']);
  assert.equal(r.enriched, 1);
  const merged = r.list[0];
  assert.equal(core.getCvss(merged), 9.1);
  assert.equal(merged._kevExploited, true);
  assert.equal(merged._kev.dateAdded, '2026-11-02');
  assert.deepEqual(merged._alsoIn, ['kev', 'github']);
});

test('mergeCves applies keyword and range filters only to new entries', () => {
  const r = core.mergeCves([], [
    cve('CVE-1', { desc: 'Apache flaw' }),
    cve('CVE-2', { desc: 'Other thing' }),
    cve('CVE-3', { desc: 'apache old', published: '2001-01-01' }),
  ], { keyword: 'apache', inRange: v => v.cve.published > '2020' });
  assert.deepEqual(r.added.map(v => v.cve.id), ['CVE-1']);
});

test('countsBySeverity keeps unscored separate from low', () => {
  assert.deepEqual(core.countsBySeverity([cve('a', { score: 9.8 }), cve('b', { score: 2 }), cve('c')]),
    { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1, UNSCORED: 1 });
});

test('sortCves supports cvss, date, epss and kev modes without mutating input', () => {
  const list = [
    cve('old-crit', { score: 9.8, published: '2026-10-01' }),
    cve('new-low', { score: 2.0, published: '2026-11-05' }),
    cve('unscored', { published: '2026-11-04' }),
    cve('kev-med', { score: 5.0, published: '2026-10-20', kev: true }),
  ];
  const ids = l => l.map(v => v.cve.id);
  assert.deepEqual(ids(core.sortCves(list, 'cvss')), ['old-crit', 'kev-med', 'new-low', 'unscored']);
  assert.deepEqual(ids(core.sortCves(list, 'date')), ['new-low', 'unscored', 'kev-med', 'old-crit']);
  assert.deepEqual(ids(core.sortCves(list, 'kev')), ['kev-med', 'old-crit', 'new-low', 'unscored']);
  const epss = { unscored: 0.9, 'new-low': 0.1 };
  assert.deepEqual(ids(core.sortCves(list, 'epss', id => epss[id])), ['unscored', 'new-low', 'old-crit', 'kev-med']);
  assert.equal(list[0].cve.id, 'old-crit', 'input not mutated');
});

test('toCsv quotes cells and guards against formula injection', () => {
  const csv = core.toCsv([['ID', 'Desc'], ['CVE-1', '=HYPERLINK("http://x")'], ['CVE-2', 'say "hi"\nnext']]);
  const lines = csv.split('\r\n');
  assert.equal(lines[0], '"ID","Desc"');
  assert.equal(lines[1], '"CVE-1","\'=HYPERLINK(""http://x"")"');
  assert.ok(lines[2].startsWith('"CVE-2","say ""hi""'));
  assert.equal(core.csvCell('-1+1'), '"\'-1+1"');
  assert.equal(core.csvCell(9.8), '"9.8"');
});

test('hash state round-trips and rejects invalid values', () => {
  const s = core.parseHashState('#range=30&sev=CRITICAL&src=kev&sort=epss&page=3&new=1&cve=cve-2026-1234');
  assert.equal(s.range, '30'); assert.equal(s.sev, 'CRITICAL'); assert.equal(s.src, 'kev');
  assert.equal(s.sort, 'epss'); assert.equal(s.page, 3); assert.equal(s.new, true);
  assert.equal(s.cve, 'CVE-2026-1234');
  assert.equal(core.parseHashState(core.buildHashState(s)).sort, 'epss');

  const bad = core.parseHashState('#range=9999&sev=<script>&src=evil&page=-4&cve=<x>');
  assert.equal(bad.range, '7'); assert.equal(bad.sev, 'ALL'); assert.equal(bad.src, 'ALL');
  assert.equal(bad.page, 1); assert.equal(bad.cve, undefined);

  assert.equal(core.buildHashState(core.parseHashState('')), '', 'defaults produce an empty hash');
  const custom = core.parseHashState('#range=custom&from=2026-01-01&to=2026-06-30&kw=apache');
  assert.deepEqual([custom.from, custom.to, custom.kw], ['2026-01-01', '2026-06-30', 'apache']);
  assert.equal(core.parseHashState('#range=custom&from=bad').range, '7', 'custom without dates falls back');
});

test('dailyCounts buckets by day, and by week for long ranges', () => {
  const list = [
    cve('a', { score: 9.8, published: '2026-11-01T03:00:00' }),
    cve('b', { published: '2026-11-01T22:00:00' }),
    cve('c', { score: 5, published: '2026-11-03T12:00:00' }),
    cve('outside', { score: 5, published: '2026-10-01T12:00:00' }),
  ];
  const r = core.dailyCounts(list, new Date('2026-11-01T00:00:00Z'), new Date('2026-11-03T23:00:00Z'));
  assert.equal(r.weekly, false);
  assert.deepEqual(r.buckets.map(b => b.key), ['2026-11-01', '2026-11-02', '2026-11-03']);
  assert.deepEqual(r.buckets[0].counts, { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNSCORED: 1 });
  assert.equal(r.buckets[2].total, 1);

  const w = core.dailyCounts(list, new Date('2026-06-01T00:00:00Z'), new Date('2026-11-03T00:00:00Z'));
  assert.equal(w.weekly, true);
  assert.equal(w.buckets.reduce((n, b) => n + b.total, 0), 4);
  assert.ok(w.buckets.every(b => new Date(b.key + 'T00:00:00Z').getUTCDay() === 1), 'weeks start on Monday');
});

test('isNewSince uses KEV dateAdded when present', () => {
  const since = Date.parse('2026-11-02T00:00:00Z');
  assert.equal(core.isNewSince(cve('a', { published: '2026-11-03T00:00:00Z' }), since), true);
  assert.equal(core.isNewSince(cve('b', { published: '2026-11-01T00:00:00Z' }), since), false);
  assert.equal(core.isNewSince({ ...cve('c', { published: '2020-01-01' }), _kev: { dateAdded: '2026-11-04' } }, since), true);
  assert.equal(core.isNewSince(cve('d'), 0), false);
});

test('parseFeedDate treats zone-less NVD timestamps as UTC', () => {
  assert.equal(core.parseFeedDate('2026-11-01T22:00:00.000'), Date.UTC(2026, 10, 1, 22));
  assert.equal(core.parseFeedDate('2026-11-01T22:00:00Z'), Date.UTC(2026, 10, 1, 22));
  assert.equal(core.parseFeedDate('2026-11-01'), Date.UTC(2026, 10, 1));
  assert.equal(core.parseFeedDate(''), 0);
  assert.equal(core.parseFeedDate('garbage'), 0);
});
