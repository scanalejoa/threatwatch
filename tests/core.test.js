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

test('priorityTier: KEV beats EPSS beats CVSS; medium/low/unscored need no action', () => {
  assert.equal(core.priorityTier(cve('a', { score: 4, kev: true })), 1, 'exploited medium is still P1');
  assert.equal(core.priorityTier(cve('b'), 0.4), 2, 'unscored but likely exploited is P2');
  assert.equal(core.priorityTier(cve('c', { score: 5 }), 0.1), 2, 'EPSS threshold is inclusive');
  assert.equal(core.priorityTier(cve('d', { score: 9.8 }), 0.02), 3);
  assert.equal(core.priorityTier(cve('e', { score: 7.5 })), 4);
  assert.equal(core.priorityTier(cve('f', { score: 6.9 }), 0.05), 0);
  assert.equal(core.priorityTier(cve('g')), 0);
});

test('rankByPriority orders by tier, ransomware, EPSS, CVSS, then newest', () => {
  const kevRansom = { ...cve('kev-ransom', { score: 6, kev: true }), _kev: { knownRansomwareCampaignUse: 'Known', dateAdded: '2026-11-01' } };
  const kevHighEpss = { ...cve('kev-epss', { score: 9.8, kev: true }), _kev: { knownRansomwareCampaignUse: 'Unknown', dateAdded: '2026-11-02' } };
  const list = [
    cve('p4', { score: 8 }),
    cve('p3-old', { score: 9.8, published: '2026-11-01T00:00:00' }),
    cve('p3-new', { score: 9.8, published: '2026-11-05T00:00:00' }),
    cve('p2', { score: 5 }),
    kevHighEpss, kevRansom,
    cve('ignored', { score: 5 }),
  ];
  const epss = { p2: 0.3, 'kev-epss': 0.9, 'kev-ransom': 0.01 };
  const rows = core.rankByPriority(list, id => epss[id]);
  assert.deepEqual(rows.map(r => r.v.cve.id), ['kev-ransom', 'kev-epss', 'p2', 'p3-new', 'p3-old', 'p4']);
  assert.deepEqual(rows.map(r => r.tier), [1, 1, 2, 3, 3, 4]);
  assert.equal(rows[0].ransomware, true);
  assert.equal(rows[2].epss, 0.3);
});

test('daysUntil counts whole days and goes negative when overdue', () => {
  const now = Date.parse('2026-11-08T15:00:00Z');
  assert.equal(core.daysUntil('2026-11-22', now), 14);
  assert.equal(core.daysUntil('2026-11-08', now), 0);
  assert.equal(core.daysUntil('2026-11-05', now), -3);
  assert.equal(core.daysUntil('', now), null);
});

test('hash state: priority is the default view and pt filters tiers', () => {
  assert.equal(core.parseHashState('').view, 'priority');
  assert.equal(core.buildHashState(core.parseHashState('#view=threat-intel')), '#view=threat-intel');
  assert.equal(core.parseHashState('#pt=2').pt, '2');
  assert.equal(core.parseHashState('#pt=9').pt, 'ALL');
  assert.equal(core.buildHashState({ ...core.parseHashState(''), pt: '1' }), '#pt=1');
});

const withVector = (id, score, vector, extra = {}) => ({
  _source: 'nvd', ...extra,
  cve: { id, published: extra.published || '2026-11-07T10:00:00.000', descriptions: [{ lang: 'en', value: extra.desc || 'x' }],
    metrics: score ? { cvssMetricV31: [{ type: 'Secondary', cvssData: { baseScore: score, vectorString: vector, version: '3.1' } }] } : {},
    references: extra.refs || [], configurations: extra.cpe ? [{ nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${extra.cpe}:*:*:*` }] }] }] : [],
    ...(extra.affected ? { _affected: extra.affected } : {}) },
});

test('coreSoftwareOf matches core packages narrowly', () => {
  const of = v => core.coreSoftwareOf(v);
  assert.equal(of(withVector('a', 8, '', { cpe: 'openbsd:openssh' })), 'OpenSSH');
  assert.equal(of(withVector('b', 0, '', { desc: 'In the Linux kernel, the following vulnerability has been resolved: net: fix UAF' })), 'Linux kernel');
  assert.equal(of(withVector('c', 0, '', { affected: ['linux'] })), 'Linux kernel', 'Ubuntu/CNA package name');
  assert.equal(of(withVector('d', 9, '', { desc: 'In PHP versions 8.3.* before 8.3.20, a crafted request…' })), 'PHP');
  assert.equal(of(withVector('e', 9, '', { desc: 'The Foo plugin for WordPress (requires PHP 7.4) allows SQL injection' })), null, 'WordPress plugin is not PHP itself');
  assert.equal(of(withVector('f', 7, '', { desc: 'lodash-like Node.js library allows prototype pollution' })), null, 'npm package is not Node.js runtime');
  assert.equal(of({ ...withVector('g', 7, ''), _upstream: { product: 'Node.js' } }), 'Node.js');
  assert.equal(core.coreSoftwareOf(withVector('h', 8, '', { cpe: 'openbsd:openssh' }), ['openssh']), null, 'built-in can be switched off');
  assert.equal(core.coreSoftwareOf(withVector('i', 8, '', { desc: 'Bug in FooCorp Gateway' }), [], ['foocorp']), 'foocorp', 'user keyword');
});

test('prioritySignals: public exploits, SSVC, core remote bugs and early warning', () => {
  const now = Date.parse('2026-11-08T10:00:00Z');
  const ctx = { core: v => core.coreSoftwareOf(v), exploitIds: new Set(['CVE-NUC']), now };
  const sig = v => core.prioritySignals(v, ctx);

  assert.equal(sig({ ...withVector('CVE-A', 5, ''), _ssvc: { e: 'active' } }).tier, 1, 'CISA SSVC active = exploited');
  assert.equal(sig(withVector('CVE-NUC', 6.1, '')).tier, 2, 'nuclei template = public exploit');
  assert.equal(sig(withVector('CVE-NVD', 6.1, '', { refs: [{ url: 'https://x', tags: ['Exploit'] }] })).exploit, 'nvd');
  assert.equal(sig({ ...withVector('CVE-POC', 6.1, ''), _ssvc: { e: 'poc' } }).tier, 2);

  const sshRemote = withVector('CVE-SSH', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', { cpe: 'openbsd:openssh', published: '2026-11-07T10:00:00.000' });
  const s = sig(sshRemote);
  assert.equal(s.tier, 2);
  assert.equal(s.early, true, 'core + remote + 24h old');
  assert.ok(s.reasons.some(r => /Remote, no auth, in OpenSSH/.test(r)));
  assert.equal(sig({ ...sshRemote, cve: { ...sshRemote.cve, published: '2026-11-01T00:00:00.000' } }).early, false, 'older than 72h');

  const local = withVector('CVE-SSH-L', 7.0, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', { cpe: 'openbsd:openssh' });
  assert.equal(sig(local).tier, 4, 'local core bug stays on CVSS');

  const kernel = withVector('CVE-K', 0, '', { desc: 'In the Linux kernel, the following vulnerability has been resolved' });
  const k = sig(kernel);
  assert.equal(k.tier, 4, 'unscored kernel CVE goes to triage instead of vanishing');
  assert.match(k.reasons[0], /Linux kernel, not scored yet/);
  assert.equal(core.prioritySignals(kernel, {}).tier, 0, 'without the core watch it is dropped (old behaviour)');
});

test('rankByPriority puts early warnings first inside a tier', () => {
  const now = Date.parse('2026-11-08T10:00:00Z');
  const vec = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const oldCore = withVector('old-core', 9.8, vec, { cpe: 'openbsd:openssh', published: '2026-11-01T00:00:00.000' });
  const newCore = withVector('new-core', 7.5, vec, { cpe: 'openbsd:openssh', published: '2026-11-08T00:00:00.000' });
  const rows = core.rankByPriority([oldCore, newCore], () => undefined, { core: v => core.coreSoftwareOf(v), now });
  assert.deepEqual(rows.map(r => [r.v.cve.id, r.tier, r.early]), [['new-core', 2, true], ['old-core', 2, false]]);
});

test('mergeCves carries SSVC, upstream and CVE.org products onto an existing entry', () => {
  const nvd = withVector('CVE-M', 9.8, '');
  const fromOrg = { ...withVector('CVE-M', 0, '', { affected: ['openssh'] }), _source: 'cveorg', _ssvc: { e: 'poc', a: 'yes' } };
  const fromUp = { ...withVector('CVE-M', 0, ''), _source: 'upstream', _upstream: { product: 'OpenSSH' } };
  const r = core.mergeCves([nvd], [fromOrg, fromUp]);
  assert.equal(r.list.length, 1);
  assert.deepEqual(r.list[0]._ssvc, { e: 'poc', a: 'yes' });
  assert.equal(r.list[0]._upstream.product, 'OpenSSH');
  assert.deepEqual(r.list[0].cve._affected, ['openssh']);
  assert.deepEqual(r.list[0]._alsoIn, ['cveorg', 'upstream']);
});

test('distro patch bundles do not flood the kernel triage tier', () => {
  const ctx = { core: v => core.coreSoftwareOf(v) };
  const kernelDesc = { desc: 'In the Linux kernel, the following vulnerability has been resolved' };
  const ubuntu = { ...withVector('CVE-U', 0, '', kernelDesc), _source: 'ubuntu' };
  assert.equal(core.prioritySignals(ubuntu, ctx).tier, 0, 'Ubuntu-only kernel CVE is not triage');
  assert.equal(core.prioritySignals({ ...ubuntu, _alsoIn: ['cveorg'] }, ctx).tier, 4, 'also reported by CVE.org → triage');
  assert.equal(core.prioritySignals(withVector('CVE-N', 0, '', kernelDesc), ctx).tier, 4, 'NVD kernel CVE → triage');
});

test('within P2, a Nuclei template outranks an NVD exploit reference', () => {
  const rows = core.rankByPriority([
    withVector('CVE-REF', 9.8, '', { refs: [{ url: 'https://x', tags: ['Exploit'] }] }),
    withVector('CVE-NUC', 6.5, ''),
  ], () => undefined, { exploitIds: new Set(['CVE-NUC']) });
  assert.deepEqual(rows.map(r => r.v.cve.id), ['CVE-NUC', 'CVE-REF']);
});

test('ssvcOf reads NVD ssvcV203 when the CVE.org _ssvc is absent (CVE-2026-123158)', () => {
  const v = { _source: 'nvd', cve: {
    id: 'CVE-2026-123158', published: '2026-11-05T16:17:47.110',
    descriptions: [{ lang: 'en', value: 'sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass.' }],
    metrics: {
      cvssMetricV31: [{ source: 'cve@mitre.org', type: 'Secondary', cvssData: { baseScore: 8.1, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', attackVector: 'NETWORK', privilegesRequired: 'NONE' } }],
      ssvcV203: [{ source: 'cisa', ssvcData: { id: 'CVE-2026-123158', role: 'CISA Coordinator', version: '2.0.3',
        options: [{ exploitation: 'poc' }, { automatable: 'no' }, { technicalImpact: 'total' }] } }],
    },
  } };
  assert.deepEqual(core.ssvcOf(v), { e: 'poc', a: 'no', t: 'total' });
  assert.equal(core.publicExploitSource(v, new Set()), 'ssvc');
  const s = core.prioritySignals(v, { core: x => core.coreSoftwareOf(x), exploitIds: new Set(), now: Date.parse('2026-11-09T15:00:00Z') });
  assert.equal(s.tier, 2);
  assert.equal(s.core, 'OpenSSH');
  assert.ok(s.reasons.includes('CISA: proof of concept public'));
  // the CVE.org form wins when both exist
  assert.equal(core.ssvcOf({ ...v, _ssvc: { e: 'active', a: 'yes', t: 'total' } }).e, 'active');
  assert.equal(core.ssvcOf({ cve: { id: 'CVE-1', metrics: {} } }), null);
});
