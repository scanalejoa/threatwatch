const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const feeds = require('../js/feeds.js');
const core = require('../js/core.js');
const fx = name => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

test('parseDeltaLogPrefix reads a truncated, newest-first log and stops at the last seen delta', () => {
  const text = fx('deltalog-prefix.json');
  const all = feeds.parseDeltaLogPrefix(text);
  assert.match(all.latest, /^2026-11-08T/);
  assert.ok(all.newIds.length >= 3, 'collects new ids from every complete delta');
  assert.ok(all.newIds.includes('CVE-2026-18893'));
  const times = [...text.matchAll(/"fetchTime": "([^"]+)"/g)].map(m => m[1]);
  const since = feeds.parseDeltaLogPrefix(text, times[1]);
  assert.deepEqual(since.newIds, ['CVE-2026-18893'], 'only deltas newer than the cursor');
  assert.equal(feeds.parseDeltaLogPrefix(text, times[0]).newIds.length, 0);
});

test('cveRecordUrl builds cvelistV5 bucket paths', () => {
  assert.equal(feeds.cveRecordUrl('CVE-2026-18546'), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/18xxx/CVE-2026-18546.json');
  assert.equal(feeds.cveRecordUrl('CVE-2024-6387'), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/6xxx/CVE-2024-6387.json');
  assert.equal(feeds.cveRecordUrl('CVE-2024-123'.replace('123', '0123')), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/0xxx/CVE-2024-0123.json');
  assert.equal(feeds.cveRecordUrl('nope'), '');
});

test('trimCveRecord keeps CNA data and CISA SSVC enrichment', () => {
  const r = feeds.trimCveRecord(JSON.parse(fx('cve-2024-6387.json')));
  assert.equal(r.id, 'CVE-2024-6387');
  assert.deepEqual(r.ssvc, { e: 'poc', a: 'no', t: 'total' });
  assert.ok(r.affected.some(a => /openssh/i.test(a)));
  assert.ok(r.desc.length > 20 && r.desc.length <= 500);
  assert.ok(JSON.stringify(r).length < 3000, 'compact');
  const ibm = feeds.trimCveRecord(JSON.parse(fx('cve-2026-18546.json')));
  assert.equal(ibm.cna, 'ibm');
  assert.equal(typeof ibm.cvss.score, 'number');
  assert.equal(feeds.trimCveRecord({ cveMetadata: { cveId: 'CVE-1-1', state: 'REJECTED' } }), null);
});

test('cveOrgToEntry produces an entry the dashboard can score', () => {
  const rec = feeds.trimCveRecord(JSON.parse(fx('cve-2026-18546.json')));
  const e = feeds.cveOrgToEntry(rec);
  assert.equal(e._source, 'cveorg');
  assert.equal(core.getCvss(e), rec.cvss.score);
  assert.equal(core.getDescription(e), rec.desc);
  const ssh = feeds.cveOrgToEntry(feeds.trimCveRecord(JSON.parse(fx('cve-2024-6387.json'))));
  assert.equal(ssh._ssvc.e, 'poc');
});

test('Node.js RSS and release posts', () => {
  const items = feeds.parseNodeRss(fx('node-rss.xml'));
  assert.equal(items.length, 3);
  assert.match(items[0].title, /Security Releases/);
  assert.match(items[0].link, /^https:\/\/nodejs\.org\/en\/blog\/vulnerability\//);
  assert.match(items[0].date, /^2026-11-03T/);

  const rel = feeds.parseNodePost(fx('node-release.html'), items[1]);
  assert.equal(rel.upcoming, null);
  assert.ok(rel.cves.length >= 3);
  const dns = rel.cves.find(c => c.id === 'CVE-2026-105482');
  assert.equal(dns.severity, 'HIGH');
  assert.match(dns.title, /dns\.resolve truncates/);
  assert.match(dns.desc, /NUL byte/);

  const pre = feeds.parseNodePost(fx('node-preannounce.html'), items[0]);
  assert.equal(pre.cves.length, 0);
  assert.deepEqual(pre.upcoming && [pre.upcoming.releaseDate, pre.upcoming.severity, pre.upcoming.lines.join('|')], ['2026-11-11', 'HIGH', '26.x|24.x|22.x']);
});

test('OpenSSH security page entries', () => {
  const list = feeds.parseOpensshSecurity(fx('openssh.html'));
  assert.ok(list.length >= 3);
  assert.equal(list[0].date.slice(0, 10), '2025-04-09');
  assert.match(list[0].versions, /OpenSSH versions 7\.4 to 9\.9/);
  assert.match(list[0].title, /DisableForwarding/);
  assert.deepEqual(list[0].cves, []);
  assert.deepEqual(list[1].cves, ['CVE-2025-26465']);
  assert.equal(list[1].link, 'https://www.openssh.com/txt/release-9.9p2');
});

test('PHP advisories and nuclei exploit ids', () => {
  const php = feeds.parsePhpAdvisories(JSON.parse(fx('php-ghsa.json')));
  assert.ok(php.length >= 1);
  assert.match(php[0].id, /^CVE-/);
  assert.match(php[0].link, /github\.com\/php\/php-src\/security\/advisories/);
  const e = feeds.upstreamToEntry(php[0], 'PHP');
  assert.equal(e._upstream.product, 'PHP');
  assert.match(core.getDescription(e), /^PHP: /);
  if (php[0].cvss) assert.equal(core.getCvss(e), php[0].cvss.score);

  const ids = feeds.parseNucleiIds(fx('nuclei.ndjson'));
  assert.equal(ids.length, 5);
  assert.ok(ids.includes('CVE-2000-0114'));
});
