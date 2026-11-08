const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fx = name => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const load = () => import('../intel-worker/lib.js');

function memKV() {
  const m = new Map();
  return {
    m,
    async get(k, type) { const v = m.get(k); if (v === undefined) return null; return type === 'json' ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, v); },
  };
}

const NOW = Date.parse('2026-11-08T18:30:00Z');
const deltaLog = (entries) => '[\n' + entries.map(e => `  {\n    "fetchTime": "${e.t}",\n    "numberOfChanges": 1,\n    "new": [${(e.new || []).map(id => `{"cveId": "${id}"}`).join(',')}],\n    "updated": [${(e.upd || []).map(id => `{"cveId": "${id}"}`).join(',')}],\n    "error": []\n  }`).join(',\n');

function fakeFetch(log, records, calls = []) {
  return async (url, init = {}) => {
    calls.push({ url, range: init.headers?.Range });
    if (url.endsWith('deltaLog.json')) return new Response(log, { status: 206 });
    const id = url.match(/(CVE-\d+-\d+)\.json$/)?.[1];
    if (records[id]) return new Response(JSON.stringify(records[id]));
    return new Response('nope', { status: 404 });
  };
}

test('ingestCveOrg stores new records by day, keeps a cursor, and only fetches newer deltas next time', async () => {
  const { ingestCveOrg, recentJson } = await load();
  const env = { INTEL: memKV() };
  const rec = JSON.parse(fx('cve-2026-18546.json'));
  const calls = [];
  const log1 = deltaLog([{ t: '2026-11-08T18:17:08.435Z', new: ['CVE-2026-18546', 'CVE-2026-99999'] }, { t: '2026-11-08T18:08:09.868Z', new: ['CVE-2026-1'] }]);
  const s1 = await ingestCveOrg(env, fakeFetch(log1, { 'CVE-2026-18546': rec }, calls), NOW);
  assert.match(calls[0].range, /^bytes=0-/, 'deltaLog is read with a Range request');
  assert.equal(s1.cursor, '2026-11-08T18:17:08.435Z');
  assert.equal(s1.stats.stored, 1, '404 records are dropped, not retried forever');
  assert.deepEqual(s1.pending, []);
  const shard = JSON.parse(env.INTEL.m.get('day:2026-11-08'));
  assert.equal(shard[0].id, 'CVE-2026-18546');

  // Second run: same log plus one newer delta → only the newer CVE is fetched
  const calls2 = [];
  const log2 = deltaLog([{ t: '2026-11-08T18:25:00.000Z', new: ['CVE-2026-18546'] }]) + ',\n' + log1.slice(2);
  const s2 = await ingestCveOrg(env, fakeFetch(log2, { 'CVE-2026-18546': rec }, calls2), NOW);
  assert.equal(calls2.length, 2, 'deltaLog + one record');
  assert.equal(s2.cursor, '2026-11-08T18:25:00.000Z');
  assert.equal(JSON.parse(env.INTEL.m.get('day:2026-11-08')).length, 1, 'upsert, no duplicate');

  const body = JSON.parse(await recentJson(env.INTEL, 7, NOW));
  assert.equal(body.cves.length, 1);
  assert.equal(body.cves[0].cna, 'ibm');
});

test('ingestCveOrg caps fetches per run and queues the rest; transient errors are retried', async () => {
  const { ingestCveOrg } = await load();
  const env = { INTEL: memKV() };
  const ids = Array.from({ length: 55 }, (_, i) => `CVE-2026-${70000 + i}`);
  const rec = JSON.parse(fx('cve-2026-18546.json'));
  let n = 0;
  const f = async (url) => {
    if (url.endsWith('deltaLog.json')) return new Response(deltaLog([{ t: '2026-11-08T18:00:00.000Z', new: ids }]), { status: 206 });
    n++;
    if (url.includes('70001')) return new Response('busy', { status: 503 });
    const id = url.match(/(CVE-\d+-\d+)\.json$/)[1];
    return new Response(JSON.stringify({ ...rec, cveMetadata: { ...rec.cveMetadata, cveId: id } }));
  };
  const s = await ingestCveOrg(env, f, NOW);
  assert.equal(n, 40, 'stays under the free-plan subrequest limit');
  assert.equal(s.stats.stored, 39);
  assert.equal(s.pending.length, 16, '15 not yet fetched + 1 transient failure');
  assert.ok(s.pending.includes('CVE-2026-70001'));
});

test('ingestCveOrg flags a gap when its cursor fell out of the window', async () => {
  const { ingestCveOrg } = await load();
  const env = { INTEL: memKV() };
  await env.INTEL.put('state', JSON.stringify({ cursor: '2026-11-07T01:00:00.000Z', pending: [] }));
  const s = await ingestCveOrg(env, fakeFetch(deltaLog([{ t: '2026-11-08T18:00:00.000Z', new: [] }]), {}), NOW);
  assert.equal(s.gap, true);
});

test('refreshAdvisories parses Node.js, OpenSSH and PHP, and keeps last good data on failure', async () => {
  const { refreshAdvisories } = await load();
  const env = { INTEL: memKV() };
  const rss = fx('node-rss.xml');
  const ok = async url => {
    if (url.includes('vulnerability.xml')) return new Response(rss);
    if (url.includes('november-2026')) return new Response(fx('node-preannounce.html'));
    if (url.includes('nodejs.org/en/blog')) return new Response(fx('node-release.html'));
    if (url.includes('openssh.com')) return new Response(fx('openssh.html'));
    if (url.includes('php-src')) return new Response(fx('php-ghsa.json'));
    return new Response('', { status: 404 });
  };
  const a = await refreshAdvisories(env, ok, NOW);
  assert.equal(a.node.ok, true);
  assert.ok(a.node.items.some(i => i.id === 'CVE-2026-105482' && i.severity === 'HIGH'));
  assert.deepEqual(a.node.upcoming.map(u => u.releaseDate), ['2026-11-11']);
  assert.equal(a.openssh.ok, true);
  assert.ok(a.openssh.items.length >= 3);
  assert.equal(a.php.ok, true);

  const failing = async url => (url.includes('openssh.com') ? new Response('', { status: 500 }) : ok(url));
  const b = await refreshAdvisories(env, failing, NOW);
  assert.equal(b.openssh.ok, false);
  assert.match(b.openssh.error, /HTTP 500/);
  assert.equal(b.openssh.items.length, a.openssh.items.length, 'previous items kept');
});

test('HTTP: CORS allowlist, recent endpoint and 404', async () => {
  const worker = (await import('../intel-worker/worker.js')).default;
  const env = { INTEL: memKV() };
  const get = (p, origin = 'http://localhost:3000') => worker.fetch(new Request('https://intel.example' + p, { headers: origin ? { Origin: origin } : {} }), env);
  const r = await get('/v1/recent?days=99');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'http://localhost:3000');
  assert.equal(JSON.parse(await r.text()).days, 14, 'days clamped');
  assert.equal((await get('/v1/recent', 'https://evil.example')).status, 403);
  assert.equal((await get('/nope')).status, 404);
  assert.equal((await get('/v1/health')).status, 200);
});
