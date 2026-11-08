const test = require('node:test');
const assert = require('node:assert/strict');

const load = () => import('../cors-proxy/worker.js');
const call = async (worker, target, init = {}) => {
  const url = 'https://proxy.example/' + (target === undefined ? '' : '?url=' + encodeURIComponent(target));
  return worker.default.fetch(new Request(url, { headers: { Origin: 'http://localhost:3000' }, ...init }));
};

test('isAllowedHost matches exact hosts and subdomains only', async () => {
  const { isAllowedHost } = await load();
  assert.equal(isAllowedHost('ubuntu.com'), true);
  assert.equal(isAllowedHost('usn.ubuntu.com'), true);
  assert.equal(isAllowedHost('UBUNTU.COM.'), true);
  assert.equal(isAllowedHost('evilubuntu.com'), false);
  assert.equal(isAllowedHost('ubuntu.com.evil.net'), false);
  assert.equal(isAllowedHost('api.first.org'), true);
  assert.equal(isAllowedHost(''), false);
});

test('proxy rejects missing, malformed, non-https and look-alike targets', async () => {
  const worker = await load();
  assert.equal((await call(worker)).status, 400);
  assert.equal((await call(worker, 'not a url')).status, 400);
  assert.equal((await call(worker, 'http://ubuntu.com/security/notices.json')).status, 403);
  const r = await call(worker, 'https://evilubuntu.com/x');
  assert.equal(r.status, 403);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'http://localhost:3000');
});

test('proxy forwards allowed targets and adds CORS headers', async (t) => {
  const worker = await load();
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (u) => { calls.push(u); return new Response('{"ok":1}', { status: 200, headers: { 'Content-Type': 'application/json' } }); });
  const r = await call(worker, 'https://api.first.org/data/v1/epss?cve=CVE-2024-3400');
  assert.equal(r.status, 200);
  assert.equal(await r.text(), '{"ok":1}');
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'http://localhost:3000');
  assert.deepEqual(calls, ['https://api.first.org/data/v1/epss?cve=CVE-2024-3400']);
});

test('proxy allows the upstream advisory hosts used as fallback', async () => {
  const { isAllowedHost } = await load();
  assert.equal(isAllowedHost('nodejs.org'), true);
  assert.equal(isAllowedHost('www.openssh.com'), true);
  assert.equal(isAllowedHost('evilnodejs.org'), false);
});
