/**
 * THREATWATCH — Intel Worker logic (imported by worker.js and the tests).
 * See worker.js for the cron/HTTP overview.
 *
 * Cron jobs:
 *   every 15 min  ingestCveOrg()       — new CVEs from CVE.org (cvelistV5) minutes after
 *                                        publication, hours or days before NVD analyses them.
 *                                        Keeps CNA CVSS and CISA's SSVC enrichment.
 *   hourly (:07)  refreshAdvisories()  — Node.js, OpenSSH and PHP upstream advisories,
 *                                        including Node.js pre-announcements of security releases.
 *
 * HTTP (GET, CORS for the dashboard origins):
 *   /v1/recent?days=7   compact CVE.org records published in the last N days (max 14)
 *   /v1/advisories      upstream advisories + upcoming security releases
 *   /v1/health          ingestion state
 *
 * Storage (KV binding INTEL):
 *   state        { cursor, pending[], lastRun, lastError, gap, stats }
 *   day:YYYY-MM-DD  array of compact records published that UTC day (TTL KEEP_DAYS)
 *   index        { cveId: day } for every stored record (to apply updates)
 *   advisories   JSON served by /v1/advisories
 *
 * Built to stay inside the Workers free plan: ≤ 50 subrequests and little CPU
 * per run (the 37 MB deltaLog is read with a Range request; records are
 * sharded by day so a run parses only small shards).
 */
import feeds from '../js/feeds.js';

export const ALLOWED_ORIGINS = [
  'https://threatwatch-7du.pages.dev',
  'https://threatwatch.pages.dev',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];
const DELTA_LOG_URL = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json';
const DELTA_RANGE_BYTES = 262144;  // ≈ the last 5 hours of deltas
const MAX_RECORDS_PER_RUN = 40;    // + 1 deltaLog request stays under the 50-subrequest free limit
const FETCH_CONCURRENCY = 8;
const MAX_PENDING = 3000;
export const KEEP_DAYS = 14;
const UA = 'THREATWATCH-Intel/1.0 (+https://threatwatch-7du.pages.dev)';

const dayKey = iso => 'day:' + String(iso || '').slice(0, 10);

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const run = async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return out;
}

// ── CVE.org ingestion ──────────────────────────────────────────
export async function ingestCveOrg(env, fetchFn = fetch, now = Date.now()) {
  const kv = env.INTEL;
  const state = (await kv.get('state', 'json')) || { cursor: '', pending: [] };
  const index = (await kv.get('index', 'json')) || {};
  const oldest = new Date(now - KEEP_DAYS * 86400000).toISOString().slice(0, 10);

  // Drop index entries whose shard has expired
  for (const [id, day] of Object.entries(index)) if (day < oldest) delete index[id];

  const resp = await fetchFn(DELTA_LOG_URL, { headers: { Range: `bytes=0-${DELTA_RANGE_BYTES - 1}`, 'User-Agent': UA } });
  if (!resp.ok) throw new Error(`deltaLog HTTP ${resp.status}`);
  const text = await resp.text();
  const delta = feeds.parseDeltaLogPrefix(text, state.cursor);
  // If the cursor is not inside the window we read, deltas were missed (worker was down for hours).
  const gap = !!state.cursor && !text.includes(`"fetchTime": "${state.cursor}"`) && !text.includes(`"fetchTime":"${state.cursor}"`);

  const firstRun = !state.cursor;
  const wanted = [...delta.newIds, ...(firstRun ? [] : delta.updatedIds.filter(id => index[id]))];
  const queue = [...new Set([...wanted, ...(state.pending || [])])];
  const batch = queue.slice(0, MAX_RECORDS_PER_RUN);
  const pending = queue.slice(MAX_RECORDS_PER_RUN, MAX_RECORDS_PER_RUN + MAX_PENDING);

  const records = await mapLimit(batch, FETCH_CONCURRENCY, async id => {
    try {
      const r = await fetchFn(feeds.cveRecordUrl(id), { headers: { 'User-Agent': UA } });
      if (r.status === 404) return null;           // not mirrored yet / rejected: drop
      if (!r.ok) { pending.push(id); return null; } // transient: retry next run
      return feeds.trimCveRecord(await r.json());
    } catch { pending.push(id); return null; }
  });

  // Group by publication day and upsert into the day shards
  const byDay = new Map();
  for (const rec of records) {
    if (!rec || !rec.pub || rec.pub.slice(0, 10) < oldest) continue;
    const k = dayKey(rec.pub);
    if (!byDay.has(k)) byDay.set(k, []);
    byDay.get(k).push(rec);
  }
  let stored = 0;
  for (const [k, recs] of byDay) {
    const shard = (await kv.get(k, 'json')) || [];
    const pos = new Map(shard.map((r, i) => [r.id, i]));
    for (const rec of recs) {
      if (pos.has(rec.id)) shard[pos.get(rec.id)] = rec; else { pos.set(rec.id, shard.length); shard.push(rec); }
      index[rec.id] = k.slice(4);
      stored++;
    }
    await kv.put(k, JSON.stringify(shard), { expirationTtl: (KEEP_DAYS + 1) * 86400 });
  }
  if (stored) await kv.put('index', JSON.stringify(index));

  const next = {
    cursor: delta.latest || state.cursor,
    pending: [...new Set(pending)].slice(0, MAX_PENDING),
    lastRun: new Date(now).toISOString(),
    lastError: '',
    gap: gap || false,
    stats: { fetched: batch.length, stored, newInWindow: delta.newIds.length, stored14d: Object.keys(index).length },
  };
  await kv.put('state', JSON.stringify(next));
  return next;
}

// ── Upstream advisories ────────────────────────────────────────
async function getText(fetchFn, url, accept = 'text/html') {
  const r = await fetchFn(url, { headers: { 'User-Agent': UA, Accept: accept } });
  if (!r.ok) throw new Error(`${new URL(url).hostname} HTTP ${r.status}`);
  return r.text();
}

export async function refreshAdvisories(env, fetchFn = fetch, now = Date.now()) {
  const kv = env.INTEL;
  const prev = (await kv.get('advisories', 'json')) || {};
  const cutoff = new Date(now - 120 * 86400000).toISOString();

  const node = async () => {
    const items = feeds.parseNodeRss(await getText(fetchFn, 'https://nodejs.org/en/feed/vulnerability.xml', 'application/rss+xml'))
      .filter(i => i.date >= cutoff).slice(0, 3);
    const posts = await Promise.all(items.map(async i => ({ i, p: feeds.parseNodePost(await getText(fetchFn, i.link), i) })));
    return {
      items: posts.flatMap(({ i, p }) => p.cves.map(c => ({ ...c, date: i.date, link: i.link }))),
      upcoming: posts.map(x => x.p.upcoming).filter(u => u && u.releaseDate >= new Date(now - 86400000).toISOString().slice(0, 10)),
    };
  };
  const openssh = async () => ({
    items: feeds.parseOpensshSecurity(await getText(fetchFn, 'https://www.openssh.com/security.html')).slice(0, 10),
  });
  const php = async () => {
    const json = JSON.parse(await getText(fetchFn, 'https://api.github.com/repos/php/php-src/security-advisories?per_page=30&sort=published&direction=desc', 'application/vnd.github+json'));
    return { items: feeds.parsePhpAdvisories(json) };
  };

  const out = { updated: new Date(now).toISOString() };
  const jobs = { node, openssh, php };
  const results = await Promise.allSettled(Object.values(jobs).map(f => f()));
  Object.keys(jobs).forEach((name, i) => {
    const r = results[i];
    out[name] = r.status === 'fulfilled'
      ? { ok: true, fetched: out.updated, ...r.value }
      : { ...(prev[name] || { items: [] }), ok: false, error: String(r.reason?.message || r.reason) }; // keep last good data
  });
  await kv.put('advisories', JSON.stringify(out));
  return out;
}

// ── HTTP ────────────────────────────────────────────────────────
export function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  return ALLOWED_ORIGINS.includes(origin)
    ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'GET, OPTIONS', Vary: 'Origin' }
    : {};
}

export function reply(request, body, status = 200, maxAge = 300) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': `public, max-age=${maxAge}`, ...corsHeaders(request) },
  });
}

/** Concatenate day shards as text — no JSON.parse of the whole store. */
export async function recentJson(kv, days, now = Date.now()) {
  const keys = [];
  for (let d = 0; d < days; d++) keys.push(dayKey(new Date(now - d * 86400000).toISOString()));
  const shards = await Promise.all(keys.map(k => kv.get(k, 'text')));
  const body = shards.filter(Boolean).map(s => s.trim().replace(/^\[|\]$/g, '').trim()).filter(Boolean).join(',');
  const state = (await kv.get('state', 'json')) || {};
  return `{"generated":${JSON.stringify(new Date(now).toISOString())},"lastRun":${JSON.stringify(state.lastRun || '')},"days":${days},"cves":[${body}]}`;
}

