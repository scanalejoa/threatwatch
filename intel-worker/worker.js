/**
 * THREATWATCH — Intel Worker (early warning). Entry point only: the
 * Workers runtime accepts nothing but handlers as module exports, so the
 * logic lives in lib.js.
 *
 * Cron:  every 15 min → ingestCveOrg (new CVEs from CVE.org, with CNA CVSS + CISA SSVC)
 *        :07 hourly → refreshAdvisories (Node.js, OpenSSH, PHP upstream advisories)
 * HTTP:  GET /v1/recent?days=7 · /v1/advisories · /v1/health
 */
import { ALLOWED_ORIGINS, KEEP_DAYS, ingestCveOrg, refreshAdvisories, recentJson, corsHeaders, reply } from './lib.js';

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(request) });
    const origin = request.headers.get('Origin');
    if (origin && !ALLOWED_ORIGINS.includes(origin)) return reply(request, '{"error":"origin not allowed"}', 403, 0);
    if (request.method !== 'GET') return reply(request, '{"error":"method not allowed"}', 405, 0);

    const url = new URL(request.url);
    if (url.pathname === '/v1/recent') {
      const days = Math.min(KEEP_DAYS, Math.max(1, parseInt(url.searchParams.get('days'), 10) || 7));
      return reply(request, await recentJson(env.INTEL, days));
    }
    if (url.pathname === '/v1/advisories') {
      let body = await env.INTEL.get('advisories', 'text');
      if (!body) { // fresh deploy: fill once instead of waiting for the hourly cron (6 subrequests)
        try { body = JSON.stringify(await refreshAdvisories(env)); } catch { body = '{"updated":""}'; }
      }
      return reply(request, body);
    }
    if (url.pathname === '/v1/health') {
      const s = (await env.INTEL.get('state', 'json')) || {};
      return reply(request, JSON.stringify({ cursor: s.cursor || '', lastRun: s.lastRun || '', lastError: s.lastError || '', gap: !!s.gap, pending: (s.pending || []).length, stats: s.stats || {} }), 200, 30);
    }
    return reply(request, '{"error":"not found","endpoints":["/v1/recent?days=7","/v1/advisories","/v1/health"]}', 404, 0);
  },

  async scheduled(event, env, ctx) {
    const job = event.cron === '7 * * * *' ? refreshAdvisories : ingestCveOrg;
    ctx.waitUntil(job(env).catch(async e => {
      const s = (await env.INTEL.get('state', 'json')) || {};
      await env.INTEL.put('state', JSON.stringify({ ...s, lastError: `${new Date().toISOString()} ${job.name}: ${e.message}` }));
    }));
  },
};
