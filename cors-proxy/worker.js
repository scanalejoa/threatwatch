/**
 * THREATWATCH — CORS Proxy Worker
 * Deployed as a Cloudflare Worker to proxy external APIs blocked by CORS.
 *
 * Usage: https://cors-proxy.<your-account>.workers.dev/?url=<encoded-api-url>
 */

// Allowed origin(s) — update this to your Cloudflare Pages domain
const ALLOWED_ORIGINS = [
  'https://threatwatch.pages.dev',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: { ...CORS_HEADERS, 'Access-Control-Allow-Origin': allowedOrigin },
      });
    }

    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');

    if (!targetUrl) {
      return new Response(JSON.stringify({ error: 'Missing ?url= parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': allowedOrigin },
      });
    }

    // Basic security: only allow known safe API domains
    const allowed = [
      'access.redhat.com',
      'security.paloaltonetworks.com',
      'tools.cisco.com',
      'api.github.com',
      'services.nvd.nist.gov',
      'www.cisa.gov',
    ];
    const targetHost = new URL(targetUrl).hostname;
    if (!allowed.some(h => targetHost.endsWith(h))) {
      return new Response(JSON.stringify({ error: 'Domain not allowed' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': allowedOrigin },
      });
    }

    try {
      const resp = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'THREATWATCH-Proxy/1.0',
          'Accept': 'application/json',
        },
      });

      const body = await resp.arrayBuffer();
      return new Response(body, {
        status: resp.status,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'application/json',
          'Access-Control-Allow-Origin': allowedOrigin,
          ...CORS_HEADERS,
        },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': allowedOrigin },
      });
    }
  },
};
