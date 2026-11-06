/**
 * THREATWATCH — CORS Proxy Worker
 * Deployed as a Cloudflare Worker to proxy external APIs blocked by CORS.
 *
 * Usage: https://cors-proxy.<your-account>.workers.dev/?url=<encoded-api-url>
 */

// Allowed origin(s) — update this to your Cloudflare Pages domain
const ALLOWED_ORIGINS = [
  'https://threatwatch-7du.pages.dev',
  'https://threatwatch.pages.dev',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Upstream API hosts the proxy may fetch. A host matches when it equals an
// entry or is a subdomain of it ("usn.ubuntu.com" matches "ubuntu.com"), so a
// look-alike such as "evilubuntu.com" does not match "ubuntu.com".
export const ALLOWED_HOSTS = [
  'access.redhat.com',
  'security.paloaltonetworks.com',
  'tools.cisco.com',
  'sec.cloudapps.cisco.com',
  'api.cisco.com',
  'www.fortiguard.com',
  'api.github.com',
  'services.nvd.nist.gov',
  'www.cisa.gov',
  'ubuntu.com',
  'api.msrc.microsoft.com',
  'api.osv.dev',
  'api.first.org',
];

export function isAllowedHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  return ALLOWED_HOSTS.some(a => h === a || h.endsWith('.' + a));
}

function jsonError(message, status, allowedOrigin) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': allowedOrigin, ...CORS_HEADERS },
  });
}

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
      return jsonError('Missing ?url= parameter', 400, allowedOrigin);
    }

    // Only proxy to known API hosts, over HTTPS.
    let target;
    try {
      target = new URL(targetUrl);
    } catch {
      return jsonError('Invalid url parameter', 400, allowedOrigin);
    }
    if (target.protocol !== 'https:' || !isAllowedHost(target.hostname)) {
      return jsonError('Domain not allowed', 403, allowedOrigin);
    }

    try {
      const isPost = request.method === 'POST';
      const fetchInit = {
        method: isPost ? 'POST' : 'GET',
        headers: {
          'User-Agent': 'THREATWATCH-Proxy/1.0',
          'Accept': 'application/json',
          ...(isPost ? { 'Content-Type': request.headers.get('Content-Type') || 'application/json' } : {}),
        },
        ...(isPost ? { body: await request.arrayBuffer() } : {}),
      };
      const resp = await fetch(target.href, fetchInit);

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
      return jsonError(e.message, 502, allowedOrigin);
    }
  },
};
