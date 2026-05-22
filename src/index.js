/**
 * Cherry Proxy — Cloudflare Worker
 *
 * GET /proxy?url=https://target-site.com/path
 * GET /proxy?url=https://target-site.com/path&key=YOUR_SECRET
 *
 * Returns the upstream response body with CORS headers injected.
 * Does NOT modify the response body — pure relay.
 */

const TIMEOUT_MS = 15000;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return corsResponse('', 204);
    }

    const isPost = request.method === 'POST';
    if (request.method !== 'GET' && !isPost) {
      return corsResponse('Method not allowed', 405);
    }

    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');

    if (!targetUrl) {
      return corsResponse('Missing ?url= parameter', 400);
    }

    const secret = env.PROXY_KEY;
    if (secret) {
      if (url.searchParams.get('key') !== secret) {
        return corsResponse('Forbidden', 403);
      }
    }

    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedTarget.protocol)) throw new Error();
    } catch {
      return corsResponse('Invalid target URL', 400);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    // Pass body and Content-Type for POST requests (SpankBang stream API etc.)
    const upstreamBody = isPost ? await request.text() : undefined;
    const upstreamContentType = isPost ? (request.headers.get('X-Body-Content-Type') || 'application/x-www-form-urlencoded') : undefined;

    let upstream;
    try {
      upstream = await fetch(parsedTarget.toString(), {
        method: isPost ? 'POST' : 'GET',
        signal: controller.signal,
        body: upstreamBody,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8',
          // Use target origin as Referer — required by VePorn, Spankbang, NoodleMagazine
          'Referer': parsedTarget.origin + '/',
          ...(upstreamContentType ? { 'Content-Type': upstreamContentType } : {}),
          ...(isPost ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
        },
        redirect: 'follow',
      });
    } catch (err) {
      if (err.name === 'AbortError') return corsResponse('Upstream timeout', 504);
      return corsResponse('Upstream fetch failed: ' + err.message, 502);
    } finally {
      clearTimeout(timer);
    }

    // Build response headers: pass through Content-Type + add CORS
    const responseHeaders = new Headers();
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    responseHeaders.set('Access-Control-Expose-Headers', 'Content-Type, Content-Length');

    const contentType = upstream.headers.get('Content-Type');
    if (contentType) responseHeaders.set('Content-Type', contentType);

    const contentLength = upstream.headers.get('Content-Length');
    if (contentLength) responseHeaders.set('Content-Length', contentLength);

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  },
};

function corsResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Content-Type': 'text/plain',
    },
  });
}
