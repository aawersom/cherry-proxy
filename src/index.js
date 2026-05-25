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

// Constant-time string comparison via HMAC to prevent timing attacks on the proxy key.
async function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const da = new Uint8Array(sigA), db = new Uint8Array(sigB);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i] ^ db[i];
  return diff === 0;
}

// SSRF guard: block requests to private/loopback/link-local IP ranges.
function isPrivateHostname(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  const parts = h.split('.');
  if (parts.length === 4) {
    const nums = parts.map(Number);
    if (nums.some(isNaN)) return false;
    const [a, b] = nums;
    if (a === 0 || a === 127 || a === 240) return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

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
    const customReferer = url.searchParams.get('referer');

    if (!targetUrl) {
      return corsResponse('Missing ?url= parameter', 400);
    }

    const secret = env.PROXY_KEY;
    if (!secret) {
      return corsResponse('Proxy not configured', 500);
    }
    if (!await timingSafeEqual(url.searchParams.get('key') || '', secret)) {
      return corsResponse('Forbidden', 403);
    }

    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedTarget.protocol)) throw new Error();
    } catch {
      return corsResponse('Invalid target URL', 400);
    }

    if (isPrivateHostname(parsedTarget.hostname)) {
      return corsResponse('Target not allowed', 403);
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
          // customReferer overrides default — used for CDN requests needing a different origin (e.g. phncdn.com needs pornhub.com)
          'Referer': customReferer || (parsedTarget.origin + '/'),
          ...(upstreamContentType ? { 'Content-Type': upstreamContentType } : {}),
          ...(isPost ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
          // Forward Range header so upstream can return 206 Partial Content (required for video seeking)
          ...(request.headers.get('Range') ? { 'Range': request.headers.get('Range') } : {}),
        },
        redirect: 'follow',
      });
    } catch (err) {
      if (err.name === 'AbortError') return corsResponse('Upstream timeout', 504);
      return corsResponse('Upstream error', 502);
    } finally {
      clearTimeout(timer);
    }

    // Build response headers: pass through Content-Type + range headers + add CORS
    const responseHeaders = new Headers();
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    responseHeaders.set('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges');

    const contentType = upstream.headers.get('Content-Type') || '';
    if (contentType) responseHeaders.set('Content-Type', contentType);

    const contentLength = upstream.headers.get('Content-Length');
    if (contentLength) responseHeaders.set('Content-Length', contentLength);

    // Range support: pass through Accept-Ranges and Content-Range so video players can seek
    const acceptRanges = upstream.headers.get('Accept-Ranges');
    if (acceptRanges) responseHeaders.set('Accept-Ranges', acceptRanges);

    const contentRange = upstream.headers.get('Content-Range');
    if (contentRange) responseHeaders.set('Content-Range', contentRange);

    // M3U8 rewriting: when the upstream returns an HLS playlist, relative segment/playlist
    // URLs inside it must be rewritten to absolute proxied URLs. Without this, HLS players
    // resolve relative URLs against the proxy origin and get 400/404.
    const isM3u8 = contentType.includes('mpegurl') || contentType.includes('x-mpegurl') ||
      parsedTarget.pathname.toLowerCase().endsWith('.m3u8');

    if (isM3u8) {
      const text = await upstream.text();
      const proxyOrigin = new URL(request.url).origin;
      const rewritten = rewriteM3u8(text, parsedTarget.toString(), proxyOrigin, env.PROXY_KEY);
      responseHeaders.set('Content-Type', 'application/vnd.apple.mpegurl');
      responseHeaders.delete('Content-Length'); // length changes after rewriting
      return new Response(rewritten, { status: upstream.status, headers: responseHeaders });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  },
};

// Rewrite an M3U8 playlist so that all segment/variant URLs go through the proxy.
// Handles:
//   - Non-comment lines (segment .ts / variant .m3u8 URLs, relative or absolute)
//   - URI="..." attributes inside #EXT-X-MAP, #EXT-X-KEY, #EXT-X-MEDIA tags
function rewriteM3u8(text, baseUrl, proxyOrigin, key) {
  const base = new URL(baseUrl);
  function proxify(rawUrl) {
    let abs;
    try { abs = new URL(rawUrl, base).toString(); } catch { return rawUrl; }
    if (abs.startsWith(proxyOrigin)) return rawUrl; // already proxied
    return proxyOrigin + '/proxy?url=' + encodeURIComponent(abs) + '&key=' + encodeURIComponent(key);
  }
  return text.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    // Rewrite URI="..." attributes in tag lines
    if (trimmed.startsWith('#')) {
      return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + proxify(u) + '"');
    }
    // Rewrite segment / variant playlist lines
    return proxify(trimmed);
  }).join('\n');
}

function corsResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Content-Type': 'text/plain',
    },
  });
}

// Named exports for unit testing only — Cloudflare Workers ignores these.
export { timingSafeEqual, isPrivateHostname };
