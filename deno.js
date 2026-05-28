/**
 * Cherry Proxy — Deno Deploy edition
 * Same interface as the Cloudflare Worker version.
 *
 * GET /proxy?url=https://target-site.com/path&key=SECRET
 * POST /proxy?url=https://target-site.com/path&key=SECRET  (body = form data)
 */

const TIMEOUT_MS = 15000;

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

function rewriteM3u8(text, baseUrl, proxyOrigin, key) {
  const base = new URL(baseUrl);
  function proxify(rawUrl) {
    let abs;
    try { abs = new URL(rawUrl, base).toString(); } catch { return rawUrl; }
    if (abs.startsWith(proxyOrigin)) return rawUrl;
    return proxyOrigin + '/proxy?url=' + encodeURIComponent(abs) + '&key=' + encodeURIComponent(key);
  }
  return text.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    if (trimmed.startsWith('#')) {
      return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + proxify(u) + '"');
    }
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

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return corsResponse('', 204);

  const isPost = request.method === 'POST';
  if (request.method !== 'GET' && !isPost) return corsResponse('Method not allowed', 405);

  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  const customReferer = url.searchParams.get('referer');

  if (!targetUrl) return corsResponse('Missing ?url= parameter', 400);

  const secret = Deno.env.get('PROXY_KEY') || '';
  if (!secret) return corsResponse('Proxy not configured', 500);
  if (!await timingSafeEqual(url.searchParams.get('key') || '', secret)) return corsResponse('Forbidden', 403);

  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsedTarget.protocol)) throw new Error();
  } catch {
    return corsResponse('Invalid target URL', 400);
  }

  if (isPrivateHostname(parsedTarget.hostname)) return corsResponse('Target not allowed', 403);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const upstreamBody = isPost ? await request.text() : undefined;
  const upstreamContentType = isPost
    ? (request.headers.get('X-Body-Content-Type') || 'application/x-www-form-urlencoded')
    : undefined;

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
        'Referer': customReferer || (parsedTarget.origin + '/'),
        ...(upstreamContentType ? { 'Content-Type': upstreamContentType } : {}),
        ...(isPost ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
        ...(request.headers.get('Range') ? { 'Range': request.headers.get('Range') } : {}),
      },
      redirect: 'follow',
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') return corsResponse('Upstream timeout', 504);
    return corsResponse('Upstream error', 502);
  }
  clearTimeout(timer);

  const responseHeaders = new Headers();
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  responseHeaders.set('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges');

  const contentType = upstream.headers.get('Content-Type') || '';
  if (contentType) responseHeaders.set('Content-Type', contentType);

  const contentLength = upstream.headers.get('Content-Length');
  if (contentLength) responseHeaders.set('Content-Length', contentLength);

  const acceptRanges = upstream.headers.get('Accept-Ranges');
  if (acceptRanges) responseHeaders.set('Accept-Ranges', acceptRanges);

  const contentRange = upstream.headers.get('Content-Range');
  if (contentRange) responseHeaders.set('Content-Range', contentRange);

  const isM3u8 = contentType.includes('mpegurl') || contentType.includes('x-mpegurl') ||
    parsedTarget.pathname.toLowerCase().endsWith('.m3u8');

  if (isM3u8) {
    const text = await upstream.text();
    const proxyOrigin = new URL(request.url).origin;
    const key = Deno.env.get('PROXY_KEY') || '';
    const rewritten = rewriteM3u8(text, parsedTarget.toString(), proxyOrigin, key);
    responseHeaders.set('Content-Type', 'application/vnd.apple.mpegurl');
    responseHeaders.delete('Content-Length');
    return new Response(rewritten, { status: upstream.status, headers: responseHeaders });
  }

  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
});
