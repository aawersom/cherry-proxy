/**
 * Cherry Proxy — Cloudflare Worker with rotating residential SOCKS5 proxies
 *
 * GET /proxy?url=https://target-site.com/path&key=SECRET[&referer=...]
 *
 * For domains that block Cloudflare datacenter IPs (pornhub, pornone),
 * outbound requests tunnel through a rotating pool of Dutch residential SOCKS5 proxies.
 * Domain-hash affinity ensures page fetch and CDN stream use the same exit IP (KVS IP-bound tokens).
 *
 * All other domains: direct CF Worker fetch (unchanged behaviour).
 */

import { connect } from 'cloudflare:sockets';

const TIMEOUT_MS = 20000;

// ---- Rotating Dutch residential proxies ----------------------------------------
const PROXIES = [
  { host: '45.91.209.155', port: 11750, user: 'hgTr0m', pass: '6H3nY1' },
  { host: '45.91.209.155', port: 11751, user: 'hgTr0m', pass: '6H3nY1' },
  { host: '45.91.209.155', port: 11752, user: 'hgTr0m', pass: '6H3nY1' },
  { host: '45.91.209.155', port: 11753, user: 'hgTr0m', pass: '6H3nY1' },
  { host: '45.91.209.155', port: 11756, user: 'hgTr0m', pass: '6H3nY1' },
];

// Domains that need residential IP (blocked by CF datacenter IPs)
const RESIDENTIAL = new Set([
  'www.pornhub.com', 'rt.pornhub.com',
  // pornone: moved back to Deno (PROXY_URL_2) — Deno fixed IP for page+CDN token affinity
  // spankbang: reverted to Deno — SOCKS5 Dutch residential also blocked; browse needs Deno
]);

// ---- SOCKS5 helper: buffered byte reader from a ReadableStream -----------------
class ByteReader {
  constructor(readable) {
    this._reader = readable.getReader();
    this._buf    = new Uint8Array(0);
  }
  async read(n) {
    while (this._buf.length < n) {
      const { value, done } = await this._reader.read();
      if (done) throw new Error('Socket closed');
      const tmp = new Uint8Array(this._buf.length + value.length);
      tmp.set(this._buf);
      tmp.set(value, this._buf.length);
      this._buf = tmp;
    }
    const out   = this._buf.slice(0, n);
    this._buf   = this._buf.slice(n);
    return out;
  }
  release() { this._reader.releaseLock(); }
}

// ---- SOCKS5 fetch through one proxy -------------------------------------------
async function socks5Fetch(targetUrl, referer, proxy) {
  const enc     = new TextEncoder();
  const dec     = new TextDecoder();
  const parsed  = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const tgtPort = parseInt(parsed.port) || (isHttps ? 443 : 80);
  const tgtHost = parsed.hostname;

  const sock = connect({ hostname: proxy.host, port: proxy.port }, { allowHalfOpen: true });

  try {
    const br     = new ByteReader(sock.readable);
    const writer = sock.writable.getWriter();

    // Step 1: greeting — request username/password auth (method 0x02)
    await writer.write(new Uint8Array([0x05, 0x01, 0x02]));
    const greet = await br.read(2);
    if (greet[0] !== 0x05 || greet[1] !== 0x02) throw new Error('SOCKS5 method not accepted: ' + greet[1]);

    // Step 2: auth
    const userB = enc.encode(proxy.user);
    const passB = enc.encode(proxy.pass);
    const auth  = new Uint8Array([0x01, userB.length, ...userB, passB.length, ...passB]);
    await writer.write(auth);
    const authR = await br.read(2);
    if (authR[1] !== 0x00) throw new Error('SOCKS5 auth failed');

    // Step 3: CONNECT
    const hostB  = enc.encode(tgtHost);
    const conn   = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostB.length, ...hostB, tgtPort >> 8, tgtPort & 0xff]);
    await writer.write(conn);
    const connR  = await br.read(4); // VER REP RSV ATYP
    if (connR[1] !== 0x00) throw new Error('SOCKS5 CONNECT failed: ' + connR[1]);
    // skip bound address
    if      (connR[3] === 0x01) await br.read(4 + 2);       // IPv4 + port
    else if (connR[3] === 0x03) { const l = (await br.read(1))[0]; await br.read(l + 2); } // domain + port
    else if (connR[3] === 0x04) await br.read(16 + 2);      // IPv6 + port

    // Release streams before startTls
    br.release();
    writer.releaseLock();

    // Step 4: TLS upgrade for HTTPS
    const dataSock = isHttps ? sock.startTls({ expectedServerHostname: tgtHost }) : sock;

    // Step 5: HTTP/1.1 request through the tunnel
    const dw = dataSock.writable.getWriter();
    const db = new ByteReader(dataSock.readable);

    const reqPath = parsed.pathname + parsed.search;
    const req =
      'GET ' + reqPath + ' HTTP/1.1\r\n' +
      'Host: ' + tgtHost + '\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n' +
      'Accept: */*\r\n' +
      'Accept-Language: ru,en;q=0.9\r\n' +
      (referer ? 'Referer: ' + referer + '\r\n' : '') +
      'Connection: close\r\n\r\n';
    await dw.write(enc.encode(req));
    await dw.close();

    // Step 6: read full raw HTTP response
    const chunks = [];
    while (true) {
      let chunk;
      try { chunk = await db._reader.read(); } catch (_) { break; }
      if (chunk.done) break;
      chunks.push(chunk.value);
    }
    db.release();

    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const raw      = new Uint8Array(totalLen);
    let off = 0;
    for (const c of chunks) { raw.set(c, off); off += c.length; }

    // Parse response
    const rawStr   = dec.decode(raw);
    const hdrEnd   = rawStr.indexOf('\r\n\r\n');
    if (hdrEnd === -1) throw new Error('No HTTP header boundary');

    const hdrStr   = rawStr.slice(0, hdrEnd);
    const bodyRaw  = raw.slice(hdrEnd + 4);
    const lines    = hdrStr.split('\r\n');
    const status   = parseInt((lines[0].match(/HTTP\/\S+ (\d+)/) || [])[1] || '0');
    if (!status) throw new Error('Bad HTTP status line: ' + lines[0]);

    const headers  = {};
    for (let i = 1; i < lines.length; i++) {
      const col = lines[i].indexOf(':');
      if (col > 0) headers[lines[i].slice(0, col).trim().toLowerCase()] = lines[i].slice(col + 1).trim();
    }

    const ct   = headers['content-type'] || 'application/octet-stream';
    const body = headers['transfer-encoding'] === 'chunked' ? unchunk(bodyRaw) : bodyRaw;

    return new Response(body, {
      status,
      headers: {
        'Content-Type': ct,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Expose-Headers': 'Content-Type, Content-Length',
      },
    });

  } catch (e) {
    try { sock.close(); } catch (_) {}
    throw e;
  }
}

// ---- DJB2 hash: deterministic proxy selection by domain (no shared state) ------
// Guarantees that all requests for the same origin use the same SOCKS5 exit IP,
// keeping KVS IP-bound tokens (pornone, phncdn ipa=1) valid across page+CDN fetches.
// NOTE: segment URLs in rewriteM3u8 do not carry &referer= — safe for phncdn because
// segment auth uses signed query params (validfrom/hash), not Referer header.
// If future RESIDENTIAL CDNs validate Referer on segments, propagate referer in rewriteM3u8.
function djb2Domain(referer, targetUrl) {
  let domain;
  try { domain = referer ? new URL(referer).hostname : new URL(targetUrl).hostname; }
  catch (_) { try { domain = new URL(targetUrl).hostname; } catch (__) { domain = ''; } }
  let h = 5381;
  for (let i = 0; i < domain.length; i++) h = ((h << 5) + h) ^ domain.charCodeAt(i);
  return Math.abs(h) % PROXIES.length;
}

// ---- Rotation: try all proxies starting from domain-hash index -----------------
async function fetchViaResidential(targetUrl, referer) {
  const startIdx = djb2Domain(referer, targetUrl);
  const h = new URL(targetUrl).hostname;
  const retryOn403 = /\.pornone\.com$/.test(h) || h === 'pornone.com' || h === 'www.pornone.com';
  // phncdn CDN: tokens are IP-bound — no fallback to preserve IP affinity.
  // www.pornhub.com browse/API: no IP-bound token, fallback is safe.
  // pornone: fallback on 403 is intentional (CDN IP ban, not token mismatch).
  const noFallback = /\.phncdn\.com$/.test(h);
  const maxTries = noFallback ? 1 : PROXIES.length;
  let lastError;
  for (let i = 0; i < maxTries; i++) {
    const proxy = PROXIES[(startIdx + i) % PROXIES.length];
    try {
      const resp = await socks5Fetch(targetUrl, referer, proxy);
      if (retryOn403 && resp.status === 403) {
        lastError = new Error('Upstream 403 on port ' + proxy.port + ' (CDN IP block)');
        console.warn('cherry-proxy: pornone port ' + proxy.port + ' returned 403, trying next');
        continue;
      }
      return resp;
    } catch (e) {
      lastError = e;
      console.warn('cherry-proxy: SOCKS5 port ' + proxy.port + ' failed:', e.message);
    }
  }
  throw lastError || new Error('All proxies failed');
}

// ---- Timing-safe key comparison -----------------------------------------------
async function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const [sa, sb] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const da = new Uint8Array(sa), db = new Uint8Array(sb);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i] ^ db[i];
  return diff === 0;
}

// ---- SSRF guard ---------------------------------------------------------------
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

// ---- Chunked transfer-encoding decoder ----------------------------------------
function unchunk(buf) {
  const dec = new TextDecoder();
  const out = [];
  let pos = 0;
  while (pos < buf.length) {
    let end = pos;
    while (end < buf.length - 1 && !(buf[end] === 0x0d && buf[end + 1] === 0x0a)) end++;
    const size = parseInt(dec.decode(buf.slice(pos, end)), 16);
    if (isNaN(size) || size === 0) break;
    out.push(buf.slice(end + 2, end + 2 + size));
    pos = end + 2 + size + 2;
  }
  const total = out.reduce((s, c) => s + c.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const c of out) { result.set(c, off); off += c.length; }
  return result;
}

// ---- M3U8 rewriting -----------------------------------------------------------
// referer is propagated to segment proxy URLs so DJB2 domain-hash selects the SAME
// SOCKS5 port (and thus same exit IP) for M3U8 and all segment fetches.
// Without this, M3U8 uses port DJB2(www.pornhub.com) but segments use DJB2(ev-h.phncdn.com)
// → different residential exit IPs → IP-bound token (ipa=1) fails → 404 on segments.
function rewriteM3u8(text, baseUrl, proxyOrigin, key, referer) {
  const base = new URL(baseUrl);
  function proxify(rawUrl) {
    let abs;
    try { abs = new URL(rawUrl, base).toString(); } catch { return rawUrl; }
    if (abs.startsWith(proxyOrigin)) return rawUrl;
    let p = proxyOrigin + '/proxy?url=' + encodeURIComponent(abs) + '&key=' + encodeURIComponent(key);
    if (referer) p += '&referer=' + encodeURIComponent(referer);
    return p;
  }
  return text.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    if (trimmed.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, u) => 'URI="' + proxify(u) + '"');
    return proxify(trimmed);
  }).join('\n');
}

function corsResponse(body, status) {
  return new Response(body, {
    status,
    headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Content-Type': 'text/plain' },
  });
}

// ---- Main handler -------------------------------------------------------------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return corsResponse('', 204);

    const isPost = request.method === 'POST';
    if (request.method !== 'GET' && !isPost) return corsResponse('Method not allowed', 405);

    const url       = new URL(request.url);
    const targetUrl = url.searchParams.get('url');
    const referer   = url.searchParams.get('referer') || '';

    if (!targetUrl) return corsResponse('Missing ?url=', 400);

    const secret = env.PROXY_KEY;
    if (!secret) return corsResponse('Proxy not configured', 500);
    if (!await timingSafeEqual(url.searchParams.get('key') || '', secret)) return corsResponse('Forbidden', 403);

    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedTarget.protocol)) throw new Error();
    } catch { return corsResponse('Invalid target URL', 400); }

    if (isPrivateHostname(parsedTarget.hostname)) return corsResponse('Target not allowed', 403);

    // ---- Route residential-blocked domains via SOCKS5 -------------------------
    // phncdn: all subdomains share same IP-bound token — must use SOCKS5 residential
    const needsResidential = RESIDENTIAL.has(parsedTarget.hostname)
      || /\.phncdn\.com$/.test(parsedTarget.hostname);
    if (!isPost && needsResidential) {
      try {
        return await fetchViaResidential(targetUrl, referer);
      } catch (e) {
        console.error('cherry-proxy: residential fetch failed, fallback to direct:', e.message);
        // fall through to direct fetch as last resort
      }
    }

    // ---- Direct CF Worker fetch (all other domains) ---------------------------
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const upstreamBody        = isPost ? await request.text() : undefined;
    const upstreamContentType = isPost ? (request.headers.get('X-Body-Content-Type') || 'application/x-www-form-urlencoded') : undefined;

    let upstream;
    try {
      upstream = await fetch(parsedTarget.toString(), {
        method:  isPost ? 'POST' : 'GET',
        signal:  controller.signal,
        body:    upstreamBody,
        headers: {
          'User-Agent':     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept':         'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8',
          'Referer':        referer || (parsedTarget.origin + '/'),
          ...(upstreamContentType ? { 'Content-Type': upstreamContentType } : {}),
          ...(isPost ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
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
      const rewritten   = rewriteM3u8(text, parsedTarget.toString(), proxyOrigin, env.PROXY_KEY, referer);
      responseHeaders.set('Content-Type', 'application/vnd.apple.mpegurl');
      responseHeaders.delete('Content-Length');
      return new Response(rewritten, { status: upstream.status, headers: responseHeaders });
    }

    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  },
};

export { timingSafeEqual, isPrivateHostname };
