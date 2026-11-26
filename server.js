'use strict';
/**
 * Fixed-IP forwarding proxy for the AG game API.
 *   Our Supabase function  ->  https://<this-host>/<PROXY_TOKEN>/game/v5/...  ->  TARGET_URL/game/v5/...
 * The request (method, headers, raw body) is passed through untouched, so the AG signature stays valid,
 * and the response body is returned byte-for-byte so response signatures stay valid too.
 * Only requests whose first path segment equals PROXY_TOKEN are forwarded (not an open relay).
 * No dependencies. Node 18+.
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const TOKEN = process.env.PROXY_TOKEN || '';
const TARGET = (process.env.TARGET_URL || '').replace(/\/+$/, '');
const TIMEOUT_MS = 20000;
const MAX_BODY = 1024 * 1024;
if (!TOKEN || TOKEN.length < 16 || !TARGET.startsWith('https://')) {
  console.error('Set PROXY_TOKEN (16+ chars) and TARGET_URL (https://...)'); process.exit(1);
}
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const HOP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade', 'proxy-connection', 'te', 'trailer', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'x-request-id', 'accept-encoding']);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/' || url.pathname === '/healthz') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ok'); }
  const m = url.pathname.match(/^\/([^/]+)(\/.*)$/);
  if (!m || !same(m[1], TOKEN)) { res.writeHead(404); return res.end('not found'); }
  const chunks = []; let size = 0; let dead = false;
  req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { dead = true; res.writeHead(413); res.end('too large'); req.destroy(); } else chunks.push(c); });
  req.on('end', async () => {
    if (dead) return;
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k.toLowerCase())) headers[k] = v;
    const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    try {
      const up = await fetch(TARGET + m[2] + url.search, {
        method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks), signal: ctl.signal, redirect: 'manual',
      });
      const buf = Buffer.from(await up.arrayBuffer());
      const out = {};
      up.headers.forEach((v, k) => { if (!['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)) out[k] = v; });
      out['content-length'] = buf.length;
      res.writeHead(up.status, out); res.end(buf);
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ code: 'C10001', msg: 'proxy: ' + (e.name === 'AbortError' ? 'upstream timeout' : e.message) }));
    } finally { clearTimeout(timer); }
  });
});
server.keepAliveTimeout = 65000;
server.listen(PORT, () => console.log('proxy listening on', PORT, '->', TARGET));
