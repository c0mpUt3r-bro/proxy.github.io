import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { URL } from 'node:url';
import crypto from 'node:crypto';

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '127.0.0.1';

// Security: Auth required by default; set AUTH_REQUIRED=false to disable
const AUTH_REQUIRED = String(process.env.AUTH_REQUIRED ?? 'true').toLowerCase() !== 'false';
let AUTH_USER = process.env.PROXY_USERNAME || '';
let AUTH_PASS = process.env.PROXY_PASSWORD || '';

// Optional IP allowlist (comma-separated). If set, only these IPs may access.
// Examples: "127.0.0.1,::1,192.168.1.10"
const ALLOW_IPS = (process.env.ALLOW_IPS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

function isLoopback(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip?.startsWith('::ffff:127.0.0.1');
}

function getClientIp(socket) {
  // If running behind a reverse proxy, consider honoring X-Forwarded-For (not default here)
  let ip = socket.remoteAddress || '';
  // Normalize IPv4-mapped IPv6 addresses ::ffff:a.b.c.d
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function ipAllowed(socket) {
  if (!ALLOW_IPS.length) return true; // not configured
  const ip = getClientIp(socket);
  if (ALLOW_IPS.includes(ip)) return true;
  if (ALLOW_IPS.includes('loopback') && isLoopback(ip)) return true;
  return false;
}

// If auth is required but no creds provided, generate ephemeral ones
if (AUTH_REQUIRED && (!AUTH_USER || !AUTH_PASS)) {
  AUTH_USER ||= 'user';
  // 16 bytes random hex
  AUTH_PASS = [...crypto.getRandomValues(new Uint8Array(16))]
    .map(b => b.toString(16).padStart(2, '0')).join('');
  console.log('Generated proxy credentials (ephemeral):');
  console.log(`  Username: ${AUTH_USER}`);
  console.log(`  Password: ${AUTH_PASS}`);
  console.log('Set PROXY_USERNAME/PROXY_PASSWORD to define your own.');
}

function parseProxyAuth(headerValue = '') {
  // Expecting: "Basic base64(user:pass)"
  const [scheme, token] = headerValue.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'basic' || !token) return null;
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}

function authOk(req) {
  if (AUTH_REQUIRED === false) return true;
  const creds = parseProxyAuth(req.headers['proxy-authorization']);
  return creds && creds.user === AUTH_USER && creds.pass === AUTH_PASS;
}

function denyAuth(res) {
  res.writeHead(407, {
    'Proxy-Authenticate': 'Basic realm="LocalProxy"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Proxy authentication required.');
}

function logRequest(prefix, req, extra = '') {
  const host = req.headers.host || '-';
  console.log(`${prefix} ${req.method} ${req.url} [host=${host}] ${extra}`);
}

function parseBasicAuth(headerValue = '') {
  const [scheme, token] = headerValue.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'basic' || !token) return null;
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}

function portalAuthOk(req) {
  if (AUTH_REQUIRED === false) return true;
  const creds = parseBasicAuth(req.headers['authorization']);
  return creds && creds.user === AUTH_USER && creds.pass === AUTH_PASS;
}

function portalDenyAuth(res) {
  res.writeHead(401, {
    'WWW-Authenticate': 'Basic realm="LocalPortal"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Authentication required.');
}

function htmlEscape(s) {
  return s.replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function renderPortal(res, opts = {}) {
  const { error = '' } = opts;
  const body = `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local Web Proxy Portal</title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
      header{margin-bottom:1rem}
      form{display:flex;gap:.5rem}
      input[type=url]{flex:1;padding:.6rem;border:1px solid #ccc;border-radius:6px}
      button{padding:.6rem 1rem;border:0;background:#0b5fff;color:#fff;border-radius:6px}
      .err{color:#b00020;margin:.5rem 0}
      footer{margin-top:2rem;color:#666;font-size:.9rem}
    </style>
  </head>
  <body>
    <header>
      <h1>Local Web Proxy Portal</h1>
      <p>For authorized testing on your own network. Do not use to bypass policies you are not permitted to test.</p>
    </header>
    ${error ? `<div class="err">${htmlEscape(error)}</div>` : ''}
    <form method="GET" action="/browse">
      <input type="url" name="url" placeholder="https://example.com" required />
      <button type="submit">Go</button>
    </form>
    <footer>
      <p>Notes: Basic HTML/CSS link rewriting only. Dynamic sites may not fully work. Credentials/cookies to remote sites are not persisted by this portal.</p>
    </footer>
  </body>
  </html>`;
  res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
  res.end(body);
}

function rewriteHtml(html, baseUrl) {
  // Rewrite href/src/action to route back via /browse
  const attrRe = /(href|src|action)=("|')(.*?)(\2)/gi;
  const replaced = html.replace(attrRe, (m, attr, q, val) => {
    try {
      if (val.startsWith('data:') || val.startsWith('javascript:') || val.startsWith('#')) return m;
      const abs = new URL(val, baseUrl).toString();
      return `${attr}=${q}/browse?url=${encodeURIComponent(abs)}${q}`;
    } catch {
      return m;
    }
  });
  // Basic CSS url(...) rewriting inside inline styles
  const cssUrlRe = /url\((['"]?)([^)'"]+)\1\)/gi;
  return replaced.replace(cssUrlRe, (m, q, val) => {
    try {
      if (val.startsWith('data:')) return m;
      const abs = new URL(val, baseUrl).toString();
      return `url(${q}/browse?url=${encodeURIComponent(abs)}${q})`;
    } catch {
      return m;
    }
  });
}

async function handleBrowse(req, res, u) {
  const target = u.searchParams.get('url');
  if (!target) {
    renderPortal(res, { error: 'Missing url parameter' });
    return;
  }
  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch {
    renderPortal(res, { error: 'Invalid URL' });
    return;
  }
  if (!/^https?:$/.test(targetUrl.protocol)) {
    renderPortal(res, { error: 'Only http/https URLs allowed' });
    return;
  }
  try {
    const resp = await fetch(targetUrl, {
      redirect: 'manual',
      headers: {
        'User-Agent': req.headers['user-agent'] || 'LocalPortal/1.0',
        'Accept': req.headers['accept'] || '*/*'
      }
    });
    // Handle redirects by bouncing through portal
    if (resp.status >= 300 && resp.status < 400 && resp.headers.get('location')) {
      const loc = new URL(resp.headers.get('location'), targetUrl).toString();
      res.writeHead(302, { Location: `/browse?url=${encodeURIComponent(loc)}` });
      res.end();
      return;
    }
    const ctype = resp.headers.get('content-type') || 'application/octet-stream';
    if (ctype.includes('text/html')) {
      const text = await resp.text();
      const rewritten = rewriteHtml(text, targetUrl);
      res.writeHead(resp.status, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(rewritten);
    } else if (ctype.includes('text/css')) {
      const text = await resp.text();
      const cssUrlRe = /url\((['"]?)([^)'"]+)\1\)/gi;
      const rewritten = text.replace(cssUrlRe, (m, q, val) => {
        try {
          if (val.startsWith('data:')) return m;
          const abs = new URL(val, targetUrl).toString();
          return `url(${q}/browse?url=${encodeURIComponent(abs)}${q})`;
        } catch { return m; }
      });
      res.writeHead(resp.status, { 'Content-Type': 'text/css; charset=utf-8' });
      res.end(rewritten);
    } else {
      // Stream other content as-is
      res.writeHead(resp.status, { 'Content-Type': ctype });
      const reader = resp.body.getReader();
      const pump = () => reader.read().then(({ done, value }) => {
        if (done) { res.end(); return; }
        res.write(Buffer.from(value));
        return pump();
      }).catch(() => { try { res.end(); } catch {} });
      pump();
    }
  } catch (err) {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Fetch error: ' + err.message);
  }
}

const server = http.createServer(async (clientReq, clientRes) => {
  // Dispatch: portal vs proxy. Proxy uses absolute-form URLs, portal uses path-form.
  const rawUrl = clientReq.url || '/';
  const isAbsolute = /^https?:\/\//i.test(rawUrl);

  if (!isAbsolute) {
    if (!ipAllowed(clientReq.socket)) {
      clientRes.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      clientRes.end('Forbidden: IP not allowed');
      return;
    }
    // Portal routes
    if (!portalAuthOk(clientReq)) {
      portalDenyAuth(clientRes);
      return;
    }
    const u = new URL(rawUrl, `http://${clientReq.headers.host || 'localhost'}`);
    if (clientReq.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
      renderPortal(clientRes);
      return;
    }
    if (clientReq.method === 'GET' && u.pathname === '/browse') {
      await handleBrowse(clientReq, clientRes, u);
      return;
    }
    clientRes.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    clientRes.end('Not found');
    return;
  }

  // Proxy flow
  if (!ipAllowed(clientReq.socket)) {
    clientRes.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    clientRes.end('Forbidden: IP not allowed');
    return;
  }
  if (!authOk(clientReq)) {
    denyAuth(clientRes);
    return;
  }

  logRequest('HTTP', clientReq);

  // clientReq.url is absolute-form for proxies (e.g., http://host/path)
  let targetUrl;
  try {
    targetUrl = new URL(clientReq.url);
  } catch {
    clientRes.writeHead(400);
    clientRes.end('Bad request: expected absolute URL.');
    return;
  }

  const isHttps = targetUrl.protocol === 'https:';
  const mod = isHttps ? https : http;

  // Sanitize headers for proxying
  const headers = { ...clientReq.headers };
  delete headers['proxy-authorization'];
  delete headers['proxy-connection'];
  // Ensure host header matches the target host
  headers['host'] = targetUrl.host;

  const options = {
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    method: clientReq.method,
    path: targetUrl.pathname + targetUrl.search,
    headers,
    timeout: 30_000
  };

  const upstreamReq = mod.request(options, (upstreamRes) => {
    // Strip hop-by-hop headers
    const hopByHop = new Set([
      'transfer-encoding',
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'upgrade'
    ]);
    const resHeaders = Object.fromEntries(
      Object.entries(upstreamRes.headers).filter(([k]) => !hopByHop.has(k.toLowerCase()))
    );
    clientRes.writeHead(upstreamRes.statusCode || 502, resHeaders);
    upstreamRes.pipe(clientRes);
  });

  upstreamReq.on('timeout', () => {
    upstreamReq.destroy(new Error('Upstream timeout'));
  });

  upstreamReq.on('error', (err) => {
    clientRes.writeHead(502);
    clientRes.end('Bad gateway: ' + err.message);
  });

  clientReq.pipe(upstreamReq);
});

server.on('connect', (req, clientSocket, head) => {
  if (!ipAllowed(clientSocket)) {
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    clientSocket.destroy();
    return;
  }
  if (!authOk(req)) {
    const msg = 'HTTP/1.1 407 Proxy Authentication Required\r\n' +
      'Proxy-Authenticate: Basic realm="LocalProxy"\r\n' +
      'Connection: close\r\n' +
      '\r\n';
    clientSocket.write(msg);
    clientSocket.destroy();
    return;
  }

  // req.url for CONNECT is "host:port"
  const [host, portStr] = (req.url || '').split(':');
  const port = Number(portStr) || 443;
  if (!host) {
    clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    clientSocket.destroy();
    return;
  }

  console.log(`TUNNEL CONNECT ${host}:${port}`);

  const upstreamSocket = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // If there was buffered data (head), forward it
    if (head && head.length) upstreamSocket.write(head);
    // Bi-directional piping
    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
  });

  const onErr = (err, who) => {
    console.error(`Tunnel error (${who}):`, err.message);
    try { clientSocket.destroy(); } catch {}
    try { upstreamSocket.destroy(); } catch {}
  };

  upstreamSocket.on('error', (e) => onErr(e, 'upstream'));
  clientSocket.on('error', (e) => onErr(e, 'client'));
});

server.on('clientError', (err, socket) => {
  try {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  } catch {}
});

server.listen(PORT, HOST, () => {
  console.log(`Forward proxy listening on http://${HOST}:${PORT}`);
  console.log(`Auth required: ${AUTH_REQUIRED ? 'yes' : 'no'} (toggle with AUTH_REQUIRED)`);
  if (AUTH_REQUIRED) {
    console.log('Set credentials with PROXY_USERNAME/PROXY_PASSWORD.');
  }
  if (ALLOW_IPS.length) {
    console.log('Allowed IPs:', ALLOW_IPS.join(', '));
  } else {
    console.log('Allowed IPs: any (set ALLOW_IPS to restrict)');
  }
  console.log('Note: Intended for authorized, local use only.');
});
