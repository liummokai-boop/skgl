import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';
import { LocalD1Database } from './d1-sqlite.js';
import { seedLocalAdmin } from './local-auth.js';

const LOCAL_JWT_SECRET = 'skgl-desktop-local-secret-20260606-please-change-only-in-code';
const LOCAL_DATA_ENCRYPTION_KEY = 'skgl-desktop-local-data-key-20260607-please-change-only-in-code';

function ensureWebGlobals() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  }
  if (!globalThis.btoa) {
    globalThis.btoa = value => Buffer.from(String(value), 'binary').toString('base64');
  }
  if (!globalThis.atob) {
    globalThis.atob = value => Buffer.from(String(value), 'base64').toString('binary');
  }
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.js') return 'application/javascript; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.png') return 'image/png';
  if (ext === '.icns') return 'image/icns';
  if (ext === '.json') return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

function desktopIndexHtml(sourceRoot) {
  const indexPath = path.join(sourceRoot, 'index.html');
  let html = fs.readFileSync(indexPath, 'utf8');
  html = html.replace("var API='https://skgl.pages.dev';", "var API=window.SKGL_API_BASE||location.origin;");
  html = html.replace('</head>', `
<script>
window.SKGL_DESKTOP=true;
window.SKGL_API_BASE=location.origin;
window.addEventListener('DOMContentLoaded',function(){
  var phone=document.getElementById('loginPhone'); if(phone&&!phone.value) phone.value='13399330020';
});
</script>
<style>
.desktop-login-tip{font-size:12px;color:#607587;margin-top:8px}
</style>
</head>`);
  html = html.replace('<button type="submit" class="btn btn-primary" id="loginSubmitBtn" onclick="doLogin();return false;">登 录</button>', '<button type="submit" class="btn btn-primary" id="loginSubmitBtn" onclick="doLogin();return false;">登 录</button><div class="desktop-login-tip">桌面版默认账号：13399330020 / 123456</div>');
  return html;
}

function safeStaticPath(sourceRoot, urlPath) {
  const pathname = decodeURIComponent(urlPath.split('?')[0]);
  const clean = pathname === '/' ? '/index.html' : pathname;
  const resolved = path.resolve(sourceRoot, clean.replace(/^\/+/, ''));
  if (!resolved.startsWith(path.resolve(sourceRoot))) return null;
  return resolved;
}

function splitSetCookie(value) {
  if (!value) return [];
  return String(value)
    .replace(/,\s*(skgl_csrf=)/g, '\n$1')
    .replace(/,\s*(skgl_token=)/g, '\n$1')
    .split('\n')
    .map(v => v.trim())
    .filter(Boolean);
}

function localizeCookie(cookie) {
  return cookie
    .replace(/;\s*Secure/gi, '')
    .replace(/SameSite=Strict/gi, 'SameSite=Lax');
}

function copyApiRuntime(sourceRoot, userDataDir) {
  const src = path.join(sourceRoot, 'functions');
  const runtimeRoot = path.join(userDataDir, 'runtime-api');
  const dst = path.join(runtimeRoot, 'functions');
  fs.rmSync(runtimeRoot, { recursive: true, force: true });
  fs.mkdirSync(runtimeRoot, { recursive: true });
  fs.cpSync(src, dst, { recursive: true });
  fs.writeFileSync(path.join(runtimeRoot, 'package.json'), '{"type":"module"}\n');
  return path.join(dst, 'api', '[[path]].js');
}

function collectBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function writeFunctionResponse(nodeRes, response) {
  nodeRes.statusCode = response.status || 200;
  for (const [key, value] of response.headers.entries()) {
    if (key.toLowerCase() === 'set-cookie') continue;
    nodeRes.setHeader(key, value);
  }
  const setCookie = response.headers.get('set-cookie');
  const cookies = splitSetCookie(setCookie).map(localizeCookie);
  if (cookies.length) nodeRes.setHeader('Set-Cookie', cookies);
  const buffer = Buffer.from(await response.arrayBuffer());
  nodeRes.end(buffer);
}

export async function startDesktopServer({ sourceRoot, userDataDir }) {
  ensureWebGlobals();
  fs.mkdirSync(userDataDir, { recursive: true });

  const dbPath = path.join(userDataDir, 'skgl-local.sqlite');
  const DB = new LocalD1Database(dbPath);
  await seedLocalAdmin(DB);

  const apiEntry = copyApiRuntime(sourceRoot, userDataDir);
  const apiModule = await import(`${pathToFileURL(apiEntry).href}?t=${Date.now()}`);

  const env = {
    DB,
    JWT_SECRET: LOCAL_JWT_SECRET,
    DATA_ENCRYPTION_KEY: process.env.DATA_ENCRYPTION_KEY || LOCAL_DATA_ENCRYPTION_KEY,
    DISABLE_PUBLIC_REGISTER: '0',
    SERVICE_EMAIL: process.env.SERVICE_EMAIL || process.env.FEEDBACK_TO_EMAIL || '',
    SERVICE_WECHAT_QR_URL: process.env.SERVICE_WECHAT_QR_URL || '',
    SERVICE_WECHAT_NAME: process.env.SERVICE_WECHAT_NAME || '',
    FEEDBACK_TO_EMAIL: process.env.FEEDBACK_TO_EMAIL || process.env.SERVICE_EMAIL || '',
    FEEDBACK_FROM_EMAIL: process.env.FEEDBACK_FROM_EMAIL || '',
    RESEND_API_KEY: process.env.RESEND_API_KEY || '',
    FEEDBACK_WEBHOOK_URL: process.env.FEEDBACK_WEBHOOK_URL || ''
  };

  const server = http.createServer(async (req, res) => {
    try {
      const host = req.headers.host || '127.0.0.1';
      const requestUrl = `http://${host}${req.url || '/'}`;
      const url = new URL(requestUrl);

      if (url.pathname.startsWith('/api/')) {
        const body = ['POST', 'PUT', 'DELETE'].includes(req.method || '') ? await collectBody(req) : undefined;
        const headers = new Headers();
        for (const [key, value] of Object.entries(req.headers)) {
          if (Array.isArray(value)) headers.set(key, value.join(', '));
          else if (value !== undefined) headers.set(key, value);
        }
        headers.set('Origin', `http://${host}`);
        const request = new Request(requestUrl, {
          method: req.method,
          headers,
          body: body && body.length ? body : undefined
        });
        const response = await apiModule.onRequest({ request, env });
        await writeFunctionResponse(res, response);
        return;
      }

      const filePath = safeStaticPath(sourceRoot, url.pathname);
      if (!filePath) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      if (path.basename(filePath) === 'index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(desktopIndexHtml(sourceRoot));
        return;
      }
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType(filePath) });
      fs.createReadStream(filePath).pipe(res);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: err.message || String(err) }));
    }
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}/`,
    dbPath,
    close() {
      server.close();
      DB.close();
    }
  };
}
