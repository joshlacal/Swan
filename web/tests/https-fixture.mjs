import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const fixtureDir = join(tmpdir(), 'swan-portal-https-fixture');
mkdirSync(fixtureDir, { recursive: true });
const key = join(fixtureDir, 'key.pem');
const cert = join(fixtureDir, 'cert.pem');
if (!existsSync(key) || !existsSync(cert)) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=127.0.0.1'], { stdio: 'ignore' });
}

// Match the generated inline stylesheet and CSP contract used by the server.
// This remains a presentation fixture; it does not exercise account authority.
const styleSource = readFileSync(new URL('../Sources/SwanHTTP/SwanBrowserStyleSheet.swift', new URL('../', import.meta.url)), 'utf8');
const styleMatch = styleSource.match(/static let styleSheet = #"""\n([\s\S]*)\n"""#/);
if (!styleMatch) throw new Error('generated Swan browser stylesheet is missing');
const oauthStyle = styleMatch[1];
const oauthStyleHash = createHash('sha256').update(oauthStyle).digest('base64');

const snapshot = {
  account: { did: 'did:plc:fixture', handle: 'reader.test', lifecycle: 'active' },
  identity: { method: 'plc', handle: 'reader.test', state: 'active' },
  strength: 'password', factors: [], sessions: [{ id: 'fixture', label: 'Playwright device', kind: 'management', lastSeen: 'now', current: true }], apps: [], passwords: []
};
const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (request, response) => {
  const url = new URL(request.url ?? '/', 'https://127.0.0.1:3443');
  response.setHeader('Cache-Control', 'no-store');
  if (url.pathname === '/account/api/bootstrap') {
    response.setHeader('Set-Cookie', 'swan_csrf_pre=fixture-token; Path=/account; Secure; SameSite=Strict');
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ csrf: 'fixture-token' })); return;
  }
  if (url.pathname === '/account/api/portal') {
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(snapshot)); return;
  }
  if (url.pathname === '/oauth/authorize') {
    response.setHeader('Content-Security-Policy', `default-src 'none'; style-src 'sha256-${oauthStyleHash}'; frame-ancestors 'none'; base-uri 'none'`);
    response.setHeader('Content-Type', 'text/html'); response.end(`<!doctype html><style>${oauthStyle}</style><main class="swan-auth"><h1>Sign in to <em>your data.</em></h1></main>`); return;
  }
  const relative = url.pathname.replace('/account/', '') || 'index.html';
  const file = join(process.cwd(), 'build', relative.includes('.') ? relative : 'index.html');
  if (existsSync(file)) {
    const type = relative.endsWith('.css') ? 'text/css' : relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.json') ? 'application/json' : 'text/html';
    response.setHeader('Content-Type', type); response.end(readFileSync(file)); return;
  }
  response.statusCode = 404; response.end('not found');
});
server.listen(3443, '127.0.0.1');
