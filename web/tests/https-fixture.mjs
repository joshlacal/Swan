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

const snapshot = {
  account: { did: 'did:plc:fixture', handle: 'reader.test', lifecycle: 'active' },
  identity: { method: 'plc', handle: 'reader.test', state: 'active' },
  strength: 'password', factors: [], sessions: [{ id: 'fixture', label: 'Playwright device', kind: 'management', lastSeen: 'now', current: true }], apps: [], passwords: []
};
const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (request, response) => {
  const url = new URL(request.url, 'https://127.0.0.1:3443');
  response.setHeader('Cache-Control', 'no-store');
  if (url.pathname === '/account/api/bootstrap') {
    response.setHeader('Set-Cookie', 'swan_csrf_pre=fixture-token; Path=/account; Secure; SameSite=Strict');
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ csrf: 'fixture-token' })); return;
  }
  if (url.pathname === '/account/api/portal') {
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(snapshot)); return;
  }
  if (url.pathname === '/oauth/authorize') {
    response.setHeader('Content-Type', 'text/html'); response.end('<!doctype html><link rel="stylesheet" href="/account/auth-tokens.css"><main class="swan-auth"><h1>Sign in to <em>your data.</em></h1></main>'); return;
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
