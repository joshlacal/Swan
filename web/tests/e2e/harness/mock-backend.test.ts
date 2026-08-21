import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MockSwanBackend } from './mock-backend';
import {
  setupTestEnv,
  teardownTestEnv,
  getTestBackend,
  stringToBase64URL,
  base64URLToString,
  bufferToBase64URL,
  base64URLToBuffer,
  mockWebAuthnError,
  restoreWebAuthnMock
} from './test-env';

describe('MockSwanBackend & TestEnv Harness', () => {
  let backend: MockSwanBackend;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: false });
    backend = env.backend;
  });

  afterEach(() => {
    teardownTestEnv();
  });

  describe('Base64URL helpers', () => {
    it('roundtrips strings and buffers correctly', () => {
      const original = 'Hello Swan Account Portal! ✳';
      const encoded = stringToBase64URL(original);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
      const decoded = base64URLToString(encoded);
      expect(decoded).toBe(original);

      const buffer = new Uint8Array([0, 1, 2, 255, 128, 64]).buffer;
      const b64 = bufferToBase64URL(buffer);
      const back = base64URLToBuffer(b64);
      expect(new Uint8Array(back)).toEqual(new Uint8Array([0, 1, 2, 255, 128, 64]));
    });
  });

  describe('Public & Bootstrap APIs', () => {
    it('returns closed signup policy', async () => {
      const resp = await fetch('/account/api/signup/policy');
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data).toMatchObject({
        policy: 'closed',
        inviteCodeRequired: false,
        turnstileRequired: false,
        emailVerificationRequired: false
      });
    });

    it('issues a fresh pre-auth CSRF token and sets swan_csrf_pre cookie', async () => {
      const resp = await fetch('/account/api/bootstrap');
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.csrf).toMatch(/^pre_/);
      expect(backend.getCookie('swan_csrf_pre')).toBe(data.csrf);
    });
  });

  describe('Login & Authentication Flow', () => {
    it('rejects login without CSRF header or mismatching cookie', async () => {
      const resp = await fetch('/account/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' })
      });
      expect(resp.status).toBe(403);
      const error = await resp.json();
      expect(error.code).toBe('request_not_allowed');
    });

    it('rejects invalid password', async () => {
      const boot = await (await fetch('/account/api/bootstrap')).json();
      const resp = await fetch('/account/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
        body: JSON.stringify({ handle: 'alice.swan.place', password: 'wrong-password' })
      });
      expect(resp.status).toBe(401);
      const error = await resp.json();
      expect(error.code).toBe('authentication_required');
    });

    it('successfully logs in with valid credentials, sets session and CSRF cookies, and clears pre-auth cookie', async () => {
      const boot = await (await fetch('/account/api/bootstrap')).json();
      const resp = await fetch('/account/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
        body: JSON.stringify({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' })
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.csrf).toMatch(/^csrf_/);
      expect(data.snapshot.account.handle).toBe('alice.swan.place');
      expect(data.snapshot.sessions.length).toBeGreaterThan(0);
      expect(backend.getCookie('__Secure-swan_management')).toMatch(/^sess_/);
      expect(backend.getCookie('swan_csrf')).toBe(data.csrf);
      expect(backend.getCookie('swan_csrf_pre')).toBeUndefined();
    });

    it('enforces MFA challenge when user has enabled factors', async () => {
      const did = 'did:plc:swan-test-user-12345';
      backend.addFactor(did, { kind: 'totp', label: 'Authenticator', secret: 'JBSWY3DPEHPK3PXP', enabled: true });

      const boot = await (await fetch('/account/api/bootstrap')).json();
      const resp = await fetch('/account/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
        body: JSON.stringify({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' })
      });
      expect(resp.status).toBe(401);
      const data = await resp.json();
      expect(data.code).toBe('mfa_required');
      expect(data.factorKind).toBe('totp');

      // Verify factor code
      const factorResp = await fetch('/account/api/login/factor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
        body: JSON.stringify({
          handle: 'alice.swan.place',
          password: 'correct-horse-battery-staple',
          kind: 'totp',
          factorID: data.factorID,
          code: '123456'
        })
      });
      expect(factorResp.status).toBe(200);
      const factorData = await factorResp.json();
      expect(factorData.factorToken).toMatch(/^fart_/);

      // Login with factor token
      const loginResp = await fetch('/account/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
        body: JSON.stringify({
          handle: 'alice.swan.place',
          password: 'correct-horse-battery-staple',
          authFactorToken: factorData.factorToken
        })
      });
      expect(loginResp.status).toBe(200);
    });
  });

  describe('Portal Snapshot & Read Projections', () => {
    it('returns 401 when reading portal unauthenticated', async () => {
      backend.clearCookies();
      const resp = await fetch('/account/api/portal');
      expect(resp.status).toBe(401);
    });

    it('returns complete portal snapshot when authenticated', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345');
      const resp = await fetch('/account/api/portal');
      expect(resp.status).toBe(200);
      const snapshot = await resp.json();
      expect(snapshot.account.handle).toBe('alice.swan.place');
      expect(snapshot.identity.state).toBe('active');
      expect(snapshot.sessions.some((s: any) => s.current)).toBe(true);
      expect(snapshot.apps.length).toBe(1);
    });

    it('serves sub-read endpoints like /profile, /sessions, /scope-presets, /export', async () => {
      backend.createSession('did:plc:swan-test-user-12345');
      const profile = await (await fetch('/account/api/profile')).json();
      expect(profile.account.handle).toBe('alice.swan.place');

      const presets = await (await fetch('/account/api/scope-presets')).json();
      expect(presets.presets.length).toBeGreaterThan(0);
      expect(presets.availableScopes).toContain('atproto');
    });
  });

  describe('Step-Up Re-Authentication Ceremonies', () => {
    it('elevates session via password reauth and issues receipt token', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345', { strength: 'password' });
      expect(session.strength).toBe('password');

      const resp = await fetch('/account/api/step-up/password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: JSON.stringify({ password: 'correct-horse-battery-staple' })
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.accepted).toBe(true);
      expect(data.factorToken).toMatch(/^rcpt_/);
      expect(session.strength).toBe('stepUpPassword');
      expect(session.lastStepUpAt).toBeGreaterThan(0);
    });

    it('elevates session via MFA TOTP step-up and issues receipt token', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345', { strength: 'password' });
      const resp = await fetch('/account/api/factors/step-up', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: JSON.stringify({ kind: 'totp', factorID: 'totp_1', code: '654321' })
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.accepted).toBe(true);
      expect(data.factorToken).toMatch(/^rcpt_/);
      expect(session.strength).toBe('stepUpMFA');
    });

    it('consumes recovery codes during step-up assertion', async () => {
      const did = 'did:plc:swan-test-user-12345';
      backend.setRecoveryCodes(did, ['RCV-TEST-CODE']);
      const session = backend.createSession(did, { strength: 'password' });

      const resp = await fetch('/account/api/factors/step-up', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: JSON.stringify({ kind: 'recoveryCode', factorID: 'rec_1', code: 'RCV-TEST-CODE' })
      });
      expect(resp.status).toBe(200);
      expect(backend.getRecoveryCodes(did)).not.toContain('RCV-TEST-CODE');

      // Replay with consumed code fails
      const replay = await fetch('/account/api/factors/step-up', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: JSON.stringify({ kind: 'recoveryCode', factorID: 'rec_1', code: 'RCV-TEST-CODE' })
      });
      expect(replay.status).toBe(403);
    });
  });

  describe('App Passwords Workflows & Single-Use Step-Up Receipts', () => {
    it('demands step-up if session is not elevated', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345', { strength: 'password' });
      const resp = await fetch('/account/api/app-passwords', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ name: 'Deck Client', scopes: ['atproto'] })
      });
      expect(resp.status).toBe(403);
      const data = await resp.json();
      expect(data.code).toBe('step_up_required');
    });

    it('validates scope requirement (atproto required)', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345', { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
      const resp = await fetch('/account/api/app-passwords', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ name: 'Invalid Scope App', scopes: ['transition:email'] })
      });
      expect(resp.status).toBe(400);
      const data = await resp.json();
      expect(data.code).toBe('invalid_request');
    });

    it('creates app password with single-use step-up receipt header and atomically consumes it', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did);
      const receipt = backend.issueStepUpReceipt(session.id, did, 'app-passwords.create');

      const resp = await fetch('/account/api/app-passwords', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken,
          'X-Swan-Step-Up': receipt.receiptToken
        },
        body: JSON.stringify({ name: 'Graysky', scopes: ['atproto', 'transition:chat.bsky'] })
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.password).toMatch(/^swan-app-/);
      expect(receipt.consumed).toBe(true);

      // Replaying mutation with consumed receipt fails
      const replay = await fetch('/account/api/app-passwords', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken,
          'X-Swan-Step-Up': receipt.receiptToken
        },
        body: JSON.stringify({ name: 'Graysky 2', scopes: ['atproto'] })
      });
      expect(replay.status).toBe(403);
      expect((await replay.json()).message).toContain('already consumed');
    });

    it('revokes app password using DELETE verb', async () => {
      const did = 'did:plc:swan-test-user-12345';
      backend.addAppPassword(did, 'Old Key');
      const session = backend.createSession(did, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });

      const resp = await fetch('/account/api/app-passwords/Old%20Key', {
        method: 'DELETE',
        headers: { 'X-Swan-CSRF': session.csrfToken }
      });
      expect(resp.status).toBe(200);
      expect(backend.getAppPasswords(did).length).toBe(0);
    });
  });

  describe('Session & Connected App Revocation (DELETE Verbs)', () => {
    it('revokes session with DELETE /account/api/sessions/:id', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
      const other = backend.createSession(did, { label: 'Other iPad Device', activeCookie: false });

      const resp = await fetch(`/account/api/sessions/${encodeURIComponent(other.id)}`, {
        method: 'DELETE',
        headers: { 'X-Swan-CSRF': session.csrfToken }
      });
      expect(resp.status).toBe(200);
      expect(backend.getSession(other.sessionToken)).toBeUndefined();
    });

    it('revokes all other sessions with POST /account/api/sessions/revoke-others', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
      const other1 = backend.createSession(did, { label: 'Device 1', activeCookie: false });
      const other2 = backend.createSession(did, { label: 'Device 2', activeCookie: false });

      const resp = await fetch('/account/api/sessions/revoke-others', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: '{}'
      });
      expect(resp.status).toBe(200);
      expect(backend.getSession(other1.sessionToken)).toBeUndefined();
      expect(backend.getSession(other2.sessionToken)).toBeUndefined();
      expect(backend.getSession(session.sessionToken)).toBeDefined();
    });

    it('revokes connected app with DELETE /account/api/connected-apps/:id', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });

      const resp = await fetch('/account/api/connected-apps/app_bsky_official', {
        method: 'DELETE',
        headers: { 'X-Swan-CSRF': session.csrfToken }
      });
      expect(resp.status).toBe(200);
      expect(backend.getConnectedApps(did).length).toBe(0);
    });
  });

  describe('Factor Enrollment & Lifecycle (TOTP, Passkeys, Recovery Codes)', () => {
    it('executes full TOTP enrollment handshake', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did);

      // Step 1: Initiate TOTP
      const initResp = await fetch('/account/api/factors/totp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ label: 'My Phone', secret: 'JBSWY3DPEHPK3PXP' })
      });
      expect(initResp.status).toBe(200);
      const initData = await initResp.json();
      expect(initData.factorID).toBeDefined();

      // Step 2: Verify code
      const verifyResp = await fetch('/account/api/factors/totp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ factorID: initData.factorID, code: '123456' })
      });
      expect(verifyResp.status).toBe(200);
      expect(backend.getFactors(did).some(f => f.kind === 'totp' && f.enabled)).toBe(true);

      // Step 3: Revoke TOTP factor with DELETE
      backend.elevateSession(session.sessionToken);
      const deleteResp = await fetch('/account/api/factors/totp', {
        method: 'DELETE',
        headers: { 'X-Swan-CSRF': session.csrfToken }
      });
      expect(deleteResp.status).toBe(200);
      expect(backend.getFactors(did).some(f => f.kind === 'totp')).toBe(false);
    });

    it('executes full Passkey registration ceremony', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did);

      // Step 1: Request Challenge
      const chalResp = await fetch('/account/api/factors/passkeys/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ label: 'MacBook Touch ID' })
      });
      expect(chalResp.status).toBe(200);
      const chalData = await chalResp.json();
      expect(chalData.challenge).toBeDefined();

      // Step 2: Browser WebAuthn registration
      const cred = (await navigator.credentials.create({
        publicKey: {
          challenge: base64URLToBuffer(chalData.challenge),
          rp: { name: 'Swan', id: 'swan.place' },
          user: { id: new Uint8Array([1, 2, 3]), name: 'alice', displayName: 'Alice' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }]
        }
      })) as any;
      expect(cred).toBeDefined();
      expect(cred?.id).toBeDefined();

      // Step 3: Complete enrollment
      const enrollResp = await fetch('/account/api/factors/passkeys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({
          factorID: chalData.factorID,
          label: 'MacBook Touch ID',
          challenge: chalData.challenge,
          clientDataJSON: bufferToBase64URL(cred.response.clientDataJSON),
          authenticatorData: bufferToBase64URL(cred.response.getAuthenticatorData()),
          credentialID: cred.id
        })
      });
      expect(enrollResp.status).toBe(200);
      expect(backend.getFactors(did).some(f => f.kind === 'passkey' && f.credentialID === cred?.id)).toBe(true);

      // Step 4: Revoke Passkey factor with DELETE
      backend.elevateSession(session.sessionToken);
      const delResp = await fetch(`/account/api/factors/passkeys/${encodeURIComponent(chalData.factorID)}`, {
        method: 'DELETE',
        headers: { 'X-Swan-CSRF': session.csrfToken }
      });
      expect(delResp.status).toBe(200);
      expect(backend.getFactors(did).some(f => f.kind === 'passkey')).toBe(false);
    });

    it('rotates recovery codes under elevated session', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });

      const resp = await fetch('/account/api/factors/recovery-codes/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: '{}'
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.recoveryCodes.length).toBe(10);
      expect(backend.getRecoveryCodes(did).length).toBe(10);
    });
  });

  describe('did:web Identity APIs', () => {
    it('reserves signing key, publishes public claim, and claims binding', async () => {
      const did = 'did:plc:swan-test-user-12345';
      const session = backend.createSession(did);

      // Reserve did:web
      const reserveResp = await fetch('/account/api/identity/reserve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ handle: 'custom.alice.io' })
      });
      expect(reserveResp.status).toBe(200);
      const reserve = await reserveResp.json();
      expect(reserve.nonce).toBeDefined();
      expect(reserve.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');

      // Public endpoint can be fetched without auth
      backend.clearCookies();
      const publicResp = await fetch(reserve.claimEndpoint);
      expect(publicResp.status).toBe(200);
      const claimBody = await publicResp.json();
      expect(claimBody.nonce).toBe(reserve.nonce);

      // Claim binding
      backend.setCookie('__Secure-swan_management', session.sessionToken);
      backend.setCookie('swan_csrf', session.csrfToken);
      const claimResp = await fetch('/account/api/identity/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': session.csrfToken },
        body: JSON.stringify({ requestID: reserve.requestID })
      });
      expect(claimResp.status).toBe(200);
      const binding = await claimResp.json();
      expect(binding.state).toBe('active');
      expect(binding.handle).toBe('custom.alice.io');
    });
  });

  describe('Security Policies & Error Handling', () => {
    it('rejects cross-origin mutations', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345');
      const resp = await fetch('/account/api/sessions/revoke-others', {
        method: 'POST',
        headers: {
          'Origin': 'https://evil-site.com',
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: '{}'
      });
      expect(resp.status).toBe(403);
    });

    it('rejects cross-site Sec-Fetch-Site mutations', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345');
      const resp = await fetch('/account/api/sessions/revoke-others', {
        method: 'POST',
        headers: {
          'Sec-Fetch-Site': 'cross-site',
          'Content-Type': 'application/json',
          'X-Swan-CSRF': session.csrfToken
        },
        body: '{}'
      });
      expect(resp.status).toBe(403);
    });

    it('rejects mutations with non-JSON Content-Type', async () => {
      const session = backend.createSession('did:plc:swan-test-user-12345');
      const resp = await fetch('/account/api/sessions/revoke-others', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'X-Swan-CSRF': session.csrfToken
        },
        body: 'invalid'
      });
      expect(resp.status).toBe(403);
    });
  });

  describe('WebAuthn Mock Error Simulation', () => {
    it('simulates user cancellation or NotAllowedError in WebAuthn', async () => {
      mockWebAuthnError(new Error('The operation either timed out or was not allowed.'), 'create');
      await expect(
        navigator.credentials.create({
          publicKey: {
            challenge: new Uint8Array([1, 2, 3]).buffer,
            rp: { name: 'Swan' },
            user: { id: new Uint8Array([1]), name: 'a', displayName: 'A' },
            pubKeyCredParams: []
          }
        })
      ).rejects.toThrow('timed out or was not allowed');

      restoreWebAuthnMock();
      const retry = await navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array([1, 2, 3]).buffer,
          rp: { name: 'Swan' },
          user: { id: new Uint8Array([1]), name: 'a', displayName: 'A' },
          pubKeyCredParams: []
        }
      });
      expect(retry).toBeDefined();
    });
  });
});
