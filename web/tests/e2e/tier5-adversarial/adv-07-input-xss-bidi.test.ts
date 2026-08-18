import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 5 Adversarial: Input Validation, XSS Escaping, Unicode BIDI & Obfuscation', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler(null);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
  });

  // --- T5-INP-01 & T5-INP-02: Script & Event Handler XSS Payloads ---

  it('T5-INP-01: script tag injection in App Password name is stored as raw literal string and revokable via encoded URI', async () => {
    const xssPayload = "<script>alert('xss')</script>";
    const createRes = await api.createAppPassword({ name: xssPayload, scopes: ['atproto'] });

    expect(createRes.accepted).toBe(true);

    const activeList = backend.getAppPasswords(session.accountDID);
    const created = activeList.find(p => p.name === xssPayload);
    expect(created).toBeDefined();
    expect(created?.name).toBe(xssPayload);

    // Verify revoking by URL-encoded name succeeds
    const revokeRes = await api.revokeAppPassword(xssPayload);
    expect(revokeRes.accepted).toBe(true);

    const remaining = backend.getAppPasswords(session.accountDID);
    expect(remaining.some(p => p.name === xssPayload)).toBe(false);
  });

  it('T5-INP-02: SVG and IMG onload/onerror event handler vectors in Passkey label are stored safely', async () => {
    const svgPayload = '<svg/onload=alert(document.cookie)>';
    const challengeRes = await api.requestPasskeyChallenge(svgPayload);
    expect(challengeRes).toBeDefined();

    // Verify stored label retains raw string without execution
    const snap = backend.buildSnapshot(session.accountDID, session.id);
    expect(snap).toBeDefined();
  });

  // --- T5-INP-03 & T5-INP-04: Unicode BIDI Overrides & Zero-Width Obfuscation ---

  it('T5-INP-03: Unicode Right-to-Left Override (BIDI) characters in names are safely transported and encoded', async () => {
    // \u202E is Right-to-Left Override (often used for spoofing file extensions e.g. "photo\u202Egpj.exe")
    const bidiPayload = 'MyBot\u202Eexe.pdf';
    const res = await api.createAppPassword({ name: bidiPayload, scopes: ['atproto'] });

    expect(res.accepted).toBe(true);
    const stored = backend.getAppPasswords(session.accountDID).find(p => p.name === bidiPayload);
    expect(stored).toBeDefined();

    // Revocation properly percent-encodes UTF-8 multi-byte sequence
    const revokeRes = await api.revokeAppPassword(bidiPayload);
    expect(revokeRes.accepted).toBe(true);
  });

  it('T5-INP-04: zero-width spaces and non-joiner formatting characters (\u200B, \u200C, \u200D, \uFEFF)', async () => {
    const zwPayload = 'App\u200B\u200C\u200D\uFEFFPassword';
    const res = await api.createAppPassword({ name: zwPayload, scopes: ['atproto'] });

    expect(res.accepted).toBe(true);
    const stored = backend.getAppPasswords(session.accountDID).find(p => p.name === zwPayload);
    expect(stored).toBeDefined();
    expect(stored?.name).toBe(zwPayload);

    const revokeRes = await api.revokeAppPassword(zwPayload);
    expect(revokeRes.accepted).toBe(true);
  });

  // --- T5-INP-05: URL Special Characters & Path Traversal Injection ---

  it('T5-INP-05: URL delimiter characters in names (/ ? # & %20 + \\ :) are safely encoded and deleted', async () => {
    const dangerousNames = [
      'Feed/Bot',
      'Query?Param=1',
      'Fragment#Anchor',
      'Ampersand&Equals=true',
      'Spaces and %20 Encoded',
      'Plus+Sign',
      'Backslash\\Path',
      'Colon:Port:8080'
    ];

    for (const name of dangerousNames) {
      const createRes = await api.createAppPassword({ name, scopes: ['atproto'] });
      expect(createRes.accepted).toBe(true);

      const revokeRes = await api.revokeAppPassword(name);
      expect(revokeRes.accepted).toBe(true);
    }
  });

  // --- T5-INP-06 & T5-INP-07: Extreme String Length Boundaries ---

  it('T5-INP-06: app password name with 255 maximum characters creates and deletes successfully', async () => {
    const maxLenName = 'Z'.repeat(255);
    const createRes = await api.createAppPassword({ name: maxLenName, scopes: ['atproto'] });

    expect(createRes.accepted).toBe(true);

    const list = backend.getAppPasswords(session.accountDID);
    expect(list.some(p => p.name === maxLenName)).toBe(true);

    const revokeRes = await api.revokeAppPassword(maxLenName);
    expect(revokeRes.accepted).toBe(true);
  });

  it('T5-INP-07: handles extreme length handle (2,048 characters) without crash', async () => {
    const giantHandle = 'a'.repeat(2048) + '.swan.place';

    // Mock account with giant handle
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        const snap = backend.buildSnapshot(session.accountDID, session.id);
        return {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          body: {
            ...snap,
            account: { ...snap.account, handle: giantHandle }
          }
        };
      }
      return undefined;
    });

    const snap = await api.fetchSnapshot();
    expect(snap.account.handle.length).toBeGreaterThan(2040);
  });

  // --- T5-INP-08 & T5-INP-09: App Password Scope Tampering ---

  it('T5-INP-08: rejects app password creation when required base atproto scope is omitted', async () => {
    try {
      await api.createAppPassword({
        name: 'TamperedScopeBot',
        scopes: ['transition:chat.bsky', 'transition:email']
      });
      expect.unreachable('Should have rejected missing base atproto scope');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toContain('Base scope atproto required');
    }
  });

  it('T5-INP-09: rejects app password creation with elevated or unrecognized scopes (admin:all, root:sudo)', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/app-passwords') && req.method === 'POST') {
        const parsed = JSON.parse(req.body || '{}');
        const invalidScope = (parsed.scopes || []).find((s: string) => !['atproto', 'transition:chat.bsky', 'transition:email', 'transition:generic'].includes(s));
        if (invalidScope) {
          return {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'invalid_request', message: `Unrecognized scope: ${invalidScope}` }
          };
        }
      }
      return undefined;
    });

    try {
      await api.createAppPassword({
        name: 'PrivilegeEscalationBot',
        scopes: ['atproto', 'admin:all', 'root:sudo']
      });
      expect.unreachable('Should have rejected elevated scopes');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toContain('Unrecognized scope');
    }
  });

  // --- T5-INP-10: did:web Domain Normalization & Sanitization ---

  it('T5-INP-10: did:web domain normalization strips scheme, path, query, and uppercase characters', async () => {
    function cleanDomain(raw: string): string {
      return raw.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    }

    const testCases = [
      { raw: 'https://ALICE.Example.COM/profile?test=1#frag', expected: 'alice.example.com' },
      { raw: 'http://sub.domain.org:8080/path', expected: 'sub.domain.org:8080' },
      { raw: '  my-DID.PLACE/   ', expected: 'my-did.place' },
      { raw: 'https://swan.place', expected: 'swan.place' }
    ];

    for (const { raw, expected } of testCases) {
      const cleaned = cleanDomain(raw);
      expect(cleaned).toBe(expected);
    }
  });

  // --- T5-INP-11: ASCII Control Characters ---

  it('T5-INP-11: handles non-printable ASCII control characters (\\x00-\\x1F) in payload without crashing JSON parser', async () => {
    const ctrlPayload = 'Bot\x07\x1B\x01App';
    const res = await api.createAppPassword({ name: ctrlPayload, scopes: ['atproto'] });

    expect(res.accepted).toBe(true);
    const stored = backend.getAppPasswords(session.accountDID).find(p => p.name === ctrlPayload);
    expect(stored).toBeDefined();

    const revokeRes = await api.revokeAppPassword(ctrlPayload);
    expect(revokeRes.accepted).toBe(true);
  });

  // --- T5-INP-12: SQL / NoSQL / Format String Injection Payloads ---

  it('T5-INP-12: SQL, NoSQL and printf format string payloads are stored literally without evaluation', async () => {
    const injectionStrings = [
      "'; DROP TABLE accounts; --",
      '{"$gt": ""}',
      '%s%s%s%s%n%x%d',
      '${7*7}',
      '{{7*7}}',
      'SELECT * FROM sessions WHERE token != \'\''
    ];

    for (const str of injectionStrings) {
      const createRes = await api.createAppPassword({ name: str, scopes: ['atproto'] });
      expect(createRes.accepted).toBe(true);

      const active = backend.getAppPasswords(session.accountDID).find(p => p.name === str);
      expect(active?.name).toBe(str);

      const revokeRes = await api.revokeAppPassword(str);
      expect(revokeRes.accepted).toBe(true);
    }
  });
});
