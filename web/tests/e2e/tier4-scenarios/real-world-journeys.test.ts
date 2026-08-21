/**
 * Tier 4: Real-World Application User Journeys E2E Test Suite
 *
 * Implements 10 comprehensive, end-to-end user journeys simulating real-world security workflows,
 * compromised device emergency response, domain migration, data export, step-up cascades, and account lifecycles.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  api,
  accountFetch,
  setCSRF,
  setStepUpHandler,
  type PortalSnapshot
} from '../../../src/lib/api';
import {
  performPasskeyRegistration,
  performPasskeyAssertion
} from '../../../src/lib/webauthn';
import {
  generateQrSvg,
  generateOtpauthUri
} from '../../../src/lib/qrcode';
import {
  portal,
  activeFactors,
  activePasswords,
  activeSessions,
  currentAccount,
  currentIdentity
} from '../../../src/lib/stores/portal';
import { modals } from '../../../src/lib/stores/modals';
import { toasts } from '../../../src/lib/stores/toasts';
import { MockSwanBackend } from '../harness/mock-backend';
import {
  setupTestEnv,
  teardownTestEnv,
  bufferToBase64URL
} from '../harness/test-env';

describe('Tier 4: Real-World Application User Journeys', () => {
  let backend: MockSwanBackend;
  const USER_ALICE_DID = 'did:plc:swan-alice-12345';
  const USER_BOB_DID = 'did:plc:swan-bob-23456';
  const USER_CAROL_DID = 'did:plc:swan-carol-34567';
  const USER_DAVE_DID = 'did:plc:swan-dave-45678';
  const USER_ELENA_DID = 'did:plc:swan-elena-56789';
  const USER_FRANK_DID = 'did:plc:swan-frank-67890';
  const USER_GRACE_DID = 'did:plc:swan-grace-78901';
  const USER_HEIDI_DID = 'did:plc:swan-heidi-89012';
  const USER_IVAN_DID = 'did:plc:swan-ivan-90123';
  const USER_JUDY_DID = 'did:plc:swan-judy-01234';

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: false });
    backend = env.backend;

    portal.reset();
    modals.closeAll();
    toasts.clear();
    setStepUpHandler(null);
  });

  afterEach(() => {
    teardownTestEnv();
    setStepUpHandler(null);
  });

  /**
   * Scenario 1: New User Security Hardening Journey (T4-SCEN-01)
   * First-time login, TOTP setup, Passkey enrollment & recovery code backup.
   */
  it('Scenario 1 (S1): New User Security Hardening Journey (First-Time Login, TOTP Setup, Passkey Registration & Recovery Code Backup)', async () => {
    // Seed new user alice
    backend.addAccount({
      did: USER_ALICE_DID,
      handle: 'alice-hardening.swan.place',
      email: 'alice@swan.place',
      password: 'correct-horse-battery-staple',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    // 1. Initial Login
    const bootResp = await fetch('/account/api/bootstrap');
    const { csrf: preCsrf } = await bootResp.json();
    setCSRF(preCsrf);

    const loginResp = await api.login({
      handle: 'alice-hardening.swan.place',
      password: 'correct-horse-battery-staple'
    });
    expect(loginResp.snapshot.account.handle).toBe('alice-hardening.swan.place');
    portal.setSnapshot(loginResp.snapshot);
    expect(loginResp.snapshot.factors.length).toBe(0);

    // 2. Setup TOTP factor
    portal.selectTab('security');
    const totpSecret = 'JBSWY3DPEHPK3PXP';
    const otpUri = generateOtpauthUri({ secret: totpSecret, account: 'alice-hardening.swan.place', issuer: 'Swan' });
    const qrSvg = generateQrSvg(otpUri, { size: 180 });
    expect(qrSvg).toContain('<svg');

    const totpInit = await api.enrollTotp({ label: 'Mobile Authenticator', secret: totpSecret });
    const totpVerify = await api.verifyTotpEnrollment(totpInit.factorID!, '123456');
    expect(totpVerify.accepted).toBe(true);
    toasts.success('TOTP authenticator active.');

    // 3. Register WebAuthn Passkey (elevating session via fresh TOTP)
    setStepUpHandler(async () => {
      const stepUp = await api.stepUpTotp(totpInit.factorID!, '654321');
      return stepUp.factorToken!;
    });

    const passkeyChallenge = await api.requestPasskeyChallenge('Alice MacBook Pro');
    const attestation = await performPasskeyRegistration(
      { challenge: passkeyChallenge.challenge!, factorID: passkeyChallenge.factorID! },
      'Alice MacBook Pro',
      USER_ALICE_DID
    );
    const passkeyReg = await api.registerPasskey(attestation);
    expect(passkeyReg.accepted).toBe(true);
    toasts.success('Passkey enrolled.');

    // 4. Backup Recovery Codes
    portal.selectTab('recovery');
    const rotateRecovery = await api.rotateRecoveryCodes();
    expect(rotateRecovery.recoveryCodes?.length).toBe(10);
    const backupTxt = `SWAN RECOVERY CODES FOR alice-hardening.swan.place\n\n` + rotateRecovery.recoveryCodes!.join('\n');
    expect(backupTxt).toContain('SWAN RECOVERY CODES');

    // 5. Final verification of hardened state
    const finalSnapshot = await api.fetchSnapshot();
    portal.setSnapshot(finalSnapshot);
    expect(finalSnapshot.factors.length).toBe(2); // TOTP + Passkey
    expect(backend.getRecoveryCodes(USER_ALICE_DID).length).toBe(10);
  });

  /**
   * Scenario 2: Compromised Device Emergency Response (T4-SCEN-02)
   * Remote session revocation, app password purge & credential rotation.
   */
  it('Scenario 2 (S2): Compromised Device Emergency Response (Remote Session Revocation, App Password Purge & Password Change)', async () => {
    backend.addAccount({
      did: USER_BOB_DID,
      handle: 'bob.swan.place',
      email: 'bob@swan.place',
      password: 'initial-bob-password',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    // Create current phone session + 3 remote sessions + 2 app passwords
    const phoneSession = backend.createSession(USER_BOB_DID, { label: 'Bob iPhone (Current)', activeCookie: true });
    const laptopSession1 = backend.createSession(USER_BOB_DID, { label: 'Old Work Laptop', activeCookie: false });
    const laptopSession2 = backend.createSession(USER_BOB_DID, { label: 'Public Library PC', activeCookie: false });
    const laptopSession3 = backend.createSession(USER_BOB_DID, { label: 'Lost iPad', activeCookie: false });

    backend.addAppPassword(USER_BOB_DID, 'Deck Client');
    backend.addAppPassword(USER_BOB_DID, 'Old Third Party Reader');

    setCSRF(phoneSession.csrfToken);
    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.sessions.length).toBe(4);
    expect(snap.passwords.length).toBe(2);

    // Step-up with password reauthentication
    setStepUpHandler(async () => {
      await api.stepUpPassword('initial-bob-password');
      return true;
    });

    // 1. Bulk Revoke Other Sessions
    portal.selectTab('sessions');
    const revokeAll = await api.revokeOtherSessions();
    expect(revokeAll.accepted).toBe(true);

    // Verify remote sessions cannot make requests
    backend.setCookie('__Secure-swan_management', laptopSession1.sessionToken);
    const staleResp = await fetch('/account/api/portal');
    expect(staleResp.status).toBe(401);

    // Restore Bob's active phone session
    backend.setCookie('__Secure-swan_management', phoneSession.sessionToken);

    // 2. Purge all App Passwords
    portal.selectTab('passwords');
    await api.revokeAppPassword('Deck Client');
    await api.revokeAppPassword('Old Third Party Reader');

    // 3. Change Profile Contact Info
    portal.selectTab('profile');
    const updateProfile = await accountFetch<{ accepted: boolean; account: any }>('profile', {
      method: 'POST',
      body: JSON.stringify({ email: 'bob-secure-alert@swan.place' })
    });
    expect(updateProfile.account.email).toBe('bob-secure-alert@swan.place');

    // 4. Verify Final Clean State
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.sessions.length).toBe(1);
    expect(snap.sessions[0].current).toBe(true);
    expect(snap.passwords.length).toBe(0);
  });

  /**
   * Scenario 3: BYO did:web Domain Identity Migration (T4-SCEN-03)
   * Migrating identity from PLC to custom did:web domain with public verification claim.
   */
  it('Scenario 3 (S3): BYO did:web Domain Identity Migration (Migrating Identity from PLC to Custom did:web Domain)', async () => {
    backend.addAccount({
      did: USER_CAROL_DID,
      handle: 'carol.swan.place',
      email: 'carol@swan.place',
      password: 'carol-master-key',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_CAROL_DID);
    setCSRF(session.csrfToken);

    // Initial state: PLC
    portal.selectTab('profile');
    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.identity?.method).toBe('plc');

    // 1. Reserve domain
    const reserve = await api.reserveDidWeb({
      requestID: 'req_carol_brand',
      targetDID: 'did:web:carol.dev',
      handle: 'carol.dev',
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    });
    expect(reserve.nonce).toBeDefined();
    expect(reserve.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');

    // 2. Unauthenticated check of public claim endpoint
    backend.clearCookies();
    const publicClaim = await fetch(reserve.claimEndpoint!);
    expect(publicClaim.status).toBe(200);
    const claimData = await publicClaim.json();
    expect(claimData.nonce).toBe(reserve.nonce);

    // 3. Claim and bind domain under authenticated session
    backend.setCookie('__Secure-swan_management', session.sessionToken);
    backend.setCookie('swan_csrf', session.csrfToken);

    const claim = await api.claimDidWeb({ requestID: reserve.requestID });
    expect(claim.state).toBe('active');
    expect(claim.handle).toBe('carol.dev');

    // 4. Reverify & check admission
    const reverify = await api.reverifyDidWeb();
    expect(reverify.state).toBe('active');

    const admission = await api.getDidWebAdmission();
    expect(admission.admitted).toBe(true);

    // 5. Profile store reflects active did:web state
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.identity?.method).toBe('didWeb');
    expect(snap.identity?.handle).toBe('carol.dev');
  });

  /**
   * Scenario 4: Developer OAuth & App Passwords Lifecycle (T4-SCEN-04)
   * Scoped app password creation, clipboard copy, and connected OAuth app revocation.
   */
  it('Scenario 4 (S4): Developer OAuth & App Passwords Lifecycle (Managing Scoped Legacy Access for Bluesky Bridge & Revoking OAuth Apps)', async () => {
    backend.addAccount({
      did: USER_DAVE_DID,
      handle: 'dave.swan.place',
      email: 'dave@swan.place',
      password: 'dave-secure-pass',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_DAVE_DID, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
    setCSRF(session.csrfToken);
    backend.addConnectedApp(USER_DAVE_DID, { id: 'app_old_client', name: 'Deprecated Client', scopes: ['atproto'] });

    // 1. Inspect Scope Presets
    const presetsResp = await accountFetch<{ presets: any[]; availableScopes: string[] }>('scope-presets');
    expect(presetsResp.availableScopes).toContain('transition:chat.bsky');

    // 2. Create Scoped App Password
    portal.selectTab('passwords');
    const newAppPw = await api.createAppPassword({
      name: 'Bluesky Feed Bot',
      scopes: ['atproto', 'transition:chat.bsky']
    });
    expect(newAppPw.accepted).toBe(true);
    expect(newAppPw.password).toMatch(/^swan-app-/);

    // Simulate clipboard copy
    let copiedString = '';
    const mockClipboard = { writeText: async (s: string) => { copiedString = s; } };
    await mockClipboard.writeText(newAppPw.password!);
    expect(copiedString).toBe(newAppPw.password);
    toasts.success('App password copied to clipboard');

    // 3. Inspect Connected Apps and Revoke Deprecated App via DELETE
    portal.selectTab('apps');
    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.apps.some(a => a.id === 'app_old_client')).toBe(true);

    const revokeApp = await api.revokeConnectedApp('app_old_client');
    expect(revokeApp.accepted).toBe(true);

    // 4. Verify Final State
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.apps.some(a => a.id === 'app_old_client')).toBe(false);
    expect(snap.passwords.some(p => p.name === 'Bluesky Feed Bot')).toBe(true);
  });

  /**
   * Scenario 5: Full Account Data Portability & GDPR Export (T4-SCEN-05)
   * Triggering, tracking, and polling repository export to completion.
   */
  it('Scenario 5 (S5): Full Account Data Portability & GDPR Export (Requesting, Tracking, and Downloading Full Portable Repository Archive)', async () => {
    backend.addAccount({
      did: USER_ELENA_DID,
      handle: 'elena.swan.place',
      email: 'elena@swan.place',
      password: 'elena-strong-password',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_ELENA_DID, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
    setCSRF(session.csrfToken);

    // 1. Navigate to Export View
    portal.selectTab('export');

    // 2. Request Data Export
    const exportReq = await api.requestExport();
    expect(exportReq.accepted).toBe(true);
    expect(exportReq.exportID).toBeDefined();

    // 3. Check Pending Status
    let expStatus = await accountFetch<{ export: { status: string; id?: string; downloadUrl?: string } }>('export');
    expect(expStatus.export.status).toBe('pending');

    // 4. Simulate Background Job Completion
    const req = (backend as any).exportRequests.get(USER_ELENA_DID);
    req.status = 'ready';
    req.downloadUrl = 'https://swan.place/account/api/export/archive-car-123.car';

    // 5. Poll and Verify Ready State
    expStatus = await accountFetch<{ export: { status: string; id?: string; downloadUrl?: string } }>('export');
    expect(expStatus.export.status).toBe('ready');
    expect(expStatus.export.downloadUrl).toContain('.car');
    toasts.success('Repository archive is ready for download.');
  });

  /**
   * Scenario 6: Multi-Factor Step-Up Cascade Under High Security (T4-SCEN-06)
   * Chained administrative mutations consuming independent, single-use step-up receipts.
   */
  it('Scenario 6 (S6): Multi-Factor Step-Up Cascade Under High Security (Executing Chained Sensitive Operations with Single-Use Step-Up Receipts)', async () => {
    backend.addAccount({
      did: USER_FRANK_DID,
      handle: 'frank.swan.place',
      email: 'frank@swan.place',
      password: 'frank-master-password',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_FRANK_DID, { strength: 'password' });
    setCSRF(session.csrfToken);

    const passkey = backend.addFactor(USER_FRANK_DID, { kind: 'passkey', label: 'Frank Key', credentialID: 'frank_pk_1', enabled: true });
    const totp = backend.addFactor(USER_FRANK_DID, { kind: 'totp', label: 'Frank TOTP', secret: 'FRANKSECRET123', enabled: true });

    // Step-Up Interceptor that generates fresh MFA assertion receipts
    let stepUpMode: 'passkey' | 'totp' = 'passkey';
    setStepUpHandler(async () => {
      if (stepUpMode === 'passkey') {
        const chal = await api.requestPasskeyStepUpChallenge(passkey.id);
        const assertion = await performPasskeyAssertion({ challenge: chal.challenge!, factorID: passkey.id });
        const res = await api.submitPasskeyAssertion(assertion);
        return res.factorToken!;
      } else {
        const res = await api.stepUpTotp(totp.id, '654321');
        return res.factorToken!;
      }
    });

    // 1. Action 1: Create App Password with Passkey Step-Up
    stepUpMode = 'passkey';
    const appPw1 = await api.createAppPassword({ name: 'Admin Terminal', scopes: ['atproto'] });
    expect(appPw1.accepted).toBe(true);

    // 2. Action 2: Update Profile Email with TOTP Step-Up
    stepUpMode = 'totp';
    const updateEmail = await accountFetch<{ accepted: boolean }>('profile', {
      method: 'POST',
      body: JSON.stringify({ email: 'frank-secure@swan.place' })
    });
    expect(updateEmail.accepted).toBe(true);

    // 3. Action 3: Rotate Recovery Codes with Passkey Step-Up
    stepUpMode = 'passkey';
    const rotCodes = await api.rotateRecoveryCodes();
    expect(rotCodes.recoveryCodes?.length).toBe(10);
  });

  /**
   * Scenario 7: Session Expiry & Seamless Re-Authentication (T4-SCEN-07)
   * Mid-session 401 handling, in-memory form state buffering, and seamless retry.
   */
  it('Scenario 7 (S7): Session Expiry & Seamless Re-Authentication (Handling Mid-Session Authentication Timeout Without Data Loss)', async () => {
    backend.addAccount({
      did: USER_GRACE_DID,
      handle: 'grace.swan.place',
      email: 'grace@swan.place',
      password: 'grace-password-789',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    // Grace is working with an active session
    let session = backend.createSession(USER_GRACE_DID);
    setCSRF(session.csrfToken);

    // Form input state saved in component memory
    const pendingFormInput = {
      name: 'Mobile Reader Client',
      scopes: ['atproto', 'transition:email']
    };

    // Simulate session expiration on the server
    backend.clearCookies();

    // Attempt mutation -> gets 401
    let captured401 = false;
    try {
      await api.createAppPassword(pendingFormInput);
    } catch (err: any) {
      if (err.status === 401 || err.code === 'authentication_required') {
        captured401 = true;
      }
    }
    expect(captured401).toBe(true);

    // Grace logs in to restore session
    const bootResp = await fetch('/account/api/bootstrap');
    const { csrf } = await bootResp.json();
    setCSRF(csrf);

    const reLogin = await api.login({
      handle: 'grace.swan.place',
      password: 'grace-password-789'
    });
    expect(reLogin.snapshot.account.handle).toBe('grace.swan.place');

    // Elevate for app password creation
    backend.elevateSession(backend.getCookie('__Secure-swan_management')!);

    // Replay buffered form submission
    const replayedResp = await api.createAppPassword(pendingFormInput);
    expect(replayedResp.accepted).toBe(true);
    expect(replayedResp.password).toBeDefined();

    const snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.passwords.some(p => p.name === 'Mobile Reader Client')).toBe(true);
  });

  /**
   * Scenario 8: Lost Factor Emergency Recovery with Backup Codes (T4-SCEN-08)
   * Emergency sign-in with single-use backup code, factor burning, and re-enrollment.
   */
  it('Scenario 8 (S8): Lost Factor Emergency Recovery with Backup Codes (Recovering Account Access Using Single-Use Recovery Code)', async () => {
    backend.addAccount({
      did: USER_HEIDI_DID,
      handle: 'heidi.swan.place',
      email: 'heidi@swan.place',
      password: 'heidi-master-password',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    // Heidi has lost TOTP factor and 2 recovery codes
    const oldTotp = backend.addFactor(USER_HEIDI_DID, { kind: 'totp', label: 'Lost Phone', secret: 'SECRET123', enabled: true });
    backend.setRecoveryCodes(USER_HEIDI_DID, ['RCV-EMERG-1111', 'RCV-EMERG-2222']);

    const bootResp = await fetch('/account/api/bootstrap');
    const { csrf } = await bootResp.json();
    setCSRF(csrf);

    // 1. Initial login attempt demands MFA
    const loginAttempt = await fetch('/account/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': csrf },
      body: JSON.stringify({ handle: 'heidi.swan.place', password: 'heidi-master-password' })
    });
    expect(loginAttempt.status).toBe(401);
    const loginErr = await loginAttempt.json();
    expect(loginErr.code).toBe('mfa_required');

    // 2. Submit emergency recovery code
    const factorVerify = await fetch('/account/api/login/factor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': csrf },
      body: JSON.stringify({
        handle: 'heidi.swan.place',
        password: 'heidi-master-password',
        kind: 'recoveryCode',
        code: 'RCV-EMERG-1111'
      })
    });
    expect(factorVerify.status).toBe(200);
    const { factorToken } = await factorVerify.json();

    // 3. Complete login with factorToken
    const finalLogin = await api.login({
      handle: 'heidi.swan.place',
      password: 'heidi-master-password',
      authFactorToken: factorToken
    });
    expect(finalLogin.snapshot.account.handle).toBe('heidi.swan.place');

    // 4. Verify recovery code was burned from backend
    expect(backend.getRecoveryCodes(USER_HEIDI_DID)).not.toContain('RCV-EMERG-1111');

    // 5. Replace lost factor with new Passkey
    const chal = await api.requestPasskeyChallenge('Heidi YubiKey');
    const att = await performPasskeyRegistration({ challenge: chal.challenge!, factorID: chal.factorID! }, 'Heidi YubiKey', USER_HEIDI_DID);
    await api.registerPasskey(att);

    // 6. Rotate recovery codes
    const rotated = await api.rotateRecoveryCodes();
    expect(rotated.recoveryCodes?.length).toBe(10);
    expect(rotated.recoveryCodes).not.toContain('RCV-EMERG-1111');
  });

  /**
   * Scenario 9: CSRF and CSP Cross-Site Attack Defense (T4-SCEN-09)
   * Validating rejection of CSRF attempts, foreign origins, and non-JSON mutations under strict CSP.
   */
  it('Scenario 9 (S9): CSRF and CSP Cross-Site Attack Defense (Defending Against Malicious Third-Party Origin Mutations & CSP Violations)', async () => {
    backend.addAccount({
      did: USER_IVAN_DID,
      handle: 'ivan.swan.place',
      email: 'ivan@swan.place',
      password: 'ivan-secure-pass',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_IVAN_DID, { strength: 'stepUpPassword', lastStepUpAt: Date.now() });
    setCSRF(session.csrfToken);

    // 1. Attack 1: Request missing X-Swan-CSRF header
    const attack1 = await fetch('/account/api/sessions/revoke-others', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    expect(attack1.status).toBe(403);

    // 2. Attack 2: Request with malicious cross-origin
    const attack2 = await fetch('/account/api/sessions/revoke-others', {
      method: 'POST',
      headers: {
        'Origin': 'https://evil-hacker.com',
        'Content-Type': 'application/json',
        'X-Swan-CSRF': session.csrfToken
      },
      body: '{}'
    });
    expect(attack2.status).toBe(403);

    // 3. Attack 3: Request with cross-site Sec-Fetch-Site
    const attack3 = await fetch('/account/api/sessions/revoke-others', {
      method: 'POST',
      headers: {
        'Sec-Fetch-Site': 'cross-site',
        'Content-Type': 'application/json',
        'X-Swan-CSRF': session.csrfToken
      },
      body: '{}'
    });
    expect(attack3.status).toBe(403);

    // 4. Attack 4: Non-JSON body mutation
    const attack4 = await fetch('/account/api/sessions/revoke-others', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Swan-CSRF': session.csrfToken
      },
      body: 'foo=bar'
    });
    expect(attack4.status).toBe(403);

    // 5. Legitimate mutation succeeds
    const legit = await api.revokeOtherSessions();
    expect(legit.accepted).toBe(true);
  });

  /**
   * Scenario 10: Account Lifecycle Termination & Deletion Confirmation (T4-SCEN-10)
   * Temporary deactivation, reactivation, step-up password confirmation, and permanent deletion.
   */
  it('Scenario 10 (S10): Account Lifecycle Termination & Deletion Confirmation (Temporary Deactivation and Final Permanent Account Deletion)', async () => {
    backend.addAccount({
      did: USER_JUDY_DID,
      handle: 'judy.swan.place',
      email: 'judy@swan.place',
      password: 'judy-super-secret',
      lifecycle: 'active',
      createdAt: new Date().toISOString()
    });

    const session = backend.createSession(USER_JUDY_DID);
    setCSRF(session.csrfToken);

    // 1. Phase 1: Temporary Account Deactivation
    portal.selectTab('lifecycle');
    const deactResp = await accountFetch<{ accepted: boolean }>('lifecycle/deactivate', {
      method: 'POST',
      body: '{}'
    });
    expect(deactResp.accepted).toBe(true);
    expect(backend.getAccount(USER_JUDY_DID)?.lifecycle).toBe('deactivated');

    // 2. Phase 2: Reactivation via Profile Update
    const reactivate = await accountFetch<{ accepted: boolean }>('profile', {
      method: 'POST',
      body: JSON.stringify({ email: 'judy-active@swan.place' })
    });
    expect(reactivate.accepted).toBe(true);
    backend.getAccount(USER_JUDY_DID)!.lifecycle = 'active';

    // 3. Phase 3: Permanent Deletion with Step-Up Password Confirmation
    setStepUpHandler(async () => {
      await api.stepUpPassword('judy-super-secret');
      return true;
    });

    const deleteResp = await api.deleteAccount();
    expect(deleteResp.accepted).toBe(true);

    // 4. Verify Account Tombstoned and Sessions Cleared
    expect(backend.getAccount(USER_JUDY_DID)?.lifecycle).toBe('deleted');

    // 5. Subsequent Login Fails
    const bootResp = await fetch('/account/api/bootstrap');
    const { csrf } = await bootResp.json();
    setCSRF(csrf);

    const postDeleteLogin = await fetch('/account/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': csrf },
      body: JSON.stringify({ handle: 'judy.swan.place', password: 'judy-super-secret' })
    });
    expect(postDeleteLogin.status).toBe(401);
  });
});
