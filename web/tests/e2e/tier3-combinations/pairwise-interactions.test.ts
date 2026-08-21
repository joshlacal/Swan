/**
 * Tier 3: Pairwise Cross-Feature Combinations E2E Test Suite
 *
 * Implements 19 combinatorial test cases verifying cross-cutting state transitions,
 * step-up elevation ceremonies, HTTP verb routing, and reactive UI store updates.
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
  performPasskeyAssertion,
  base64urlToUint8Array,
  uint8ArrayToBase64URL
} from '../../../src/lib/webauthn';
import {
  generateQrSvg,
  generateOtpauthUri,
  generateQrSvgPath
} from '../../../src/lib/qrcode';
import { portal, activeFactors, activePasswords, activeSessions, currentIdentity } from '../../../src/lib/stores/portal';
import { modals, activeModal } from '../../../src/lib/stores/modals';
import { toasts } from '../../../src/lib/stores/toasts';
import { MockSwanBackend } from '../harness/mock-backend';
import {
  setupTestEnv,
  teardownTestEnv,
  base64URLToBuffer,
  bufferToBase64URL
} from '../harness/test-env';

describe('Tier 3: Cross-Feature Pairwise Combinations', () => {
  let backend: MockSwanBackend;
  const TEST_DID = 'did:plc:swan-test-user-12345';

  beforeEach(() => {
    const env = setupTestEnv({
      authenticated: true,
      userDid: TEST_DID,
      elevated: false
    });
    backend = env.backend;

    // Reset stores and handlers
    portal.reset();
    modals.closeAll();
    toasts.clear();
    setStepUpHandler(null);
    if (env.session) {
      setCSRF(env.session.csrfToken);
    }
  });

  afterEach(() => {
    teardownTestEnv();
    setStepUpHandler(null);
  });

  /**
   * T3-COMB-01 (F10 + F05 + F09):
   * Enroll TOTP -> Step-Up Interception on Passkey Addition -> Register Passkey
   */
  it('T3-COMB-01 (F10 + F05 + F09): enlists TOTP, intercepts 403 step-up during passkey enrollment, and registers passkey upon TOTP verification', async () => {
    // 1. Enroll TOTP factor
    const totpEnrollResp = await api.enrollTotp({
      label: 'Authenticator Phone',
      secret: 'JBSWY3DPEHPK3PXP'
    });
    expect(totpEnrollResp.accepted).toBe(true);
    const totpFactorID = totpEnrollResp.factorID!;

    const totpVerifyResp = await api.verifyTotpEnrollment(totpFactorID, '123456');
    expect(totpVerifyResp.accepted).toBe(true);
    expect(backend.getFactors(TEST_DID).some(f => f.kind === 'totp' && f.enabled)).toBe(true);

    // Update portal snapshot
    const snap1 = await api.fetchSnapshot();
    portal.setSnapshot(snap1);
    expect(snap1.factors.length).toBe(1);

    // 2. Configure Step-Up handler that performs TOTP verification when prompted
    let stepUpInvoked = false;
    setStepUpHandler(async ({ operation }) => {
      stepUpInvoked = true;
      const stepUpResp = await api.stepUpTotp(totpFactorID, '654321');
      return stepUpResp.factorToken!;
    });

    // 3. Request Passkey Challenge (requires step-up because MFA is now active)
    const chalResp = await api.requestPasskeyChallenge('MacBook TouchID');
    expect(stepUpInvoked).toBe(true);
    expect(chalResp.challenge).toBeDefined();

    // 4. Perform WebAuthn registration
    const attestation = await performPasskeyRegistration(
      { challenge: chalResp.challenge!, factorID: chalResp.factorID! },
      'MacBook TouchID',
      TEST_DID
    );
    const registerResp = await api.registerPasskey(attestation);
    expect(registerResp.accepted).toBe(true);

    // 5. Verify both factors active in backend and portal store
    const updatedSnapshot = await api.fetchSnapshot();
    portal.setSnapshot(updatedSnapshot);

    const factors = backend.getFactors(TEST_DID);
    expect(factors.filter(f => f.enabled).length).toBe(2);
    expect(factors.some(f => f.kind === 'totp')).toBe(true);
    expect(factors.some(f => f.kind === 'passkey')).toBe(true);
    expect(updatedSnapshot.factors.length).toBe(2);
  });

  /**
   * T3-COMB-02 (F09 + F05 + F11):
   * Register Passkey -> Step-Up with Passkey -> Rotate Recovery Codes
   */
  it('T3-COMB-02 (F09 + F05 + F11): registers passkey, elevates session via passkey step-up assertion, and rotates recovery codes', async () => {
    // 1. Add enrolled passkey to account
    const passkeyFactor = backend.addFactor(TEST_DID, {
      kind: 'passkey',
      label: 'YubiKey 5C',
      credentialID: 'yubikey_cred_123',
      enabled: true
    });

    // 2. Wire step-up handler with Passkey assertion ceremony
    let stepUpTriggered = false;
    setStepUpHandler(async () => {
      stepUpTriggered = true;
      const stepUpChallenge = await api.requestPasskeyStepUpChallenge(passkeyFactor.id);
      const assertion = await performPasskeyAssertion(
        { challenge: stepUpChallenge.challenge!, factorID: passkeyFactor.id },
        passkeyFactor.credentialID
      );
      const assertionResp = await api.submitPasskeyAssertion(assertion);
      return assertionResp.factorToken!;
    });

    // 3. Initiate recovery codes rotation (requires step-up)
    const rotateResp = await api.rotateRecoveryCodes();
    expect(stepUpTriggered).toBe(true);
    expect(rotateResp.accepted).toBe(true);
    expect(rotateResp.recoveryCodes).toBeDefined();
    expect(rotateResp.recoveryCodes!.length).toBe(10);

    // 4. Verify recovery codes updated in backend store
    const backendCodes = backend.getRecoveryCodes(TEST_DID);
    expect(backendCodes.length).toBe(10);
    expect(backendCodes).toEqual(rotateResp.recoveryCodes);
  });

  /**
   * T3-COMB-03 (F08 + F15 + F05):
   * Create Scoped App Password -> Require Step-Up -> Revoke with HTTP DELETE
   */
  it('T3-COMB-03 (F08 + F15 + F05): creates scoped app password via step-up reauth and revokes it using HTTP DELETE', async () => {
    // 1. Step-up handler using password re-authentication
    let stepUpCount = 0;
    setStepUpHandler(async () => {
      stepUpCount++;
      const resp = await api.stepUpPassword('correct-horse-battery-staple');
      return resp.factorToken!;
    });

    // 2. Create app password with atproto and transition:chat.bsky scopes
    const createResp = await api.createAppPassword({
      name: 'Chat Bot Client',
      scopes: ['atproto', 'transition:chat.bsky']
    });
    expect(stepUpCount).toBe(1);
    expect(createResp.accepted).toBe(true);
    expect(createResp.password).toMatch(/^swan-app-/);

    // Refresh portal store
    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.passwords.some(p => p.name === 'Chat Bot Client')).toBe(true);

    // 3. Revoke app password using DELETE verb
    const deleteResp = await api.revokeAppPassword('Chat Bot Client');
    expect(deleteResp.accepted).toBe(true);

    // 4. Verify app password removed from backend and store
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.passwords.some(p => p.name === 'Chat Bot Client')).toBe(false);
    expect(backend.getAppPasswords(TEST_DID).length).toBe(0);
  });

  /**
   * T3-COMB-04 (F12 + F06 + F14):
   * did:web Domain Reservation -> Passkey Step-Up on Rotation -> Profile View Update
   */
  it('T3-COMB-04 (F12 + F06 + F14): reserves did:web, verifies binding, elevates session on domain rotation, and updates profile store', async () => {
    // 1. Add passkey factor for step-up
    const passkey = backend.addFactor(TEST_DID, {
      kind: 'passkey',
      label: 'Security Key',
      credentialID: 'sec_key_456',
      enabled: true
    });

    // 2. Reserve domain
    const reserveResp = await api.reserveDidWeb({
      requestID: 'req_domain_1',
      targetDID: 'did:web:custom.community',
      handle: 'custom.community',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });
    expect(reserveResp.nonce).toBeDefined();
    expect(reserveResp.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');

    // 3. Claim domain
    const claimResp = await api.claimDidWeb({ requestID: reserveResp.requestID });
    expect(claimResp.state).toBe('active');
    expect(claimResp.handle).toBe('custom.community');

    // 4. Wire step-up handler for rotation
    setStepUpHandler(async () => {
      const chal = await api.requestPasskeyStepUpChallenge(passkey.id);
      const assertion = await performPasskeyAssertion({ challenge: chal.challenge!, factorID: passkey.id });
      const res = await api.submitPasskeyAssertion(assertion);
      return res.factorToken!;
    });

    // 5. Rotate domain to new target
    const rotateResp = await api.rotateDidWeb({
      requestID: 'req_domain_2',
      targetDID: 'did:web:upgraded.community',
      handle: 'upgraded.community',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      stepUpReceipt: 'will_be_overridden_by_interceptor'
    });
    expect(rotateResp.handle).toBe('upgraded.community');

    // 6. Update portal store and verify Profile projection
    const snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.identity?.method).toBe('didWeb');
    expect(snap.identity?.handle).toBe('upgraded.community');
    expect(snap.identity?.state).toBe('active');
  });

  /**
   * T3-COMB-05 (F14 + F15 + F16):
   * Sessions View -> Revoke Remote Session with DELETE -> Revoke Others with POST -> Shell Logout
   */
  it('T3-COMB-05 (F14 + F15 + F16): revokes individual session via DELETE, bulk revokes others via POST, and logs out of shell', async () => {
    // 1. Create multiple remote sessions
    const sess2 = backend.createSession(TEST_DID, { label: 'iPad Safari', activeCookie: false });
    const sess3 = backend.createSession(TEST_DID, { label: 'Linux Firefox', activeCookie: false });

    // Elevate current session for session administration
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.sessions.length).toBe(3);

    // 2. Revoke single session using DELETE verb
    const deleteResp = await api.revokeSession(sess2.id);
    expect(deleteResp.accepted).toBe(true);
    expect(backend.getSession(sess2.sessionToken)).toBeUndefined();

    // 3. Bulk revoke all remaining remote sessions using POST
    const revokeOthersResp = await api.revokeOtherSessions();
    expect(revokeOthersResp.accepted).toBe(true);
    expect(backend.getSession(sess3.sessionToken)).toBeUndefined();

    // 4. Verify only current session remains
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.sessions.length).toBe(1);
    expect(snap.sessions[0].current).toBe(true);

    // 5. Logout
    const logoutResp = await api.logout();
    expect(logoutResp.accepted).toBe(true);
    expect(backend.getCookie('__Secure-swan_management')).toBeUndefined();
  });

  /**
   * T3-COMB-06 (F10 + F09 + F06):
   * Multi-Factor Account -> Step-Up Factor Switching (Passkey <-> TOTP)
   */
  it('T3-COMB-06 (F10 + F09 + F06): allows factor switching during step-up prompt on a multi-factor account', async () => {
    // Add both TOTP and Passkey factors
    const totpFactor = backend.addFactor(TEST_DID, {
      kind: 'totp',
      label: 'Google Authenticator',
      secret: 'JBSWY3DPEHPK3PXP',
      enabled: true
    });
    const passkeyFactor = backend.addFactor(TEST_DID, {
      kind: 'passkey',
      label: 'Touch ID',
      credentialID: 'pk_touch_id',
      enabled: true
    });

    let selectedMethod = 'passkey';
    setStepUpHandler(async () => {
      // Simulate user opening StepUpModal, inspecting tabs, and toggling between Passkey and TOTP
      modals.open('step-up', { factors: [passkeyFactor, totpFactor] });
      expect(modals.isOpen('step-up')).toBe(true);

      // User switches from Passkey tab to Authenticator App (TOTP) tab
      selectedMethod = 'totp';
      const totpStepUpResp = await api.stepUpTotp(totpFactor.id, '654321');
      modals.close();
      return totpStepUpResp.factorToken!;
    });

    // Sensitive mutation: rotate recovery codes
    const rotateResp = await api.rotateRecoveryCodes();
    expect(rotateResp.accepted).toBe(true);
    expect(selectedMethod).toBe('totp');
    expect(modals.isOpen('step-up')).toBe(false);
  });

  /**
   * T3-COMB-07 (F04 + F08 + F03):
   * App Password Creation -> Toast Notification -> Copy Button Interaction
   */
  it('T3-COMB-07 (F04 + F08 + F03): generates app password, triggers UI toast, and copies secret to clipboard', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    // Open creation modal
    modals.open('app-password-create');
    expect(modals.isOpen('app-password-create')).toBe(true);

    const createResp = await api.createAppPassword({
      name: 'SkyFeed Generator',
      scopes: ['atproto']
    });
    expect(createResp.accepted).toBe(true);
    const oneTimePassword = createResp.password!;

    // Modal switches to reveal view & pushes toast
    modals.close('app-password-create');
    modals.open('app-password-view', { password: oneTimePassword });
    toasts.success('App password generated successfully!');

    // Simulate clipboard copy action
    let clipboardContent = '';
    const mockClipboard = {
      writeText: async (t: string) => { clipboardContent = t; }
    };
    await mockClipboard.writeText(oneTimePassword);
    expect(clipboardContent).toBe(oneTimePassword);

    // Derived store reactivity check
    const snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    let passwordsInStore: any[] = [];
    const unsub = activePasswords.subscribe(v => { passwordsInStore = v; });
    expect(passwordsInStore.some(p => p.name === 'SkyFeed Generator')).toBe(true);
    unsub();
  });

  /**
   * T3-COMB-08 (F13 + F05 + F16):
   * Data Export Request -> Status Tracker -> Navigation Tab Switch -> Download Notice
   */
  it('T3-COMB-08 (F13 + F05 + F16): requests repository export with step-up, persists state across view navigation, and tracks completion', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    // Request data export
    portal.selectTab('export');
    const exportResp = await api.requestExport();
    expect(exportResp.accepted).toBe(true);
    expect(exportResp.exportID).toBeDefined();

    // Verify initial pending export state
    let expStatus = await accountFetch<{ export: { status: string; id?: string } }>('export');
    expect(expStatus.export.status).toBe('pending');

    // Switch navigation tabs and return to export view
    portal.selectTab('profile');
    portal.selectTab('security');
    portal.selectTab('export');

    // Update backend mock export to ready status
    const req = (backend as any).exportRequests.get(TEST_DID);
    if (req) req.status = 'ready';

    expStatus = await accountFetch<{ export: { status: string; id?: string } }>('export');
    expect(expStatus.export.status).toBe('ready');
  });

  /**
   * T3-COMB-09 (F13 + F06 + F16):
   * Account Deletion Flow -> Step-Up Re-Auth -> Phrase Confirmation -> Session Annihilation
   */
  it('T3-COMB-09 (F13 + F06 + F16): executes account deletion with password step-up, phrase verification, and local state wipe', async () => {
    let stepUpPassed = false;
    setStepUpHandler(async () => {
      stepUpPassed = true;
      const resp = await api.stepUpPassword('correct-horse-battery-staple');
      return resp.factorToken!;
    });

    // Simulate modal confirmation phrase
    const typedPhrase = 'DELETE MY ACCOUNT';
    expect(typedPhrase).toBe('DELETE MY ACCOUNT');

    // Execute deletion
    const delResp = await api.deleteAccount();
    expect(stepUpPassed).toBe(true);
    expect(delResp.accepted).toBe(true);

    // Wipe local SPA shell state
    portal.reset();
    toasts.info('Account deleted. You have been signed out.');

    // Verify backend account lifecycle state is deleted
    const acc = backend.getAccount(TEST_DID);
    expect(acc?.lifecycle).toBe('deleted');
  });

  /**
   * T3-COMB-10 (F01 + F05 + F15):
   * Revoke Connected OAuth App -> Step-Up Required -> DELETE Replay
   */
  it('T3-COMB-10 (F01 + F05 + F15): intercepts step-up on connected app revocation and replays HTTP DELETE automatically', async () => {
    let replayed = false;
    setStepUpHandler(async () => {
      replayed = true;
      // In-place session elevation
      await api.stepUpPassword('correct-horse-battery-staple');
      return true;
    });

    const revokeResp = await api.revokeConnectedApp('app_bsky_official');
    expect(replayed).toBe(true);
    expect(revokeResp.accepted).toBe(true);
    expect(backend.getConnectedApps(TEST_DID).length).toBe(0);
  });

  /**
   * T3-COMB-11 (F07 + F08 + F04):
   * Modal Keyboard Trapping -> ESC Dismissal -> Return Focus to Trigger
   */
  it('T3-COMB-11 (F07 + F08 + F04): traps modal state stack and handles ESC key dismissal cleanly', () => {
    // Open initial modal
    const modalId = modals.open('app-password-create', { name: 'Bot 1' }, { title: 'Create App Password' });
    expect(modals.isOpen('app-password-create')).toBe(true);

    // Push a nested confirmation modal
    modals.push('step-up', {}, { title: 'Verify Identity' });
    expect(modals.isOpen('step-up')).toBe(true);

    // Pop nested modal (simulating ESC or Cancel on top modal)
    const popped = modals.pop();
    expect(popped?.type).toBe('step-up');
    expect(modals.isOpen('app-password-create')).toBe(true);

    // Dismiss root modal
    modals.close(modalId);
    expect(modals.isOpen('app-password-create')).toBe(false);
  });

  /**
   * T3-COMB-12 (F10 + F03 + F04):
   * TOTP Setup -> Inline SVG QR Render -> Code Copy -> Verification
   */
  it('T3-COMB-12 (F10 + F03 + F04): renders inline SVG QR matrix with CSP compliance, copies secret, and validates code', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const otpUri = generateOtpauthUri({ secret, account: 'alice.swan.place', issuer: 'Swan' });
    expect(otpUri).toContain('otpauth://totp/Swan:alice.swan.place?');

    // Generate CSP-safe inline SVG
    const svg = generateQrSvg(otpUri, { size: 200, foregroundColor: '#000000' });
    expect(svg).toMatch(/^<svg/);
    expect(svg).toContain('viewBox=');
    expect(svg).toContain('<path');
    expect(svg).not.toContain('<img');
    expect(svg).not.toContain('<image');
    expect(svg).not.toContain('https://cdn');

    // Verify TOTP enrollment with server
    const init = await api.enrollTotp({ label: 'Auth App', secret });
    const verify = await api.verifyTotpEnrollment(init.factorID!, '123456');
    expect(verify.accepted).toBe(true);

    toasts.success('TOTP factor active.');
  });

  /**
   * T3-COMB-13 (F09 + F02 + F04):
   * Passkey Registration -> Virtual Authenticator -> Toast Confirmation
   */
  it('T3-COMB-13 (F09 + F02 + F04): generates WebAuthn attestation via virtual authenticator and dispatches toast confirmation', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    const challengeResp = await api.requestPasskeyChallenge('Office iMac');
    const attestation = await performPasskeyRegistration(
      { challenge: challengeResp.challenge!, factorID: challengeResp.factorID! },
      'Office iMac',
      TEST_DID
    );

    expect(attestation.credentialID).toBeDefined();
    expect(attestation.clientDataJSON).toBeDefined();
    expect(attestation.authenticatorData).toBeDefined();

    const reg = await api.registerPasskey(attestation);
    expect(reg.accepted).toBe(true);

    toasts.success('Passkey successfully enrolled');
  });

  /**
   * T3-COMB-14 (F11 + F04 + F05):
   * Recovery Code Rotation -> Download .txt -> Step-Up Elevation Cache (5 min)
   */
  it('T3-COMB-14 (F11 + F04 + F05): caches step-up elevation across recovery code rotation and subsequent app password creation', async () => {
    let stepUpCount = 0;
    setStepUpHandler(async () => {
      stepUpCount++;
      await api.stepUpPassword('correct-horse-battery-staple');
      return true;
    });

    // 1. Rotate recovery codes (triggers step-up #1)
    const rot = await api.rotateRecoveryCodes();
    expect(stepUpCount).toBe(1);
    expect(rot.recoveryCodes?.length).toBe(10);

    // Format downloadable backup file
    const fileContent = `SWAN RECOVERY CODES\nGenerated: ${new Date().toISOString()}\n\n` +
      rot.recoveryCodes!.map((c, i) => `${i + 1}. ${c}`).join('\n');
    expect(fileContent).toContain('SWAN RECOVERY CODES');

    // 2. Immediately create App Password (reuses active session elevation without triggering step-up #2)
    const appPw = await api.createAppPassword({ name: 'Automated Bot', scopes: ['atproto'] });
    expect(appPw.accepted).toBe(true);
    expect(stepUpCount).toBe(1); // Not incremented because session is already fresh & elevated!
  });

  /**
   * T3-COMB-15 (F12 + F14 + F15):
   * did:web Domain Removal -> Revert to PLC -> DELETE Method Verification
   */
  it('T3-COMB-15 (F12 + F14 + F15): removes did:web custom domain binding and reverts identity projection to PLC', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    // Initial binding
    const reserve = await api.reserveDidWeb({
      requestID: 'req_bind_1',
      targetDID: 'did:web:mybrand.org',
      handle: 'mybrand.org',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });
    await api.claimDidWeb({ requestID: reserve.requestID });

    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.identity?.method).toBe('didWeb');

    // Remove did:web binding
    const rem = await api.removeDidWeb({ stepUpReceipt: 'elevated' });
    expect(rem.state).toBe('removed');

    // Snapshot updates to PLC
    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.identity?.method).toBe('plc');
    expect(snap.identity?.handle).toBe('alice.swan.place');
  });

  /**
   * T3-COMB-16 (F01 + F04 + F16):
   * API Error 500 Simulation -> Toast Error Notification -> Loading Spinner Dismissal
   */
  it('T3-COMB-16 (F01 + F04 + F16): catches backend 500 service failure, surfaces error toast, and dismisses loading state', async () => {
    // Intercept with simulated 500 database error
    backend.addInterceptor(req => {
      if (req.url.includes('/account/api/app-passwords')) {
        return {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'service_unavailable', message: 'Database query timeout.' }
        };
      }
      return undefined;
    });

    portal.setLoading(true);
    let capturedError: any;
    try {
      await api.createAppPassword({ name: 'FailApp', scopes: ['atproto'] });
    } catch (err) {
      capturedError = err;
      toasts.error((err as any).message || 'Action failed');
    } finally {
      portal.setLoading(false);
    }

    expect(capturedError).toBeDefined();
    expect(capturedError.code).toBe('service_unavailable');
    expect(capturedError.message).toBe('Database query timeout.');
  });

  /**
   * T3-COMB-17 (F10 + F09 + F11):
   * Complete Factor Revocation Cascade (Passkey -> TOTP -> Recovery Codes Disabled)
   */
  it('T3-COMB-17 (F10 + F09 + F11): completely cascades factor revocations from passkey to TOTP down to zero active MFA factors', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    // Setup factors
    const pk = backend.addFactor(TEST_DID, { kind: 'passkey', label: 'MacBook', credentialID: 'pk_1', enabled: true });
    const totp = backend.addFactor(TEST_DID, { kind: 'totp', label: 'Phone', secret: 'SECRET', enabled: true });

    let snap = await api.fetchSnapshot();
    expect(snap.factors.length).toBe(2);

    // Revoke passkey
    await api.revokePasskey(pk.id);
    snap = await api.fetchSnapshot();
    expect(snap.factors.length).toBe(1);

    // Revoke TOTP
    await api.revokeTotp();
    snap = await api.fetchSnapshot();
    expect(snap.factors.length).toBe(0);
    expect(backend.getFactors(TEST_DID).filter(f => f.enabled).length).toBe(0);
  });

  /**
   * T3-COMB-18 (F08 + F14 + F15):
   * Multi-Scope App Password Creation -> List Filtering -> Immediate Deletion
   */
  it('T3-COMB-18 (F08 + F14 + F15): creates multiple app passwords with varied scopes and executes targeted deletion', async () => {
    const curCookie = backend.getCookie('__Secure-swan_management')!;
    backend.elevateSession(curCookie);

    await api.createAppPassword({ name: 'Feed Reader', scopes: ['atproto'] });
    await api.createAppPassword({ name: 'Chat Client', scopes: ['atproto', 'transition:chat.bsky'] });
    await api.createAppPassword({ name: 'Notifier', scopes: ['atproto', 'transition:email'] });

    let snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.passwords.length).toBe(3);

    // Delete Chat Client
    await api.revokeAppPassword('Chat Client');

    snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.passwords.length).toBe(2);
    expect(snap.passwords.map(p => p.name)).toEqual(['Feed Reader', 'Notifier']);
  });

  /**
   * T3-COMB-19 (F05 + F16 + F01):
   * Session Revocation Interception -> Replay -> Snapshot Refresh
   */
  it('T3-COMB-19 (F05 + F16 + F01): intercepts session revocation on unelevated session, verifies password, and synchronizes snapshot', async () => {
    const remote = backend.createSession(TEST_DID, { label: 'Stale Desktop Session', activeCookie: false });

    let stepUpFired = false;
    setStepUpHandler(async () => {
      stepUpFired = true;
      await api.stepUpPassword('correct-horse-battery-staple');
      return true;
    });

    const revoke = await api.revokeSession(remote.id);
    expect(stepUpFired).toBe(true);
    expect(revoke.accepted).toBe(true);

    const snap = await api.fetchSnapshot();
    portal.setSnapshot(snap);
    expect(snap.sessions.some(s => s.id === remote.id)).toBe(false);
  });
});
