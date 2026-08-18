import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, setCSRF } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 2 Boundary: Account Lifecycle, Factor Revocations, Identity & Data Export', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
  });

  // --- Idempotent Deletions & Factor Revocations ---

  it('T2-LIFE-01: revoking nonexistent session ID returns 200 OK idempotently', async () => {
    const res = await api.revokeSession('non_existent_session_id_999');
    expect(res.accepted).toBe(true);
  });

  it('T2-LIFE-02: revoking other sessions when only 1 session exists leaves current session active', async () => {
    const res = await api.revokeOtherSessions();
    expect(res.accepted).toBe(true);
    expect(backend.getSession(session.sessionToken)).toBeDefined();
  });

  it('T2-LIFE-03: revoking nonexistent connected app returns 200 OK idempotently', async () => {
    const res = await api.revokeConnectedApp('app_nonexistent_xyz');
    expect(res.accepted).toBe(true);
  });

  it('T2-LIFE-04: revoking nonexistent passkey factor returns 200 OK idempotently', async () => {
    const res = await api.revokePasskey('pk_nonexistent_123');
    expect(res.accepted).toBe(true);
  });

  it('T2-LIFE-05: revoking TOTP factor when none is active returns 200 OK', async () => {
    const res = await api.revokeTotp();
    expect(res.accepted).toBe(true);
  });

  it('T2-LIFE-06: revoking last MFA factor removes factor from account state', async () => {
    const factor = backend.addFactor(session.accountDID, {
      kind: 'passkey',
      label: 'Security Key',
      credentialID: 'cred_last_key'
    });

    expect(backend.getFactors(session.accountDID).length).toBe(1);

    const res = await api.revokePasskey(factor.id);
    expect(res.accepted).toBe(true);
    expect(backend.getFactors(session.accountDID).length).toBe(0);
  });

  it('T2-LIFE-07: rotating recovery codes invalidates old codes and replaces with new set', async () => {
    backend.setRecoveryCodes(session.accountDID, ['OLD-CODE-1', 'OLD-CODE-2']);

    const res = await api.rotateRecoveryCodes();
    expect(res.accepted).toBe(true);
    const newCodes = (res as any).recoveryCodes as string[];
    expect(newCodes.length).toBe(10);
    expect(newCodes).not.toContain('OLD-CODE-1');
    expect(backend.getRecoveryCodes(session.accountDID)).toEqual(newCodes);
  });

  // --- Enrollment Error Boundaries ---

  it('T2-LIFE-08: TOTP verification rejects code with invalid length (<6 digits)', async () => {
    // Initiate TOTP
    const initRes = await api.enrollTotp({ secret: 'JBSWY3DPEHPK3PXP' });
    const factorID = (initRes as any).factorID;

    try {
      await api.verifyTotpEnrollment(factorID, '123'); // 3 digits
      expect.unreachable('Should have rejected invalid TOTP code length');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-LIFE-09: TOTP verification rejects non-existent factorID', async () => {
    try {
      await api.verifyTotpEnrollment('totp_ghost_factor', '123456');
      expect.unreachable('Should have rejected nonexistent factorID');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-LIFE-10: Passkey registration rejects payload missing required credentialID or factorID', async () => {
    try {
      await accountFetch('factors/passkeys', {
        method: 'POST',
        body: JSON.stringify({ label: 'Missing ID Key' }) // missing factorID & credentialID
      });
      expect.unreachable('Should have rejected missing fields');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
    }
  });

  // --- Account Deactivation, Deletion & Lifecycle Boundaries ---

  it('T2-LIFE-11: account deactivation updates account lifecycle to deactivated', async () => {
    const res = await accountFetch<{ accepted: boolean }>('lifecycle/deactivate', {
      method: 'POST',
      body: '{}'
    });

    expect(res.accepted).toBe(true);
    const account = backend.getAccount(session.accountDID);
    expect(account?.lifecycle).toBe('deactivated');
  });

  it('T2-LIFE-12: account deletion under elevated session marks lifecycle as deleted', async () => {
    const res = await api.deleteAccount();
    expect(res.accepted).toBe(true);

    const account = backend.getAccount(session.accountDID);
    expect(account?.lifecycle).toBe('deleted');
  });

  it('T2-LIFE-13: login attempt on deleted account is rejected with 401 authentication_required', async () => {
    const account = backend.getAccount(session.accountDID)!;
    account.lifecycle = 'deleted';

    // Clear session to attempt fresh login
    backend.clearCookies();
    const boot = await (await fetch('/account/api/bootstrap')).json();

    const resp = await fetch('/account/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Swan-CSRF': boot.csrf },
      body: JSON.stringify({ handle: account.handle, password: account.password })
    });

    expect(resp.status).toBe(401);
    const data = await resp.json();
    expect(data.code).toBe('authentication_required');
    expect(data.message).toContain('deleted');
  });

  // --- did:web Custom Domain Identity Lifecycle Boundaries ---

  it('T2-LIFE-14: did:web reservation generates nonce, claimEndpoint, and valid claimPayload', async () => {
    const res = await api.reserveDidWeb({ handle: 'custom.alice.io' });

    expect(res.requestID).toBeDefined();
    expect(res.nonce).toBeDefined();
    expect(res.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');
    expect(res.claimPayload).toBeDefined();

    const payload = JSON.parse(res.claimPayload!);
    expect(payload.did).toBe('did:web:custom.alice.io');
    expect(payload.handle).toBe('custom.alice.io');
  });

  it('T2-LIFE-15: did:web public claim endpoint serves JSON claim verification document', async () => {
    const res = await api.reserveDidWeb({ handle: 'verify.alice.io' });

    // Public endpoint fetch
    backend.clearCookies();
    const publicResp = await fetch(res.claimEndpoint!);
    expect(publicResp.status).toBe(200);

    const claimData = await publicResp.json();
    expect(claimData.nonce).toBe(res.nonce);
    expect(claimData.targetDID).toBe('did:web:verify.alice.io');
  });

  it('T2-LIFE-16: did:web claim binding updates account identity to active did:web method', async () => {
    const reserve = await api.reserveDidWeb({ handle: 'bound.alice.io' });
    const claimRes = await api.claimDidWeb({ requestID: reserve.requestID! });

    expect(claimRes.state).toBe('active');
    expect(claimRes.handle).toBe('bound.alice.io');
    expect(claimRes.did).toBe('did:web:bound.alice.io');

    const snap = await api.fetchSnapshot();
    expect(snap.identity?.method).toBe('didWeb');
    expect(snap.identity?.handle).toBe('bound.alice.io');
  });

  it('T2-LIFE-17: claiming already consumed did:web reservation returns 400 invalid_request', async () => {
    const reserve = await api.reserveDidWeb({ handle: 'once.alice.io' });

    // First claim succeeds
    await api.claimDidWeb({ requestID: reserve.requestID });

    // Replay fails
    try {
      await api.claimDidWeb({ requestID: reserve.requestID });
      expect.unreachable('Should have rejected consumed reservation');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toContain('already consumed');
    }
  });

  it('T2-LIFE-18: claiming nonexistent reservation returns 404 not_found', async () => {
    try {
      await api.claimDidWeb({ requestID: 'req_ghost_12345' });
      expect.unreachable('Should have rejected nonexistent reservation');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.code).toBe('not_found');
    }
  });

  it('T2-LIFE-19: rotating did:web identity without step-up returns 403 step_up_required', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    try {
      await accountFetch('identity/rotate', {
        method: 'POST',
        body: JSON.stringify({ handle: 'new-domain.com' })
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for identity rotation');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-LIFE-20: rotating did:web identity under elevated session updates handle and timestamp', async () => {
    const res = await api.rotateDidWeb({ handle: 'rotated.alice.org' });
    expect(res.state).toBe('active');
    expect(res.handle).toBe('rotated.alice.org');
    expect(res.did).toBe('did:web:rotated.alice.org');
    expect(res.verifiedAt).toBeDefined();
  });

  it('T2-LIFE-21: removing did:web identity without step-up returns 403 step_up_required', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    try {
      await accountFetch('identity/remove', {
        method: 'POST',
        body: JSON.stringify({ did: 'did:web:alice.com' })
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for identity removal');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-LIFE-22: removing did:web identity under elevated session marks state as removed', async () => {
    const res = await api.removeDidWeb({ did: 'did:web:bound.alice.io' });
    expect(res.state).toBe('removed');
  });

  it('T2-LIFE-23: reverifying did:web identity returns active binding', async () => {
    const res = await api.reverifyDidWeb();
    expect(res.state).toBe('active');
    expect(res.verifiedAt).toBeDefined();
  });

  it('T2-LIFE-24: queries did:web admission status successfully', async () => {
    const res = await api.getDidWebAdmission();
    expect(res.admitted).toBe(true);
    expect(res.method).toBe('didWeb');
    expect(res.state).toBe('active');
  });

  // --- Data Export Request Boundaries ---

  it('T2-LIFE-25: data export request without step-up returns 403 step_up_required', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    try {
      await accountFetch('export/request', {
        method: 'POST',
        body: '{}'
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for export request');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-LIFE-26: data export request under elevated session creates export job', async () => {
    const res = await api.requestExport();
    expect(res.accepted).toBe(true);
    expect((res as any).exportID).toMatch(/^exp_/);

    const exportStatus = await accountFetch<{ export: any }>('export');
    expect(exportStatus.export.status).toBe('pending');
    expect(exportStatus.export.accountDID).toBe(session.accountDID);
  });
});
