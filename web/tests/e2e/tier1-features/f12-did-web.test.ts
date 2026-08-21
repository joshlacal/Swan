import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F12: did:web Domain Wizard Modal', () => {
  let backend: MockSwanBackend;
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

  it('T1-F12-01: reserveDidWeb initiates domain reservation and returns nonce and claim endpoint', async () => {
    const reserveReq = {
      requestID: 'req_test_123',
      targetDID: 'did:web:custom.alice.io',
      handle: 'custom.alice.io',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    };

    const reservation = await api.reserveDidWeb(reserveReq);

    expect(reservation).toBeDefined();
    expect(reservation.requestID).toBe('req_test_123');
    expect(reservation.nonce).toBeDefined();
    expect(reservation.nonce!.length).toBeGreaterThan(0);
    expect(reservation.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');
  });

  it('T1-F12-02: Public claim endpoint serves verification payload without authentication', async () => {
    const reservation = await api.reserveDidWeb({
      requestID: 'req_claim_check',
      targetDID: 'did:web:public.alice.io',
      handle: 'public.alice.io',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });

    // Unauthenticated fetch directly to the public claim endpoint
    backend.clearCookies();
    const publicResp = await fetch(reservation.claimEndpoint!);

    expect(publicResp.status).toBe(200);
    const body = await publicResp.json();
    expect(body.nonce).toBe(reservation.nonce);
    expect(body.targetDID).toBe('did:web:public.alice.io');
  });

  it('T1-F12-03: claimDidWeb verifies claim and binds custom domain to account', async () => {
    const reservation = await api.reserveDidWeb({
      requestID: 'req_bind_flow',
      targetDID: 'did:web:verified.alice.io',
      handle: 'verified.alice.io',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });

    const binding = await api.claimDidWeb({
      requestID: reservation.requestID
    });

    expect(binding).toBeDefined();
    expect(binding.state).toBe('active');
    expect(binding.handle).toBe('verified.alice.io');
    expect(binding.did).toBe('did:web:verified.alice.io');
  });

  it('T1-F12-04: rotateDidWeb updates domain binding with step-up elevation verification', async () => {
    const rotateReq = {
      requestID: 'req_rotate',
      targetDID: 'did:web:new.alice.io',
      handle: 'new.alice.io',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      stepUpReceipt: 'receipt_rotate'
    };

    const rotated = await api.rotateDidWeb(rotateReq);

    expect(rotated).toBeDefined();
    expect(rotated.state).toBe('active');
    expect(rotated.handle).toBe('new.alice.io');
    expect(rotated.did).toBe('did:web:new.alice.io');
  });

  it('T1-F12-05: removeDidWeb removes custom domain binding and reverts to default identity', async () => {
    const removeResult = await api.removeDidWeb({
      stepUpReceipt: 'receipt_remove'
    });

    expect(removeResult).toBeDefined();
    expect(removeResult.state).toBe('removed');
  });
});
