import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { generateOtpauthUri, generateQrSvg } from '../../../src/lib/qrcode';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F10: TOTP Enrollment Modal', () => {
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

  it('T1-F10-01: enrollTotp initiates TOTP enrollment and receives factor ID', async () => {
    const result = await api.enrollTotp({
      label: 'Google Authenticator',
      secret: 'JBSWY3DPEHPK3PXP'
    });

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.factorID).toBeDefined();
    expect(result.message).toBe('TOTP enrollment pending verification');
  });

  it('T1-F10-02: Generates valid otpauth URI and inline SVG QR code for authenticator setup', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const uri = generateOtpauthUri({
      account: 'alice.swan.place',
      secret,
      issuer: 'Swan',
      digits: 6,
      period: 30
    });

    expect(uri).toContain('otpauth://totp/Swan:alice.swan.place');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');

    const svg = generateQrSvg(uri, { size: 180, title: 'Scan TOTP' });
    expect(svg).toContain('<svg');
    expect(svg).toContain('viewBox=');
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="Scan TOTP"');
  });

  it('T1-F10-03: verifyTotpEnrollment verifies 6-digit code and activates factor', async () => {
    const init = await api.enrollTotp({
      label: '1Password TOTP',
      secret: 'JBSWY3DPEHPK3PXP'
    });

    const verifyResult = await api.verifyTotpEnrollment(init.factorID!, '123456');

    expect(verifyResult).toBeDefined();
    expect(verifyResult.accepted).toBe(true);
    expect(verifyResult.message).toBe('TOTP factor enrolled');
  });

  it('T1-F10-04: Successful TOTP enrollment registers enabled factor in portal snapshot', async () => {
    const init = await api.enrollTotp({
      label: 'Authenticator App',
      secret: 'JBSWY3DPEHPK3PXP'
    });

    await api.verifyTotpEnrollment(init.factorID!, '654321');

    const factors = backend.getFactors(session.accountDID);
    const totpFactor = factors.find((f) => f.id === init.factorID);
    expect(totpFactor).toBeDefined();
    expect(totpFactor?.kind).toBe('totp');
    expect(totpFactor?.enabled).toBe(true);
    expect(totpFactor?.label).toBe('Authenticator App');
  });

  it('T1-F10-05: revokeTotp sends HTTP DELETE to remove TOTP factor from account', async () => {
    backend.addFactor(session.accountDID, {
      kind: 'totp',
      label: 'Old Authenticator',
      secret: 'OLDSECRET123',
      enabled: true
    });

    expect(backend.getFactors(session.accountDID).some((f) => f.kind === 'totp')).toBe(true);

    const result = await api.revokeTotp();

    expect(result.accepted).toBe(true);
    expect(result.message).toBe('Authentication factor revoked');
    expect(backend.getFactors(session.accountDID).some((f) => f.kind === 'totp')).toBe(false);
  });
});
