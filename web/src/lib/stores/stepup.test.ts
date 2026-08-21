import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { stepup } from './stepup';
import { modals } from './modals';
import { portal } from './portal';
import { accountFetch, setCSRF, setStepUpHandler } from '../api';

describe('Step-Up Re-Authentication Store (stepup.ts)', () => {
  beforeEach(() => {
    stepup.reset();
    modals.closeAll();
    portal.reset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('initializes in closed idle state with default factors', () => {
    const state = get(stepup);
    expect(state.isOpen).toBe(false);
    expect(state.context).toBeNull();
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
    expect(state.allowedFactors).toEqual(['password']);
  });

  it('requestStepUp opens dialog and resolves when resolveStepUp is called', async () => {
    const promise = stepup.requestStepUp({ operation: 'app-passwords' });

    const state = get(stepup);
    expect(state.isOpen).toBe(true);
    expect(state.context?.operation).toBe('app-passwords');
    expect(modals.isOpen('step-up')).toBe(true);

    stepup.resolveStepUp('receipt-token-abc');
    const result = await promise;

    expect(result).toBe('receipt-token-abc');
    expect(get(stepup).isOpen).toBe(false);
    expect(modals.isOpen('step-up')).toBe(false);
  });

  it('requestStepUp resolves with true when in-place session elevation succeeds', async () => {
    const promise = stepup.requestStepUp({ operation: 'recovery-rotate' });
    stepup.resolveStepUp(true);
    const result = await promise;

    expect(result).toBe(true);
    expect(get(stepup).isOpen).toBe(false);
  });

  it('requestStepUp rejects when cancelStepUp is called by user', async () => {
    const promise = stepup.requestStepUp({ operation: 'delete-account' });
    expect(get(stepup).isOpen).toBe(true);

    stepup.cancelStepUp('User closed step-up dialog');

    await expect(promise).rejects.toThrow('User closed step-up dialog');
    expect(get(stepup).isOpen).toBe(false);
    expect(modals.isOpen('step-up')).toBe(false);
  });

  it('coalesces multiple concurrent step-up requests into a single prompt and resolves all', async () => {
    const p1 = stepup.requestStepUp({ operation: 'op-1' });
    const p2 = stepup.requestStepUp({ operation: 'op-2' });
    const p3 = stepup.requestStepUp({ operation: 'op-3' });

    expect(get(stepup).isOpen).toBe(true);

    stepup.resolveStepUp('shared-receipt-123');

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    expect(r1).toBe('shared-receipt-123');
    expect(r2).toBe('shared-receipt-123');
    expect(r3).toBe('shared-receipt-123');
    expect(get(stepup).isOpen).toBe(false);
  });

  it('coalesces multiple concurrent step-up requests and rejects all on cancel', async () => {
    const p1 = stepup.requestStepUp({ operation: 'op-1' });
    const p2 = stepup.requestStepUp({ operation: 'op-2' });

    stepup.cancelStepUp('Cancelled by user');

    await expect(p1).rejects.toThrow('Cancelled by user');
    await expect(p2).rejects.toThrow('Cancelled by user');
    expect(get(stepup).isOpen).toBe(false);
  });

  it('dynamically computes allowed factors from active factors in portal store', () => {
    portal.setSnapshot({
      account: { did: 'did:plc:test', handle: 'test', lifecycle: 'active' },
      strength: 'password',
      factors: [
        { id: 'f-totp', kind: 'totp', label: 'Auth App', enabled: true },
        { id: 'f-pk', kind: 'passkey', label: 'Key', enabled: true }
      ],
      sessions: [],
      apps: [],
      passwords: []
    });

    stepup.requestStepUp();
    const state = get(stepup);
    expect(state.allowedFactors).toContain('password');
    expect(state.allowedFactors).toContain('totp');
    expect(state.allowedFactors).toContain('recoveryCode');
  });

  it('supports factor selection, loading state, and error updates', () => {
    stepup.requestStepUp();
    stepup.selectFactor('totp');
    expect(get(stepup).selectedFactor).toBe('totp');

    stepup.setLoading(true);
    expect(get(stepup).loading).toBe(true);

    stepup.setError('Invalid code');
    expect(get(stepup).error).toBe('Invalid code');
    expect(get(stepup).loading).toBe(false);

    stepup.selectFactor('password');
    expect(get(stepup).error).toBeNull();
  });
});
