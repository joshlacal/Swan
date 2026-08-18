import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { activeModal, modals } from '../../../src/lib/stores/modals';

describe('Tier 1 - F07: Accessible Modal Dialog Base', () => {
  beforeEach(() => {
    modals.closeAll();
  });

  it('T1-F07-01: Modal manager creates accessible modal instance with unique ID, type, and title', () => {
    const id = modals.open('app-password-create', { defaultScopes: ['atproto'] }, { title: 'Create App Password' });

    const active = get(activeModal);
    expect(active).not.toBeNull();
    expect(active?.id).toBe(id);
    expect(active?.type).toBe('app-password-create');
    expect(active?.title).toBe('Create App Password');
    expect(active?.createdAt).toBeGreaterThan(0);
    expect(active?.payload).toEqual({ defaultScopes: ['atproto'] });
  });

  it('T1-F07-02: Modal stack handles nested dialog workflows using push and pop', () => {
    const parentId = modals.open('app-password-create', { name: 'Bot' });
    expect(get(modals).stack.length).toBe(1);

    // Push step-up modal on top of create modal
    const stepUpId = modals.push('step-up', { operation: 'app-passwords.create' });
    expect(get(modals).stack.length).toBe(2);
    expect(get(activeModal)?.id).toBe(stepUpId);
    expect(get(activeModal)?.type).toBe('step-up');

    // Popping restores the parent modal
    const popped = modals.pop();
    expect(popped?.id).toBe(stepUpId);
    expect(get(modals).stack.length).toBe(1);
    expect(get(activeModal)?.id).toBe(parentId);
    expect(get(activeModal)?.type).toBe('app-password-create');
  });

  it('T1-F07-03: Targeted modal dismissal by ID or type removes only that modal from stack', () => {
    const m1 = modals.push('totp-enroll');
    const m2 = modals.push('passkey-enroll');
    const m3 = modals.push('did-web');

    expect(get(modals).stack.length).toBe(3);

    // Dismiss middle modal by type
    modals.close('passkey-enroll');
    const remaining = get(modals).stack;
    expect(remaining.length).toBe(2);
    expect(remaining.map((m) => m.id)).toEqual([m1, m3]);
    expect(get(activeModal)?.id).toBe(m3);

    // Dismiss active modal by calling close() without args
    modals.close();
    expect(get(modals).stack.length).toBe(1);
    expect(get(activeModal)?.id).toBe(m1);
  });

  it('T1-F07-04: isOpen check accurately identifies active modal types in the stack', () => {
    expect(modals.isOpen('recovery-rotate')).toBe(false);

    modals.open('recovery-rotate');
    expect(modals.isOpen('recovery-rotate')).toBe(true);
    expect(modals.isOpen('totp-enroll')).toBe(false);

    modals.push('totp-enroll');
    expect(modals.isOpen('recovery-rotate')).toBe(true);
    expect(modals.isOpen('totp-enroll')).toBe(true);

    modals.closeAll();
    expect(modals.isOpen('recovery-rotate')).toBe(false);
    expect(modals.isOpen('totp-enroll')).toBe(false);
  });

  it('T1-F07-05: Modal payload is reactively updated and accessible to subscribers', () => {
    let observedPayload: any = null;
    const unsubscribe = activeModal.subscribe((modal) => {
      observedPayload = modal?.payload;
    });

    modals.open('export', { initialProgress: 0, exportFormat: 'car' });
    expect(observedPayload).toEqual({ initialProgress: 0, exportFormat: 'car' });

    modals.open('lifecycle-delete', { confirmHandle: 'alice.swan.place' });
    expect(observedPayload).toEqual({ confirmHandle: 'alice.swan.place' });

    modals.closeAll();
    expect(observedPayload).toBeUndefined();

    unsubscribe();
  });
});
