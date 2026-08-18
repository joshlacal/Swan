import { describe, expect, it, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { modals, activeModal } from './modals';

describe('modals store', () => {
  beforeEach(() => {
    modals.closeAll();
  });

  it('initializes with no active modal', () => {
    expect(get(modals)).toEqual({ active: null, stack: [] });
    expect(get(activeModal)).toBeNull();
  });

  it('opens a single modal and sets it as active', () => {
    const id = modals.open('app-password-create', { defaultScope: 'atproto' }, { title: 'New Password' });
    const state = get(modals);

    expect(state.active).not.toBeNull();
    expect(state.active?.id).toBe(id);
    expect(state.active?.type).toBe('app-password-create');
    expect(state.active?.payload).toEqual({ defaultScope: 'atproto' });
    expect(state.active?.title).toBe('New Password');
    expect(state.stack.length).toBe(1);
    expect(get(activeModal)?.id).toBe(id);
  });

  it('pushes a modal onto the stack and sets active to topmost', () => {
    const id1 = modals.open('app-password-create');
    const id2 = modals.push('step-up', { reason: 'password_required' });

    const state = get(modals);
    expect(state.stack.length).toBe(2);
    expect(state.active?.id).toBe(id2);
    expect(state.active?.type).toBe('step-up');

    const popped = modals.pop();
    expect(popped?.id).toBe(id2);

    const afterPop = get(modals);
    expect(afterPop.stack.length).toBe(1);
    expect(afterPop.active?.id).toBe(id1);
  });

  it('closes a modal by type or id', () => {
    modals.open('did-web');
    modals.push('step-up');

    modals.close('step-up');
    expect(get(modals).stack.length).toBe(1);
    expect(get(modals).active?.type).toBe('did-web');

    modals.close();
    expect(get(modals).stack.length).toBe(0);
    expect(get(modals).active).toBeNull();
  });

  it('closes all modals', () => {
    modals.open('export');
    modals.push('step-up');
    expect(get(modals).stack.length).toBe(2);

    modals.closeAll();
    expect(get(modals).stack.length).toBe(0);
    expect(get(modals).active).toBeNull();
  });

  it('checks if a specific modal is open', () => {
    expect(modals.isOpen('totp-enroll')).toBe(false);
    modals.open('totp-enroll');
    expect(modals.isOpen('totp-enroll')).toBe(true);
    modals.closeAll();
    expect(modals.isOpen('totp-enroll')).toBe(false);
  });
});
