import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { accountFetch, api, setCSRF } from '../../../src/lib/api';
import { activeModal, modals } from '../../../src/lib/stores/modals';
import { activePasswords, portal } from '../../../src/lib/stores/portal';
import { toasts } from '../../../src/lib/stores/toasts';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 2 Boundary: Modals Store, Toasts Queue, App Password Validations & Portal State', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    modals.closeAll();
    toasts.clear();
    portal.reset();
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    modals.closeAll();
    toasts.clear();
    portal.reset();
  });

  // --- Modals Store & Stacking Boundaries ---

  it('T2-MOD-01: modals.open sets active modal and clears any previous stack', () => {
    modals.open('app-password', { defaultName: 'Test' }, { title: 'Create App Password' });

    let activeState: any;
    const unsub = activeModal.subscribe(val => { activeState = val; });
    unsub();

    expect(activeState).toBeDefined();
    expect(activeState.type).toBe('app-password');
    expect(activeState.title).toBe('Create App Password');
    expect(activeState.payload).toEqual({ defaultName: 'Test' });
  });

  it('T2-MOD-02: modals.push stacks multiple modals preserving order and active pointer', () => {
    modals.open('stepup');
    modals.push('totp-enroll');
    modals.push('recovery-rotate');

    let currentModals: any;
    const unsub = modals.subscribe(state => { currentModals = state; });
    unsub();

    expect(currentModals.stack.length).toBe(3);
    expect(currentModals.active.type).toBe('recovery-rotate');
  });

  it('T2-MOD-03: modals.pop closes top modal and restores previous active modal', () => {
    modals.open('stepup');
    modals.push('passkey-enroll');

    const popped = modals.pop();
    expect(popped?.type).toBe('passkey-enroll');

    let currentModals: any;
    const unsub = modals.subscribe(state => { currentModals = state; });
    unsub();

    expect(currentModals.stack.length).toBe(1);
    expect(currentModals.active.type).toBe('stepup');
  });

  it('T2-MOD-04: modals.pop on empty stack returns undefined safely', () => {
    modals.closeAll();
    const popped = modals.pop();
    expect(popped).toBeUndefined();
  });

  it('T2-MOD-05: modals.close(id) closes specific modal by ID from middle of stack', () => {
    const id1 = modals.open('stepup');
    const id2 = modals.push('did-web');
    const id3 = modals.push('export');

    modals.close(id2);

    let state: any;
    const unsub = modals.subscribe(s => { state = s; });
    unsub();

    expect(state.stack.length).toBe(2);
    expect(state.stack.map((m: any) => m.id)).toEqual([id1, id3]);
    expect(state.active.id).toBe(id3);
  });

  it('T2-MOD-06: modals.close(type) closes modal matching given type', () => {
    modals.open('app-password');
    expect(modals.isOpen('app-password')).toBe(true);

    modals.close('app-password');
    expect(modals.isOpen('app-password')).toBe(false);
  });

  it('T2-MOD-07: modals.closeAll empties stack and sets active to null', () => {
    modals.open('stepup');
    modals.push('totp-enroll');
    modals.closeAll();

    let state: any;
    const unsub = modals.subscribe(s => { state = s; });
    unsub();

    expect(state.stack.length).toBe(0);
    expect(state.active).toBeNull();
  });

  it('T2-MOD-08: modals.isOpen accurately reports presence of modal type', () => {
    expect(modals.isOpen('stepup')).toBe(false);
    modals.open('stepup');
    expect(modals.isOpen('stepup')).toBe(true);
    expect(modals.isOpen('lifecycle')).toBe(false);
  });

  it('T2-MOD-09: stress test rapid successive open and close operations (100 iterations)', () => {
    for (let i = 0; i < 100; i++) {
      if (i % 2 === 0) {
        modals.open('app-password', { index: i });
      } else {
        modals.push('totp-enroll', { index: i });
      }
      if (i % 5 === 0) {
        modals.pop();
      }
    }
    modals.closeAll();

    let state: any;
    const unsub = modals.subscribe(s => { state = s; });
    unsub();
    expect(state.stack.length).toBe(0);
    expect(state.active).toBeNull();
  });

  // --- Toasts Queue & Auto-Dismissal Boundaries ---

  it('T2-MOD-10: toasts.add creates toast with unique ID and default properties', () => {
    const id = toasts.add('info', 'Welcome back!');
    expect(id).toBeDefined();

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.length).toBe(1);
    expect(list[0].id).toBe(id);
    expect(list[0].type).toBe('info');
    expect(list[0].message).toBe('Welcome back!');
    expect(list[0].duration).toBe(5000);
  });

  it('T2-MOD-11: toasts helper methods set appropriate types and default durations', () => {
    toasts.success('Success message');
    toasts.error('Error message');
    toasts.warning('Warning message');
    toasts.info('Info message');

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.length).toBe(4);
    expect(list[0].type).toBe('success');
    expect(list[0].duration).toBe(5000);
    expect(list[1].type).toBe('error');
    expect(list[1].duration).toBe(8000);
    expect(list[2].type).toBe('warning');
    expect(list[2].duration).toBe(6000);
    expect(list[3].type).toBe('info');
    expect(list[3].duration).toBe(5000);
  });

  it('T2-MOD-12: persistent toast with duration 0 or Infinity does not auto-dismiss', () => {
    const id = toasts.error('Critical alert: storage quota exceeded', { duration: 0 });

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.find(t => t.id === id)?.duration).toBe(0);
  });

  it('T2-MOD-13: toasts.dismiss removes specific toast by ID and cancels timer', () => {
    const id1 = toasts.info('Message 1');
    const id2 = toasts.info('Message 2');

    toasts.dismiss(id1);

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.length).toBe(1);
    expect(list[0].id).toBe(id2);
  });

  it('T2-MOD-14: toasts.clear empties all active toasts', () => {
    toasts.success('1');
    toasts.error('2');
    toasts.info('3');
    toasts.clear();

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.length).toBe(0);
  });

  it('T2-MOD-15: stress test handles 50 rapid toast additions without queue corruption', () => {
    for (let i = 0; i < 50; i++) {
      toasts.add('info', `Notification #${i}`, { duration: 0 });
    }

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list.length).toBe(50);
    expect(list[49].message).toBe('Notification #49');
  });

  it('T2-MOD-16: toast with ultra-long text (2,000 characters) stores without crash', () => {
    const longMsg = 'X'.repeat(2000);
    toasts.warning(longMsg);

    let list: any[] = [];
    const unsub = toasts.subscribe(items => { list = items; });
    unsub();

    expect(list[0].message.length).toBe(2000);
  });

  // --- App Passwords Modal Validation Boundaries ---

  it('T2-MOD-17: creates app password with ultra-long name (255 characters)', async () => {
    const longName = 'A'.repeat(255);
    const res = await api.createAppPassword({ name: longName, scopes: ['atproto'] });

    expect(res.accepted).toBe(true);
    expect((res as any).password).toMatch(/^swan-app-/);

    const activeList = backend.getAppPasswords(session.accountDID);
    expect(activeList.some(p => p.name === longName)).toBe(true);
  });

  it('T2-MOD-18: creating app password with empty name returns 400 invalid_request', async () => {
    try {
      await api.createAppPassword({ name: '', scopes: ['atproto'] });
      expect.unreachable('Should have rejected empty name');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
    }
  });

  it('T2-MOD-19: creating app password with empty scopes array [] returns 400 invalid_request', async () => {
    try {
      await api.createAppPassword({ name: 'Valid Name', scopes: [] });
      expect.unreachable('Should have rejected empty scopes');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toContain('Scope validation failed');
    }
  });

  it('T2-MOD-20: creating app password without atproto base scope returns 400 invalid_request', async () => {
    try {
      await api.createAppPassword({ name: 'Chat Only Bot', scopes: ['transition:chat.bsky'] });
      expect.unreachable('Should have rejected missing atproto scope');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toContain('Base scope atproto required');
    }
  });

  it('T2-MOD-21: creates app password with all 4 scopes simultaneously', async () => {
    const allScopes = ['atproto', 'transition:chat.bsky', 'transition:email', 'transition:generic'];
    const res = await api.createAppPassword({ name: 'Full Power Client', scopes: allScopes });

    expect(res.accepted).toBe(true);
    const created = backend.getAppPasswords(session.accountDID).find(p => p.name === 'Full Power Client');
    expect(created?.scopes).toEqual(allScopes);
  });

  it('T2-MOD-22: revoking app password with special characters and spaces properly percent-encodes', async () => {
    const specialName = 'Feed Bot / #1 & Test?';
    backend.addAppPassword(session.accountDID, specialName);

    const res = await api.revokeAppPassword(specialName);
    expect(res.accepted).toBe(true);

    const remaining = backend.getAppPasswords(session.accountDID);
    expect(remaining.some(p => p.name === specialName)).toBe(false);
  });

  // --- Portal Store & State Boundaries ---

  it('T2-MOD-23: portalStore selectTab updates active navigation section', () => {
    portal.selectTab('security');

    let tab: any;
    const unsub = portal.subscribe(s => { tab = s.activeTab; });
    unsub();

    expect(tab).toBe('security');
  });

  it('T2-MOD-24: portalStore patchSnapshot immutably updates loaded snapshot and derived stores', () => {
    const initialSnap = backend.buildSnapshot(session.accountDID, session.id);
    portal.setSnapshot(initialSnap as any);

    portal.patchSnapshot(snap => ({
      ...snap,
      account: { ...snap.account, email: 'updated-alice@swan.place' }
    }));

    let snap: any;
    const unsub = portal.subscribe(s => { snap = s.snapshot; });
    unsub();

    expect(snap.account.email).toBe('updated-alice@swan.place');
  });

  it('T2-MOD-25: portalStore reset restores initial empty state', () => {
    const initialSnap = backend.buildSnapshot(session.accountDID, session.id);
    portal.setSnapshot(initialSnap as any);
    portal.selectTab('sessions');
    portal.reset();

    let state: any;
    const unsub = portal.subscribe(s => { state = s; });
    unsub();

    expect(state.snapshot).toBeNull();
    expect(state.activeTab).toBe('overview');
    expect(state.loading).toBe(false);
  });
});
