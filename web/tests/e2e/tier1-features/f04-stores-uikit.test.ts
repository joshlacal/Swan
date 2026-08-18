import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { toasts } from '../../../src/lib/stores/toasts';
import { activeModal, modals } from '../../../src/lib/stores/modals';
import {
  activeApps,
  activeFactors,
  activePasswords,
  activeSessions,
  currentAccount,
  currentIdentity,
  portal
} from '../../../src/lib/stores/portal';
import type { PortalSnapshot } from '../../../src/lib/types';

describe('Tier 1 - F04: Reactive Stores & UI Kit', () => {
  beforeEach(() => {
    toasts.clear();
    modals.closeAll();
    portal.reset();
  });

  it('T1-F04-01: toastsStore pushes notifications with type, title, and auto-generated ID', () => {
    const infoId = toasts.info('System update available', { title: 'Notice' });
    const successId = toasts.success('Session revoked successfully');
    const errorId = toasts.error('Operation failed', { duration: 0 });

    const currentToasts = get(toasts);
    expect(currentToasts.length).toBe(3);

    expect(currentToasts.find((t) => t.id === infoId)).toMatchObject({
      type: 'info',
      message: 'System update available',
      title: 'Notice'
    });

    expect(currentToasts.find((t) => t.id === successId)).toMatchObject({
      type: 'success',
      message: 'Session revoked successfully'
    });

    expect(currentToasts.find((t) => t.id === errorId)).toMatchObject({
      type: 'error',
      message: 'Operation failed',
      duration: 0
    });
  });

  it('T1-F04-02: toastsStore supports manual dismissal by ID and clearAll', () => {
    const id1 = toasts.info('Message 1');
    const id2 = toasts.warning('Message 2');

    expect(get(toasts).length).toBe(2);

    toasts.dismiss(id1);
    expect(get(toasts).length).toBe(1);
    expect(get(toasts)[0].id).toBe(id2);

    toasts.clear();
    expect(get(toasts).length).toBe(0);
  });

  it('T1-F04-03: modalsStore opens, tracks active modal, and pushes onto modal stack', () => {
    expect(get(activeModal)).toBeNull();

    const m1Id = modals.open('app-password-create', { defaultScope: 'atproto' }, { title: 'New App Password' });
    let active = get(activeModal);

    expect(active).not.toBeNull();
    expect(active?.id).toBe(m1Id);
    expect(active?.type).toBe('app-password-create');
    expect(active?.payload).toEqual({ defaultScope: 'atproto' });
    expect(active?.title).toBe('New App Password');
    expect(modals.isOpen('app-password-create')).toBe(true);

    // Push step-up modal over the active modal
    const m2Id = modals.push('step-up', { operation: 'app-password' });
    active = get(activeModal);
    expect(active?.id).toBe(m2Id);
    expect(active?.type).toBe('step-up');

    // Pop returns to the previous modal
    const popped = modals.pop();
    expect(popped?.id).toBe(m2Id);
    expect(get(activeModal)?.id).toBe(m1Id);
  });

  it('T1-F04-04: modalsStore handles close by id/type and closeAll', () => {
    modals.open('totp-enroll');
    expect(modals.isOpen('totp-enroll')).toBe(true);

    modals.close('totp-enroll');
    expect(modals.isOpen('totp-enroll')).toBe(false);
    expect(get(activeModal)).toBeNull();

    modals.push('passkey-enroll');
    modals.push('recovery-rotate');
    expect(get(modals).stack.length).toBe(2);

    modals.closeAll();
    expect(get(modals).stack.length).toBe(0);
    expect(get(activeModal)).toBeNull();
  });

  it('T1-F04-05: portalStore manages snapshot state and synchronizes derived stores', () => {
    const mockSnapshot: PortalSnapshot = {
      account: {
        did: 'did:plc:alice-snapshot-test',
        handle: 'alice.swan.place',
        email: 'alice@swan.place',
        lifecycle: 'active'
      },
      identity: {
        method: 'plc',
        handle: 'alice.swan.place',
        state: 'active'
      },
      strength: 'password',
      factors: [
        { id: 'f1', kind: 'totp', label: 'Phone Authenticator', enabled: true }
      ],
      sessions: [
        { id: 's1', label: 'MacBook', kind: 'management', lastSeen: 'now', current: true }
      ],
      apps: [
        { id: 'app1', name: 'Deck Client', scopes: ['atproto'], createdAt: '2026-01-01' }
      ],
      passwords: [
        { name: 'Feed Bot', scopes: ['atproto'], createdAt: '2026-01-01' }
      ]
    };

    portal.setSnapshot(mockSnapshot);

    const state = get(portal);
    expect(state.snapshot).toEqual(mockSnapshot);
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
    expect(state.lastUpdated).toBeGreaterThan(0);

    // Derived stores verification
    expect(get(currentAccount)?.handle).toBe('alice.swan.place');
    expect(get(currentIdentity)?.method).toBe('plc');
    expect(get(activeFactors).length).toBe(1);
    expect(get(activeSessions).length).toBe(1);
    expect(get(activeApps).length).toBe(1);
    expect(get(activePasswords).length).toBe(1);

    // Tab navigation
    portal.selectTab('security');
    expect(get(portal).activeTab).toBe('security');

    // Patch snapshot
    portal.patchSnapshot((snap) => ({
      ...snap,
      passwords: [...snap.passwords, { name: 'New Bot', scopes: ['atproto'], createdAt: 'now' }]
    }));
    expect(get(activePasswords).length).toBe(2);
  });
});
