import { describe, expect, it, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors,
  SECTIONS
} from './portal';
import type { PortalSnapshot } from '../types';

const mockSnapshot: PortalSnapshot = {
  account: {
    did: 'did:plc:12345',
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
    { id: 'f-1', kind: 'passkey', label: 'MacBook', enabled: true },
    { id: 'f-2', kind: 'totp', label: 'Authenticator App', enabled: true }
  ],
  sessions: [
    { id: 's-1', label: 'Current Device', kind: 'management', lastSeen: '2026-08-18', current: true },
    { id: 's-2', label: 'Phone', kind: 'legacy', lastSeen: '2026-08-17', current: false }
  ],
  apps: [
    { id: 'a-1', name: 'Catbird iOS', scopes: ['atproto'], createdAt: '2026-08-01' }
  ],
  passwords: [
    { name: 'CLI Tool', scopes: ['atproto'], createdAt: '2026-08-05' }
  ]
};

describe('portal store', () => {
  beforeEach(() => {
    portal.reset();
  });

  it('initializes with default empty state', () => {
    const state = get(portal);
    expect(state.snapshot).toBeNull();
    expect(state.activeTab).toBe('overview');
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
    expect(get(currentAccount)).toBeNull();
    expect(get(activeSessions)).toEqual([]);
  });

  it('defines the 9 standard navigation sections', () => {
    expect(SECTIONS.length).toBe(9);
    expect(SECTIONS.map((s) => s.id)).toEqual([
      'overview',
      'profile',
      'security',
      'recovery',
      'sessions',
      'apps',
      'passwords',
      'export',
      'lifecycle'
    ]);
  });

  it('sets snapshot and updates derived stores', () => {
    portal.setSnapshot(mockSnapshot);

    const state = get(portal);
    expect(state.snapshot).toEqual(mockSnapshot);
    expect(state.lastUpdated).not.toBeNull();

    expect(get(currentAccount)?.handle).toBe('alice.swan.place');
    expect(get(currentIdentity)?.method).toBe('plc');
    expect(get(activeSessions).length).toBe(2);
    expect(get(activeApps).length).toBe(1);
    expect(get(activePasswords).length).toBe(1);
    expect(get(activeFactors).length).toBe(2);
  });

  it('selects active tab', () => {
    portal.selectTab('security');
    expect(get(portal).activeTab).toBe('security');

    portal.selectTab('passwords');
    expect(get(portal).activeTab).toBe('passwords');
  });

  it('handles loading and error states', () => {
    portal.setLoading(true);
    expect(get(portal).loading).toBe(true);

    portal.setError('Failed to fetch snapshot');
    expect(get(portal).loading).toBe(false);
    expect(get(portal).error).toBe('Failed to fetch snapshot');
  });

  it('patches snapshot in place', () => {
    portal.setSnapshot(mockSnapshot);

    portal.patchSnapshot((current) => ({
      ...current,
      passwords: [...current.passwords, { name: 'New Key', scopes: ['atproto'], createdAt: '2026-08-18' }]
    }));

    expect(get(activePasswords).length).toBe(2);
    expect(get(activePasswords)[1].name).toBe('New Key');
  });
});
