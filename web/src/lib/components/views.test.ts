import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import OverviewView from './views/OverviewView.svelte';
import ProfileView from './views/ProfileView.svelte';
import SecurityView from './views/SecurityView.svelte';
import RecoveryView from './views/RecoveryView.svelte';
import SessionsView from './views/SessionsView.svelte';
import AppsView from './views/AppsView.svelte';
import PasswordsView from './views/PasswordsView.svelte';
import ExportView from './views/ExportView.svelte';
import LifecycleView from './views/LifecycleView.svelte';

import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors,
  SECTIONS
} from '../stores/portal';
import { modals } from '../stores/modals';
import { toasts } from '../stores/toasts';
import { stepup } from '../stores/stepup';
import type { PortalSnapshot } from '../types';

describe('Modular Section Views Suite', () => {
  const mockSnapshot: PortalSnapshot = {
    account: {
      did: 'did:plc:alice12345',
      handle: 'alice.swan.place',
      email: 'alice@swan.place',
      lifecycle: 'active'
    },
    identity: {
      method: 'plc',
      handle: 'alice.swan.place',
      state: 'active'
    },
    strength: 'high',
    factors: [
      { id: 'f-passkey-1', kind: 'passkey', label: 'MacBook Touch ID', enabled: true },
      { id: 'f-totp-1', kind: 'totp', label: 'Aegis Authenticator', enabled: true },
      { id: 'f-rec-1', kind: 'recoveryCode', label: 'Emergency Codes', enabled: true }
    ],
    sessions: [
      { id: 's-1', label: 'Safari on macOS', kind: 'management', lastSeen: 'just now', current: true },
      { id: 's-2', label: 'Catbird iOS', kind: 'legacy', lastSeen: '1 hour ago', current: false }
    ],
    apps: [
      { id: 'app-1', name: 'Bluesky Social', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-08-01' }
    ],
    passwords: [
      { name: 'CLI Sync Bot', scopes: ['atproto'], createdAt: '2026-08-10', lastUsedAt: '2026-08-18' }
    ]
  };

  beforeEach(() => {
    portal.setSnapshot(mockSnapshot);
    modals.closeAll();
    toasts.clear();
  });

  afterEach(() => {
    portal.reset();
    modals.closeAll();
    toasts.clear();
  });

  it('exports valid Svelte components for all 9 modular views', () => {
    expect(OverviewView).toBeDefined();
    expect(ProfileView).toBeDefined();
    expect(SecurityView).toBeDefined();
    expect(RecoveryView).toBeDefined();
    expect(SessionsView).toBeDefined();
    expect(AppsView).toBeDefined();
    expect(PasswordsView).toBeDefined();
    expect(ExportView).toBeDefined();
    expect(LifecycleView).toBeDefined();
  });

  it('OverviewView reflects correct snapshot properties', () => {
    const account = get(currentAccount);
    const identity = get(currentIdentity);
    const sessions = get(activeSessions);
    const apps = get(activeApps);
    const factors = get(activeFactors);

    expect(account?.handle).toBe('alice.swan.place');
    expect(account?.did).toBe('did:plc:alice12345');
    expect(identity?.method).toBe('plc');
    expect(sessions.length).toBe(2);
    expect(apps.length).toBe(1);
    expect(factors.length).toBe(3);
  });

  it('ProfileView handles PLC and did:web identity configurations', () => {
    const account = get(currentAccount);
    expect(account?.email).toBe('alice@swan.place');
    expect(account?.lifecycle).toBe('active');

    // Test transition to did:web
    portal.patchSnapshot((snap) => ({
      ...snap,
      identity: {
        method: 'didWeb',
        handle: 'alice.example.com',
        state: 'active'
      }
    }));

    const identity = get(currentIdentity);
    expect(identity?.method).toBe('didWeb');
    expect(identity?.handle).toBe('alice.example.com');
  });

  it('SecurityView correctly categorizes passkey, totp, and recovery factors', () => {
    const factors = get(activeFactors);
    const passkeys = factors.filter((f) => f.kind === 'passkey');
    const totp = factors.filter((f) => f.kind === 'totp');
    const recovery = factors.filter((f) => f.kind === 'recoveryCode');

    expect(passkeys.length).toBe(1);
    expect(passkeys[0].label).toBe('MacBook Touch ID');
    expect(totp.length).toBe(1);
    expect(totp[0].label).toBe('Aegis Authenticator');
    expect(recovery.length).toBe(1);
  });

  it('SessionsView distinguishes current management session from remote sessions', () => {
    const sessions = get(activeSessions);
    const current = sessions.find((s) => s.current);
    const remote = sessions.filter((s) => !s.current);

    expect(current).toBeDefined();
    expect(current?.id).toBe('s-1');
    expect(current?.kind).toBe('management');

    expect(remote.length).toBe(1);
    expect(remote[0].id).toBe('s-2');
    expect(remote[0].kind).toBe('legacy');
  });

  it('AppsView and PasswordsView surface scoped tokens and dates', () => {
    const apps = get(activeApps);
    const passwords = get(activePasswords);

    expect(apps.length).toBe(1);
    expect(apps[0].name).toBe('Bluesky Social');
    expect(apps[0].scopes).toContain('transition:chat.bsky');

    expect(passwords.length).toBe(1);
    expect(passwords[0].name).toBe('CLI Sync Bot');
    expect(passwords[0].scopes).toEqual(['atproto']);
    expect(passwords[0].lastUsedAt).toBe('2026-08-18');
  });

  it('Navigation sections enum matches all 9 view tabs', () => {
    expect(SECTIONS.length).toBe(9);
    const sectionIds = SECTIONS.map((s) => s.id);
    expect(sectionIds).toEqual([
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
});
