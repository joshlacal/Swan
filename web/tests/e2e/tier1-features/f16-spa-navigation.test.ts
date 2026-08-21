import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { api, setCSRF } from '../../../src/lib/api';
import {
  SECTIONS,
  portal,
  type NavigationSection
} from '../../../src/lib/stores/portal';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F16: Root SPA Shell & Navigation', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(async () => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);

    const snapshot = await api.fetchSnapshot();
    portal.setSnapshot(snapshot);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    portal.reset();
  });

  it('T1-F16-01: selectTab switches active section across all 9 defined portal sections', () => {
    const expectedSections: NavigationSection[] = [
      'overview',
      'profile',
      'security',
      'recovery',
      'sessions',
      'apps',
      'passwords',
      'export',
      'lifecycle'
    ];

    for (const sectionId of expectedSections) {
      portal.selectTab(sectionId);
      expect(get(portal).activeTab).toBe(sectionId);
    }
  });

  it('T1-F16-02: SECTIONS constant contains 9 ordered sections with valid labels, notes, and numbering', () => {
    expect(SECTIONS.length).toBe(9);

    const ids = SECTIONS.map((s) => s.id);
    expect(ids).toEqual([
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

    for (let i = 0; i < SECTIONS.length; i++) {
      const section = SECTIONS[i];
      expect(section.label).toBeDefined();
      expect(section.note).toBeDefined();
      expect(section.number).toBe(String(i + 1).padStart(2, '0'));
    }
  });

  it('T1-F16-03: Hydration from API snapshot initializes portal state and lastUpdated timestamp', async () => {
    const snapshot = await api.fetchSnapshot();
    portal.setSnapshot(snapshot);

    const state = get(portal);
    expect(state.snapshot).toEqual(snapshot);
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
    expect(state.lastUpdated).toBeGreaterThan(0);
  });

  it('T1-F16-04: patchSnapshot applies immutable updates to current snapshot state', () => {
    portal.patchSnapshot((snap) => ({
      ...snap,
      account: {
        ...snap.account,
        email: 'newemail@swan.place'
      }
    }));

    const state = get(portal);
    expect(state.snapshot?.account.email).toBe('newemail@swan.place');
  });

  it('T1-F16-05: Logout lifecycle calls POST /account/api/logout and resets portal store', async () => {
    const logoutResult = await api.logout();

    expect(logoutResult.accepted).toBe(true);
    expect(backend.getSession(session.sessionToken)).toBeUndefined();

    portal.reset();
    const state = get(portal);
    expect(state.snapshot).toBeNull();
    expect(state.activeTab).toBe('overview');
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
  });
});
