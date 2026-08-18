import { writable, derived } from 'svelte/store';
import type {
  AccountDetails,
  AppPassword,
  ConnectedApp,
  Factor,
  IdentityDetails,
  PortalSnapshot,
  SectionId,
  Session
} from '../types';

export type NavigationSection = SectionId;

export interface SectionMeta {
  id: NavigationSection;
  label: string;
  note: string;
  number: string;
}

export const SECTIONS: readonly SectionMeta[] = [
  { id: 'overview', label: 'Overview', note: 'Account pulse', number: '01' },
  { id: 'profile', label: 'Profile', note: 'Identity & contact', number: '02' },
  { id: 'security', label: 'Security', note: 'Factors & sign-in', number: '03' },
  { id: 'recovery', label: 'Recovery', note: 'Your way back in', number: '04' },
  { id: 'sessions', label: 'Sessions', note: 'Devices & access', number: '05' },
  { id: 'apps', label: 'Connected apps', note: 'OAuth grants', number: '06' },
  { id: 'passwords', label: 'App passwords', note: 'Scoped legacy access', number: '07' },
  { id: 'export', label: 'Export & migrate', note: 'Move your data', number: '08' },
  { id: 'lifecycle', label: 'Lifecycle', note: 'Pause or leave', number: '09' }
] as const;

export interface PortalStoreState {
  snapshot: PortalSnapshot | null;
  activeTab: NavigationSection;
  loading: boolean;
  error: string | null;
  lastUpdated: number | null;
}

const INITIAL_STATE: PortalStoreState = {
  snapshot: null,
  activeTab: 'overview',
  loading: false,
  error: null,
  lastUpdated: null
};

function createPortalStore() {
  const { subscribe, update, set } = writable<PortalStoreState>(INITIAL_STATE);

  function setSnapshot(snapshot: PortalSnapshot): void {
    update((state) => ({
      ...state,
      snapshot,
      error: null,
      loading: false,
      lastUpdated: Date.now()
    }));
  }

  function selectTab(activeTab: NavigationSection): void {
    update((state) => ({ ...state, activeTab }));
  }

  function setLoading(loading: boolean): void {
    update((state) => ({ ...state, loading }));
  }

  function setError(error: string | null): void {
    update((state) => ({ ...state, error, loading: false }));
  }

  function patchSnapshot(updater: (current: PortalSnapshot) => PortalSnapshot): void {
    update((state) => {
      if (!state.snapshot) return state;
      return {
        ...state,
        snapshot: updater(state.snapshot),
        lastUpdated: Date.now()
      };
    });
  }

  function reset(): void {
    set(INITIAL_STATE);
  }

  return {
    subscribe,
    setSnapshot,
    selectTab,
    setLoading,
    setError,
    patchSnapshot,
    reset
  };
}

export const portal = createPortalStore();

// Convenience derived stores
export const currentAccount = derived(portal, ($p): AccountDetails | null => $p.snapshot?.account ?? null);
export const currentIdentity = derived(portal, ($p): IdentityDetails | null => $p.snapshot?.identity ?? null);
export const activeSessions = derived(portal, ($p): Session[] => $p.snapshot?.sessions ?? []);
export const activeApps = derived(portal, ($p): ConnectedApp[] => $p.snapshot?.apps ?? []);
export const activePasswords = derived(portal, ($p): AppPassword[] => $p.snapshot?.passwords ?? []);
export const activeFactors = derived(portal, ($p): Factor[] => $p.snapshot?.factors ?? []);
