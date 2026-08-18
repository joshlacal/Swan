import { writable, get } from 'svelte/store';
import { modals } from './modals';
import { activeFactors } from './portal';
import { isWebAuthnSupported } from '../webauthn';
import type { StepUpFactorKind, StepUpChallengeContext, StepUpStoreState } from '../types';

export type { StepUpFactorKind, StepUpChallengeContext, StepUpStoreState };

interface PendingDeferred {
  resolve: (token: string | boolean) => void;
  reject: (error: Error) => void;
  context: StepUpChallengeContext;
}

const INITIAL_STATE: StepUpStoreState = {
  isOpen: false,
  context: null,
  allowedFactors: ['password'],
  selectedFactor: 'password',
  loading: false,
  error: null
};

function createStepUpStore() {
  const { subscribe, update, set } = writable<StepUpStoreState>(INITIAL_STATE);
  const pendingQueue: PendingDeferred[] = [];

  function determineAllowedFactors(context?: StepUpChallengeContext): StepUpFactorKind[] {
    if (context?.allowedFactors && context.allowedFactors.length > 0) {
      return context.allowedFactors;
    }

    const factors = get(activeFactors);
    const kinds: StepUpFactorKind[] = ['password'];

    const hasPasskey = factors.some(
      (f) => f.kind === 'passkey' && (f.enabled === true || f.enabled === 'true')
    );
    if (hasPasskey && isWebAuthnSupported()) {
      kinds.push('passkey');
    }

    const hasTotp = factors.some(
      (f) => f.kind === 'totp' && (f.enabled === true || f.enabled === 'true')
    );
    if (hasTotp) {
      kinds.push('totp');
    }

    // Recovery code is available if any MFA factor exists or explicitly configured
    if (hasPasskey || hasTotp) {
      kinds.push('recoveryCode');
    }

    return kinds;
  }

  function requestStepUp(context: StepUpChallengeContext = {}): Promise<string | boolean> {
    return new Promise((resolve, reject) => {
      pendingQueue.push({ resolve, reject, context });

      update((state) => {
        if (state.isOpen) {
          // Already open: enqueue and keep active dialog
          return state;
        }

        const allowed = determineAllowedFactors(context);
        // Default to passkey/totp if present, otherwise password
        let defaultFactor: StepUpFactorKind = 'password';
        if (allowed.includes('passkey')) defaultFactor = 'passkey';
        else if (allowed.includes('totp')) defaultFactor = 'totp';

        // Push 'step-up' to modals store for stack tracking
        modals.push('step-up', context, { title: 'Authentication Required' });

        return {
          isOpen: true,
          context,
          allowedFactors: allowed,
          selectedFactor: defaultFactor,
          loading: false,
          error: null
        };
      });
    });
  }

  function resolveStepUp(tokenOrSuccess: string | boolean): void {
    const queue = pendingQueue.splice(0, pendingQueue.length);
    queue.forEach((d) => d.resolve(tokenOrSuccess));

    update(() => {
      if (modals.isOpen('step-up')) {
        modals.close('step-up');
      }
      return { ...INITIAL_STATE };
    });
  }

  function cancelStepUp(error?: Error | string): void {
    const err =
      typeof error === 'string'
        ? new Error(error)
        : error || new Error('User cancelled step-up prompt');
    const queue = pendingQueue.splice(0, pendingQueue.length);
    queue.forEach((d) => d.reject(err));

    update(() => {
      if (modals.isOpen('step-up')) {
        modals.close('step-up');
      }
      return { ...INITIAL_STATE };
    });
  }

  function selectFactor(factor: StepUpFactorKind): void {
    update((state) => ({ ...state, selectedFactor: factor, error: null }));
  }

  function setLoading(loading: boolean): void {
    update((state) => ({ ...state, loading }));
  }

  function setError(error: string | null): void {
    update((state) => ({ ...state, error, loading: false }));
  }

  function reset(): void {
    pendingQueue.splice(0, pendingQueue.length);
    set(INITIAL_STATE);
  }

  return {
    subscribe,
    requestStepUp,
    resolveStepUp,
    cancelStepUp,
    selectFactor,
    setLoading,
    setError,
    reset
  };
}

export const stepup = createStepUpStore();
