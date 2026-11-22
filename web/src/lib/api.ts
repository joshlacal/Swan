import type {
  ApiError,
  AppPasswordCreateRequest,
  BootstrapResponse,
  DidWebAdmissionResponse,
  DidWebClaimRequest,
  DidWebIdentityBindingResponse,
  DidWebReservationResponse,
  DidWebReserveRequest,
  DidWebRemoveRequest,
  DidWebRotateRequest,
  LoginRequest,
  LoginResponse,
  MutationResponse,
  PortalSnapshot,
  SignupPolicy,
  StepUpHandler,
  TotpEnrollRequest,
  WebAuthnAssertionPayload,
  WebAuthnAttestationPayload
} from './types';

import { stepup } from './stores/stepup';

export * from './types';

let csrfToken: string | undefined;
let stepUpHandler: StepUpHandler | null = (context) => stepup.requestStepUp(context);

export function setCSRF(value: string | undefined): void {
  csrfToken = value;
}

export function getCSRF(): string | undefined {
  return csrfToken;
}

export function setStepUpHandler(handler: StepUpHandler | null): void {
  stepUpHandler = handler;
}

export async function bootstrap(): Promise<string> {
  const response = await fetch('/account/api/bootstrap', {
    method: 'GET',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' }
  });
  if (!response.ok) throw await readError(response);
  const body = (await response.json()) as BootstrapResponse;
  csrfToken = body.csrf;
  return csrfToken;
}

export interface AccountFetchOptions {
  skipStepUp?: boolean;
  stepUpReceipt?: string;
}

export async function accountFetch<T>(
  path: string,
  init: RequestInit = {},
  options: AccountFetchOptions = {}
): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');

  const isMutation = method !== 'GET' && method !== 'HEAD';
  if (isMutation) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (!csrfToken) {
      await bootstrap();
    }
    if (csrfToken) {
      headers.set('X-Swan-CSRF', csrfToken);
    }
  }

  if (options.stepUpReceipt) {
    headers.set('X-Swan-Step-Up', options.stepUpReceipt);
  }

  const endpoint = `/account/api/${path.replace(/^\//, '')}`;
  const response = await fetch(endpoint, {
    ...init,
    method,
    headers,
    credentials: 'same-origin'
  });

  if (!response.ok) {
    const error = await readError(response);

    // Step-up interception on HTTP 403 / step_up_required / request_not_allowed
    const isStepUpFailure =
      response.status === 403 ||
      error.code === 'step_up_required' ||
      error.code === 'request_not_allowed';

    if (isStepUpFailure && !options.skipStepUp && stepUpHandler) {
      let stepUpResult: string | boolean | void;
      try {
        stepUpResult = await stepUpHandler({ operation: path, error });
      } catch {
        throw error;
      }

      if (typeof stepUpResult === 'string' && stepUpResult.length > 0) {
        // Replay with one-time receipt
        return await accountFetch<T>(path, init, {
          ...options,
          skipStepUp: true,
          stepUpReceipt: stepUpResult
        });
      } else if (stepUpResult === true) {
        // Session was elevated in-place (e.g. password reauth); replay directly
        return await accountFetch<T>(path, init, {
          ...options,
          skipStepUp: true
        });
      }
    }

    throw error;
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export async function readError(response: Response): Promise<ApiError> {
  try {
    const body = (await response.json()) as Record<string, any>;
    const code =
      body.code ??
      body.error ??
      (response.status === 403 ? 'request_not_allowed' : 'unknown_error');
    const message = body.message ?? defaultErrorMessage(code, response.status);
    return { code, message, status: response.status };
  } catch {
    return {
      code: response.status === 403 ? 'request_not_allowed' : 'service_unavailable',
      message: defaultErrorMessage('service_unavailable', response.status),
      status: response.status
    };
  }
}

function defaultErrorMessage(code: string, status: number): string {
  switch (code) {
    case 'authentication_required':
      return 'Authentication required. Please sign in.';
    case 'request_not_allowed':
    case 'step_up_required':
      return 'This action requires password or MFA verification.';
    case 'invalid_request':
      return 'Invalid request parameters.';
    case 'rate_limited':
      return 'Too many attempts. Please wait a moment.';
    case 'not_found':
      return 'The requested resource was not found.';
    case 'conflict':
      return 'The request conflicts with existing state.';
    case 'service_unavailable':
    default:
      return status === 403 ? 'Request not allowed.' : 'The account service is temporarily unavailable.';
  }
}

// ============================================================================
// Typed API Client Operations
// ============================================================================

export const api = {
  // Snapshot & Policy
  fetchBootstrap: () => bootstrap(),
  fetchSignupPolicy: () => accountFetch<SignupPolicy>('signup/policy'),
  fetchSnapshot: () => accountFetch<PortalSnapshot>('portal'),

  // Auth Lifecycle
  login: async (credentials: LoginRequest): Promise<LoginResponse> => {
    const result = await accountFetch<LoginResponse>('login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });
    setCSRF(result.csrf);
    return result;
  },
  logout: () => accountFetch<MutationResponse>('logout', { method: 'POST', body: '{}' }),
  changePassword: (currentPassword: string, newPassword: string) =>
    accountFetch<MutationResponse>('password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword })
    }),
  stepUpPassword: (password: string) =>
    accountFetch<MutationResponse>('step-up/password', {
      method: 'POST',
      body: JSON.stringify({ password })
    }),

  // Sessions
  revokeSession: (sessionId: string) =>
    accountFetch<MutationResponse>(`sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE'
    }),
  revokeOtherSessions: () =>
    accountFetch<MutationResponse>('sessions/revoke-others', {
      method: 'POST',
      body: '{}'
    }),

  // App Passwords
  createAppPassword: (request: AppPasswordCreateRequest, stepUpReceipt?: string) =>
    accountFetch<MutationResponse>(
      'app-passwords',
      {
        method: 'POST',
        body: JSON.stringify(request)
      },
      { stepUpReceipt }
    ),
  revokeAppPassword: (name: string, stepUpReceipt?: string) =>
    accountFetch<MutationResponse>(
      `app-passwords/${encodeURIComponent(name)}`,
      {
        method: 'DELETE'
      },
      { stepUpReceipt }
    ),

  // Connected OAuth Apps
  revokeConnectedApp: (appId: string, stepUpReceipt?: string) =>
    accountFetch<MutationResponse>(
      `connected-apps/${encodeURIComponent(appId)}`,
      {
        method: 'DELETE'
      },
      { stepUpReceipt }
    ),

  // MFA - WebAuthn Passkeys
  requestPasskeyChallenge: (label?: string, factorID?: string) =>
    accountFetch<MutationResponse>('factors/passkeys/challenge', {
      method: 'POST',
      body: JSON.stringify({ label, factorID })
    }),
  registerPasskey: (attestation: WebAuthnAttestationPayload, factorID?: string) =>
    accountFetch<MutationResponse>(
      factorID ? `factors/passkeys/${encodeURIComponent(factorID)}` : 'factors/passkeys',
      {
        method: 'POST',
        body: JSON.stringify(attestation)
      }
    ),
  requestPasskeyStepUpChallenge: (factorID?: string) =>
    accountFetch<MutationResponse>('factors/passkeys/step-up-challenge', {
      method: 'POST',
      body: JSON.stringify({ factorID })
    }),
  submitPasskeyAssertion: (assertion: WebAuthnAssertionPayload) =>
    accountFetch<MutationResponse>('factors/step-up', {
      method: 'POST',
      body: JSON.stringify(assertion)
    }),
  revokePasskey: (factorID: string) =>
    accountFetch<MutationResponse>(`factors/passkeys/${encodeURIComponent(factorID)}`, {
      method: 'DELETE'
    }),

  // MFA - TOTP
  enrollTotp: (request: TotpEnrollRequest) =>
    accountFetch<MutationResponse>('factors/totp', {
      method: 'POST',
      body: JSON.stringify(request)
    }),
  verifyTotpEnrollment: (factorID: string, code: string) =>
    accountFetch<MutationResponse>('factors/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ factorID, code })
    }),
  stepUpTotp: (factorID: string, code: string) =>
    accountFetch<MutationResponse>('factors/step-up', {
      method: 'POST',
      body: JSON.stringify({ kind: 'totp', factorID, code })
    }),
  revokeTotp: (factorID?: string) =>
    accountFetch<MutationResponse>(
      factorID ? `factors/totp/${encodeURIComponent(factorID)}` : 'factors/totp',
      { method: 'DELETE' }
    ),

  // MFA - Recovery Codes
  rotateRecoveryCodes: () =>
    accountFetch<MutationResponse>('factors/recovery-codes/rotate', {
      method: 'POST',
      body: '{}'
    }),
  stepUpRecoveryCode: (code: string, factorID?: string) =>
    accountFetch<MutationResponse>('factors/step-up', {
      method: 'POST',
      body: JSON.stringify({ kind: 'recoveryCode', factorID: factorID ?? 'recovery', code })
    }),

  // did:web Identity
  reserveDidWeb: (request: DidWebReserveRequest) =>
    accountFetch<DidWebReservationResponse>('identity/reserve', {
      method: 'POST',
      body: JSON.stringify(request)
    }),
  claimDidWeb: (request: DidWebClaimRequest) =>
    accountFetch<DidWebIdentityBindingResponse>('identity/claim', {
      method: 'POST',
      body: JSON.stringify(request)
    }),
  rotateDidWeb: (request: DidWebRotateRequest) =>
    accountFetch<DidWebIdentityBindingResponse>('identity/rotate', {
      method: 'POST',
      body: JSON.stringify(request)
    }),
  removeDidWeb: (request: DidWebRemoveRequest) =>
    accountFetch<DidWebIdentityBindingResponse>('identity/remove', {
      method: 'POST',
      body: JSON.stringify(request)
    }),
  reverifyDidWeb: () =>
    accountFetch<DidWebIdentityBindingResponse>('identity/reverify', {
      method: 'POST',
      body: '{}'
    }),
  getDidWebAdmission: () =>
    accountFetch<DidWebAdmissionResponse>('identity/admission', {
      method: 'POST',
      body: '{}'
    }),

  // Data Export & Account Lifecycle
  requestExport: () =>
    accountFetch<MutationResponse>('export/request', {
      method: 'POST',
      body: '{}'
    }),
  deactivateAccount: () =>
    accountFetch<MutationResponse>('lifecycle/deactivate', {
      method: 'POST',
      body: '{}'
    }),
  deleteAccount: () =>
    accountFetch<MutationResponse>('lifecycle/delete', {
      method: 'POST',
      body: '{}'
    })
};
