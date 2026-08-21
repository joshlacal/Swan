import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  accountFetch,
  api,
  bootstrap,
  getCSRF,
  readError,
  setCSRF,
  setStepUpHandler
} from './api';

describe('account API client', () => {
  beforeEach(() => {
    setCSRF(undefined);
    setStepUpHandler(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('CSRF & Headers', () => {
    it('bootstraps a CSRF token before a mutation and sends same-origin credentials', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response(JSON.stringify({ csrf: 'fresh-token' }), { status: 200 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

      await accountFetch('sessions/revoke-others', { method: 'POST', body: '{}' });

      expect(fetchMock).toHaveBeenNthCalledWith(
        1,
        '/account/api/bootstrap',
        expect.objectContaining({
          method: 'GET',
          credentials: 'same-origin'
        })
      );
      const [, request] = fetchMock.mock.calls[1];
      expect((request as RequestInit).credentials).toBe('same-origin');
      expect(((request as RequestInit).headers as Headers).get('X-Swan-CSRF')).toBe('fresh-token');
      expect(getCSRF()).toBe('fresh-token');
    });

    it('does not re-bootstrap if CSRF token is already present', async () => {
      setCSRF('existing-csrf-token');
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

      await accountFetch('logout', { method: 'POST', body: '{}' });

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [, request] = fetchMock.mock.calls[0];
      expect(((request as RequestInit).headers as Headers).get('X-Swan-CSRF')).toBe('existing-csrf-token');
    });

    it('sets X-Swan-Step-Up header when stepUpReceipt option is provided', async () => {
      setCSRF('csrf-123');
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

      await accountFetch('app-passwords', { method: 'POST', body: '{}' }, { stepUpReceipt: 'receipt-xyz' });

      const [, request] = fetchMock.mock.calls[0];
      expect(((request as RequestInit).headers as Headers).get('X-Swan-Step-Up')).toBe('receipt-xyz');
    });
  });

  describe('HTTP Verbs & Routing', () => {
    it('uses GET for read endpoints', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response(JSON.stringify({ policy: 'open' }), { status: 200 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ account: { handle: 'test' } }), { status: 200 }));

      await api.fetchSignupPolicy();
      expect(fetchMock.mock.calls[0][0]).toBe('/account/api/signup/policy');
      expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('GET');

      await api.fetchSnapshot();
      expect(fetchMock.mock.calls[1][0]).toBe('/account/api/portal');
      expect((fetchMock.mock.calls[1][1] as RequestInit).method).toBe('GET');
    });

    it('uses DELETE for revocation endpoints', async () => {
      setCSRF('csrf-token');
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(() =>
          Promise.resolve(new Response(JSON.stringify({ message: 'Revoked' }), { status: 200 }))
        );

      await api.revokeSession('sess-123');
      expect(fetchMock.mock.calls[0][0]).toBe('/account/api/sessions/sess-123');
      expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('DELETE');

      await api.revokeAppPassword('my-key');
      expect(fetchMock.mock.calls[1][0]).toBe('/account/api/app-passwords/my-key');
      expect((fetchMock.mock.calls[1][1] as RequestInit).method).toBe('DELETE');

      await api.revokeConnectedApp('app-456');
      expect(fetchMock.mock.calls[2][0]).toBe('/account/api/connected-apps/app-456');
      expect((fetchMock.mock.calls[2][1] as RequestInit).method).toBe('DELETE');

      await api.revokePasskey('factor-789');
      expect(fetchMock.mock.calls[3][0]).toBe('/account/api/factors/passkeys/factor-789');
      expect((fetchMock.mock.calls[3][1] as RequestInit).method).toBe('DELETE');

      await api.revokeTotp();
      expect(fetchMock.mock.calls[4][0]).toBe('/account/api/factors/totp');
      expect((fetchMock.mock.calls[4][1] as RequestInit).method).toBe('DELETE');
    });

    it('uses POST for mutation endpoints', async () => {
      setCSRF('csrf-token');
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(() =>
          Promise.resolve(new Response(JSON.stringify({ message: 'Success' }), { status: 200 }))
        );

      await api.createAppPassword({ name: 'test', scopes: ['atproto'] });
      expect(fetchMock.mock.calls[0][0]).toBe('/account/api/app-passwords');
      expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('POST');

      await api.rotateRecoveryCodes();
      expect(fetchMock.mock.calls[1][0]).toBe('/account/api/factors/recovery-codes/rotate');
      expect((fetchMock.mock.calls[1][1] as RequestInit).method).toBe('POST');
    });

    it('handles 204 No Content responses cleanly by returning undefined', async () => {
      setCSRF('csrf-token');
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(null, { status: 204 }));

      const result = await accountFetch<void>('test-204', { method: 'POST', body: '{}' });
      expect(result).toBeUndefined();
    });
  });

  describe('Error Handling', () => {
    it('turns stable JSON failures with code and message into an ApiError', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(
          JSON.stringify({ code: 'request_not_allowed', message: 'Custom forbidden message' }),
          { status: 403 }
        )
      );

      await expect(bootstrap()).rejects.toMatchObject({
        code: 'request_not_allowed',
        message: 'Custom forbidden message',
        status: 403
      });
    });

    it('parses error field from did:web backend responses', async () => {
      const response = new Response(JSON.stringify({ error: 'invalid_did_binding' }), { status: 400 });
      const apiError = await readError(response);

      expect(apiError.code).toBe('invalid_did_binding');
      expect(apiError.status).toBe(400);
    });

    it('handles non-JSON failure responses gracefully with default error strings', async () => {
      const response = new Response('<html>502 Bad Gateway</html>', { status: 502 });
      const apiError = await readError(response);

      expect(apiError.code).toBe('service_unavailable');
      expect(apiError.message).toBe('The account service is temporarily unavailable.');
      expect(apiError.status).toBe(502);
    });
  });

  describe('Step-Up Interception & Replay Engine', () => {
    it('intercepts 403 step-up required and replays with receipt token returned by handler', async () => {
      setCSRF('csrf-token');

      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ code: 'step_up_required', message: 'Elevate session' }),
            { status: 403 }
          )
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ message: 'Created successfully', password: 'one-time-secret' }),
            { status: 200 }
          )
        );

      const handlerMock = vi.fn().mockResolvedValue('mfa-step-up-receipt-token-123');
      setStepUpHandler(handlerMock);

      const result = await api.createAppPassword({ name: 'CLI', scopes: ['atproto'] });

      expect(handlerMock).toHaveBeenCalledWith({
        operation: 'app-passwords',
        error: expect.objectContaining({ code: 'step_up_required', status: 403 })
      });

      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [, secondCallRequest] = fetchMock.mock.calls[1];
      expect(((secondCallRequest as RequestInit).headers as Headers).get('X-Swan-Step-Up')).toBe(
        'mfa-step-up-receipt-token-123'
      );
      expect(result).toEqual({ message: 'Created successfully', password: 'one-time-secret' });
    });

    it('replays request without receipt token when step-up handler returns true (in-place elevation)', async () => {
      setCSRF('csrf-token');

      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ code: 'step_up_required', message: 'Elevate session' }),
            { status: 403 }
          )
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ message: 'Operation succeeded' }),
            { status: 200 }
          )
        );

      const handlerMock = vi.fn().mockResolvedValue(true);
      setStepUpHandler(handlerMock);

      const result = await api.rotateRecoveryCodes();

      expect(handlerMock).toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ message: 'Operation succeeded' });
    });

    it('throws original error if step-up handler throws or cancels', async () => {
      setCSRF('csrf-token');

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(
          JSON.stringify({ code: 'request_not_allowed', message: 'Step-up required' }),
          { status: 403 }
        )
      );

      const handlerMock = vi.fn().mockRejectedValue(new Error('User cancelled step-up prompt'));
      setStepUpHandler(handlerMock);

      await expect(api.rotateRecoveryCodes()).rejects.toMatchObject({
        code: 'request_not_allowed',
        status: 403
      });
    });

    it('throws the replayed error directly if the replayed request fails with a non-403 error', async () => {
      setCSRF('csrf-token');

      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ code: 'step_up_required', message: 'Elevate session' }),
            { status: 403 }
          )
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ code: 'internal_error', message: 'Database connection failed' }),
            { status: 500 }
          )
        );

      const handlerMock = vi.fn().mockResolvedValue('receipt-abc');
      setStepUpHandler(handlerMock);

      await expect(
        api.createAppPassword({ name: 'test', scopes: ['atproto'] })
      ).rejects.toMatchObject({
        code: 'internal_error',
        message: 'Database connection failed',
        status: 500
      });

      expect(handlerMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('does not intercept if skipStepUp option is true', async () => {
      setCSRF('csrf-token');

      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Step-up required' }),
          { status: 403 }
        )
      );

      const handlerMock = vi.fn();
      setStepUpHandler(handlerMock);

      await expect(
        accountFetch('app-passwords', { method: 'POST', body: '{}' }, { skipStepUp: true })
      ).rejects.toMatchObject({
        code: 'step_up_required',
        status: 403
      });

      expect(handlerMock).not.toHaveBeenCalled();
    });
  });
});
