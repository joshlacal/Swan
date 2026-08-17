import { afterEach, describe, expect, it, vi } from 'vitest';
import { accountFetch, bootstrap } from './api';

afterEach(() => vi.restoreAllMocks());

describe('account API client', () => {
  it('bootstraps a CSRF token before a mutation and sends same-origin credentials', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf: 'fresh-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    await accountFetch('sessions/revoke-others', { method: 'POST', body: '{}' });

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/account/api/bootstrap', { credentials: 'same-origin' });
    const [, request] = fetchMock.mock.calls[1];
    expect((request as RequestInit).credentials).toBe('same-origin');
    expect(((request as RequestInit).headers as Headers).get('X-Swan-CSRF')).toBe('fresh-token');
  });

  it('turns stable JSON failures into a safe API error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify({ code: 'request_not_allowed', message: 'Request not allowed.' }), { status: 403 }
    ));
    await expect(bootstrap()).rejects.toMatchObject({ code: 'request_not_allowed' });
  });
});
