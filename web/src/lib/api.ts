export type ApiError = { code: string; message: string; retryAfter?: number };

export type Session = {
  account: { did: string; handle: string; email?: string; lifecycle: string };
  identity?: { method: 'plc' | 'didWeb'; handle: string; state: string };
  strength: string;
  factors: { kind: string; label: string; enabled: boolean }[];
};

export type PortalSnapshot = {
  account: Session['account'];
  identity?: Session['identity'];
  strength: string;
  factors: Session['factors'];
  sessions: { id: string; label: string; kind: string; lastSeen: string; current?: boolean }[];
  apps: { id: string; name: string; scopes: string[]; createdAt: string }[];
  passwords: { name: string; scopes: string[]; createdAt: string; lastUsedAt?: string }[];
};

let csrf: string | undefined;
export function setCSRF(value: string) { csrf = value; }

export async function bootstrap(): Promise<string> {
  const response = await fetch('/account/api/bootstrap', { credentials: 'same-origin' });
  if (!response.ok) throw await readError(response);
  const body = (await response.json()) as { csrf: string };
  csrf = body.csrf;
  return csrf;
}

export async function accountFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (method !== 'GET' && method !== 'HEAD') {
    headers.set('Content-Type', 'application/json');
    if (!csrf) await bootstrap();
    headers.set('X-Swan-CSRF', csrf ?? '');
  }
  const response = await fetch(`/account/api/${path.replace(/^\//, '')}`, {
    ...init,
    headers,
    credentials: 'same-origin'
  });
  if (!response.ok) throw await readError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function readError(response: Response): Promise<ApiError> {
  try { return (await response.json()) as ApiError; }
  catch { return { code: 'service_unavailable', message: 'The account service is unavailable.' }; }
}
