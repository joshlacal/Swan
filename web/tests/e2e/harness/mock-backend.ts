/**
 * Mock Swan Backend - Stateful In-Memory Backend Server for E2E and Integration Tests.
 *
 * Implements the full HTTP REST specification of the Swan Account Management Portal:
 * - CSRF verification (pre-auth swan_csrf_pre and authenticated swan_csrf / X-Swan-CSRF)
 * - Origin and Sec-Fetch-Site validation
 * - Content-Type validation on mutations
 * - Single-use X-Swan-Step-Up receipt tokens
 * - Step-up elevation state machine (password, TOTP, WebAuthn passkeys, recovery codes)
 * - Complete CRUD across accounts, sessions, factors, app passwords, connected apps, export, and did:web
 */

export interface MockAccount {
  did: string;
  handle: string;
  email?: string;
  password: string;
  lifecycle: 'active' | 'deactivated' | 'deleted';
  createdAt: string;
}

export interface MockSession {
  id: string; // stable session identifier
  sessionToken: string; // Cookie value in __Secure-swan_management
  csrfToken: string; // Value in swan_csrf
  accountDID: string;
  label: string;
  kind: 'management' | 'legacy';
  issuedAt: number; // ms timestamp
  lastStepUpAt?: number; // ms timestamp
  strength: 'password' | 'stepUpPassword' | 'stepUpMFA' | 'emailRecovery';
  current?: boolean;
}

export interface MockFactor {
  id: string;
  accountDID: string;
  kind: 'totp' | 'passkey' | 'recoveryCode';
  label: string;
  secret?: string; // for TOTP (Base32)
  publicKey?: string; // for passkey
  credentialID?: string; // for passkey
  transports?: string[];
  enabled: boolean;
  createdAt: string;
}

export interface MockAppPassword {
  did: string;
  name: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface MockConnectedApp {
  did: string;
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
}

export interface MockStepUpReceipt {
  receiptToken: string;
  sessionID: string;
  accountDID: string;
  operation?: string;
  issuedAt: number;
  expiresAt: number; // TTL (default 300s)
  consumed: boolean;
}

export interface MockDidWebReservation {
  requestID: string;
  targetDID: string;
  handle: string;
  nonce: string;
  claimPayload: string;
  expiresAt: string;
  consumed: boolean;
}

export interface MockDidWebBinding {
  did: string;
  handle: string;
  state: 'active' | 'pending' | 'removed';
  verifiedAt: string;
}

export interface MockExportRequest {
  id: string;
  accountDID: string;
  status: 'pending' | 'ready' | 'completed';
  requestedAt: string;
  downloadUrl?: string;
}

export interface MockHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: any;
}

function generateChallengeBytes(): string {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export class MockSwanBackend {
  public origin = 'https://swan.place';

  // Internal state stores
  private accounts = new Map<string, MockAccount>();
  private sessions = new Map<string, MockSession>(); // sessionToken -> MockSession
  private preAuthTokens = new Map<string, number>(); // token -> expiresAt (ms)
  private factors = new Map<string, MockFactor[]>(); // accountDID -> MockFactor[]
  private appPasswords = new Map<string, MockAppPassword[]>(); // accountDID -> MockAppPassword[]
  private connectedApps = new Map<string, MockConnectedApp[]>(); // accountDID -> MockConnectedApp[]
  private recoveryCodes = new Map<string, Set<string>>(); // accountDID -> Set<code string>
  private stepUpReceipts = new Map<string, MockStepUpReceipt>(); // receiptToken -> Receipt
  private pendingPasskeyChallenges = new Map<string, { factorID: string; challenge: string; expiresAt: number; accountDID: string }>();
  private pendingTotpEnvelopes = new Map<string, { secret: string; expiresAt: number; accountDID: string }>(); // factorID -> envelope
  private didWebReservations = new Map<string, MockDidWebReservation>(); // requestID -> Reservation
  private didWebPublicClaims = new Map<string, { nonce: string; payload: any; status: number; contentType: string }>(); // nonce -> Claim
  private didWebBindings = new Map<string, MockDidWebBinding>(); // accountDID -> Binding
  private exportRequests = new Map<string, MockExportRequest>(); // exportID -> Request
  private loginFactorTokens = new Map<string, { accountDID: string; factorID: string; expiresAt: number }>();

  // In-memory cookie jar for simulating browser session state across fetch calls
  private cookies = new Map<string, string>();

  // Diagnostic / Simulation hooks
  private simulatedDelayMs = 0;
  private customInterceptors: Array<(req: { url: string; method: string; headers: Record<string, string | string[] | undefined>; body?: string }) => MockHttpResponse | undefined> = [];

  constructor() {
    this.seedDefaultAccount();
  }

  /**
   * Reset all state to clean default
   */
  public reset(): void {
    this.accounts.clear();
    this.sessions.clear();
    this.preAuthTokens.clear();
    this.factors.clear();
    this.appPasswords.clear();
    this.connectedApps.clear();
    this.recoveryCodes.clear();
    this.stepUpReceipts.clear();
    this.pendingPasskeyChallenges.clear();
    this.pendingTotpEnvelopes.clear();
    this.didWebReservations.clear();
    this.didWebPublicClaims.clear();
    this.didWebBindings.clear();
    this.exportRequests.clear();
    this.loginFactorTokens.clear();
    this.cookies.clear();
    this.customInterceptors = [];
    this.simulatedDelayMs = 0;
    this.seedDefaultAccount();
  }

  /**
   * Seed the default test account: alice.swan.place
   */
  public seedDefaultAccount(): void {
    const did = 'did:plc:swan-test-user-12345';
    this.accounts.set(did, {
      did,
      handle: 'alice.swan.place',
      email: 'alice@swan.place',
      password: 'correct-horse-battery-staple',
      lifecycle: 'active',
      createdAt: '2026-01-01T00:00:00.000Z'
    });
    this.factors.set(did, []);
    this.appPasswords.set(did, []);
    this.connectedApps.set(did, [
      { did, id: 'app_bsky_official', name: 'Bluesky Social', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-01-02T00:00:00.000Z' }
    ]);
    this.recoveryCodes.set(did, new Set(['RCV-1111-2222', 'RCV-3333-4444']));
    this.didWebBindings.set(did, {
      did,
      handle: 'alice.swan.place',
      state: 'active',
      verifiedAt: '2026-01-01T00:00:00.000Z'
    });
  }

  // --- State Mutation / Inspection Helpers for Test Suites ---

  public setSimulatedDelay(ms: number): void {
    this.simulatedDelayMs = ms;
  }

  public addInterceptor(interceptor: (req: { url: string; method: string; headers: Record<string, string | string[] | undefined>; body?: string }) => MockHttpResponse | undefined): void {
    this.customInterceptors.push(interceptor);
  }

  public addAccount(account: MockAccount): void {
    this.accounts.set(account.did, account);
    if (!this.factors.has(account.did)) this.factors.set(account.did, []);
    if (!this.appPasswords.has(account.did)) this.appPasswords.set(account.did, []);
    if (!this.connectedApps.has(account.did)) this.connectedApps.set(account.did, []);
    if (!this.recoveryCodes.has(account.did)) this.recoveryCodes.set(account.did, new Set());
  }

  public getAccount(did: string): MockAccount | undefined {
    return this.accounts.get(did);
  }

  public getAccountByHandle(handle: string): MockAccount | undefined {
    return Array.from(this.accounts.values()).find(a => a.handle === handle);
  }

  public createSession(did: string, options?: { id?: string; strength?: MockSession['strength']; lastStepUpAt?: number; label?: string; activeCookie?: boolean }): MockSession {
    const sessionToken = 'sess_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    const csrfToken = 'csrf_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    const id = options?.id ?? ('session_id_' + Math.random().toString(36).substring(2, 10));
    const session: MockSession = {
      id,
      sessionToken,
      csrfToken,
      accountDID: did,
      label: options?.label ?? 'Test Active Session',
      kind: 'management',
      issuedAt: Date.now(),
      strength: options?.strength ?? 'password',
      lastStepUpAt: options?.lastStepUpAt,
      current: true
    };
    this.sessions.set(sessionToken, session);
    if (options?.activeCookie !== false) {
      this.cookies.set('__Secure-swan_management', sessionToken);
      this.cookies.set('swan_csrf', csrfToken);
    }
    return session;
  }

  public getSession(sessionToken: string): MockSession | undefined {
    return this.sessions.get(sessionToken);
  }

  public expireSessionStepUp(sessionToken: string): void {
    const session = this.sessions.get(sessionToken);
    if (session) {
      session.strength = 'password';
      session.lastStepUpAt = 0;
    }
  }

  public elevateSession(sessionToken: string, kind: 'stepUpPassword' | 'stepUpMFA' = 'stepUpPassword'): void {
    const session = this.sessions.get(sessionToken);
    if (session) {
      session.strength = kind;
      session.lastStepUpAt = Date.now();
    }
  }

  public addFactor(did: string, factor: Partial<MockFactor> & { kind: MockFactor['kind']; label: string }): MockFactor {
    const id = factor.id ?? 'factor_' + Math.random().toString(36).substring(2);
    const fullFactor: MockFactor = {
      id,
      accountDID: did,
      kind: factor.kind,
      label: factor.label,
      secret: factor.secret,
      publicKey: factor.publicKey,
      credentialID: factor.credentialID,
      transports: factor.transports,
      enabled: factor.enabled ?? true,
      createdAt: factor.createdAt ?? new Date().toISOString()
    };
    const list = this.factors.get(did) || [];
    list.push(fullFactor);
    this.factors.set(did, list);
    return fullFactor;
  }

  public getFactors(did: string): MockFactor[] {
    return this.factors.get(did) || [];
  }

  public addAppPassword(did: string, name: string, scopes: string[] = ['atproto']): MockAppPassword {
    const appPw: MockAppPassword = {
      did,
      name,
      scopes,
      createdAt: new Date().toISOString(),
      lastUsedAt: null
    };
    const list = this.appPasswords.get(did) || [];
    list.push(appPw);
    this.appPasswords.set(did, list);
    return appPw;
  }

  public getAppPasswords(did: string): MockAppPassword[] {
    return this.appPasswords.get(did) || [];
  }

  public addConnectedApp(did: string, app: Partial<MockConnectedApp> & { name: string; scopes: string[] }): MockConnectedApp {
    const id = app.id ?? 'app_' + Math.random().toString(36).substring(2);
    const connApp: MockConnectedApp = {
      did,
      id,
      name: app.name,
      scopes: app.scopes,
      createdAt: app.createdAt ?? new Date().toISOString()
    };
    const list = this.connectedApps.get(did) || [];
    list.push(connApp);
    this.connectedApps.set(did, list);
    return connApp;
  }

  public getConnectedApps(did: string): MockConnectedApp[] {
    return this.connectedApps.get(did) || [];
  }

  public setRecoveryCodes(did: string, codes: string[]): void {
    this.recoveryCodes.set(did, new Set(codes));
  }

  public getRecoveryCodes(did: string): string[] {
    return Array.from(this.recoveryCodes.get(did) || []);
  }

  public issueStepUpReceipt(sessionID: string, accountDID: string, operation: string = 'app-passwords.create', ttlMs: number = 300_000): MockStepUpReceipt {
    const receiptToken = 'rcpt_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    const receipt: MockStepUpReceipt = {
      receiptToken,
      sessionID,
      accountDID,
      operation,
      issuedAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
      consumed: false
    };
    this.stepUpReceipts.set(receiptToken, receipt);
    return receipt;
  }

  public getStepUpReceipt(token: string): MockStepUpReceipt | undefined {
    return this.stepUpReceipts.get(token);
  }

  // --- Cookie Jar Helpers ---

  public getCookie(name: string): string | undefined {
    return this.cookies.get(name);
  }

  public setCookie(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  public clearCookies(): void {
    this.cookies.clear();
  }

  public getCookieHeader(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  // --- Fetch API Interceptor Bridge ---

  public async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    let urlStr: string;
    let method = 'GET';
    let headers: Record<string, string> = {};
    let body: string | undefined;

    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      urlStr = input.toString();
    } else {
      // Request object
      urlStr = input.url;
      method = input.method;
      input.headers.forEach((v, k) => {
        headers[k] = v;
      });
      if (input.body) {
        body = await input.text();
      }
    }

    if (init) {
      if (init.method) method = init.method;
      if (init.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((v, k) => {
            headers[k] = v;
          });
        } else if (Array.isArray(init.headers)) {
          for (const [k, v] of init.headers) {
            headers[k] = v;
          }
        } else {
          headers = { ...headers, ...(init.headers as Record<string, string>) };
        }
      }
      if (init.body) {
        body = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
      }
    }

    // Attach Cookie header from simulated jar if not explicitly provided
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'cookie')) {
      const cookieStr = this.getCookieHeader();
      if (cookieStr) headers['cookie'] = cookieStr;
    }

    const response = await this.handleRequest({
      url: urlStr,
      method,
      headers,
      body
    });

    const respHeaders = new Headers(response.headers);
    const isNullBodyStatus = response.status === 204 || response.status === 205 || response.status === 304;
    const bodyInit = isNullBodyStatus
      ? null
      : typeof response.body === 'string'
        ? response.body
        : response.body !== undefined
          ? JSON.stringify(response.body)
          : null;

    return new Response(bodyInit, {
      status: response.status,
      headers: respHeaders
    });
  }

  // --- Core Request Dispatcher ---

  public async handleRequest(req: {
    url: string;
    method: string;
    headers: Record<string, string | string[] | undefined>;
    body?: string;
  }): Promise<MockHttpResponse> {
    if (this.simulatedDelayMs > 0) {
      await new Promise(r => setTimeout(r, this.simulatedDelayMs));
    }

    // Check custom interceptors first
    for (const interceptor of this.customInterceptors) {
      const intercepted = interceptor(req);
      if (intercepted) return intercepted;
    }

    const rawUrl = req.url;
    let path = rawUrl;
    try {
      const parsed = new URL(rawUrl, this.origin);
      path = parsed.pathname;
    } catch {
      // relative path
      if (!path.startsWith('/')) path = '/' + path;
    }

    const method = (req.method || 'GET').toUpperCase();

    const getHeader = (name: string): string | undefined => {
      const found = Object.entries(req.headers).find(([k]) => k.toLowerCase() === name.toLowerCase());
      if (!found) return undefined;
      return Array.isArray(found[1]) ? found[1][0] : found[1];
    };

    const parseCookies = (): Record<string, string> => {
      const cookieHeader = getHeader('cookie') || '';
      const result: Record<string, string> = {};
      for (const part of cookieHeader.split(';')) {
        const [k, v] = part.trim().split('=');
        if (k && v !== undefined) result[k] = v;
      }
      return result;
    };

    const requestCookies = parseCookies();

    const setCookiesInJar = (setCookieHeaders: string[]) => {
      for (const sc of setCookieHeaders) {
        const parts = sc.split(';');
        const [k, v] = parts[0].trim().split('=');
        if (k) {
          const isMaxAgeZero = parts.some(p => p.trim().toLowerCase() === 'max-age=0');
          if (isMaxAgeZero || !v) {
            this.cookies.delete(k);
          } else {
            this.cookies.set(k, v);
          }
        }
      }
    };

    const makeResponse = (
      status: number,
      body: any,
      cookiesToSet: string[] = [],
      extraHeaders: Record<string, string> = {}
    ): MockHttpResponse => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...extraHeaders
      };
      if (cookiesToSet.length > 0) {
        headers['Set-Cookie'] = cookiesToSet.join(', ');
        setCookiesInJar(cookiesToSet);
      }
      return { status, headers, body };
    };

    const errorResponse = (status: number, code: string, message: string): MockHttpResponse => {
      return makeResponse(status, { code, message });
    };

    // Public Claim Endpoint (did:web)
    if (path.startsWith('/.well-known/swan/did-web-claim/')) {
      const nonce = path.replace('/.well-known/swan/did-web-claim/', '');
      const claim = this.didWebPublicClaims.get(nonce);
      if (!claim) {
        return errorResponse(404, 'not_found', 'Claim not found or expired.');
      }
      return {
        status: claim.status,
        headers: { 'Content-Type': claim.contentType, 'Cache-Control': 'no-store' },
        body: claim.payload
      };
    }

    // Normalize endpoint path: ensure starts with /account/api
    let apiPath = path;
    if (!apiPath.startsWith('/account/api/')) {
      if (apiPath.startsWith('/api/')) {
        apiPath = '/account' + apiPath;
      } else if (apiPath.startsWith('/')) {
        apiPath = '/account/api' + apiPath;
      } else {
        apiPath = '/account/api/' + apiPath;
      }
    }

    // 1. GET /account/api/signup/policy
    if (apiPath === '/account/api/signup/policy' && method === 'GET') {
      return makeResponse(200, {
        policy: 'closed',
        inviteCodeRequired: false,
        turnstileRequired: false,
        emailVerificationRequired: false
      });
    }

    // 2. GET /account/api/bootstrap
    if (apiPath === '/account/api/bootstrap' && method === 'GET') {
      const preAuthToken = 'pre_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      this.preAuthTokens.set(preAuthToken, Date.now() + 600_000);
      return makeResponse(
        200,
        { csrf: preAuthToken },
        [`swan_csrf_pre=${preAuthToken}; Path=/account; Secure; SameSite=Strict`]
      );
    }

    // Security policies for mutations
    if (method === 'POST' || method === 'DELETE' || method === 'PUT' || method === 'PATCH') {
      const originHeader = getHeader('origin');
      if (originHeader && originHeader !== this.origin) {
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }
      const fetchSite = getHeader('sec-fetch-site');
      if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }
      if (req.body && req.body.length > 0) {
        const cType = getHeader('content-type') || '';
        const lowerCT = cType.toLowerCase();
        if (!lowerCT.startsWith('application/json')) {
          return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
        }
      }
    }

    // 3. POST /account/api/login
    if (apiPath === '/account/api/login' && method === 'POST') {
      const preAuthCookie = requestCookies['swan_csrf_pre'];
      const csrfHeader = getHeader('x-swan-csrf');
      if (!preAuthCookie || !csrfHeader || preAuthCookie !== csrfHeader || !this.preAuthTokens.has(preAuthCookie)) {
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }
      const expiresAt = this.preAuthTokens.get(preAuthCookie)!;
      if (Date.now() > expiresAt) {
        this.preAuthTokens.delete(preAuthCookie);
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }

      let payload: any = {};
      try {
        payload = JSON.parse(req.body || '{}');
      } catch {
        return errorResponse(400, 'invalid_request', 'Invalid JSON body.');
      }

      if (!payload.handle || !payload.password) {
        return errorResponse(400, 'invalid_request', 'Handle and password are required.');
      }

      const account = Array.from(this.accounts.values()).find(a => a.handle === payload.handle);
      if (!account || account.password !== payload.password) {
        return errorResponse(401, 'authentication_required', 'Sign-in was not accepted.');
      }

      if (account.lifecycle === 'deleted') {
        return errorResponse(401, 'authentication_required', 'Account has been deleted.');
      }

      // MFA check
      const userFactors = (this.factors.get(account.did) || []).filter(f => f.enabled);
      if (userFactors.length > 0) {
        if (!payload.authFactorToken) {
          const primaryFactor = userFactors[0];
          return makeResponse(401, {
            code: 'mfa_required',
            message: 'MFA proof required.',
            factorKind: primaryFactor.kind,
            factorID: primaryFactor.id
          });
        }
        // Validate loginFactorToken
        const tokenRecord = this.loginFactorTokens.get(payload.authFactorToken);
        if (!tokenRecord || tokenRecord.accountDID !== account.did || Date.now() > tokenRecord.expiresAt) {
          return errorResponse(401, 'authentication_required', 'Invalid or expired factor token.');
        }
        this.loginFactorTokens.delete(payload.authFactorToken);
      }

      // Issue management session
      const sessionToken = 'sess_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const csrfToken = 'csrf_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const sessionId = 'session_id_' + Math.random().toString(36).substring(2, 10);

      const sessionObj: MockSession = {
        id: sessionId,
        sessionToken,
        csrfToken,
        accountDID: account.did,
        label: 'Current Web Session',
        kind: 'management',
        issuedAt: Date.now(),
        strength: userFactors.length > 0 ? 'stepUpMFA' : 'password',
        lastStepUpAt: userFactors.length > 0 ? Date.now() : undefined,
        current: true
      };
      this.sessions.set(sessionToken, sessionObj);
      this.preAuthTokens.delete(preAuthCookie);

      const snapshot = this.buildSnapshot(account.did, sessionObj.id);
      return makeResponse(
        200,
        { snapshot, csrf: csrfToken },
        [
          `__Secure-swan_management=${sessionToken}; Path=/account; Secure; HttpOnly; SameSite=Strict`,
          `swan_csrf=${csrfToken}; Path=/account; Secure; SameSite=Strict`,
          `swan_csrf_pre=; Path=/account; Secure; SameSite=Strict; Max-Age=0`
        ]
      );
    }

    // 4. POST /account/api/login/factor-challenge
    if (apiPath === '/account/api/login/factor-challenge' && method === 'POST') {
      const preAuthCookie = requestCookies['swan_csrf_pre'];
      const csrfHeader = getHeader('x-swan-csrf');
      if (!preAuthCookie || !csrfHeader || preAuthCookie !== csrfHeader || !this.preAuthTokens.has(preAuthCookie)) {
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }
      const payload = JSON.parse(req.body || '{}');
      const account = Array.from(this.accounts.values()).find(a => a.handle === payload.handle);
      if (!account || account.password !== payload.password) {
        return errorResponse(401, 'authentication_required', 'Sign-in was not accepted.');
      }
      const challenge = generateChallengeBytes();
      this.pendingPasskeyChallenges.set(challenge, {
        factorID: payload.factorID || 'passkey_1',
        challenge,
        expiresAt: Date.now() + 300_000,
        accountDID: account.did
      });
      return makeResponse(200, {
        accepted: true,
        message: 'Passkey challenge issued',
        challenge,
        factorID: payload.factorID || 'passkey_1',
        accountDID: account.did
      });
    }

    // 5. POST /account/api/login/factor
    if (apiPath === '/account/api/login/factor' && method === 'POST') {
      const preAuthCookie = requestCookies['swan_csrf_pre'];
      const csrfHeader = getHeader('x-swan-csrf');
      if (!preAuthCookie || !csrfHeader || preAuthCookie !== csrfHeader || !this.preAuthTokens.has(preAuthCookie)) {
        return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
      }
      const payload = JSON.parse(req.body || '{}');
      const account = Array.from(this.accounts.values()).find(a => a.handle === payload.handle);
      if (!account || account.password !== payload.password) {
        return errorResponse(401, 'authentication_required', 'Sign-in was not accepted.');
      }

      if (payload.kind === 'totp') {
        if (!payload.code || payload.code.length !== 6) {
          return errorResponse(401, 'authentication_required', 'Invalid TOTP code.');
        }
      } else if (payload.kind === 'recoveryCode') {
        const codes = this.recoveryCodes.get(account.did);
        if (!codes || !codes.has(payload.code)) {
          return errorResponse(401, 'authentication_required', 'Invalid recovery code.');
        }
        codes.delete(payload.code);
      }

      const factorToken = 'fart_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      this.loginFactorTokens.set(factorToken, {
        accountDID: account.did,
        factorID: payload.factorID,
        expiresAt: Date.now() + 300_000
      });

      return makeResponse(200, {
        accepted: true,
        message: 'Factor verified',
        factorToken,
        factorID: payload.factorID,
        factorKind: payload.kind
      });
    }

    // --- Authenticated Session Guard ---
    const sessionCookie = requestCookies['__Secure-swan_management'];
    const session = sessionCookie ? this.sessions.get(sessionCookie) : undefined;
    if (!session) {
      return errorResponse(401, 'authentication_required', 'Authentication required.');
    }

    // --- Authenticated Read Surfaces (GET) ---
    if (method === 'GET') {
      if (apiPath === '/account/api/portal') {
        return makeResponse(200, this.buildSnapshot(session.accountDID, session.id));
      }
      if (apiPath === '/account/api/session' || apiPath === '/account/api/sessions') {
        return makeResponse(200, this.buildSnapshot(session.accountDID, session.id));
      }
      if (apiPath === '/account/api/profile') {
        const snap = this.buildSnapshot(session.accountDID, session.id);
        return makeResponse(200, { account: snap.account, identity: snap.identity });
      }
      if (apiPath === '/account/api/identity') {
        const snap = this.buildSnapshot(session.accountDID, session.id);
        return makeResponse(200, snap.identity ?? { method: 'plc', handle: snap.account.handle, state: 'active' });
      }
      if (apiPath === '/account/api/app-passwords') {
        const snap = this.buildSnapshot(session.accountDID, session.id);
        return makeResponse(200, { passwords: snap.passwords });
      }
      if (apiPath === '/account/api/scope-presets') {
        return makeResponse(200, {
          presets: [
            { id: 'atproto', name: 'Standard AT Protocol', scopes: ['atproto'] },
            { id: 'chat', name: 'Direct Messaging', scopes: ['atproto', 'transition:chat.bsky'] },
            { id: 'email', name: 'Email Notifications', scopes: ['atproto', 'transition:email'] },
            { id: 'generic', name: 'Full Access', scopes: ['atproto', 'transition:generic', 'transition:chat.bsky', 'transition:email'] }
          ],
          availableScopes: ['atproto', 'transition:chat.bsky', 'transition:email', 'transition:generic']
        });
      }
      if (apiPath === '/account/api/factors') {
        const snap = this.buildSnapshot(session.accountDID, session.id);
        return makeResponse(200, { factors: snap.factors });
      }
      if (apiPath === '/account/api/connected-apps') {
        const snap = this.buildSnapshot(session.accountDID, session.id);
        return makeResponse(200, { apps: snap.apps });
      }
      if (apiPath === '/account/api/export') {
        const exp = this.exportRequests.get(session.accountDID);
        return makeResponse(200, exp ? { export: exp } : { export: { status: 'none' } });
      }
      if (apiPath === '/account/api/migration') {
        return makeResponse(200, { migration: { available: true, supportedTargets: ['did:web', 'plc'] } });
      }

      // Default fallback GET
      return makeResponse(200, this.buildSnapshot(session.accountDID, session.id));
    }

    // --- Authenticated Mutation CSRF Guard ---
    const csrfCookie = requestCookies['swan_csrf'];
    const csrfHeader = getHeader('x-swan-csrf');
    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader || csrfCookie !== session.csrfToken) {
      return errorResponse(403, 'request_not_allowed', 'Request not allowed.');
    }

    // Helper: Step-up authorization policy check
    const isStepUpActive = (): boolean => {
      const isElevated = session.strength === 'stepUpPassword' || session.strength === 'stepUpMFA';
      const isFresh = session.lastStepUpAt ? (Date.now() - session.lastStepUpAt < 600_000) : false;
      return Boolean(isElevated && isFresh);
    };

    // Helper: Validate and consume step-up receipt token
    const validateAndConsumeReceipt = (requiredOperation?: string): boolean => {
      const stepUpToken = getHeader('x-swan-step-up');
      if (!stepUpToken) return false;
      const receipt = this.stepUpReceipts.get(stepUpToken);
      if (!receipt || receipt.accountDID !== session.accountDID || Date.now() > receipt.expiresAt) {
        return false;
      }
      if (receipt.consumed) return false;
      if (requiredOperation && receipt.operation && receipt.operation !== requiredOperation) {
        return false;
      }
      receipt.consumed = true;
      return true;
    };

    // 6. POST /account/api/logout
    if (apiPath === '/account/api/logout' && method === 'POST') {
      this.sessions.delete(session.sessionToken);
      return makeResponse(
        200,
        { accepted: true, message: 'Signed out' },
        [
          `__Secure-swan_management=; Path=/account; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
          `swan_csrf=; Path=/account; Secure; SameSite=Strict; Max-Age=0`
        ]
      );
    }

    // 7. POST /account/api/step-up/password (and POST /account/api/step-up)
    if ((apiPath === '/account/api/step-up/password' || apiPath === '/account/api/step-up') && method === 'POST') {
      let payload: any = {};
      try {
        payload = JSON.parse(req.body || '{}');
      } catch {
        return errorResponse(400, 'invalid_request', 'Invalid JSON payload.');
      }
      const account = this.accounts.get(session.accountDID)!;
      if (payload.password !== account.password) {
        return errorResponse(401, 'authentication_required', 'Password incorrect.');
      }
      session.strength = 'stepUpPassword';
      session.lastStepUpAt = Date.now();

      const receipt = this.issueStepUpReceipt(session.id, session.accountDID);
      return makeResponse(200, {
        accepted: true,
        message: 'Password reauthentication accepted',
        accountDID: session.accountDID,
        factorToken: receipt.receiptToken
      });
    }

    // 8. POST /account/api/factors/passkeys/step-up-challenge (and /account/api/factors/step-up/passkey-challenge)
    if ((apiPath === '/account/api/factors/passkeys/step-up-challenge' || apiPath === '/account/api/factors/step-up/passkey-challenge') && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      const challenge = generateChallengeBytes();
      this.pendingPasskeyChallenges.set(challenge, {
        factorID: payload.factorID || 'passkey_1',
        challenge,
        expiresAt: Date.now() + 300_000,
        accountDID: session.accountDID
      });
      return makeResponse(200, {
        accepted: true,
        message: 'Passkey assertion challenge issued',
        challenge,
        factorID: payload.factorID || 'passkey_1',
        accountDID: session.accountDID
      });
    }

    // 9. POST /account/api/factors/step-up
    if (apiPath === '/account/api/factors/step-up' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      if (payload.kind === 'totp') {
        if (!payload.code || payload.code.length !== 6) {
          return errorResponse(403, 'request_not_allowed', 'Invalid TOTP verification code.');
        }
      } else if (payload.kind === 'recoveryCode') {
        const codes = this.recoveryCodes.get(session.accountDID);
        if (!codes || !codes.has(payload.code)) {
          return errorResponse(403, 'request_not_allowed', 'Invalid recovery code.');
        }
        codes.delete(payload.code);
      } else if (payload.kind === 'passkey') {
        if (!payload.challenge || !this.pendingPasskeyChallenges.has(payload.challenge)) {
          return errorResponse(403, 'request_not_allowed', 'Invalid or expired passkey challenge.');
        }
        this.pendingPasskeyChallenges.delete(payload.challenge);
      }

      session.strength = 'stepUpMFA';
      session.lastStepUpAt = Date.now();
      const receipt = this.issueStepUpReceipt(session.id, session.accountDID);

      return makeResponse(200, {
        accepted: true,
        message: 'MFA step-up accepted',
        accountDID: session.accountDID,
        factorToken: receipt.receiptToken
      });
    }

    // 10. POST /account/api/factors/passkeys/challenge
    if (apiPath === '/account/api/factors/passkeys/challenge' && method === 'POST') {
      const userFactors = (this.factors.get(session.accountDID) || []).filter(f => f.enabled);
      const stepUpReceipt = getHeader('x-swan-step-up');
      if (userFactors.length > 0 && !isStepUpActive() && !stepUpReceipt) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      const payload = JSON.parse(req.body || '{}');
      const factorID = payload.factorID || 'pk_' + Math.random().toString(36).substring(2);
      const challenge = generateChallengeBytes();
      this.pendingPasskeyChallenges.set(challenge, {
        factorID,
        challenge,
        expiresAt: Date.now() + 300_000,
        accountDID: session.accountDID
      });
      return makeResponse(200, {
        accepted: true,
        message: 'Passkey challenge issued',
        challenge,
        factorID,
        accountDID: session.accountDID
      });
    }

    // 11. POST /account/api/factors/passkeys/options
    if (apiPath === '/account/api/factors/passkeys/options' && method === 'POST') {
      const challenge = generateChallengeBytes();
      return makeResponse(200, {
        challenge,
        rp: { name: 'Swan', id: 'swan.place' },
        user: { id: session.accountDID, name: 'alice.swan.place', displayName: 'Alice' }
      });
    }

    // 12. POST /account/api/factors/passkeys
    if (apiPath === '/account/api/factors/passkeys' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      if (!payload.factorID || !payload.label || !payload.credentialID) {
        return errorResponse(400, 'invalid_request', 'Missing required passkey registration fields.');
      }
      this.addFactor(session.accountDID, {
        id: payload.factorID,
        kind: 'passkey',
        label: payload.label,
        credentialID: payload.credentialID,
        transports: payload.transports || ['internal', 'hybrid'],
        enabled: true
      });
      return makeResponse(200, {
        accepted: true,
        message: 'Passkey enrolled',
        accountDID: session.accountDID,
        factorID: payload.factorID
      });
    }

    // 13. POST /account/api/factors/totp
    if (apiPath === '/account/api/factors/totp' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      if (!payload.secret) {
        // Disables TOTP factor
        const userFactors = this.factors.get(session.accountDID) || [];
        this.factors.set(session.accountDID, userFactors.filter(f => f.kind !== 'totp'));
        return makeResponse(200, {
          accepted: true,
          message: 'Authentication factor revoked',
          accountDID: session.accountDID
        });
      }
      const factorID = payload.factorID || 'totp_' + Math.random().toString(36).substring(2);
      this.pendingTotpEnvelopes.set(factorID, {
        secret: payload.secret,
        expiresAt: Date.now() + 600_000,
        accountDID: session.accountDID
      });
      return makeResponse(200, {
        accepted: true,
        message: 'TOTP enrollment pending verification',
        factorID,
        accountDID: session.accountDID
      });
    }

    // 14. POST /account/api/factors/totp/verify
    if (apiPath === '/account/api/factors/totp/verify' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      const pending = this.pendingTotpEnvelopes.get(payload.factorID);
      if (!pending || !payload.code || payload.code.length !== 6) {
        return errorResponse(403, 'request_not_allowed', 'Invalid TOTP verification code.');
      }
      this.addFactor(session.accountDID, {
        id: payload.factorID,
        kind: 'totp',
        label: 'Authenticator App',
        secret: pending.secret,
        enabled: true
      });
      this.pendingTotpEnvelopes.delete(payload.factorID);
      return makeResponse(200, {
        accepted: true,
        message: 'TOTP factor enrolled',
        factorID: payload.factorID,
        accountDID: session.accountDID
      });
    }

    // 15. POST /account/api/factors/recovery-codes/rotate
    if (apiPath === '/account/api/factors/recovery-codes/rotate' && method === 'POST') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const newCodes = Array.from({ length: 10 }, () =>
        'RCV-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase()
      );
      this.recoveryCodes.set(session.accountDID, new Set(newCodes));
      return makeResponse(200, {
        accepted: true,
        message: 'Recovery codes rotated',
        recoveryCodes: newCodes,
        accountDID: session.accountDID
      });
    }

    // 16. POST /account/api/app-passwords
    if (apiPath === '/account/api/app-passwords' && method === 'POST') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up') || getHeader('x-swan-step-Up'));
      let receiptValid = false;
      if (stepUpReceiptProvided) {
        receiptValid = validateAndConsumeReceipt('app-passwords.create');
        if (!receiptValid) {
          const rawToken = getHeader('x-swan-step-up') || getHeader('x-swan-step-Up')!;
          const existing = this.stepUpReceipts.get(rawToken);
          if (existing?.consumed) {
            return errorResponse(403, 'request_not_allowed', 'Receipt already consumed.');
          }
          return errorResponse(403, 'request_not_allowed', 'Invalid step-up receipt.');
        }
      } else if (!isStepUpActive()) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }

      let payload: any = {};
      try {
        payload = JSON.parse(req.body || '{}');
      } catch {
        return errorResponse(400, 'invalid_request', 'Invalid JSON body.');
      }

      if (!payload.name || !payload.scopes || !Array.isArray(payload.scopes) || !payload.scopes.includes('atproto')) {
        return errorResponse(400, 'invalid_request', 'Scope validation failed. Base scope atproto required.');
      }

      const generatedPassword = 'swan-app-' + Math.random().toString(36).substring(2, 6) + '-' + Math.random().toString(36).substring(2, 6);
      this.addAppPassword(session.accountDID, payload.name, payload.scopes);

      return makeResponse(200, {
        accepted: true,
        message: 'App password created',
        accountDID: session.accountDID,
        password: generatedPassword
      });
    }

    // 17. DELETE /account/api/app-passwords/:name
    if (apiPath.startsWith('/account/api/app-passwords/') && method === 'DELETE') {
      const name = decodeURIComponent(apiPath.replace('/account/api/app-passwords/', ''));
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (stepUpReceiptProvided) {
        const valid = validateAndConsumeReceipt('app-passwords.revoke');
        if (!valid) {
          return errorResponse(403, 'request_not_allowed', 'Invalid step-up receipt.');
        }
      } else if (!isStepUpActive()) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      const list = this.appPasswords.get(session.accountDID) || [];
      this.appPasswords.set(session.accountDID, list.filter(p => p.name !== name));
      return makeResponse(200, {
        accepted: true,
        message: 'App password revoked',
        accountDID: session.accountDID
      });
    }

    // 18. POST /account/api/scopes/validate
    if (apiPath === '/account/api/scopes/validate' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      if (!payload.scopes || !Array.isArray(payload.scopes) || !payload.scopes.includes('atproto')) {
        return errorResponse(400, 'invalid_request', 'Scope validation failed. Base scope atproto required.');
      }
      return makeResponse(200, { valid: true, scopes: payload.scopes });
    }

    // 19. DELETE /account/api/sessions/:id
    if (apiPath.startsWith('/account/api/sessions/') && method === 'DELETE') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const id = decodeURIComponent(apiPath.replace('/account/api/sessions/', ''));
      // Remove matching session
      for (const [tok, sess] of Array.from(this.sessions.entries())) {
        if (sess.id === id) this.sessions.delete(tok);
      }
      return makeResponse(200, {
        accepted: true,
        message: 'Session revoked',
        accountDID: session.accountDID
      });
    }

    // 20. POST /account/api/sessions/revoke-others
    if (apiPath === '/account/api/sessions/revoke-others' && method === 'POST') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      for (const [tok, sess] of Array.from(this.sessions.entries())) {
        if (sess.accountDID === session.accountDID && sess.sessionToken !== session.sessionToken) {
          this.sessions.delete(tok);
        }
      }
      return makeResponse(200, {
        accepted: true,
        message: 'Other sessions revoked'
      });
    }

    // 21. DELETE /account/api/connected-apps/:id
    if (apiPath.startsWith('/account/api/connected-apps/') && method === 'DELETE') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const id = decodeURIComponent(apiPath.replace('/account/api/connected-apps/', ''));
      const list = this.connectedApps.get(session.accountDID) || [];
      this.connectedApps.set(session.accountDID, list.filter(a => a.id !== id));
      return makeResponse(200, {
        accepted: true,
        message: 'Connected app revoked',
        accountDID: session.accountDID
      });
    }

    // 22. DELETE /account/api/factors/passkeys/:id
    if (apiPath.startsWith('/account/api/factors/passkeys/') && method === 'DELETE') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const id = decodeURIComponent(apiPath.replace('/account/api/factors/passkeys/', ''));
      const list = this.factors.get(session.accountDID) || [];
      this.factors.set(session.accountDID, list.filter(f => f.id !== id));
      return makeResponse(200, {
        accepted: true,
        message: 'Authentication factor revoked',
        accountDID: session.accountDID
      });
    }

    // 23. DELETE /account/api/factors/totp
    if (apiPath === '/account/api/factors/totp' && method === 'DELETE') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const list = this.factors.get(session.accountDID) || [];
      this.factors.set(session.accountDID, list.filter(f => f.kind !== 'totp'));
      return makeResponse(200, {
        accepted: true,
        message: 'Authentication factor revoked',
        accountDID: session.accountDID
      });
    }

    // 24. POST /account/api/export / /account/api/export/request
    if ((apiPath === '/account/api/export' || apiPath === '/account/api/export/request') && method === 'POST') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const exportId = 'exp_' + Math.random().toString(36).substring(2, 10);
      const expReq: MockExportRequest = {
        id: exportId,
        accountDID: session.accountDID,
        status: 'pending',
        requestedAt: new Date().toISOString()
      };
      this.exportRequests.set(session.accountDID, expReq);
      return makeResponse(200, {
        accepted: true,
        message: 'Export request accepted',
        accountDID: session.accountDID,
        exportID: exportId
      });
    }

    // 25. POST /account/api/migration / /account/api/migration/request
    if ((apiPath === '/account/api/migration' || apiPath === '/account/api/migration/request') && method === 'POST') {
      return makeResponse(200, {
        accepted: true,
        message: 'Migration request accepted',
        accountDID: session.accountDID
      });
    }

    // 26. POST /account/api/profile
    if (apiPath === '/account/api/profile' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      const account = this.accounts.get(session.accountDID)!;
      if (payload.email) account.email = payload.email;
      if (payload.handle) account.handle = payload.handle;
      return makeResponse(200, {
        accepted: true,
        message: 'Profile updated.',
        account: { did: account.did, handle: account.handle, email: account.email, lifecycle: account.lifecycle }
      });
    }

    // 27. POST /account/api/identity (general update)
    if (apiPath === '/account/api/identity' && method === 'POST') {
      return makeResponse(200, {
        accepted: true,
        message: 'Identity verification requested.'
      });
    }

    // 28. POST /account/api/lifecycle/deactivate
    if (apiPath === '/account/api/lifecycle/deactivate' && method === 'POST') {
      const account = this.accounts.get(session.accountDID)!;
      account.lifecycle = 'deactivated';
      return makeResponse(200, {
        accepted: true,
        message: 'Deactivation request accepted.',
        accountDID: session.accountDID
      });
    }

    // 29. POST /account/api/lifecycle/delete
    if (apiPath === '/account/api/lifecycle/delete' && method === 'POST') {
      const stepUpReceiptProvided = Boolean(getHeader('x-swan-step-up'));
      if (!isStepUpActive() && !stepUpReceiptProvided) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      if (stepUpReceiptProvided) {
        validateAndConsumeReceipt();
      }
      const account = this.accounts.get(session.accountDID)!;
      account.lifecycle = 'deleted';
      return makeResponse(200, {
        accepted: true,
        message: 'Account deletion started',
        accountDID: session.accountDID
      });
    }

    // --- did:web Identity APIs ---

    // 30. POST /account/api/identity/reserve
    if (apiPath === '/account/api/identity/reserve' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      const requestID = payload.requestID || 'req_' + Math.random().toString(36).substring(2);
      const targetDID = payload.targetDID || `did:web:${payload.handle || 'user.example.com'}`;
      const handle = payload.handle || 'user.example.com';
      const nonce = 'nonce_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const expiresAt = payload.expiresAt || new Date(Date.now() + 86400000).toISOString();
      const claimPayload = JSON.stringify({ did: targetDID, handle, nonce, validUntil: expiresAt });

      const reservation: MockDidWebReservation = {
        requestID,
        targetDID,
        handle,
        nonce,
        claimPayload,
        expiresAt,
        consumed: false
      };
      this.didWebReservations.set(requestID, reservation);
      this.didWebPublicClaims.set(nonce, {
        nonce,
        payload: { claim: claimPayload, nonce, targetDID },
        status: 200,
        contentType: 'application/json'
      });

      return makeResponse(200, {
        requestID,
        nonce,
        claimEndpoint: `${this.origin}/.well-known/swan/did-web-claim/${nonce}`,
        expiresAt,
        claimPayload
      });
    }

    // 31. POST /account/api/identity/claim
    if (apiPath === '/account/api/identity/claim' && method === 'POST') {
      const payload = JSON.parse(req.body || '{}');
      const reservation = this.didWebReservations.get(payload.requestID);
      if (!reservation) {
        return errorResponse(404, 'not_found', 'Reservation not found.');
      }
      if (reservation.consumed) {
        return errorResponse(400, 'invalid_request', 'Reservation already consumed.');
      }
      reservation.consumed = true;

      const binding: MockDidWebBinding = {
        did: reservation.targetDID,
        handle: reservation.handle,
        state: 'active',
        verifiedAt: new Date().toISOString()
      };
      this.didWebBindings.set(session.accountDID, binding);

      return makeResponse(200, binding);
    }

    // 32. POST /account/api/identity/rotate
    if (apiPath === '/account/api/identity/rotate' && method === 'POST') {
      const stepUpHeader = getHeader('x-swan-step-up');
      if (!isStepUpActive() && !stepUpHeader) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      const payload = JSON.parse(req.body || '{}');
      const binding: MockDidWebBinding = {
        did: payload.targetDID || `did:web:${payload.handle || 'user.example.com'}`,
        handle: payload.handle || 'user.example.com',
        state: 'active',
        verifiedAt: new Date().toISOString()
      };
      this.didWebBindings.set(session.accountDID, binding);
      return makeResponse(200, binding);
    }

    // 33. POST /account/api/identity/remove
    if (apiPath === '/account/api/identity/remove' && method === 'POST') {
      const stepUpHeader = getHeader('x-swan-step-up');
      if (!isStepUpActive() && !stepUpHeader) {
        return errorResponse(403, 'step_up_required', 'Step-up authentication required.');
      }
      const binding: MockDidWebBinding = {
        did: session.accountDID,
        handle: 'alice.swan.place',
        state: 'removed',
        verifiedAt: new Date().toISOString()
      };
      this.didWebBindings.set(session.accountDID, binding);
      return makeResponse(200, binding);
    }

    // 34. POST /account/api/identity/reverify
    if (apiPath === '/account/api/identity/reverify' && method === 'POST') {
      const current = this.didWebBindings.get(session.accountDID);
      const binding: MockDidWebBinding = {
        did: current?.did || session.accountDID,
        handle: current?.handle || 'alice.swan.place',
        state: 'active',
        verifiedAt: new Date().toISOString()
      };
      this.didWebBindings.set(session.accountDID, binding);
      return makeResponse(200, binding);
    }

    // 35. POST /account/api/identity/admission
    if (apiPath === '/account/api/identity/admission' && method === 'POST') {
      return makeResponse(200, {
        admitted: true,
        method: 'didWeb',
        state: 'active'
      });
    }

    // Fallback 404 for unknown endpoints
    return errorResponse(404, 'not_found', 'Endpoint not found.');
  }

  // --- Snapshot Builder ---

  public buildSnapshot(did: string, currentSessionId: string) {
    const account = this.accounts.get(did)!;
    const userFactors = (this.factors.get(did) || []).map(f => ({
      id: f.id,
      kind: f.kind,
      label: f.label,
      enabled: f.enabled
    }));
    const passwords = (this.appPasswords.get(did) || []).map(p => ({
      name: p.name,
      scopes: p.scopes,
      createdAt: p.createdAt,
      lastUsedAt: p.lastUsedAt ?? null
    }));
    const apps = (this.connectedApps.get(did) || []).map(a => ({
      id: a.id,
      name: a.name,
      scopes: a.scopes,
      createdAt: a.createdAt
    }));
    const didBinding = this.didWebBindings.get(did);

    // Build session list
    const sessionsList: MockSession[] = [];
    for (const s of Array.from(this.sessions.values())) {
      if (s.accountDID === did) {
        sessionsList.push({
          ...s,
          current: s.id === currentSessionId
        });
      }
    }
    if (sessionsList.length === 0) {
      sessionsList.push({
        id: currentSessionId,
        sessionToken: 'mock_token',
        csrfToken: 'mock_csrf',
        accountDID: did,
        label: 'Swan Management Session (Current)',
        kind: 'management',
        issuedAt: Date.now(),
        strength: 'password',
        current: true
      });
    }

    return {
      account: {
        did: account.did,
        handle: account.handle,
        email: account.email,
        lifecycle: account.lifecycle
      },
      identity: didBinding && didBinding.state === 'active'
        ? { method: 'didWeb', handle: didBinding.handle, state: didBinding.state }
        : { method: 'plc', handle: account.handle, state: 'active' },
      strength: 'password',
      factors: userFactors,
      sessions: sessionsList.map(s => ({
        id: s.id,
        label: s.label,
        kind: s.kind,
        lastSeen: new Date(s.issuedAt).toISOString(),
        current: s.current
      })),
      apps,
      passwords
    };
  }
}
