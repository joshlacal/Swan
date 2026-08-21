# Project: Swan Account Portal Frontend & Step-Up Integration

## Architecture
The Swan Account Management Portal is a SvelteKit 2 / Svelte 5 / Vite 7 single-page application (SPA) with `@sveltejs/adapter-static` located in `web/`. It runs in browsers under a strict Content Security Policy (no inline scripts, no remote CDNs/fonts/images). It communicates with the Swan backend server (Swift HTTP service) via `/account/api/**` REST endpoints using session cookies (`__Secure-swan_management`) and CSRF tokens (`swan_csrf` cookie + `X-Swan-CSRF` header).

```
+------------------------------------------------------------------------------------------------+
|                                    Svelte 5 SPA Shell (+page.svelte)                           |
+------------------------------------------------------------------------------------------------+
| Views: Overview, Profile, Security, Recovery, Sessions, Apps, Passwords, Export, Lifecycle     |
+------------------------------------------------------------------------------------------------+
| Modals: StepUpModal, AppPasswordModal, PasskeyEnrollModal, TotpEnrollModal, RecoveryModal, ... |
+------------------------------------------------------------------------------------------------+
| Stores: portalStore (snapshot), toastsStore, modalsStore, stepupStore                          |
+------------------------------------------------------------------------------------------------+
| Helpers: api.ts (HTTP client + Step-Up retry interceptor), webauthn.ts, qrcode.ts              |
+------------------------------------------------------------------------------------------------+
                                                |
                                                | HTTP (GET, POST, DELETE) + X-Swan-CSRF + X-Swan-Step-Up
                                                v
+------------------------------------------------------------------------------------------------+
|                                 Swan HTTP Backend (/account/api/**)                            |
+------------------------------------------------------------------------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Typed Models & API Client | Types (`types.ts`), HTTP client with correct verbs (`GET`, `POST`, `DELETE`), CSRF bootstrap, error parsing (`error.code`, `error.message`) | M1 | Survey 1 & 2 |
| 2 | Base64URL & WebAuthn Helpers | Base64URL encoding/decoding for ArrayBuffer / Uint8Array, WebAuthn assertion/attestation transformers (`webauthn.ts`) | M1 | Survey 2 & 3 |
| 3 | Inline SVG QR Generator | Pure TypeScript inline SVG matrix generator for TOTP `otpauth://` URIs compliant with strict CSP (no remote images) (`qrcode.ts`) | M1 | Survey 2 & 3 |
| 4 | Reactive Stores & UI Kit | Toast notifications (`toasts.ts`), Modal controller (`modals.ts`), Spinner, CopyButton | M1 | Survey 2 |
| 5 | Step-Up Coordinator & Interceptor | Intercept 403 Step-Up Required, trigger re-auth modal, manage single-use receipt tokens, replay mutation with `X-Swan-Step-Up` | M2 | Survey 1, 2, 3 |
| 6 | Interactive Step-Up Dialog | Re-authentication dialog supporting password re-auth, TOTP code submission, and WebAuthn passkey assertion handshake | M2 | Survey 1 & 3 |
| 7 | Accessible Modal Dialog Base | `<Modal.svelte>` with focus trap, ESC listener, ARIA dialog roles, backdrop handling | M3 | Survey 2 & 3 |
| 8 | App Password Workflow Modal | Capture name & scope selection (`atproto`, `transition:chat.bsky`, `transition:email`, `transition:generic`), display one-time secret with copy button | M3 | Survey 1 & 3 |
| 9 | Passkey WebAuthn Enrollment Modal | Full WebAuthn registration ceremony (`navigator.credentials.create` -> POST attestation) | M3 | Survey 1 & 3 |
| 10 | TOTP Enrollment Modal | Display Base32 secret & inline SVG QR, 6-digit confirmation code verification (`POST /account/api/factors/totp/verify`) | M3 | Survey 1 & 3 |
| 11 | Recovery Code Rotation Modal | Elevate session, call `/account/api/factors/recovery-codes/rotate`, render single-use backup codes with copy & download `.txt` | M3 | Survey 1 & 3 |
| 12 | did:web Domain Wizard Modal | Reserve signing key, display verification claim endpoint, claim binding, rotation & removal | M3 | Survey 1 & 2 |
| 13 | Export & Lifecycle Modals | Data export trigger/status tracker, destructive account deactivation & deletion confirmation modals | M3 | Survey 1 & 2 |
| 14 | Modular Views Refactoring | Separate views for Overview, Profile, Security, Recovery, Sessions, Connected Apps, Passwords, Export, Lifecycle | M4 | Survey 2 |
| 15 | Correct HTTP Verb Routing | Enforce HTTP `DELETE` for session, app password, and connected app revocations; `POST` for mutations; `GET` for reads | M4 | Survey 1 & 2 |
| 16 | Root SPA Shell & Navigation | Wire up navigation tabs, responsive layout, toast container, modal mounts, snapshot refresh | M4 | Survey 2 |
| 17 | Test Infrastructure & Scripts | Add `"test:unit": "vitest run"` to `package.json`, expand Vitest test suites across API client, WebAuthn helpers, and step-up flows | M5 | Survey 2 & 3 |
| 18 | Opaque-Box E2E Test Suite | 4-Tier requirement-driven E2E test suite covering all portal workflows, step-up ceremonies, and error states | M5 | Survey 3 |
| 19 | Production Build & Netcup Deployment | Verify `npm run check`, `npm run test:unit`, `npm run build`, build native Docker image on Netcup, restart `swan.service`, live verify `https://swan.place/account/` | M6 | Survey 3 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Client, Types & Utilities | `types.ts`, `api.ts`, `webauthn.ts`, `qrcode.ts`, `stores/toasts.ts`, `stores/modals.ts`, `stores/portal.ts`, UI primitives | none | DONE |
| M2 | Step-Up Re-Auth Interceptor & Modal | `stores/stepup.ts`, `StepUpModal.svelte`, `api.ts` interceptor & retry engine, unit tests | M1 | DONE |
| M3 | Parameterized Modal Dialogs & Workflows | `Modal.svelte`, `AppPasswordModal.svelte`, `PasskeyEnrollModal.svelte`, `TotpEnrollModal.svelte`, `RecoveryRotateModal.svelte`, `DidWebModal.svelte`, `ExportModal.svelte`, `LifecycleModal.svelte` | M1, M2 | DONE |
| M4 | Modular Views & Root SPA Shell | `OverviewView.svelte`, `ProfileView.svelte`, `SecurityView.svelte`, `RecoveryView.svelte`, `SessionsView.svelte`, `AppsView.svelte`, `PasswordsView.svelte`, `ExportView.svelte`, `LifecycleView.svelte`, `+page.svelte` | M1, M2, M3 | DONE |
| M5 | Test Suite Expansion & 100% Pass | `"test:unit"` script in `package.json`, complete Vitest unit & integration tests, E2E test verification | M1, M2, M3, M4 | DONE |
| M6 | Live Netcup Rollout & Production Verification | Native Docker build on netcup, restart `swan.service`, live endpoint checks on `https://swan.place/account/` | M1, M2, M3, M4, M5 | DONE |

## Interface Contracts
### `web/src/lib/api.ts` ↔ Views & Modals
- `accountFetch<T>(path: string, init?: RequestInit, options?: { skipStepUp?: boolean, stepUpReceipt?: string }): Promise<T>`
- Automatic CSRF injection via `X-Swan-CSRF` header.
- Automatic 403 step-up interception: catches `request_not_allowed` / `step_up_required`, prompts user through `stepupStore.requestStepUp()`, attaches `X-Swan-Step-Up: receipt` if receipt returned, and retries the original request.
- Methods: `fetchSnapshot()`, `login(...)`, `logout()`, `stepUpPassword(password)`, `requestPasskeyChallenge(label)`, `registerPasskey(...)`, `verifyTotp(...)`, `createAppPassword(name, scopes)`, `revokeAppPassword(name)`, `revokeSession(id)`, `revokeOtherSessions()`, `revokeConnectedApp(id)`, `rotateRecoveryCodes()`, `requestExport()`, `deleteAccount()`.

### `web/src/lib/webauthn.ts` ↔ Passkey Modals & Step-Up
- `base64urlToUint8Array(base64url: string): Uint8Array`
- `uint8ArrayToBase64URL(bytes: Uint8Array | ArrayBuffer): string`
- `performPasskeyRegistration(challengeResponse: WebAuthnChallenge): Promise<WebAuthnAttestationPayload>`
- `performPasskeyAssertion(challengeResponse: WebAuthnStepUpChallenge): Promise<WebAuthnAssertionPayload>`

### Backend HTTP API ↔ Frontend Client
- Mutation Headers: `Origin: https://swan.place`, `Sec-Fetch-Site: same-origin`, `Content-Type: application/json`, `X-Swan-CSRF: <csrfToken>`, `X-Swan-Step-Up: <optionalReceiptToken>`.
- Deletion Endpoints: `DELETE /account/api/sessions/:id`, `DELETE /account/api/app-passwords/:name`, `DELETE /account/api/connected-apps/:id`, `DELETE /account/api/factors/passkeys/:id`, `DELETE /account/api/factors/totp`.

## Code Layout
```
Swan-account-integration/web/src/
├── app.d.ts
├── app.html
├── lib/
│   ├── api.ts                      # Core HTTP client, CSRF bootstrap, step-up interceptor, error parsing
│   ├── api.test.ts                 # Vitest test suite for api.ts, step-up replay, DELETE methods
│   ├── types.ts                    # Full TypeScript definitions for backend DTOs & portal entities
│   ├── webauthn.ts                 # WebAuthn Base64URL and credential transformation helpers
│   ├── webauthn.test.ts            # Unit tests for WebAuthn encoding/decoding
│   ├── qrcode.ts                   # Inline SVG QR code matrix generator (CSP-safe)
│   ├── qrcode.test.ts              # Unit tests for QR generator
│   ├── stores/
│   │   ├── portal.ts               # Reactive Svelte store for portal snapshot and active tab
│   │   ├── toasts.ts               # Reactive store for toast messages (success, error, info)
│   │   ├── modals.ts               # Active modal controller store
│   │   └── stepup.ts               # Step-up promise resolver & re-auth coordinator
│   └── components/
│       ├── ui/
│       │   ├── Modal.svelte        # Base accessible modal dialog
│       │   ├── ToastContainer.svelte # Toast container & auto-dismiss notices
│       │   ├── Spinner.svelte      # Accessible busy/loading spinner
│       │   ├── CopyButton.svelte   # Clipboard copy button with copied confirmation
│       │   └── QrCode.svelte       # SVG QR code component
│       ├── views/
│       │   ├── OverviewView.svelte # Account pulse, metrics, quick actions
│       │   ├── ProfileView.svelte  # Identity, did:web management, contact info
│       │   ├── SecurityView.svelte # Factors list, passkeys, TOTP setup triggers
│       │   ├── RecoveryView.svelte # Recovery codes view and rotate triggers
│       │   ├── SessionsView.svelte # Session list, current device badge, DELETE revoke buttons
│       │   ├── AppsView.svelte     # Connected OAuth apps list, DELETE revoke buttons
│       │   ├── PasswordsView.svelte# App passwords list, create modal trigger, DELETE revoke
│       │   ├── ExportView.svelte   # Data export request & status tracker
│       │   └── LifecycleView.svelte# Deactivation & deletion action panel
│       └── modals/
│           ├── StepUpModal.svelte          # Password / TOTP / Passkey re-authentication dialog
│           ├── AppPasswordModal.svelte     # Creation form (name, scopes) & one-time secret display
│           ├── PasskeyEnrollModal.svelte   # WebAuthn registration ceremony dialog
│           ├── TotpEnrollModal.svelte      # TOTP secret display, QR representation, 6-digit verification
│           ├── RecoveryRotateModal.svelte  # Step-up confirmation & backup codes display
│           ├── DidWebModal.svelte          # did:web domain reservation & claim wizard
│           ├── ExportModal.svelte          # Export trigger & status monitor
│           └── LifecycleModal.svelte       # Destructive confirmation modal (deactivate/delete)
└── routes/
    ├── +layout.ts                  # prerender = true, ssr = false
    └── +page.svelte                # Root view mounting layout, views, modals, and toasts
```
