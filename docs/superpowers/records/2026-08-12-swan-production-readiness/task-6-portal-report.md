# Task 6 — Account portal and management API

Status: implemented in the portal lane; no router/runtime/Docker integration,
deployment, push, or external hosting was performed.

## Sealed lane surface

The lane adds:

- `Sources/SwanAccounts/SwanManagementSessionRuntime.swift`: opaque 256-bit
  management values, SHA-256 digests at the store boundary, idle/absolute
  expiry checks, revocation, constant-time CSRF comparison, and per-session
  CSRF rotation.
- `Sources/SwanHTTP/SwanAccountPortalHTTP.swift`: `/account/api/*` adapter
  with API-before-SPA registration, exact Origin and `Sec-Fetch-Site` policy,
  JSON mutation admission, no-store JSON errors, cookie attributes, static
  fallback, and self-only account CSP. Bearer/DPoP/OAuth/app-password
  credentials are never consulted.
- `web/`: SvelteKit `adapter-static` build-only app. It has an account atlas
  covering overview, profile, security, recovery, sessions/devices, connected
  apps, app passwords, export/migration, and lifecycle capability states.
  Secrets are not placed in localStorage. The visual direction is **archival
  instrument**: warm paper, deep teal, ochre signal accents, serif editorial
  headings, compact mono labels, deliberate asymmetry, and restrained status
  lines. Responsive breakpoints, keyboard-visible controls, semantic labels,
  and `prefers-reduced-motion` support are included.
- `web/static/auth-tokens.css` plus the OAuth page changes: script-free OAuth
  login/consent pages share the account palette and typography through a
  same-origin stylesheet. OAuth CSP remains script-free and self-only for
  styles (`default-src 'none'; style-src 'self'; form-action ...;
  frame-ancestors 'none'; base-uri 'none'`).
- `web/tests/portal.spec.ts`: local-HTTPS Playwright flows are ready and are
  intentionally skipped unless `SWAN_PORTAL_TEST_URL` points at the disposable
  fixture.

## Exact integration patch (for the integration owner)

After constructing the account control store, management-session store,
account portal service, and static output directory in `SwanHTTP.buildRouter`,
register the portal before any broad public fallback:

```swift
let accountPortal = SwanAccountPortalHTTP(
    configuration: try .init(
        publicOrigin: configuration.publicURL,
        staticDirectory: accountPortalDirectory
    ),
    sessions: managementSessionRuntime,
    service: accountPortalService
)
accountPortal.register(on: router)
```

The call must occur before any `router.on("/*"...)` or static catch-all, and
must remain after the exact `/xrpc`, `/oauth`, health, discovery, and WebSocket
registrations. Do not add a portal fallback to those reserved prefixes. The
adapter's unknown `/account/api/*` guards return JSON 404 and cannot become an
HTML fallback.

The build-only Docker patch is:

```dockerfile
FROM node:22-bookworm-slim AS account-portal-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run check && npm run build

# In the existing Swift runtime stage, after the image's static directory is
# created (the runtime still contains no node/npm executable):
COPY --from=account-portal-builder /src/web/build/ /opt/swan/account/
```

The integration owner supplies the service implementation that maps frozen
account contracts to `SwanAccountPortalServing`; the lane adapter deliberately
does not edit migrations, Package.swift, generated wire, router assembly,
SwanCommand.swift, or Dockerfile.

## Verification

Passed:

```text
npm ci
npm run check          # 0 errors, 0 warnings
npm test               # 2 tests passed
npm run lint           # passed (configuration/build files; Svelte/TS checked by svelte-check)
npm run build          # adapter-static emitted build/
npm run test:browser    # 2 tests skipped: SWAN_PORTAL_TEST_URL unset
xcrun --toolchain XcodeDefault swift build --target SwanHTTP --disable-sandbox  # Build complete
```

The first clean Swift build exhausted the volume while compiling existing
dependencies; generated `.build` output was moved aside and the incremental
target build then completed. Browser gates were not run: no disposable local
HTTPS account fixture was available (`SWAN_PORTAL_TEST_URL` unset), and no live
account/OAuth/session/revocation flow or deployment was authorized.
