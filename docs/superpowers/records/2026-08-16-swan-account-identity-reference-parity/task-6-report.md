# Task 6 correction — account portal/API

Correction lane for review P0s against `cb5cef99`. The prior production-readiness
record remains untouched; this 2026-08-16 record is authoritative for the portal
lane. No router assembly, migrations, Package.swift, Dockerfile, deployment, or
push was performed.

Implemented correction: asset-aware static dispatch with MIME/cache rules and
navigation-only SPA fallback; strict default-none self-only CSP; bounded JSON
login credentials sent to an explicit account authenticator; one-time pre-auth
CSRF state and management CSRF checks; frozen API route/verb expansion; and a
disposable HTTPS Playwright fixture/gate.

Visual direction remains archival instrument: warm paper, deep teal, ochre
signals, editorial serif, compact mono labels, restrained motion, and responsive
keyboard-accessible controls.

Integration remains an explicit patch for the integration owner:

```swift
let portal = SwanAccountPortalHTTP(
  configuration: try .init(publicOrigin: configuration.publicURL,
                           staticDirectory: accountPortalDirectory),
  sessions: managementSessionRuntime,
  service: accountPortalService
)
portal.register(on: router) // before broad fallback; after reserved routes
```

The Docker build-stage patch remains Node-only:

```dockerfile
FROM node:22-bookworm-slim AS account-portal-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run check && npm run build
COPY --from=account-portal-builder /src/web/build/ /opt/swan/account/
```

Verification: `npm run check`, `npm test`, `npm run lint`, `npm run build`,
`npm run test:browser` (2 passing against the disposable self-signed HTTPS
fixture), and `xcrun --toolchain XcodeDefault swift build --target SwanHTTP
--disable-sandbox` (complete; existing repository warnings only). Browser tests
also support `SWAN_PORTAL_TEST_URL` for an integration server. External/live
account and deployment gates remain out of scope and unrun.

The pre-auth CSRF runtime now accepts an injected `SwanManagementPreAuthStore`
for durable one-time persistence; its in-memory implementation is test-only and
must not be selected by production assembly. Origin validation requires the
configured HTTPS origin and rejects credentials, paths, queries, and fragments.
The correction also adds a real bounded login form and authenticated response
that hands the rotated management CSRF to the client, pre-auth signup handlers
that do not require a management cookie, typed payload plumbing for mutations,
and durable CSRF digest injection for restart-safe validation.
Signup pre-auth state is retained through email/request and authorize, and is
consumed only after final signup returns an account-bound identity; successful
signup issues the management cookie and rotated CSRF. Mutations now admit and
forward bounded JSON payloads, including recursive identifier DELETE routes.

Integration gates still required before release acceptance: provide production
SQLite implementations of `SwanManagementPreAuthStore` and
`SwanManagementCSRFStore` (the runtime intentionally has no production
in-memory default), wire an atomic signup side-effect coordinator and injected
signup policy, and run the adapter against a disposable Swift/Hummingbird
harness. The checked-in Playwright fixture is deliberately disposable HTTPS
coverage for static/CSP/browser behavior; it is not claimed as live Swift
adapter evidence.

## Portal storage and atomic-auth correction

The dependency-neutral pre-auth and CSRF protocols now live in `SwanStorage`,
alongside `SwanManagementPreAuthSessionCoordinator`. `SwanAccounts` retains
only the runtime and test-only in-memory implementations. `SwanSQLite` adds
`AccountPortalSessionStore.swift`, which implements management-session,
pre-auth, CSRF, and atomic consume-plus-session creation against the existing
foundation `management_sessions` table. Its `migrateAccountPortalSessionSchema`
method creates only the lane-owned `management_pre_auth` table and is
intentionally not registered in the shared migration spine.

Portal login and signup now call `SwanManagementSessionRuntime.issueAfterPreAuth`;
there is no non-atomic fallback for those paths. If session insertion fails,
the held SQLite transaction rolls back pre-auth consumption and does not leave
an orphaned management session. `SwanAccountPortalConfiguration` carries the
injected `SignupPolicy`, and the API advertisement is derived from it.

Integration owner wiring:

```swift
try await database.migrateAccountPortalSessionSchema()
let portalSessions = SwanManagementSessionRuntime(
    store: database,
    preAuthStore: database,
    csrfStore: database,
    preAuthSessionCoordinator: database
)
let portal = SwanAccountPortalHTTP(
    configuration: try .init(publicOrigin: configuration.publicURL,
                             staticDirectory: accountPortalDirectory,
                             signupPolicy: signupPolicy),
    sessions: portalSessions,
    service: accountPortalService
)
portal.register(on: router)
```

The migration call, router order, Docker build stage, and signup service
assembly remain integration-owned and were not changed in this lane.
