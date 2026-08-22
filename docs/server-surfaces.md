# Server operation and exposed surfaces

This document describes Swan's server-side operational surfaces, network resolution rules, browser authentication interfaces, XRPC proxy routing, and operator diagnostic logging.

## Foreign handle resolution

By default, Swan's `com.atproto.identity.resolveHandle` endpoint answers only for accounts provisioned locally in `control.sqlite`. A query for any handle not held by the local host fails immediately with an `InvalidRequest` error. This is a deliberate divergence from reference AT Protocol PDS implementations (such as `bsky.social`), which resolve arbitrary public handles across the network.

To allow Swan to resolve external handles across the network, pass `--enable-foreign-handle-resolution` (disabled by default) to `swan serve`.

When enabled, `com.atproto.identity.resolveHandle` uses DNS TXT records (`_atproto.<handle>`) and HTTP lookups at `https://<handle>/.well-known/atproto-did` with `did:web` claim verification.

To prevent Server-Side Request Forgery (SSRF) and unauthorized scanning of internal infrastructure:
- Lookups for reserved Top-Level Domains (TLDs) are rejected before any network request is issued.
- Lookups resolving to non-public or loopback IP addresses are blocked.

Resolution results are cached in memory:
- Successful lookups (hits) are cached for 5 minutes.
- Failed lookups (misses) are cached for 30 seconds.
- Concurrent requests for the same handle use single-flight deduplication to prevent outbound request storms.

## OAuth browser surfaces and stylesheet maintenance

Swan provides interactive OAuth browser pages for login, authorization consent, and multi-factor authentication (MFA) second-factor ceremonies. These pages are implemented with daisyUI in `Sources/SwanHTTP/SwanBrowserPages.swift` and are shared between the production authorization server and the localhost development bridge.

### Content security policy and styling

The stylesheet is inlined directly into served HTML pages. Security is enforced through Content Security Policy (CSP) hash validation:
- The HTTP runtime computes a runtime SHA-256 hash from the exact inlined stylesheet bytes (`SwanBrowserPages.browserStyleCSPSource`).
- The response header includes `style-src 'sha256-<hash>'`.
- `default-src 'none'` is enforced with no `'unsafe-inline'` directive and no external origin dependencies.
- Dark and light themes adapt automatically using the browser's `prefers-color-scheme` media query.

### Rebuilding the stylesheet

The CSS stylesheet is embedded in `Sources/SwanHTTP/SwanBrowserStyleSheet.swift` and is tree-shaken during compilation. Unused CSS classes are stripped from the binary.

If you add or modify any class name in `SwanBrowserPages.swift` or `ScopeDescription.swift`, you must rebuild the embedded stylesheet:

```sh
./Scripts/build-browser-css.sh
```

## Account portal

The account management interface at `/account` is a SvelteKit web application located in `web/`.

During container builds, the Dockerfile's `account-web-build` stage compiles the static assets. The runtime server hosts these assets from `/usr/local/share/swan/account` by default. You can override the asset directory using the `--account-portal-directory` option on `swan serve`.

The account portal uses daisyUI styling matching the OAuth browser login pages. The standalone legacy stylesheet at `/account/auth-tokens.css` has been removed in favor of this integrated frontend build.

## XRPC proxy routing and destination dispatch

Swan transparently proxies unsupported XRPC requests to upstream AT Protocol services.

### Admission rules

Swan admits proxy requests by namespace prefix, not by membership in the generated lexicon registry:
- Admitted namespace prefixes: `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*`.
- Admitted exact NSIDs: `com.atproto.moderation.createReport`, `com.atproto.label.queryLabels`.

Admission by namespace prefix prevents proxy rejection when the local lexicon pin lags behind upstream releases. Gating proxying on static registry membership caused newly released upstream methods (such as `chat.bsky.convo.getUnreadCounts` and `app.bsky.video.*`) to fail with 404 errors.

### Destination dispatch

Routing behavior depends on the requested namespace and client headers:
- `chat.bsky.*` and `tools.ozone.*`: Require the client to provide an `atproto-proxy` header formatted as `<did>#<service-id>`. If the header is missing, the request fails with HTTP 404.
- `app.bsky.*`: When no `atproto-proxy` header is present, the request forwards directly to the configured AppView endpoint specified by `--appview-url` and `--appview-did`.
- Denied namespaces: Swan-owned namespaces (`com.atproto.space.*`, `blue.catbird.*`) and local account state endpoints within proxyable namespaces (`app.bsky.actor.getPreferences`, `app.bsky.actor.putPreferences`) are denied proxy admission and are never forwarded upstream.

## Operator diagnostics and failure logs

Swan produces structured log entries for authentication and proxy failures to aid debugging without exposing credentials or sensitive user data:

- `legacy createSession rejected`: Emitted when legacy password authentication or app-password verification fails on `com.atproto.server.createSession`. The log includes a structured `stage=` field with fixed values (`identifier_unresolved`, `no_credential_matched`, `auth_factor_token_required`, `rate_limited`, `malformed_request`, `token_rejected`, `unavailable`) and `factorToken=absent|empty|present`. Passwords and tokens are never logged.
- `xrpc pipethrough upstream failed`: Emitted when an outbound request to an upstream service (such as the AppView or an `atproto-proxy` target) fails. The log includes `nsid=` (the requested XRPC method), `host=` (the destination hostname), and `reason=` (the transport error, such as DNS failure, connection timeout, or TLS handshake error). Service authentication tokens are never logged.
