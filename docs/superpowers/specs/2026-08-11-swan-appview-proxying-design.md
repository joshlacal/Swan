# Swan AppView Proxying — Design

**Date:** 2026-08-11
**Status:** Approved (design), not yet implemented
**Phase:** 1 of 2. Phase 2 (read-after-write) is a separate spec.

## Goal

Make a signed-in `swan.place` account usable in Catbird and other AT Protocol
clients by serving the `app.bsky.*` surface Swan does not implement itself.

Today Swan implements `com.atproto.*` plus its own permissioned-data lexicons
and returns **404 for everything else**. A fully authenticated account cannot
load a profile or a feed: production logs show `app.bsky.actor.getProfile`
404ing repeatedly against `https://swan.place/` immediately after a successful
OAuth token exchange.

## Scope

**In scope (Phase 1):** XRPC pipethrough to an AppView, inter-service auth,
and local account preferences. On completion, a swan.place account can browse
Bluesky in Catbird.

**Out of scope (Phase 2, separate spec):** read-after-write munging of
`getTimeline`, `getProfile`, `getProfiles`, `getAuthorFeed`, `getPostThread`,
and `getActorLikes` so the account's own writes appear before the AppView has
indexed them. Phase 2 is additive — it munges responses produced by the Phase 1
proxy and requires no rework of it.

**Also out of scope:** blob proxying, `chat.bsky.*` routing, Ozone/moderation
service routing, and unauthenticated pass-through (see Decisions).

## Decisions

### D1 — Infer the AppView; do not require `atproto-proxy`

When a request carries `atproto-proxy`, honour it. When it does not, fall back
to a default service table by NSID, exactly as the reference PDS does in
`defaultService()` (`atproto/packages/pds/src/pipethrough.ts:632`).

Catbird sends the header, so Catbird works either way. Every *other* client —
Graysky, deer, the official app — sends `app.bsky.*` with no header, and under
tranquil's stricter behaviour those requests 404. Inferring is what the
reference PDS does, so it is the compatible behaviour, and it is strictly more
permissive than requiring the header. This follows the project directive to err
toward user friendliness.

### D2 — Proxying requires an authenticated session

Only OAuth/DPoP-authenticated requests are proxied, always on behalf of the
authenticated account. Swan never becomes an open forwarding path to a third
party, and needs no separate anti-abuse rate limiting for this surface. Public
logged-out views do not work through swan.place; acceptable for a personal PDS.

### D3 — AppView target is configurable with a working default

Default `did:web:api.bsky.app#bsky_appview` at `https://api.bsky.app`,
overridable by CLI flag in the same style as Swan's other service settings. A
fresh deployment proxies correctly with no configuration, and can later be
pointed at a self-hosted or alternate AppView.

### D4 — Preferences stored as plaintext JSON in the account database

Matches the reference PDS (`atproto/packages/pds/src/actor-store/preference`).
Preferences hold saved feeds, content-label settings and muted words: mildly
personal, but not credentials. KEK encryption was considered and rejected as
cost without meaningful benefit, since the same database already holds the
account's records.

## Architecture

Four units, each independently testable.

```
inbound /xrpc/<nsid>  ──▶ local route?  ──yes──▶ existing Swan handler
                              │no
                              ▼
                    SwanXRPCProxyRouter          (target selection)
                              │
                              ▼
                    SwanServiceAuthMinter        (per-request JWT)
                              │
                              ▼
                    SwanXRPCPipethrough          (forward + stream back)
                              │
                              ▼
                         AppView (https)
```

`SwanActorPreferencesStore` sits outside this path: `getPreferences` and
`putPreferences` are local routes and are never proxied.

### Unit 1 — `SwanXRPCProxyRouter`

**Responsibility:** decide where, if anywhere, a request goes.

Resolution order:

1. **Local routes win.** The proxy is a fallback that fires only when no local
   route matched, so Swan's own lexicons always take precedence.
2. **Explicit deny-list.** `com.atproto.space.*` and `blue.catbird.*` are never
   proxied, even if no local route matched. This is redundant with (1) by
   construction and deliberately kept as a second barrier: a future refactor
   that drops or renames a local route must not silently begin forwarding
   Swan-owned traffic to a third party.
3. **`atproto-proxy` header.** Parse as `did#fragment`. Resolve the DID
   document, select the service entry whose `id` matches the fragment, and use
   its `serviceEndpoint`. A malformed header, unresolvable DID, or missing
   fragment is a 400 — never a silent fallback to the default, which would send
   traffic somewhere the client did not ask for.
4. **Default table.** `app.bsky.*` → the configured AppView. Everything else
   → unrouted → 404.

Ozone and moderation lexicons are **not** defaulted to the AppView. Unconfigured
means 404, so moderation traffic is never silently misrouted.

**Interface:** given an NSID and request headers, returns either a resolved
target (service DID + https URL) or a routing failure (`denied`, `unrouted`,
`malformedProxyHeader`, `unresolvableService`).

### Unit 2 — `SwanServiceAuthMinter`

**Responsibility:** prove to the AppView which account a proxied request is for.

Mints a short-lived ES256 JWT per request, mirroring
`com.atproto.server.getServiceAuth`:

| Claim | Value |
|-------|-------|
| `iss`  | authenticated account DID |
| `aud`  | resolved target service DID |
| `lxm`  | the NSID being called |
| `exp`  | now + 60s |
| `iat`  | now |
| `jti`  | random, single-use |

Signed with the account's repo signing key, retrieved via
`AccountKeyStore.key(for:)`. Binding `lxm` means a captured token cannot be
replayed against a different method.

The key is decrypted per request. If this shows up as a hot path in practice,
caching is a later optimisation and must not be added speculatively.

### Unit 3 — `SwanXRPCPipethrough`

**Responsibility:** forward the request and stream the response back.

- Method, path and query string forwarded unchanged.
- **Inbound `Authorization`, `Cookie` and DPoP headers are stripped** and
  replaced with the minted JWT. The client's Swan credentials must never reach
  a third party.
- Only an explicit header allow-list is forwarded (`accept-language`,
  `atproto-accept-labelers`, `content-type` for writes). Everything else is
  dropped rather than filtered, so a new header is excluded by default.
- Response is streamed back with upstream status and content-type, under a size
  cap consistent with Swan's existing body limits.
- **https only.** The endpoint comes from a resolved DID document, and is
  validated against Swan's existing SSRF discipline before any connection.

This is a **new class of outbound traffic for Swan**, whose existing outbound
HTTP is deliberately hardened (peer-pinned transports in `SwanOAuth`). The
implementation must reuse that discipline rather than introducing an
unrestricted client; if the peer-pinned transports cannot express
"arbitrary AppView host", the gap must be raised before proceeding, not worked
around with a plain client.

### Unit 4 — `SwanActorPreferencesStore`

**Responsibility:** hold per-account preferences, which no AppView can serve.

New table keyed by account DID storing the preferences JSON array, plus two
local routes:

- `app.bsky.actor.getPreferences` — returns the stored array, or an empty array
  for an account that has never written preferences.
- `app.bsky.actor.putPreferences` — replaces it.

Both require authentication and are strictly scoped to the authenticated
account. These cannot be proxied: the AppView does not store preferences, and
proxying them would silently discard the user's saved feeds and content
settings.

## Error handling

| Condition | Response |
|-----------|----------|
| Upstream returns 4xx/5xx | pass through status and body unchanged |
| Upstream unreachable / times out | 502 |
| Malformed `atproto-proxy`, unresolvable service | 400 |
| Lexicon denied or unrouted | 404 (unchanged from today) |
| Unauthenticated | 401 |

Upstream error bodies pass through verbatim so clients see the AppView's own
error semantics rather than a Swan-flavoured reinterpretation.

## Testing

**Unit.** Routing table (local-wins, deny-list, header honoured, unrouted →
404, malformed header → 400 and *not* a default fallback); JWT claim
construction including `lxm` binding and expiry; header allow-list, asserting
positively that inbound `Authorization`/`Cookie`/DPoP are absent upstream.

**Integration.** A fake upstream that asserts the received path, query and
`Authorization` JWT, and returns a canned body — covering success, upstream
4xx pass-through, and unreachable upstream → 502. Preferences round-trip:
empty-array default, write, read back, and rejection of a cross-account read.

**Live verification (required before declaring done).** Per the project's
verification rules a clean build is not "done": deploy, sign in to swan.place
in Catbird, and confirm a profile and a feed actually render, capturing the
screenshot and the absence of 404s in the nest log where
`app.bsky.actor.getProfile` currently fails.

## Risks and open implementation questions

1. **Router fallback semantics.** Swan registers exact `/xrpc/<nsid>` paths.
   Hummingbird's behaviour for a `/xrpc/**` catch-all alongside more specific
   routes must be verified — the catch-all must never shadow a local route. If
   precedence is not guaranteed, resolve by explicit route registration or a
   middleware that runs after route matching fails.
2. **Peer-pinned transport fit** (see Unit 3). The likeliest source of design
   churn.
3. **Signing-key decryption cost** on every proxied request; measure before
   optimising.
4. **`chat.bsky.*`** is deliberately unrouted in Phase 1. Catbird's chat is
   served by nest/mls-ds, not by the PDS, so this is not expected to regress
   anything — but it should be confirmed against a real session rather than
   assumed.

## Phase 2 preview (separate spec)

Read-after-write munging for the six routes the reference PDS handles
(`atproto/packages/pds/src/read-after-write/`), so the account's own posts and
likes appear immediately rather than after AppView indexing. Additive to the
Phase 1 proxy.
