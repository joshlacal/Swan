# Swan Account Management UI — Design

**Date:** 2026-08-12
**Status:** Draft for review
**Depends on:** `2026-08-12-swan-scoped-app-passwords-design.md`. Scoped app
passwords are unusable without a way to create them; this is that way.

## Goal

A web UI at `swan.place` where an account holder can manage **credentials**:
create scoped app passwords, see what exists, and revoke live sessions.

v1 is credentials only. Handle, email, password change, export and migration are
deliberately out — each touches machinery with its own sharp edges (a handle
change is a live `plc.directory` write; email recovery is disabled in production
today).

## Architecture

**SvelteKit frontend, Hummingbird backend — not a SvelteKit server.**

```
                     build time
               ┌──────────────────┐
               │ SvelteKit / Vite │   Node lives here and only here
               └────────┬─────────┘
                        │ npm ci && npm run build
                        ▼
                 web/build/  →  copied into the Swift image

                     production
   ┌──── Browser ────┐
   │ SvelteKit app   │
   │    fetch()      │
   └────────┬────────┘
            │ HTTPS, same origin, HttpOnly cookie
            ▼
   ┌────────────────────────────────────────────┐
   │            Swan / Hummingbird              │
   │  /account/*      → static assets / 200.html│
   │  /account/api/*  → cookie-authenticated    │
   │  /xrpc/*         → bearer/DPoP only        │
   │  /oauth/*        → Swift-rendered          │
   └────────────────────────────────────────────┘
```

**The deployed container contains no Node executable.** Node is a build
dependency alongside the Swift toolchain; the final image is the Swift binary
plus SvelteKit's static output. The container stays `--read-only` with `/data`
as the only writable mount — static assets are baked in, not written at runtime.

### D1 — `adapter-static` in SPA-fallback mode

```js
adapter({ fallback: '200.html' })
```

Routing:

| Path | Served as |
|---|---|
| `/_app/*`, `/assets/*` | actual static files, long-cache |
| `/account/*` | `200.html`; the SvelteKit client router takes over |
| `/account/api/*` | Swift, cookie-authenticated |
| `/xrpc/*` | Swift, bearer/DPoP |
| `/oauth/*` | Swift, server-rendered |

Fallback mode rather than full prerender: the UI is behind auth and inherently
dynamic, so prerendering each route buys nothing and adds a build-time route
manifest to keep in sync.

The `/account/*` fallback must not shadow `/account/api/*`. Register the API
routes as exact paths so Hummingbird's trie prefers them over the wildcard —
the same precedence property the firehose WebSocket route relies on.

### D2 — The management API is a separate, cookie-only surface

**The UI does not call `/xrpc/*`.** It calls `/account/api/*`.

This is the load-bearing decision in this document. The obvious shortcut — have
the SPA call `com.atproto.server.listAppPasswords` with the session cookie —
costs two things that are not worth it:

1. **XRPC would accept two authentication schemes.** Every existing guard site
   was written and reviewed against exactly one. This codebase has already
   produced two production security bugs from a surface silently widening
   underneath checks that only looked at one thing, which is why legacy sessions
   get their own `AuthorizationContext` case rather than reusing
   `.accountOAuth`. The same reasoning applies here, more strongly: a cookie is
   ambient authority that the browser attaches automatically.
2. **It drags CSRF onto XRPC.** Bearer/DPoP authentication is CSRF-immune by
   construction — the browser never attaches those credentials on its own. The
   moment a cookie is honoured on `/xrpc/*`, every mutating XRPC method becomes
   a CSRF target, including ones that have nothing to do with this UI.

So: cookies are honoured **only** under `/account/api/*`, CSRF policy is applied
to that route group as a whole, and `/xrpc/*` stays single-auth.

The API is small and shaped for the UI rather than mirroring lexicons:

```
GET    /account/api/session           who am I (DID, handle, status)
POST   /account/api/login             password → sets cookie
POST   /account/api/logout
GET    /account/api/app-passwords     list (never returns secrets)
POST   /account/api/app-passwords     create → returns the secret ONCE
DELETE /account/api/app-passwords/:name
GET    /account/api/sessions          OAuth families + legacy sessions
DELETE /account/api/sessions/:id
POST   /account/api/sessions/revoke-others
GET    /account/api/scope-presets     presets + validation vocabulary
POST   /account/api/scopes/validate   parse a custom scope string
```

Where these overlap the lexicon endpoints (`createAppPassword`,
`listAppPasswords`, `revokeAppPassword`, which the official Bluesky app's
settings screen calls), both surfaces call the **same underlying service**. The
lexicon endpoints remain bearer-authenticated; only the transport and auth
differ.

### D3 — Management authentication requires the real account password

**No delegated credential may reach this surface.** Not an app password, not an
OAuth token, not a service token.

If a scoped app password could reach the page that creates app passwords, every
scope becomes advisory — a narrow credential simply mints itself a wide one. The
same holds for the session list: a credential must never be able to revoke the
constraint that binds it.

So the management session is established only by `POST /account/api/login` with
the account password, and it produces a **distinct** session type — not a legacy
session, not an OAuth grant. It gets its own `AuthorizationContext` case for the
same compile-time-enumeration reason as legacy sessions: adding a case to a
switch with no `default:` forces every existing consumer to state its position
rather than silently inheriting a grant.

Login reuses `DurableAccountDirectory.authenticateForLogin`, which is already
enumeration-resistant (exactly one Argon2id verification on every path,
including unknown accounts), and inherits the existing login rate limiting and
the `X-Swan-Client-IP` trusted-proxy handling.

Second-factor and step-up are out of scope for v1, but the session type exists
partly so they have somewhere to attach later.

### D4 — Cookie and CSRF policy

Cookie: `HttpOnly; Secure; SameSite=Strict; Path=/account`. Svelte never reads
it; the browser attaches it and Hummingbird authenticates it.

`SameSite=Strict` is most of the CSRF defence, but not all of it — it does not
protect against same-site subdomain attacks, and the Caddy block serves
`*.swan.place`. So mutating `/account/api/*` requests additionally require:

- an `Origin` header matching the configured public URL exactly, and
- a CSRF token issued at login, echoed in a custom request header.

A custom header alone would be sufficient against classic form CSRF (it forces a
preflight), but the token is cheap and the origin check is the part that closes
the subdomain gap.

Applied as one middleware over the route group, so a new endpoint cannot forget
it. This is the inverse of the pattern that has bitten this codebase: opt-out,
not opt-in.

### D5 — CSP

`/oauth/authorize` and the OAuth browser pages **keep** `default-src 'none'` and
stay Swift-rendered. They are small, unusually high-value, and have no need of
JavaScript — a genuine defence-in-depth case, unrelated to rendering taste.

`/account/*` gets its own policy allowing `script-src 'self'` and `style-src
'self'` with SvelteKit's build-time hashes (nonces need a server; static output
uses hashes). `connect-src 'self'`, `default-src 'none'`, `frame-ancestors
'none'`, `base-uri 'none'` as before.

Two distinct policies, selected by route group. The existing strict-header test
must be extended rather than relaxed, so a future change cannot quietly widen
the OAuth pages' policy.

## What the UI shows

**App passwords.** Name, scopes (preset name where it matches one, otherwise the
raw string), created, last used. Create with a preset picker plus a custom
field validated server-side before submission. The secret is shown **once**, with
no way to retrieve it later.

**Sessions.** Client, credential type (OAuth / app password / management),
started, last seen, and for OAuth the granted scopes. Revoke individually, plus
"revoke all others" — which must never revoke the current management session,
since locking yourself out of the revocation UI from the revocation UI is a
trap.

A revoked OAuth family revokes the whole family, matching the existing
reuse-detection semantics.

## Build pipeline

`web/` at the repo root: a SvelteKit project with `adapter-static`. The
Dockerfile gains a Node builder stage that runs `npm ci && npm run build` and
copies `web/build` into the final Swift image.

`npm ci` — not `npm install` — so the lockfile is authoritative and the build is
reproducible. The dependency tree is a new supply-chain surface for this repo
and should be kept deliberately small.

The Swift build must not depend on the Node stage's output existing during
development: a missing `web/build` degrades to serving nothing under `/account`,
never a build failure. `swift test` must not require Node.

## Testing

**Route precedence.** `/account/api/*` resolves to the API, not the SPA
fallback. `/account/anything` returns `200.html`. `/xrpc/*` is unaffected.

**Auth isolation — the tests that matter most.** A valid OAuth bearer token is
**rejected** by `/account/api/*`. A valid app password is rejected. A management
cookie is **rejected** by `/xrpc/*`. Each of these is a separate test, because
each is a way the surfaces could quietly merge.

**CSRF.** A mutating request with no CSRF token is refused; with a mismatched
`Origin` is refused; a `GET` is unaffected.

**Secrets.** The created app-password secret appears in exactly one response and
never in a list response, a log line, or an error body.

**Revocation.** Revoking a session invalidates it immediately. "Revoke all
others" leaves the current management session alive. Revoking an app password
kills the sessions derived from it.

**Live.** Log in at `swan.place/account`, create a "Bluesky app" preset
password, sign the official Bluesky app in with it, then see that session listed
and revoke it — and confirm the app is signed out. Per the project's
verification rules, a clean build is not "done".

## Risks

1. **New supply chain.** This is the repo's first npm dependency tree. Keep it
   small, pin with `npm ci`, and treat additions as decisions rather than
   conveniences.
2. **Two auth surfaces on one origin.** Correct by construction only as long as
   the isolation tests exist. They are the load-bearing tests in this document.
3. **`*.swan.place` is proxied and served by the same Caddy block**, so
   `SameSite=Strict` alone is not sufficient. D4's origin check is what closes
   that, and it depends on the configured public URL being exact.
4. **The UI grows.** v1 is credentials only, but sessions, export, migration and
   permissioned-data controls are all plausibly next. SvelteKit is chosen partly
   for that trajectory; the API shape should not assume credentials are the only
   resource.

## Non-goals

No SvelteKit server runtime. No Node in the production image. No cookie
authentication on `/xrpc/*`. No account creation, handle change, email change,
or password change in v1. No change to the OAuth browser pages' rendering or
CSP.
