# Swan Scoped App Passwords and Legacy Sessions — Design

**Date:** 2026-08-12
**Status:** Draft for review
**Relates to:** `2026-08-12-swan-production-readiness-design.md`, which previously
listed this family as out of scope. That ruling is reversed; the readiness spec
is amended to point here.

## Goal

Let the official Bluesky app — and other legacy clients — sign in to Swan, while
making the credential they hold **narrower than the account**.

Swan is OAuth + DPoP only today. `com.atproto.server.createSession` and the
app-password family are unimplemented, so the official client cannot log in at
all. Bluesky's own app passwords are effectively all-or-nothing: one boolean,
`privileged`, which only decides whether DMs are reachable. We adopt tranquil's
improvement — app passwords carry real scopes — rather than reproducing that
model.

## The tradeoff, stated first

Swan currently has **no long-lived bearer secret anywhere**. Every credential is
sender-constrained: an OAuth access token is useless without proof of possession
of the DPoP key, so a captured request cannot be replayed from another machine.

An app password is a bearer credential. The client sends the same secret on
every request and the server accepts whoever presents it. **Scoping narrows what
a stolen credential can do; it does not stop a captured request being
replayable.** The deployment's worst case gets strictly worse the day this
ships.

That is a legitimate price for official-client support, and it is a decision
already taken. Scoping is what keeps the price proportionate rather than total.
What it must not become is a reason to relax anything on the OAuth path: the two
credential types share the authorization model and **nothing else**.

## Decisions

### D1 — One scope grammar and one evaluator, shared with OAuth

The idea worth taking from tranquil is a single sentence: **app passwords and
OAuth share one scope grammar and one evaluator, and the app-password scope is
carried in the legacy JWT's existing `scope` claim.**

That makes the legacy path a second *credential type* over the same
*authorization model*, rather than a second authorization model. The difference
matters: two authorization models must be kept in sync forever, and the one
nobody is looking at becomes the way in.

Vocabulary is the real AT Protocol OAuth scope syntax, not an invention:

| Form | Parameters |
|---|---|
| `atproto` | — (identity only; grants nothing) |
| `transition:generic` / `transition:chat.bsky` / `transition:email` | — |
| `repo:<nsid\|*\|pkg.*>` | `?action=create\|update\|delete` |
| `blob:<mime>` | `?accept=` |
| `rpc:<lxm\|*\|ns.*>` | `?lxm=`, `?aud=<did[#frag]>\|*` |
| `account:<email\|handle\|repo\|status\|*>` | `?action=read\|manage` |
| `identity:<handle\|*>` | — |
| `include:<nsid>` | `?aud=` — permission sets, fetched and expanded |

Three grammar details are load-bearing and must be reproduced: `rpc:*?aud=*` is
rejected outright rather than treated as a wildcard; `aud` matching strips the
`#fragment`, so `did:web:api.bsky.app` matches `…#bsky_appview`; and `.*` does
dot-boundary prefix matching, not naive `starts_with`.

The lexicon extension follows tranquil: an optional `scopes` string on
`com.atproto.server.createAppPassword`, alongside the existing `name` and
`privileged`. Extending the official lexicon beats inventing a Swan NSID —
clients that do not know about `scopes` keep working, and the field is echoed in
`listAppPasswords`.

Backward-compatible default when `scopes` is absent: `privileged: false` →
`transition:generic`; otherwise `transition:generic transition:chat.bsky`.

### D2 — Scopes must be enforced per method, which is new construction

**This is the honest size of the work.** Swan validates scopes carefully at
issuance — non-empty, a subset of the client's registered metadata, an AT
Protocol resource scope mandatory — and then, per request, reduces them to a
single boolean at all four call sites:

```swift
guard case let .accountOAuth(subject, scopes) = authorization,
      scopes.contains("atproto") else { throw …unauthorized }
```

Nothing compares a scope to the NSID being invoked. The central authorizer
receives the method and uses it only to build the DPoP `htu` binding. So any
credential that reaches one protected route today reaches every protected route.

"Scoped app passwords" is therefore not a matter of passing a narrower scope set
through existing checks. **The checks do not exist yet.** A scope grammar, an
NSID-keyed matcher, and enforcement at every guard site are new work.

The in-repo precedent to model on is `PermissionedSpaceScopeSyntax`
(`Sources/SwanCore/SwanCore.swift:166-196`) — a real capability grammar with an
explicit anti-escalation rule, enforced at a policy chokepoint by
`SpaceAuthorizationPolicy.require`. It keys on space coordinates rather than
lexicon methods, so it cannot be reused directly, but its shape is right.

### D3 — Legacy sessions get their own `AuthorizationContext` case

**Legacy sessions must not produce `.accountOAuth`.** They get a distinct case:

```swift
case accountLegacySession(subject: String, scopes: Set<String>)
```

Two properties follow, and they are the reason:

- Every existing `guard case let .accountOAuth(...)` site **fails closed** for
  legacy sessions until someone deliberately opts it in. The four call sites
  become an explicit, reviewable list rather than an inherited grant.
- `SpaceAuthorizationPolicy.require` switches over all seven cases with **no
  `default:`**, so adding a case is a **compile error** until the
  permissioned-data surface states its position. Given this codebase's history
  with capability registration, having the compiler enumerate the surface is
  worth more than the cost of an extra case.

The inverse — reusing `.accountOAuth` and distinguishing by scope string — fails
open at all four sites, since each checks only `contains("atproto")`.

### D4 — The scope check sits after authentication and before the service-token mint

The proxy answers two different questions that must stay separate:

- *"May this method be proxied at all?"* — caller-independent.
  `SwanXRPCProxyRouter.route` and its allow-list.
- *"May **this caller** invoke this method?"* — caller-dependent, and needs
  scopes that only exist after authentication.

A scope check at the allow-list would be worthless: the allow-list does not know
who is calling, so any scoped credential could mint a service token for every
proxyable NSID and reach the AppView with full authority.

`lxm` binds the minted token to one exact NSID, so a check placed after
authentication and **strictly before** the mint (`SwanXRPCPipethrough.swift:394`)
is sufficient and complete — an out-of-scope method never gets a credential
minted for it. It must not be folded into `route()`, which is pure and
caller-independent by design.

This composes with the readiness spec's W2/D5 (routing ahead of authentication);
the two steps consume disjoint inputs. Resulting order:

```
1. parse NSID
2. route()   — caller-independent          -> 404
3. authenticate -> AuthorizationContext    -> 401
4. scope check (subject's scopes vs NSID)  -> 403
5. resolve / MINT / send
```

### D5 — Three deliberate deviations from tranquil

tranquil's execution is serious, but it has one real hole and two habits worth
not inheriting.

**`getServiceAuth` must require `lxm` for every non-full-access credential.**
This is a scope-laundering primitive: it converts a narrow PDS credential into a
token a *different* service will honour. tranquil checks it only when `lxm` is
supplied, and requires `lxm` only for OAuth — so a scoped app password that
simply omits `lxm` falls through with no check at all and receives a token with
`lxm: None`, which the audience honours for any method. Its own shipped
"post-only" preset, which grants zero `rpc:` scopes, can obtain one. The 60s
lifetime bounds the damage without closing the hole, and no test covers the path.
Swan requires `lxm` from every non-full-access credential and validates `aud`
and `lxm` against the granted `rpc:` scopes.

**Refresh re-derives scope from the app-password row.** tranquil stores scope on
the session row and re-mints from it, so editing an app password does not narrow
live sessions — a long window against a 90-day refresh token. Swan re-derives on
every refresh. Refresh may never widen: mirror the existing OAuth rule that a
refresh requests either the identical scope set or nothing.

**Undeclared routes fail closed.** The reference PDS defaults to permissive and
requires routes to opt into strictness, so a new route is reachable by any app
password unless someone remembers. Swan is new and does not need that default;
routes declare their required scope, and an undeclared route is denied.

### D6 — Validate scopes at creation, and say what was missing on denial

tranquil never calls its own validator, so an unparseable scope becomes
`Unknown` and grants nothing — it fails closed, but the user is told they
created a working credential when they did not. Swan validates and rejects at
creation.

On denial, return `403` with the machine-readable required scope. tranquil
computes exactly this and then discards it before serialization, leaving clients
with prose. That field is the difference between a client that can explain the
failure and one that cannot.

### D7 — Reuse the existing login and hashing paths

`DurableAccountDirectory.authenticateForLogin` is already enumeration-resistant:
exactly one Argon2id verification on every path, using a boot-generated dummy
verifier for unknown or inactive accounts, with infrastructure failure typed
separately from rejection. `createSession` calls it rather than growing a second
login path — a hand-rolled one leaks account existence by timing.

App-password hashing reuses `LibsodiumArgon2idHasher` and the existing off-thread
executors. App-password rows live in the control DB alongside `accounts`, in
`AccountControlStore`'s existing credential idiom. Passwords are hashed, shown
exactly once, and `createSession` is rate-limited — an app password is a
guessable-length secret with no second factor.

### D8 — A sibling session service, not a widened OAuth one

Legacy sessions cannot flow through `DurableOAuthTokenService.validateAccess`,
which requires a DPoP proof by signature and hard-requires a DPoP thumbprint on
the token family. Bolting a nullable `dpopJKT` onto that family would weaken the
invariant that currently makes **every** OAuth token sender-constrained.

So: a sibling `DurableLegacySessionService` with its own tables, modelled on the
OAuth one and reusing its *design* — family/rotation/revocation with reuse
detection and family-wide revocation, digests at rest, never plaintext.

## Endpoint surface

**Required for the official app to log in and stay logged in:**

`createSession` (accepts `identifier`, `password`, `authFactorToken`, and
`allowTakendown`, which social-app passes; returns `accessJwt`, `refreshJwt`,
`handle`, `did`, and `didDoc`, which drives the client's endpoint update),
`refreshSession` (called on **every** session resume and automatically on any
401 — app restart cannot work without it), `getSession` (backfills `email`,
`emailConfirmed`, `emailAuthFactor`), `deleteSession`, and `describeServer`
(already served).

The access JWT must be `typ: at+jwt` with `sub` = DID, `aud` = service DID, and
a `scope` claim.

**Required for feature parity, not for login:** `getServiceAuth` (video upload
and age assurance), XRPC pipethrough with `atproto-proxy` (where nearly all
traffic goes), and `createAppPassword` / `listAppPasswords` / `revokeAppPassword`
(only for the in-app settings screen).

**What a non-privileged password costs:** exactly `chat.bsky.*` — direct
messages — and `getServiceAuth` for those methods. Nothing else.

## Presets

Ship tranquil's three, plus one that matters here:

| Preset | Scopes |
|---|---|
| Full | none (unrestricted) |
| Read-only | `rpc:app.bsky.*?aud=* rpc:chat.bsky.*?aud=* account:status?action=read` |
| Post-only | `repo:app.bsky.feed.post?action=create blob:*/*` |
| **Bluesky app** | wide enough that the official client works end to end: repo write across `app.bsky.*`, blob upload, `rpc:app.bsky.*`, `rpc:chat.bsky.*` when DMs are wanted, and `rpc:` for the video service |

The last one is not optional. **The client never inspects scopes**, so a
too-narrow preset surfaces as unexplained 403s mid-session — the most likely way
this feature disappoints in practice.

## Testing

**Grammar.** Parser unit tests including the three load-bearing details:
`rpc:*?aud=*` rejected, `#fragment`-stripping on `aud`, dot-boundary prefix
matching. Unparseable scopes rejected at creation.

**Enforcement.** For each guard site, a granted-scope case and a denied case
asserting 403 with the required scope named. An undeclared route denies.

**The laundering paths, each with a test:** `getServiceAuth` without `lxm` from a
non-full-access credential is refused; `getServiceAuth` with an `aud`/`lxm`
outside granted `rpc:` scopes is refused; refresh cannot widen scope; editing an
app password narrows live sessions on next refresh; revoking it kills them.

**The compile-time gate.** A test that the permissioned-space surface denies
`.accountLegacySession` — the position the new enum case forces it to state.

**Live.** The official Bluesky app logs in to swan.place with a "Bluesky app"
preset password, loads a timeline, posts, and — with a privileged password —
opens DMs. Per the project's verification rules, a clean build is not "done".

## Risks

1. **Scope enforcement is new construction, not a hook.** The seam is clean; the
   matcher and the four opt-in decisions are the security-sensitive part.
2. **A bearer credential now exists.** Covered above. It must not be allowed to
   soften the OAuth path.
3. **Scope lives in the JWT**, so it is bounded by token size and fixed for the
   token's life. Permission sets (`include:`) mitigate size, at the cost of a
   fetch-and-expand step that tranquil found worth caching.
4. **Too-narrow presets fail invisibly** to a client that cannot explain them.
   D6's machine-readable denial and the "Bluesky app" preset are the mitigations.

## Non-goals

No account creation. No second authorization model. No change to the OAuth
path's DPoP requirements. No port of tranquil's code.
