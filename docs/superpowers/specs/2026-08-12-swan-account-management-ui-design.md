# Swan Account Management UI — Historical draft reconciled

**Original date:** 2026-08-12  
**Current status:** Superseded; retained as a historical decision record  
**Authoritative contract:**
[`2026-08-16-swan-account-identity-reference-parity-design.md`](2026-08-16-swan-account-identity-reference-parity-design.md)

The 2026-08-16 design is the only implementation authority. This file preserves
the useful UI decisions from the earlier draft and explicitly resolves the
parts that became stale after the security remediation and approved four-release
program.

## Reconciliation

The earlier “credentials only” v1 is replaced by the approved milestones:
M1 compatibility + portal (signup, invites, `did:web`, recovery, legacy
sessions, app passwords, portal), M2 MFA, M3 remaining reference breadth, and
M4 operations. Dependencies may be staged internally but milestone content is
not redefined. Each sensitive mutation requires the authoritative design's
fresh-step-up and evidence rules.

The following decisions remain binding:

* SvelteKit is build-only with `adapter-static`; Hummingbird serves baked
  assets. There is no SvelteKit server or Node runtime in production.
* `/account/api/*` is a separate, cookie-only management surface. Cookies do
  not authenticate `/xrpc/*`, and OAuth/DPoP, service, bearer, or app-password
  credentials do not authenticate the management API.
* The API route group wins over the `/account/*` SPA fallback. Unknown API
  routes return `404` rather than a static page.
* Management sessions are opaque, revocable, and distinct from OAuth browser
  sessions and legacy sessions. The exact cookie, CSRF, Origin, CSP, and
  failure contract is frozen in Section 3 of the authoritative design.
* OAuth browser pages retain their script-free strict CSP. Account pages have a
  separate self-only policy and never widen OAuth CSP.
* Secrets are shown once and never appear in list responses, logs, or errors.
  “Revoke all others” never revokes the management session issuing the request.

## Frozen account API groups

The exact route list is maintained in the authoritative design; these groups
are its compatibility summary:

| Group | Routes |
|---|---|
| Public onboarding | `bootstrap`, `signup/policy`, `signup/email/request`, `signup/authorize`, `signup`, `login` |
| Session | `session`, `logout`, `sessions`, `sessions/:id`, `sessions/revoke-others` |
| Account/identity | `profile`, `identity`, `connected-apps`, `export`, `migration`, `lifecycle/delete` |
| Credentials | `app-passwords`, `app-passwords/:name`, `scope-presets`, `scopes/validate` |
| Factors | `factors`, `factors/passkeys/:id`, `factors/totp`, `factors/recovery-codes/rotate`, `step-up` |

All mutating routes require exact configured Origin, matching CSRF cookie/header,
same-origin fetch-site when present, JSON body admission, and bounded rate
limits. Failure bodies use stable safe codes and do not disclose account
existence or credential material.

`GET /account/api/bootstrap` issues the pre-auth CSRF cookie/token. Login and
all signup POSTs require exact Origin, JSON, `Sec-Fetch-Site: same-origin` or
`none`, and a matching pre-auth CSRF cookie/header; successful authentication
consumes it and rotates to the management CSRF token. There is no wholesale
public-POST exemption. Once MFA is enabled, password management/OAuth/legacy
login requires a valid factor assertion; an app password remains scoped legacy
access only. Recovery/email alone cannot remove factors or authorize identity
or deletion.

## Historical architecture sketch

```text
build:       SvelteKit/Vite --(npm ci, npm run build)--> web/build
production:  browser --HTTPS--> Hummingbird
             /account/*     -> static fallback
             /account/api/* -> management cookie + CSRF + Origin
             /xrpc/*         -> existing bearer/DPoP authorization only
             /oauth/*        -> existing Swift-rendered OAuth pages
```

This sketch remains accurate only with the route and credential isolation
above. It does not authorize deployment or imply that the portal exists in the
current source; as of 2026-08-16 it remains unimplemented.

## Verification retained from the draft

Implementation must test route precedence, management/OAuth/app-password auth
isolation, exact cookie attributes, Origin and CSRF rejection, CSP separation,
one-time secret presentation, immediate revocation, and local HTTPS browser
flows. A clean build is not acceptance. The official-client post/read/delete
and session-revocation flow is a required live gate when a disposable local
environment is available; otherwise the gap is recorded explicitly.

See the authoritative design for current source reality, signup/identity
contracts, factor semantics, migration ownership, jj lane boundaries, and the
no-deploy rule.
