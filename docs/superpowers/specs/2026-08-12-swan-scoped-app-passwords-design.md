# Swan Scoped App Passwords and Legacy Sessions — Historical draft reconciled

**Original date:** 2026-08-12  
**Current status:** Superseded; retained as a historical decision record  
**Authoritative contract:**
[`2026-08-16-swan-account-identity-reference-parity-design.md`](2026-08-16-swan-account-identity-reference-parity-design.md)

The 2026-08-16 design is the only implementation authority. This file keeps the
credential-risk and scope decisions from the earlier draft while correcting its
“OAuth + DPoP only today” framing: that is current source reality, not a
permanent product boundary.

## Reconciled decisions

* App passwords are bearer credentials and therefore increase replay risk.
  Scoping narrows authority but does not make a captured secret sender
  constrained. OAuth access tokens remain DPoP-bound and are never weakened to
  share the legacy family.
* Legacy sessions are a sibling durable family with their own
  `AuthorizationContext` case, family rotation, reuse detection, digest-at-rest
  storage, and family-wide revocation. A nullable DPoP field is not added to
  OAuth rows.
* OAuth and app passwords share one grammar/evaluator. `rpc:*?aud=*` is
  rejected, audience matching strips fragments, dot-boundary prefix matching is
  used, undeclared routes fail closed, and every non-full-access
  `getServiceAuth` request requires a matching `lxm` and `aud`. Authentication
  runs first, then canonical method-policy evaluation, and only then may a
  handler or service-token mint run. Empty, missing, malformed, and undeclared
  scope requests deny. The only full-access value is the explicit internal
  `ScopeGrant.fullAccessV1` sentinel; empty scope and `atproto` are not full
  access, and no app-password or OAuth flow may widen to the sentinel.
* Scope is validated at issuance, refresh re-derives current scope from the
  app-password row, refresh never widens, and a denial names the required scope
  in a machine-readable `403`.
* App-password secrets are Argon2id-hashed, rate-limited at `createSession`,
  returned exactly once, and absent from list/log/error output. The reference
  wire shape remains the pinned local `com.atproto.server` lexicons.

## Credential and portal boundary

Official-client adapters implement `createSession`, `refreshSession`,
`getSession`, `deleteSession`, `getServiceAuth`, and app-password
create/list/revoke. The account portal uses the separate management routes
`/account/api/app-passwords`, `/account/api/sessions`,
`/account/api/sessions/:id`, and `/account/api/sessions/revoke-others`; it does
not call `/xrpc/*` with a cookie. The management cookie is never accepted by
XRPC, and an app password never authenticates the portal.

Creating, changing, or revoking an app password requires a fresh management
step-up. Revoking “all others” preserves the current management session.
Revoking an app password revokes all sessions derived from it. Failure behavior,
cookie/CSRF/Origin checks, and rate bounds are defined centrally in the
authoritative design and must not be re-specified by a lane.

When MFA is enabled, account-password management/OAuth/legacy login requires a
valid `authFactorToken` before a full session/token is minted. An app-password
login remains a scoped legacy alternative only; it cannot create management or
OAuth credentials. Recovery/email proof can revoke sessions or start password
recovery, but cannot remove factors or authorize identity or deletion.

## Presets retained for implementation

| Preset | Canonical intent |
|---|---|
| Full | Unrestricted legacy access, subject to account lifecycle. |
| Read-only | Read RPCs and account status only. |
| Post-only | Feed-post create plus blob upload. |
| Bluesky app | Official-client repository writes, blobs, AppView RPCs, and chat RPCs only when explicitly granted. |

The exact normalized strings and audience rules are owned by the shared scope
contract; a preset is not permission to bypass method enforcement. The client
does not inspect scopes, so under-granting a preset is a compatibility failure,
not a safe default.

## Required evidence and explicit non-goals

Tests cover grammar edge cases, every guard site, undeclared-route denial,
`getServiceAuth` laundering, refresh narrowing, edit/revoke behavior, and the
compile-time denial of legacy sessions by permissioned-space code until it
explicitly opts in. A disposable official-client flow must log in, load a
timeline, post, and revoke; unexecuted network gates remain recorded.

This historical draft does not authorize account creation, deployment, relay
activation, production-secret mutation, or a change to OAuth DPoP. Signup,
PLC/BYO `did:web`, management sessions, passkeys, TOTP, recovery codes,
migration ownership, and no-deploy boundaries now live only in the
authoritative 2026-08-16 design.
