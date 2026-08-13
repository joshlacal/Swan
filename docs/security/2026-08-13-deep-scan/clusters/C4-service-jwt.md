# Cluster C4-service-jwt

---

## F04 [MEDIUM] `security-control-bypass`
**Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.**
finding id: `csf_d94bd7b5d2e1d3665e22381e`

### Locations
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-570`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:456-465`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:147-183`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:197-225`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-298`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-420`  

### Attack path
- source: `Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223`
- sink: `Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420`
- outcome: Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A network attacker cannot remove iat without invalidating the signature. Exploitation requires a trusted or pinned allowed issuer that emits the optional shape, a currently accepted service-key holder that pre-mints unique-jti long-lived tokens, disclosure of such a token, or misuse or compromise of its signing key. Exact-event replay is durably idempotent and method, audience where supplied, issuer, signature, expiration, JTI, and bounded event-id controls still apply. Swan's own issuer and the checked-in TypeScript fixture include iat; no reviewed compatibility evidence requires accepting absent iat. The independently reachable write and deletion notification instances preserve their narro

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
A network attacker cannot remove iat without invalidating the signature. Exploitation requires a trusted or pinned allowed issuer that emits the optional shape, a currently accepted service-key holder that pre-mints unique-jti long-lived tokens, disclosure of such a token, or misuse or compromise of its signing key. Exact-event replay is durably idempotent and method, audience where supplied, issuer, signature, expiration, JTI, and bounded event-id controls still apply. Swan's own issuer and the checked-in TypeScript fixture include iat; no reviewed compatibility evidence requires accepting absent iat. The independently reachable write and deletion notification instances preserve their narrower impacts: prolonged authorization of write notification storage and deletion lifecycle notification respectively, rather than signer forgery. Additional context: Strongest counterevidence/proof gap: the attacker must control or compromise a trusted local/pinned service signing key, and the capability is still restricted by aud, lxm, and jti/idempotency. Locally minted tokens always include iat and use a 60-second lifetime. Confirm whether iat-omitting reference-PDS tokens are deliberately sup

### Root cause
The violated invariant is enforced incompletely at the recorded root control. SpaceServiceJWT.Claims decodes iat as optional, and validateShape requires issuer, audience, method, and event ID but not iat. The verifier always checks exp, but its future-issued-at and exp-minus-iat maximumLifetime checks execute only inside if let issuedAt. A correctly signed token without iat and with an arbitrarily distant exp therefore skips both lifetime controls and is accepted after signature, issuer, audience, method, route-shape, expiry, and event-id checks. DurableSpaceServiceAuthenticationVerifier passes a five-minute maximum, accepts the token for service-authenticated notification and control routes, and returns the distant expiry, so notifyWrite, deletion, or check-access authority and credential exposure can persist far beyond the configured window. Route-specific discovery further confirms that notifyWrite binds issuer to input.repo and audience to the space authority, while notifySpaceDeleted binds issuer to space.authority and maps its audience through the configured recipient binding; both then rely on the same verifier whose lifetime checks execute only when iat is present. These controls prevent unsigned, cross-authority, or cross-method use but do not enforce freshness for a valid no-iat bearer. Existing tests cover extreme present iat but not absent iat. Additional ordered discovery: SpaceServiceJWT.Claims declares iat optional. verify() enforces expiration relative to now, but performs the exp-minus-iat maximumLifetime check only inside `if let issuedAt`. A signer accepted by the configured resolver can therefore omit iat and choose an arbitrarily distant exp; DurableSpaceServiceAuthenticationVerifier then returns the token as authenticated after exact audience and method checks. The added discovery independently traces absent iat through Spac

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Require `iat` for service JWTs and enforce `exp <= now + maximumLifetime` independently of `iat`; add absent-`iat`, distant-`exp`, replay, audience, method, and issuer negative tests.

### Suggested regression tests
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

### Stated limitations
- No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure.

### Scan validation notes
```
{
 "assertions": [
  "Attacker-controlled or external source identified",
  "Reachable path to closest security control identified",
  "Missing control compared with adjacent defenses",
  "Strongest counterevidence evaluated",
  "Concrete protected asset or resource impact required"
 ],
 "limitations": [
  "No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure."
 ],
 "method": "static source/control/sink trace with adjacent tests and deployment/config evidence",
 "summary": "Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp. Static trace locations: entrypoint/wrapper Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381; sink Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420 SpaceServiceJWT.Claims decodes iat as optional, and validateShape requires issuer, audience, method, and event ID but not iat. The verifier always checks exp, but its future-issued-at and exp-minus-iat maximumLifetime checks execute only inside if let issuedAt. A correctly signed token without iat and with an arbitrarily distant exp therefore skips both lifetime controls and is accepted after signature, issuer, audience, method, route-shape, expiry, and event-id checks. DurableSpaceServiceAuthenticationVerifier passes a five-minute maximum, accepts the token for service-authenticated notification and control routes, and returns the distant expiry, so notifyWrite, deletion, or check-access authority and credential exposure can persist far beyond the configured window. Route-specific discovery further confirms that notifyWrite binds issuer to input.repo and audience to the space authority, while notifySpaceDeleted binds issuer to space.authority and maps its audience through the configured recipient binding; both then rely on the same verifier whose lifetime checks execute only when iat is present. These controls prevent unsigned, cross-authority, or cross-method use but do not enforce freshness for a valid no-iat bearer. Existing tests cover extreme present iat but not absent iat. Additional ordered discovery: SpaceServiceJWT.Claims declares iat optional. verify() enforces expiration relative to now, but performs the exp-minus-iat maximumLifetime check only inside `if le
```

---

## F16 [MEDIUM] `identity-resolution-confusion`
**The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.**
finding id: `csf_b9e3e6d70c45a1e9e8f91d2c`

### Locations
- `Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:67-89`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:246-318`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:340-411`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:76-83`  
- `Sources/SwanOAuth/PermissionedResolverComposition.swift:200-215`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:76-88`  
- `Sources/SwanOAuth/PermissionedResolverComposition.swift:200-215`  

### Attack path
- source: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440`
- sink: `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580`
- outcome: The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Additional context: Strongest counterevidence/proof gap: service JWTs remain signature-, audience-, method-, expiry-, and JTI-bound, and an overlapping operator pin must have been explicitly configured. Confirm production permits local/pinned issuer overlap and that account suspension is intended to revoke service-auth immediately. Unlike the credential and delegation local resolvers, this resolver has no typed terminal local-negative error, despite those adjacent resolvers explicitly preventing pin/remote fallback. Additional context: Construction rejects conflicting simultaneous local and pinned keys. It does not retain a terminal local-authority result after lifecycle changes; credential 

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Additional context: Strongest counterevidence/proof gap: service JWTs remain signature-, audience-, method-, expiry-, and JTI-bound, and an overlapping operator pin must have been explicitly configured. Confirm production permits local/pinned issuer overlap and that account suspension is intended to revoke service-auth immediately. Unlike the credential and delegation local resolvers, this resolver has no typed terminal local-negative error, despite those adjacent resolvers explicitly preventing pin/remote fallback. Additional context: Construction rejects conflicting simultaneous local and pinned keys. It does not retain a terminal local-authority result after lifecycle changes; credential and delegation compositions elsewhere distinguish managed-unavailable state.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. For service authentication, LocalAccountSpaceServicePublicKeyResolver returns nil not only for a genuinely unmanaged DID but also when a local account is missing, inactive, lacks a service reference/key, or lookup fails. CompositeSpaceServicePublicKeyResolver treats nil as permission to use the configured pinned key. Thus, if an operator has a pin for a DID that is also managed locally, a holder of that pinned private key can continue producing service JWTs after local deactivation/deletion and reach notification verification. Expected lifecycle behavior is terminal failure for an inactive managed identity. The credential and delegation resolvers demonstrate that control by distinguishing proven local absence from inactive/corrupt/racy local state and throwing instead of falling through. Prerequisites are the overlapping pin and possession of its private key; startup preflight and all JWT claim/signature checks still apply. Impact is a configuration-dependent lifecycle revocation bypass. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil not only for an unmanaged issuer, but also when the managed account is suspended, has missing key references, or lacks public-key metadata. CompositeSpaceServicePublicKeyResolver interprets nil as permission to use the configured pin. If a pin overlaps a local issuer while active, startup accepts it when key material matches; after suspension or local metadata failure, the same old pin becomes authoritative and verifies service JWTs used by the notification path. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil both when an issuer is absent and when its managed account is inactive or its key references/public projection are unavailable. CompositeSpaceServicePublicKeyRes

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

### Suggested regression tests
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

### Stated limitations
- No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure.

### Scan validation notes
```
{
 "assertions": [
  "Attacker-controlled or external source identified",
  "Reachable path to closest security control identified",
  "Missing control compared with adjacent defenses",
  "Strongest counterevidence evaluated",
  "Concrete protected asset or resource impact required"
 ],
 "limitations": [
  "No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure."
 ],
 "method": "static source/control/sink trace with adjacent tests and deployment/config evidence",
 "summary": "The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440; root_control Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234; sink Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580 For service authentication, LocalAccountSpaceServicePublicKeyResolver returns nil not only for a genuinely unmanaged DID but also when a local account is missing, inactive, lacks a service reference/key, or lookup fails. CompositeSpaceServicePublicKeyResolver treats nil as permission to use the configured pinned key. Thus, if an operator has a pin for a DID that is also managed locally, a holder of that pinned private key can continue producing service JWTs after local deactivation/deletion and reach notification verification. Expected lifecycle behavior is terminal failure for an inactive managed identity. The credential and delegation resolvers demonstrate that control by distinguishing proven local absence from inactive/corrupt/racy local state and throwing instead of falling through. Prerequisites are the overlapping pin and possession of its private key; startup preflight and all JWT claim/signature checks still apply. Impact is a configuration-dependent lifecycle revocation bypass. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil not only for an unmanaged issuer, but also when the managed account is suspended, has missing key references, or lacks public-key metadata. CompositeSpaceServicePublicKeyResolver interprets nil as permission to use the configured pin. If a pin overlaps a local issuer while active, startup accepts it when key material matches; after suspension or local metadata failure, the same old pin becomes authoritative and verifies service JWTs used by the notification path. Additional ordered discovery: LocalAcco
```

---

## F31 [MEDIUM] `authorization-capability-confusion`
**A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority**
finding id: `csf_a68878a5a920db3845c20c83`

### Locations
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:456-466`  
- `Sources/SwanSQLite/SwanSQLite.swift:6948-7023`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:722-740`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:6948-7023`
- outcome: A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: observe/obtain one valid notifySpaceDeleted Bearer JWT issued by an authority to a hosted recipient, then submit it before expiry (or longer if combined with the separate missing-iat condition). Entry point: POST /xrpc/com.atproto.space.notifySpaceDeleted. Controlled value: JSON body `space`, changed to another SpaceURI with the same authority DID. Control flow: handler verifies the unchanged JWT, checks issuer == request-selected space.authority, resolves the audience to a local account, and passes the selected space into persistence. Asset/impact: a different permissioned repository can receive a terminal deletion tombstone and have pending outbound notifications remov

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Attacker capability: observe/obtain one valid notifySpaceDeleted Bearer JWT issued by an authority to a hosted recipient, then submit it before expiry (or longer if combined with the separate missing-iat condition). Entry point: POST /xrpc/com.atproto.space.notifySpaceDeleted. Controlled value: JSON body `space`, changed to another SpaceURI with the same authority DID. Control flow: handler verifies the unchanged JWT, checks issuer == request-selected space.authority, resolves the audience to a local account, and passes the selected space into persistence. Asset/impact: a different permissioned repository can receive a terminal deletion tombstone and have pending outbound notifications removed, denying subsequent read/write/lifecycle operations. Prerequisites: another relevant space under the same authority and local recipient account; a token for a different authority or audience still fails.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. notifySpaceDeleted authenticates a JWT using only its issuer, audience, lxm, jti, and time claims. The handler then accepts any request-body SpaceURI whose authority equals the JWT issuer; neither the token nor verifier binds the JWT to the body space. The same valid Bearer token can therefore be paired with a different space URI under the same authority. The selected local audience database records a terminal recipient tombstone for that request-selected space and deletes its outbox rows atomically. Receipt uniqueness includes space_uri, so reusing the same issuer/JTI against another space is not treated as a duplicate. Signature verification, method binding, recipient binding, authority equality, and local-account preopening are strong controls, but none supplies the missing per-space authorization context.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Include the exact space URI in the signed service JWT and require equality with the request body before writing any deletion tombstone or clearing outbox state.

### Suggested regression tests
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

### Stated limitations
- No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure.

### Scan validation notes
```
{
 "assertions": [
  "Attacker-controlled or external source identified",
  "Reachable path to closest security control identified",
  "Missing control compared with adjacent defenses",
  "Strongest counterevidence evaluated",
  "Concrete protected asset or resource impact required"
 ],
 "limitations": [
  "No live production probing was performed; operational impact depends on enabled routes, limits, and external infrastructure."
 ],
 "method": "static source/control/sink trace with adjacent tests and deployment/config evidence",
 "summary": "A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299; sink Sources/SwanSQLite/SwanSQLite.swift:6948-7023 notifySpaceDeleted authenticates a JWT using only its issuer, audience, lxm, jti, and time claims. The handler then accepts any request-body SpaceURI whose authority equals the JWT issuer; neither the token nor verifier binds the JWT to the body space. The same valid Bearer token can therefore be paired with a different space URI under the same authority. The selected local audience database records a terminal recipient tombstone for that request-selected space and deletes its outbox rows atomically. Receipt uniqueness includes space_uri, so reusing the same issuer/JTI against another space is not treated as a duplicate. Signature verification, method binding, recipient binding, authority equality, and local-account preopening are strong controls, but none supplies the missing per-space authorization context."
}
```
