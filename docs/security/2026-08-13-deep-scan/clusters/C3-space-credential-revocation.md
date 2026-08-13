# Cluster C3-space-credential-revocation

---

## F03 [HIGH] `authorization-capability-confusion`
**Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.**
finding id: `csf_6439b8199b5195fa2da0943d`

### Locations
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751`  
- `Sources/SwanOAuth/SwanOAuth.swift:343-375`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907`  
- `Sources/SwanSpaces/SwanSpaces.swift:232-254`  
- `Sources/SwanSQLite/SwanSQLite.swift:10514-10520`  
- `Sources/SwanSQLite/SwanSQLite.swift:6403-6435`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:216-245`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-908`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:10514-10520`
- outcome: Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A legitimate space member (or any party holding that member's bearer credential) obtains a space credential before the owner removes the member or changes the client policy. The credential remains usable against local or cross-host permissioned read endpoints until its default two-hour expiry (plus accepted clock skew). This is especially relevant to cross-host access because the compact credential intentionally omits reader and client identity, and the repository host therefore cannot re-check the removed member or policy tuple. The strongest counterevidence is that proposal-shaped credentials are intentionally transferable read capabilities, issuance does check the current member/client po

### Impact (high)
The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

### Likelihood (high)
A legitimate space member (or any party holding that member's bearer credential) obtains a space credential before the owner removes the member or changes the client policy. The credential remains usable against local or cross-host permissioned read endpoints until its default two-hour expiry (plus accepted clock skew). This is especially relevant to cross-host access because the compact credential intentionally omits reader and client identity, and the repository host therefore cannot re-check the removed member or policy tuple. The strongest counterevidence is that proposal-shaped credentials are intentionally transferable read capabilities, issuance does check the current member/client policy, and the generated removeMember documentation describes membership as consulted at credential-mint time. If that mint-time-only revocation model is an accepted protocol property, this is residual capability lifetime rather than an implementation defect; otherwise it violates immediate membership revocation expectations and the stated cross-host membership invariant. No assigned test mints a credential, removes the member or denies its app policy, and retries a read. The standard lifetime is

### Root cause
The violated invariant is enforced incompletely at the recorded root control. PermissionedDataJWT.spaceCredentialLifetime defaults to 2 hours, while SpaceCredentialClaims contains only iss/sub/iat/exp/jti and createSpaceCredential encodes no reader, client, membership revision, or revocation epoch. Issuance does authorize the exact user/client tuple, but verification later checks only signature, authority/space, time, and JTI. DurableSpaceCredentialVerifier then constructs a read grant whose subject is the authority issuer. SpaceAuthorizationPolicy accepts that grant for any read in the matching space without consulting membership. removeSimpleSpaceMember deletes the membership row and advances the space revision but does not revoke outstanding JTIs or advance a credential epoch. DurableSpaceRepository.record (representative sink; the same context is used by the broader permissioned read surface) authorizes via the space grant and reads the record without a current membership lookup. Consequently, a credential minted immediately before removal can continue reading permissioned records after removal. Added ordered discovery extends the same post-issuance revocation root from membership removal to managing-app or client-policy denial and traces the retained grant through permissioned blob, record, CAR, and operation-log reads. Issuance checks the current member and app-policy tuple once, but removal or denial records neither JTI revocation nor a credential-policy generation, while verification later checks only signature, space or authority binding, and time. A retained credential therefore continues authorizing the broader permissioned read surface until expiry.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Bind space credentials to a membership/client-policy generation or revocation epoch and check it on every read; alternatively shorten leases to an explicitly accepted revocation window and provide durable JTI revocation propagated to repository hosts.

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
 "summary": "Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907; sink Sources/SwanSQLite/SwanSQLite.swift:10514-10520 PermissionedDataJWT.spaceCredentialLifetime defaults to 2 hours, while SpaceCredentialClaims contains only iss/sub/iat/exp/jti and createSpaceCredential encodes no reader, client, membership revision, or revocation epoch. Issuance does authorize the exact user/client tuple, but verification later checks only signature, authority/space, time, and JTI. DurableSpaceCredentialVerifier then constructs a read grant whose subject is the authority issuer. SpaceAuthorizationPolicy accepts that grant for any read in the matching space without consulting membership. removeSimpleSpaceMember deletes the membership row and advances the space revision but does not revoke outstanding JTIs or advance a credential epoch. DurableSpaceRepository.record (representative sink; the same context is used by the broader permissioned read surface) authorizes via the space grant and reads the record without a current membership lookup. Consequently, a credential minted immediately before removal can continue reading permissioned records after removal. Added ordered discovery extends the same post-issuance revocation root from membership removal to managing-app or client-policy denial and traces the retained grant through permissioned blob, record, CAR, and operation-log reads. Issuance checks the current member and app-policy tuple once, but removal or denial records neither JTI revocation nor a credential-policy generation, while verification later checks only signature, space or authority binding, and time. A retained credential therefore continues authorizing the broader permissioned read surface until expiry.
```

---

## F08 [MEDIUM] `authorization-capability-confusion`
**Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.**
finding id: `csf_5e83fd39c3ea5ea909865fd6`

### Locations
- `Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:609-638`  
- `Sources/SwanStorage/AuthorizedSimpleSpaceDirectory.swift:439-455`  
- `Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:732-744`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:744-751`  
- `Sources/SwanSQLite/SwanSQLite.swift:7033-7074`  
- `Sources/SwanSQLite/SwanSQLite.swift:6403-6434`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140`
- sink: `Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223`
- outcome: Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The caller must hold a valid delegation and be authorized under membership and app policy when the initial transaction runs, then win a concurrent authority-policy transition or prolong the signing-key read. The protected asset is permissioned repository read authority after revocation or policy tightening. The added source preserves the narrower currently authorized member racing removal or deletion; accepting ordinary validity of already-issued tokens does not explain issuance that linearizes after revocation. Additional context: The route is remotely reachable after delegation verification; a requester can keep exchanges in flight while a concurrent authorized lifecycle or policy operatio

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
The caller must hold a valid delegation and be authorized under membership and app policy when the initial transaction runs, then win a concurrent authority-policy transition or prolong the signing-key read. The protected asset is permissioned repository read authority after revocation or policy tightening. The added source preserves the narrower currently authorized member racing removal or deletion; accepting ordinary validity of already-issued tokens does not explain issuance that linearizes after revocation. Additional context: The route is remotely reachable after delegation verification; a requester can keep exchanges in flight while a concurrent authorized lifecycle or policy operation revokes the predicate that was checked. The space-policy revision race here is distinct from the separately controlled authority-account lifecycle and signing-key-generation race.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. A remote holder of a valid single-use delegation reaches getSpaceCredential, passes client-attestation verification, and receives a transactional authorizeSimpleSpaceCredentialRead decision covering current space lifecycle, app allow-list, member-list or managing-app membership. That read transaction ends before the issuer separately awaits signingKeys.signingKey and signs a fresh two-hour space credential without carrying a policy revision or rechecking policy. Concurrent removeMember, client allow-list removal, managing-app denial, space update, or deletion can therefore commit after authorization and before signing while issuance still returns a bearer the post-change policy would deny. The later verifier checks signature, space, and time rather than current membership or policy. Transactional reads, single-use delegation JTI, bounded lifetime, and sequential policy tests are counterevidence, but they do not close the post-transaction async signing window. The latest ordered discovery isolates member removal or whole-space deletion committing during the asynchronous signing-key lookup: issueSpaceCredential can then mint the same two-hour read bearer without a policy version, CAS, or second membership check, and later verification does not consult current membership. Additional ordered discovery: A credential exchange passes durable membership/managing-app policy at lines 732-737, then suspends while resolving the authority signing key. The local resolver reads active account state and key references at lines 207-213 and suspends again for key-store access. Neither the space policy nor authority lifecycle/generation is revalidated before createSpaceCredential signs at lines 744-750, so concurrent member/app revocation, authority deactivation, deletion, or key rotation

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

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
 "summary": "Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223 A remote holder of a valid single-use delegation reaches getSpaceCredential, passes client-attestation verification, and receives a transactional authorizeSimpleSpaceCredentialRead decision covering current space lifecycle, app allow-list, member-list or managing-app membership. That read transaction ends before the issuer separately awaits signingKeys.signingKey and signs a fresh two-hour space credential without carrying a policy revision or rechecking policy. Concurrent removeMember, client allow-list removal, managing-app denial, space update, or deletion can therefore commit after authorization and before signing while issuance still returns a bearer the post-change policy would deny. The later verifier checks signature, space, and time rather than current membership or policy. Transactional reads, single-use delegation JTI, bounded lifetime, and sequential policy tests are counterevidence, but they do not close the post-transaction async signing window. The latest ordered discovery isolates member removal or whole-space deletion committing during the asynchronous signing-key lookup: issueSpaceCredential can then mint the same two-hour read bearer without a policy version, CAS, or second membership check, and later verification does not consult current membership. Additional ordered discovery: A credential exchange passes durable membership/managing-app policy at lines 732-737, then suspends while resolving the authority signing key. The local resolver reads active account state and key references at lines 207-213 and suspends again for key-store access. Ne
```

---

## F14 [MEDIUM] `authorization-capability-confusion`
**Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.**
finding id: `csf_bed40c6eba082c449148f082`

### Locations
- `Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140`
- sink: `Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751`
- outcome: Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A valid delegation is still required. Local verification may reject a token after a completed lifecycle/key transition, but a cross-host verifier with an accepted prior PLC/pinned key can accept a token minted after local authority was revoked unless the transition and signer are fenced. Exact requester/user/space matching, delegation or OAuth context, durable reader policy, dedicated kid, and short lifetime are strong controls; local managed-key verification also fails closed after deactivation. Parent validation should determine whether cross-host verification can accept the old PLC or dedicated key during propagation and whether an outer lifecycle transaction prevents the interleaving.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
A valid delegation is still required. Local verification may reject a token after a completed lifecycle/key transition, but a cross-host verifier with an accepted prior PLC/pinned key can accept a token minted after local authority was revoked unless the transition and signer are fenced. Exact requester/user/space matching, delegation or OAuth context, durable reader policy, dedicated kid, and short lifetime are strong controls; local managed-key verification also fails closed after deactivation. Parent validation should determine whether cross-host verification can accept the old PLC or dedicated key during propagation and whether an outer lifecycle transaction prevents the interleaving.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The credential endpoint invokes the durable issuer, which resolves its local authority key through LocalAccountSpaceCredentialSigningKeyResolver. That resolver reads an authorizing account row and key references at lines 207-209, then awaits keyStore.key at line 213 and returns the private key without re-reading the account lifecycle or generation. The caller immediately signs a two-hour space credential at lines 744-751. Account deactivation, permanent-deletion revocation, or key rotation can therefore interleave after the authorizing snapshot and before signature creation. The verification-only resolver elsewhere explicitly re-reads the account after its external metadata read, which is strong counterevidence for verification but highlights the missing equivalent fence on this signing path. LocalAccountSpaceCredentialSigningKeyResolver checks account status and obtains key references at lines 207-212, then awaits keyStore.key(for:) at line 213 and returns without re-reading account lifecycle or generation. DurableSpaceCredentialAuthority performs policy authorization, awaits this resolver at lines 738-742, and signs at lines 744-751. Concurrent deactivation or rotation can therefore yield a key authorized only by stale facts. Verification resolvers in the same file deliberately re-read the complete account after key access (lines 304-317 and 397-410), providing internal evidence for the missing fence.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

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
 "summary": "Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751 The credential endpoint invokes the durable issuer, which resolves its local authority key through LocalAccountSpaceCredentialSigningKeyResolver. That resolver reads an authorizing account row and key references at lines 207-209, then awaits keyStore.key at line 213 and returns the private key without re-reading the account lifecycle or generation. The caller immediately signs a two-hour space credential at lines 744-751. Account deactivation, permanent-deletion revocation, or key rotation can therefore interleave after the authorizing snapshot and before signature creation. The verification-only resolver elsewhere explicitly re-reads the account after its external metadata read, which is strong counterevidence for verification but highlights the missing equivalent fence on this signing path. LocalAccountSpaceCredentialSigningKeyResolver checks account status and obtains key references at lines 207-212, then awaits keyStore.key(for:) at line 213 and returns without re-reading account lifecycle or generation. DurableSpaceCredentialAuthority performs policy authorization, awaits this resolver at lines 738-742, and signs at lines 744-751. Concurrent deactivation or rotation can therefore yield a key authorized only by stale facts. Verification resolvers in the same file deliberately re-read the complete account after key access (lines 304-317 and 397-410), providing internal evidence for the missing fence."
}
```

---

## F39 [LOW] `authorization-capability-confusion`
**PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.**
finding id: `csf_4f195fb9ce2aa7dc383f62a1`

### Locations
- `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380`  
- `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:386-392`  
- `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899`  
- `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:466-475`  

### Attack path
- source: `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380`
- sink: `Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899`
- outcome: PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Refreshes verify current PLC state, audit CIDs, and durable continuity, and the stale window is bounded; after refresh the old signature stops verifying. This candidate requires compromise of a formerly valid authority key and a populated pre-rotation cache. It is a revocation-latency/stale-key candidate, not demonstrated rollback or key substitution.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Refreshes verify current PLC state, audit CIDs, and durable continuity, and the stale window is bounded; after refresh the old signature stops verifying. This candidate requires compromise of a formerly valid authority key and a populated pre-rotation cache. It is a revocation-latency/stale-key candidate, not demonstrated rollback or key substitution.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The remote resolver caches an authenticated PLC document for 60 seconds by default and permits values up to 300 seconds. publicKey returns the cached state immediately while expiresAt remains in the future, without refreshing PLC state. DurableSpaceCredentialVerifier then uses that key to verify a bearer credential. If an authority rotates a compromised #atproto_space/#atproto key after the cache is populated, an attacker retaining the old private key can mint newly signed credentials that remain accepted until the cache expires.

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
 "summary": "PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires. Static trace locations: entrypoint Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380; root_control Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899 The remote resolver caches an authenticated PLC document for 60 seconds by default and permits values up to 300 seconds. publicKey returns the cached state immediately while expiresAt remains in the future, without refreshing PLC state. DurableSpaceCredentialVerifier then uses that key to verify a bearer credential. If an authority rotates a compromised #atproto_space/#atproto key after the cache is populated, an attacker retaining the old private key can mint newly signed credentials that remain accepted until the cache expires."
}
```
