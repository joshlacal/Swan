# Cluster C12-lifecycle-linearization

---

## F15 [MEDIUM] `authorization-capability-confusion`
**Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.**
finding id: `csf_b4cce3232eb3c610f672be87`

### Locations
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440`  
- `Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159`  
- `Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169`  
- `Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-147`  
- `Sources/SwanOAuth/ProxyServiceAuthentication.swift:149-169`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-431`  
- `Sources/SwanOAuth/ProxyServiceAuthentication.swift:120-169`  
- `Sources/SwanAccounts/AccountOperatorService.swift:325-338`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-417`  

### Attack path
- source: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364`
- sink: `Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169`
- outcome: Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The attacker begins with a valid OAuth/DPoP request and must win the concurrent transition. The protected privilege is the account's inter-service identity at an AppView/labeler/feed service after local revocation. The caller must first have an authenticated OAuth subject; proxy routing, method allowlists, audience/lxm binding, a fresh jti, and a 60-second lifetime constrain impact. Parent validation should establish whether a lifecycle transition can interleave and whether a remote service can accept the old PLC identity before rotation or tombstone propagation. Additional context: The token remains narrowly bound and short-lived, limiting impact to a raced request, but revocation does not 

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
The attacker begins with a valid OAuth/DPoP request and must win the concurrent transition. The protected privilege is the account's inter-service identity at an AppView/labeler/feed service after local revocation. The caller must first have an authenticated OAuth subject; proxy routing, method allowlists, audience/lxm binding, a fresh jti, and a 60-second lifetime constrain impact. Parent validation should establish whether a lifecycle transition can interleave and whether a remote service can accept the old PLC identity before rotation or tombstone propagation. Additional context: The token remains narrowly bound and short-lived, limiting impact to a raced request, but revocation does not stop creation of new account-signed authority. Additional context: The JWT is correctly audience/method bounded, but the issuance authority can already have been revoked by the time the signature is produced.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The authenticated wildcard XRPC proxy validates the user's OAuth request, may buffer a body and resolve a remote service, then requests a service JWT. LocalAccountProxyServiceTokenIssuer reads the account lifecycle and key references at lines 143-145, awaits keyStore.key at line 152, and signs at lines 159-169 without a post-read lifecycle/generation check. Deactivation, permanent deletion, password-recovery revocation, or key rotation can complete during that await while the request still emits and forwards a fresh 60-second service token to the remote audience. The service token is correctly bound to audience and NSID and the proxy is peer-pinned; those controls do not fence issuer lifecycle. issueProxyServiceToken authorizes the issuer and captures signing references at lines 142-146, then suspends at keyStore.key(for:) on line 152 before issuing the service JWT at lines 159-169. The source comment states no await occurs after the lifecycle decision, but line 152 is awaited. No account status, generation, or current reference is revalidated afterward. Additional ordered discovery: LocalAccountProxyServiceTokenIssuer checks active status and key references, then awaits keyStore.key and signs without a final lifecycle/reference check. Its comment claims there is no await after the checks, but the key read is async. A deactivation that wins during this suspension still leaves the in-flight request able to mint a fresh, method/audience-bound service token for the outbound proxy request. Additional ordered discovery: An authenticated pipethrough request reaches issueProxyServiceToken with a route-bound audience and method. The issuer reads active account state and signing-key references at lines 143-145, then suspends at keyStore.key on line 152 despite a comment assertin

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
 "summary": "Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364; root_control Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159; sink Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169 The authenticated wildcard XRPC proxy validates the user's OAuth request, may buffer a body and resolve a remote service, then requests a service JWT. LocalAccountProxyServiceTokenIssuer reads the account lifecycle and key references at lines 143-145, awaits keyStore.key at line 152, and signs at lines 159-169 without a post-read lifecycle/generation check. Deactivation, permanent deletion, password-recovery revocation, or key rotation can complete during that await while the request still emits and forwards a fresh 60-second service token to the remote audience. The service token is correctly bound to audience and NSID and the proxy is peer-pinned; those controls do not fence issuer lifecycle. issueProxyServiceToken authorizes the issuer and captures signing references at lines 142-146, then suspends at keyStore.key(for:) on line 152 before issuing the service JWT at lines 159-169. The source comment states no await occurs after the lifecycle decision, but line 152 is awaited. No account status, generation, or current reference is revalidated afterward. Additional ordered discovery: LocalAccountProxyServiceTokenIssuer checks active status and key references, then awaits keyStore.key and signs without a final lifecycle/reference check. Its comment claims there is no await after the checks, but the key read is async. A deactivation that wins during this suspension still leaves the in-flight request able to mint a fresh, method/audience-bound service token for the outbound proxy request. Additional ordered discovery: An authenticated
```

---

## F18 [MEDIUM] `authorization-capability-confusion`
**A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it**
finding id: `csf_9bb290639ebcd8e479e0da0b`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342`  
- `Sources/SwanSQLite/AccountControlStore.swift:2488-2515`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2633-2662`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift:218-250`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:229-320`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-343`  
- `Sources/SwanSQLite/AccountControlStore.swift:2492-2515`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342`
- sink: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730`
- outcome: A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: an account holder with a valid OAuth/DPoP request concurrent with an operator or lifecycle deactivation. Protected asset: the account's durable public repository integrity and revocation boundary. This is source-demonstrated but was not dynamically exercised during read-only discovery. Additional context: The fallback is documented as intentional for pre/post-deactivation commits, but it conflicts with the adversarial scan invariant that lifecycle races must not bypass authorization/state transitions.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Attacker capability: an account holder with a valid OAuth/DPoP request concurrent with an operator or lifecycle deactivation. Protected asset: the account's durable public repository integrity and revocation boundary. This is source-demonstrated but was not dynamically exercised during read-only discovery. Additional context: The fallback is documented as intentional for pre/post-deactivation commits, but it conflicts with the adversarial scan invariant that lifecycle races must not bypass authorization/state transitions.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Authenticated public mutation routes resolve a target and check that its status is active before preparing the write. The final SQLite control-plane fence then rechecks active status and signing generation in a transaction, but PublicFirehoseCommitFence catches AccountControlStoreError.invalidTransition and invokes the durable mutation closure again with a nil firehose context. Consequently, a request admitted while active can be prepared, lose a race to deactivation, and still commit signed repository state after revocation. The inactive state hides the new commit and suppresses firehose emission, but reactivation or later cold public-read admission can expose the post-deactivation state. The strongest counterevidence is the initial active check, inactive-login rejection, cache eviction, and comments saying non-emitting post-deactivation commits are intentional; those controls do not preserve the documented final authorization fence, and the focused fence tests cover stale signing generation rather than the inactive-race fallback. Additional ordered discovery: The HTTP handler checks that the target is active, but the durable commit occurs later. PublicFirehoseCommitFence detects an inactive account through invalidTransition and then explicitly invokes mutate(nil), allowing the record mutation to commit without a firehose event after deactivation rather than rejecting the stale request. Reactivation can subsequently expose the post-revocation repository state.

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
 "summary": "A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342; root_control Sources/SwanSQLite/AccountControlStore.swift:2488-2515; sink Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730 Authenticated public mutation routes resolve a target and check that its status is active before preparing the write. The final SQLite control-plane fence then rechecks active status and signing generation in a transaction, but PublicFirehoseCommitFence catches AccountControlStoreError.invalidTransition and invokes the durable mutation closure again with a nil firehose context. Consequently, a request admitted while active can be prepared, lose a race to deactivation, and still commit signed repository state after revocation. The inactive state hides the new commit and suppresses firehose emission, but reactivation or later cold public-read admission can expose the post-deactivation state. The strongest counterevidence is the initial active check, inactive-login rejection, cache eviction, and comments saying non-emitting post-deactivation commits are intentional; those controls do not preserve the documented final authorization fence, and the focused fence tests cover stale signing generation rather than the inactive-race fallback. Additional ordered discovery: The HTTP handler checks that the target is active, but the durable commit occurs later. PublicFirehoseCommitFence detects an inactive account through invalidTransition and then explicitly invokes mutate(nil), allowing the record mutation to commit without a firehose event after deactivation rather than rejecting the stale request. Reactivation can subsequently expose the post-revocation repository state."
}
```

---

## F32 [LOW] `authorization-state-race`
**Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.**
finding id: `csf_1f707208a0b96b7fa1bab06f`

### Locations
- `Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64`  
- `Sources/SwanSQLite/AccountControlStore.swift:2320-2373`  
- `Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:93-107`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-58`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:58-65`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-45`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:48-64`  
- `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-64`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110`
- sink: `Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64`
- outcome: Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an initially active account, a valid sender-constrained OAuth token with whole-space-read scope, and winning the concurrent lifecycle or key transition. Requests begun after deactivation are rejected. Cross-host impact is material where the authority still accepts a published or pinned old account key independently of the user PDS lifecycle. Requires an authenticated account concurrently minting a delegation while an account lifecycle or key-rotation transition occurs. Audience, space, and lifetime binding are strong controls, and a local Swan verifier rechecks managed account status. Parent validation should determine whether a remote authority can still accept the old PLC key duri

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Requires an initially active account, a valid sender-constrained OAuth token with whole-space-read scope, and winning the concurrent lifecycle or key transition. Requests begun after deactivation are rejected. Cross-host impact is material where the authority still accepts a published or pinned old account key independently of the user PDS lifecycle. Requires an authenticated account concurrently minting a delegation while an account lifecycle or key-rotation transition occurs. Audience, space, and lifetime binding are strong controls, and a local Swan verifier rechecks managed account status. Parent validation should determine whether a remote authority can still accept the old PLC key during propagation and whether lifecycle coordination elsewhere closes the race. Additional context: Concurrency/state-transition candidate; strongest counterevidence is the short token lifetime and pre-sign active-state check, neither of which closes the interleaving. Additional context: Tests reportedly cover requests begun after deactivation, and already-issued short-lived tokens may remain valid by design. The proof gap is whether lifecycle semantics linearize against an in-flight request; a gat

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The authenticated getSpaceDelegationToken path first passes sender-constrained OAuth, whole-space-read scope, and active-account checks. LocalAccountSpaceDelegationTokenIssuer then reads an authorizing account and current key references, but—despite a nearby comment claiming no await follows the status check—awaits keyStore.key before signing a fresh one-minute delegation without re-reading lifecycle or reference generation. Deactivation transactionally revokes OAuth families but does not synchronize already-running signer operations. Concurrent deactivation, permanent deletion, or key rotation can therefore complete during key lookup while the in-flight request still returns a newly signed cross-host delegation. Existing tests cover inactive accounts and missing envelopes sequentially, not a suspended key read concurrent with lifecycle or generation transition. issueDelegation checks account lifecycle and reads key references at lines 41-45, then suspends at keyStore.key(for:) on line 51 before signing at lines 58-64. Contrary to the comment that there is no await after authorization, that key-store call is awaited. Concurrent deactivation or rotation can invalidate the lifecycle/reference facts while suspended, yet the resumed task signs with the previously selected reference. LocalAccountSpaceDelegationPublicKeyResolver re-reads the complete account after external key metadata access (SpaceCredentialAuthority.swift:397-410), showing the anti-TOCTOU fence absent here. Additional ordered discovery: The route authorizes the OAuth subject and active preopened account, then the issuer independently reads active account status and key references, awaits keyStore.key, and signs a 60-second delegation with those references. No lifecycle-generation lease or compare-and-set re

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
 "summary": "Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110; root_control Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64; sink Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64 The authenticated getSpaceDelegationToken path first passes sender-constrained OAuth, whole-space-read scope, and active-account checks. LocalAccountSpaceDelegationTokenIssuer then reads an authorizing account and current key references, but\u2014despite a nearby comment claiming no await follows the status check\u2014awaits keyStore.key before signing a fresh one-minute delegation without re-reading lifecycle or reference generation. Deactivation transactionally revokes OAuth families but does not synchronize already-running signer operations. Concurrent deactivation, permanent deletion, or key rotation can therefore complete during key lookup while the in-flight request still returns a newly signed cross-host delegation. Existing tests cover inactive accounts and missing envelopes sequentially, not a suspended key read concurrent with lifecycle or generation transition. issueDelegation checks account lifecycle and reads key references at lines 41-45, then suspends at keyStore.key(for:) on line 51 before signing at lines 58-64. Contrary to the comment that there is no await after authorization, that key-store call is awaited. Concurrent deactivation or rotation can invalidate the lifecycle/reference facts while suspended, yet the resumed task signs with the previously selected reference. LocalAccountSpaceDelegationPublicKeyResolver re-reads the complete account after external key metadata access (SpaceCredentialAuthority.swift:397-410), showing the anti-TOCTOU fence absent here. Additional ordered discovery: The route author
```

---

## F37 [LOW] `authorization-state-race`
**Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.**
finding id: `csf_3a2d4a910de7617e717a6ce4`

### Locations
- `Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78`  
- `Sources/SwanSQLite/PublicLifecycleEmitter.swift:99-107`  
- `Sources/SwanAccounts/AccountOperatorService.swift:341-364`  
- `Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175`  
- `Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177`  
- `Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift:375-408`  
- `Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift:451-477`  

### Attack path
- source: `Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78`
- sink: `Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177`
- outcome: Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an authorized lifecycle operation racing the sequencer; impact is public lifecycle ordering and possible repository reannouncement after deactivation.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Requires an authorized lifecycle operation racing the sequencer; impact is public lifecycle ordering and possible repository reannouncement after deactivation.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. emitReactivationSync reads the lifecycle generation and later performs account-database reads and an independent outbox insert without withActiveAccountFirehoseAuthorization. emitActivation likewise commits its control-side lifecycle batch before independently inserting sync. Concurrent deactivation can advance and drain generation N+1 before delayed generation-N sync insertion. The sequencer then selects the account event when no lifecycle batch remains without rejecting a generation older than durable current generation, allowing sync after the inactive event. Existing deterministic race coverage applies to manual sync, while reactivation coverage is uncontended.

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
 "summary": "Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation. Static trace locations: entrypoint Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78; root_control Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175; sink Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177 emitReactivationSync reads the lifecycle generation and later performs account-database reads and an independent outbox insert without withActiveAccountFirehoseAuthorization. emitActivation likewise commits its control-side lifecycle batch before independently inserting sync. Concurrent deactivation can advance and drain generation N+1 before delayed generation-N sync insertion. The sequencer then selects the account event when no lifecycle batch remains without rejecting a generation older than durable current generation, allowing sync after the inactive event. Existing deterministic race coverage applies to manual sync, while reactivation coverage is uncontended."
}
```

---

## F43 [LOW] `authorization-state-race`
**A streaming public blob upload can commit after the account is deactivated.**
finding id: `csf_4370c62d6bb27419459a4e05`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2735`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-130`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2760-2795`  
- `Sources/SwanSQLite/SwanSQLite.swift:7122-7180`  
- `Sources/SwanAccounts/AccountOperatorService.swift:325-338`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:7122-7180`
- outcome: A streaming public blob upload can commit after the account is deactivated.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an already authenticated account and a concurrent deactivation; the blob remains content-addressed and becomes anonymously retrievable by CID if the account is later active/readable. Additional context: Public read routing may hide an inactive account until reactivation, but the write and disk consumption have already occurred under a revoked lifecycle state.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Requires an already authenticated account and a concurrent deactivation; the blob remains content-addressed and becomes anonymously retrievable by CID if the account is later active/readable. Additional context: Public read routing may hide an inactive account until reactivation, but the write and disk consumption have already occurred under a revoked lifecycle state.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. uploadBlob checks OAuth subject and target.status == active only before streaming a body of up to 256 MiB. The directory's streaming wrapper delegates directly to the account database after generation refresh, while the lifecycle/firehose authorization fence is used for repository mutations but not blob streaming. Deactivation after preflight therefore can race with completion and leave a new public-namespace blob written outside the active lifecycle. Additional ordered discovery: uploadBlob verifies OAuth and active target only before streaming up to 256 MiB. The generation-refreshing wrapper delegates putStreaming directly to the account database; unlike record commits, no control-plane lifecycle fence or final active-state check covers adoption. An in-flight request can therefore continue across deactivation and create a durable public namespace reference.

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
 "summary": "A streaming public blob upload can commit after the account is deactivated. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795; sink Sources/SwanSQLite/SwanSQLite.swift:7122-7180 uploadBlob checks OAuth subject and target.status == active only before streaming a body of up to 256 MiB. The directory's streaming wrapper delegates directly to the account database after generation refresh, while the lifecycle/firehose authorization fence is used for repository mutations but not blob streaming. Deactivation after preflight therefore can race with completion and leave a new public-namespace blob written outside the active lifecycle. Additional ordered discovery: uploadBlob verifies OAuth and active target only before streaming up to 256 MiB. The generation-refreshing wrapper delegates putStreaming directly to the account database; unlike record commits, no control-plane lifecycle fence or final active-state check covers adoption. An in-flight request can therefore continue across deactivation and create a durable public namespace reference."
}
```

---

## F44 [LOW] `authorization-state-race`
**Notification delivery can mint a service JWT after concurrent issuer deactivation.**
finding id: `csf_03f6ba48006117c2f9479e2a`

### Locations
- `Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171`  
- `Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:215-241`  
- `Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269`  
- `Sources/SwanAccounts/AccountOperatorService.swift:325-338`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171`
- sink: `recorded protected operation`
- outcome: Notification delivery can mint a service JWT after concurrent issuer deactivation.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Destinations, audience, method, and event ID remain constrained; the candidate concerns lifecycle revocation of the signing account.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Destinations, audience, method, and event ID remain constrained; the candidate concerns lifecycle revocation of the signing account.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. LocalAccountSpaceServiceAuthenticationIssuer checks active account status and signing reference, then awaits key retrieval and signs without a lifecycle/reference recheck. Writer and deletion notification transports immediately place this newly minted token in an outbound Authorization header, so a deactivation race can authorize one post-revocation delivery.

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
 "summary": "Notification delivery can mint a service JWT after concurrent issuer deactivation. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269 LocalAccountSpaceServiceAuthenticationIssuer checks active account status and signing reference, then awaits key retrieval and signs without a lifecycle/reference recheck. Writer and deletion notification transports immediately place this newly minted token in an outbound Authorization header, so a deactivation race can authorize one post-revocation delivery."
}
```

---

## F45 [LOW] `authorization-state-race`
**An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.**
finding id: `csf_f4a5dd34749be1fe3db3869e`

### Locations
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129`  
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:347-410`  
- `Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70`  
- `Sources/SwanAccounts/AccountOperatorService.swift:325-338`  
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:95-113`  
- `Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:45-58`  
- `Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129`
- sink: `Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70`
- outcome: An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an already-authorized sync request racing an operator lifecycle transition. Permanent deletion has broader quiescence, but ordinary deactivation is a separate reachable transition. Additional context: A remote credentialed reader can hold the sync request across the signing-key suspension and receive repository state authenticated after the author's local signing authority was revoked.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Requires an already-authorized sync request racing an operator lifecycle transition. Permanent deletion has broader quiescence, but ordinary deactivation is a separate reachable transition. Additional context: A remote credentialed reader can hold the sync request across the signing-key suspension and receive repository state authenticated after the author's local signing authority was revoked.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. LocalAccountSpaceRepositoryCommitSigner checks account status and key references, then suspends again while reading the signing key and signs without rechecking lifecycle or reference generation. If deactivation commits after the status check but before the key read/signature, the still-present key produces a valid reader-bound signature after revocation, contradicting the file's stated stale-request invariant. Additional ordered discovery: The sync route obtains an authorized repository snapshot and asks for a reader-specific signed commit. The signer repeats an active-author and key-reference check at lines 49-51, but then awaits keyStore.key at line 58 without a final lifecycle/generation check. A concurrent deactivation, deletion, or rotation can therefore occur before createReaderEnvelope signs at lines 65-70, contrary to the stated guarantee that a stale request cannot sign after deactivation or key-reference removal.

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
 "summary": "An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; root_control Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70; sink Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70 LocalAccountSpaceRepositoryCommitSigner checks account status and key references, then suspends again while reading the signing key and signs without rechecking lifecycle or reference generation. If deactivation commits after the status check but before the key read/signature, the still-present key produces a valid reader-bound signature after revocation, contradicting the file's stated stale-request invariant. Additional ordered discovery: The sync route obtains an authorized repository snapshot and asks for a reader-specific signed commit. The signer repeats an active-author and key-reference check at lines 49-51, but then awaits keyStore.key at line 58 without a final lifecycle/generation check. A concurrent deactivation, deletion, or rotation can therefore occur before createReaderEnvelope signs at lines 65-70, contrary to the stated guarantee that a stale request cannot sign after deactivation or key-reference removal."
}
```

---

## F46 [LOW] `authorization-capability-confusion`
**Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.**
finding id: `csf_2cf09daee8c1c7c21b202316`

### Locations
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870`  
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082`  
- `Sources/SwanSQLite/SwanSQLite.swift:10725-10732`  
- `Sources/SwanSQLite/AccountControlStore.swift:2433-2454`  
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:735-764`  
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:798-813`  
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:771-791`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:10725-10732`
- outcome: Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker prerequisite: a still-valid OAuth/DPoP request for one of the four permissioned write operations already in flight while an operator or lifecycle workflow suspends or deactivates the same account. Requests begun after deactivation fail, the directory performs a post-write active check, and public-repository publication has a lifecycle fence; none prevents or rolls back these permissioned commits. The four entrypoints and their operation-specific effects remain preserved as independently reachable instances.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Attacker prerequisite: a still-valid OAuth/DPoP request for one of the four permissioned write operations already in flight while an operator or lifecycle workflow suspends or deactivates the same account. Requests begun after deactivation fail, the directory performs a post-write active check, and public-repository publication has a lifecycle fence; none prevents or rolls back these permissioned commits. The four entrypoints and their operation-specific effects remain preserved as independently reachable instances.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Each authenticated OAuth/DPoP handler checks a self-write and routes applyWrites, createRecord, deleteRecord, or putRecord through SQLitePreMigratedAccountDirectory.apply. That shared method selects the preopened account database and awaits applyAuthorizedWrites, which durably commits record, oplog, and outbox state through database.apply, before checking isActiveAccount. A lifecycle transition can therefore linearize after initial admission but before the account-local commit; the post-commit Unauthorized result cannot roll back the mutation. AccountControlStore.withActiveAccountAuthorization already provides the relevant pattern for holding the control-plane write transaction across a staged network-free mutation, but this permissioned publication path does not use it. All four independently reachable XRPC entrypoints share this same root control and durable sink.

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
 "summary": "Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082; sink Sources/SwanSQLite/SwanSQLite.swift:10725-10732 Each authenticated OAuth/DPoP handler checks a self-write and routes applyWrites, createRecord, deleteRecord, or putRecord through SQLitePreMigratedAccountDirectory.apply. That shared method selects the preopened account database and awaits applyAuthorizedWrites, which durably commits record, oplog, and outbox state through database.apply, before checking isActiveAccount. A lifecycle transition can therefore linearize after initial admission but before the account-local commit; the post-commit Unauthorized result cannot roll back the mutation. AccountControlStore.withActiveAccountAuthorization already provides the relevant pattern for holding the control-plane write transaction across a staged network-free mutation, but this permissioned publication path does not use it. All four independently reachable XRPC entrypoints share this same root control and durable sink."
}
```
