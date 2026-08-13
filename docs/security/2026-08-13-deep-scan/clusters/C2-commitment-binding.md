# Cluster C2-commitment-binding

---

## F02 [HIGH] `cryptographic-binding-failure`
**A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.**
finding id: `csf_b9ccd64b173461eeb5d8d9ed`

### Locations
- `Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297`  
- `Sources/SwanInterop/PermissionedRemoteReplicaHTTPProvider.swift:211-251`  
- `Sources/SwanSpaces/SwanSpaces.swift:518-527`  
- `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821`  
- `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:838-900`  
- `Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:335-360`  
- `Sources/SwanSpaces/SwanSpaces.swift:530-581`  
- `Tests/SwanSpacesTests/SwanSpacesTests.swift:181-231`  
- `Sources/SwanSpaces/SwanSpaces.swift:530-570`  
- `Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:347-360`  

### Attack path
- source: `Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297`
- sink: `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821`
- outcome: A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Prerequisites are capture of a valid signed context for the exact tuple and control of the recovery/latest-commit source or authenticated transport boundary. The scan invariant requires cross-host writer identity and repository commits to be verified, but this verifies author context rather than writer-authenticated repository state. Additional context: Potential cross-host repository-authority failure. Later validation should determine whether the pinned protocol intentionally delegates all exact-content authenticity to the serving host and whether that trust is acceptable for the claimed author-verification invariant.

### Impact (high)
The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

### Likelihood (high)
Prerequisites are capture of a valid signed context for the exact tuple and control of the recovery/latest-commit source or authenticated transport boundary. The scan invariant requires cross-host writer identity and repository commits to be verified, but this verifies author context rather than writer-authenticated repository state. Additional context: Potential cross-host repository-authority failure. Later validation should determine whether the pinned protocol intentionally delegates all exact-content authenticity to the serving host and whether that trust is acceptable for the claimed author-verification invariant.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. SpaceCommitCodec signs encodedContext(space, author, rev, ikm), excluding commitment. The content binding is HMAC(commitment) under a key derived entirely from the envelope's disclosed ikm, and verification accepts the unchanged context signature plus this recomputable MAC. A source that observed a legitimate envelope for the same space/author/revision can construct arbitrary canonical records and DRISL/LtHash commitment, recompute the MAC, and pass streaming signature, MAC, CID, index and LtHash checks; SQLite then marks and can publish the result. The separately fetched freshness witness uses the same signature/MAC construction and compares only revision+commitment, so a malicious source can return a consistent forged pair. Strongest counterevidence: this explicitly implements proposal-0016's deniable-MAC design; TLS/source configuration, CAR canonicality, limits, CAS, high-water and publication authorization are fail-closed; a passive attacker without a valid envelope and source control cannot exploit it. Additional ordered discovery: The context signature covers space, author, revision, and the 32-byte IKM but excludes the repository commitment. The content-binding key is deterministically derived from that IKM, which is transmitted in the envelope, so an observer of a valid signed context can calculate a valid MAC for any replacement commitment. Streaming and in-memory recovery accept the unchanged context signature plus this recomputed MAC and install records whose LtHash matches the attacker-selected commitment. Comments correctly describe the MAC as deniable and peer-pinned HTTPS may supply transport integrity, but the recovery boundary calls these checks authentication of the exact commit root; a malicious hosting peer or response substituter with one valid env

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Bind the exact commitment into the writer-authenticated signature (with domain separation) or explicitly treat the serving PDS as the sole integrity authority and stop describing the deniable MAC as writer authentication. Reject recovery envelopes whose signed binding does not cover the installed commitment.

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
 "summary": "A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM. Static trace locations: entrypoint Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297; root_control Sources/SwanSpaces/SwanSpaces.swift:518-527; sink Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821 SpaceCommitCodec signs encodedContext(space, author, rev, ikm), excluding commitment. The content binding is HMAC(commitment) under a key derived entirely from the envelope's disclosed ikm, and verification accepts the unchanged context signature plus this recomputable MAC. A source that observed a legitimate envelope for the same space/author/revision can construct arbitrary canonical records and DRISL/LtHash commitment, recompute the MAC, and pass streaming signature, MAC, CID, index and LtHash checks; SQLite then marks and can publish the result. The separately fetched freshness witness uses the same signature/MAC construction and compares only revision+commitment, so a malicious source can return a consistent forged pair. Strongest counterevidence: this explicitly implements proposal-0016's deniable-MAC design; TLS/source configuration, CAR canonicality, limits, CAS, high-water and publication authorization are fail-closed; a passive attacker without a valid envelope and source control cannot exploit it. Additional ordered discovery: The context signature covers space, author, revision, and the 32-byte IKM but excludes the repository commitment. The content-binding key is deterministically derived from that IKM, which is transmitted in the envelope, so an observer of a valid signed context can calculate a valid MAC for any replacement commitment. Streaming and in-memory recovery accept the unchanged context signature plus this recomputed MAC and install records whose LtHash matches the attacker-
```
