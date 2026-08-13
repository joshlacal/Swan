# Cluster C1-permissioned-blob-namespace

---

## F01 [HIGH] `permissioned-data-disclosure`
**Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.**
finding id: `csf_0feb001d0f16298db4902b47`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112`  
- `Sources/SwanSQLite/SwanSQLite.swift:7446-7577`  
- `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942`  
- `Sources/SwanSQLite/SwanSQLite.swift:9889-9973`  
- `Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift:135-177`  
- `Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift:511-531`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:109-112`  
- `Sources/SwanSQLite/SwanSQLite.swift:9889-9973`  
- `Sources/SwanSQLite/SwanSQLite.swift:7234-7269`  
- `Sources/SwanSQLite/SwanSQLite.swift:7127-7179`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112`
- sink: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942`
- outcome: Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Upload requires account authentication, and the blob is not formally permissioned until referenced. Anonymous reading requires the account DID and CID; CIDs are not enumerable here. Exploitation therefore requires CID knowledge or derivation plus timing before promotion, a failed or abandoned apply, or a later same-CID re-upload. CID opacity reduces discoverability but does not enforce namespace confidentiality. Additional context: An unauthenticated reader still needs the SHA-256 CID, which is difficult to guess for high-entropy content but predictable for known content or may be disclosed by the workflow. Successful promotion removes the edge transactionally unless a public record also ref

### Impact (high)
The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

### Likelihood (high)
Upload requires account authentication, and the blob is not formally permissioned until referenced. Anonymous reading requires the account DID and CID; CIDs are not enumerable here. Exploitation therefore requires CID knowledge or derivation plus timing before promotion, a failed or abandoned apply, or a later same-CID re-upload. CID opacity reduces discoverability but does not enforce namespace confidentiality. Additional context: An unauthenticated reader still needs the SHA-256 CID, which is difficult to guess for high-entropy content but predictable for known content or may be disclosed by the workflow. Successful promotion removes the edge transactionally unless a public record also references it; that does not close the pre-promotion or abandoned-upload exposure. Additional context: Requires valid account OAuth and enabled public mutation/permissioned write capabilities; CID knowledge is needed, but low-entropy content is guessable and the stated invariant forbids any public reachability. Additional context: Directly conflicts with the permissioned-to-public isolation invariant; demonstrated by repository code and tests without live testing. The added source also preserves th

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The only authenticated production uploadBlob path stores every upload through namespace .public, and putBlobLocked immediately creates a durable public edge served by unauthenticated CID lookup and streaming without repository-record reachability. Only a later successful permissioned record transaction promotes referenced CIDs and removes the public edge when no verified public record references the bytes. A known or derivable CID is therefore fetchable between upload and apply; validation, authorization, CAS, connectivity, process failure, or abandonment can leave the edge indefinitely, and re-uploading identical content recreates the public edge after prior promotion. PermissionedBlobRepositoryReachabilityTests explicitly demonstrate that same-CID re-upload restores anonymous reachability until another permissioned update cleans it up. Successful apply atomically removes the edge, but those tests prove only eventual isolation after promotion, not confidentiality during staging. Raw SHA-256 CIDs are generally hard to guess, yet known, shared, leaked, low-entropy, or otherwise predictable content CIDs suffice and the never-public invariant is violated. Additional ordered discovery: The authenticated com.atproto.repo.uploadBlob handler stores every upload with BlobNamespace.public, which immediately inserts a public namespace edge. Anonymous sync.getBlob deliberately skips repository-generation admission and serves any CAS payload with that edge. The permissioned workflow itself uses uploadBlob and removes the public edge only inside a later successful permissioned-record transaction. A crash, network loss, validation/quota/CAS rejection, or deliberate omission leaves the blob public with no staged-edge expiry found. Additional ordered discovery: The only HTTP uploadBlob

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add a permissioned/staged upload namespace that is never served by anonymous `sync.getBlob`; promote it atomically to a space edge only within an authorized record commit, expire abandoned staging edges, and make same-CID re-upload preserve the private namespace.

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
 "summary": "Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112; root_control Sources/SwanSQLite/SwanSQLite.swift:7446-7577; sink Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942 The only authenticated production uploadBlob path stores every upload through namespace .public, and putBlobLocked immediately creates a durable public edge served by unauthenticated CID lookup and streaming without repository-record reachability. Only a later successful permissioned record transaction promotes referenced CIDs and removes the public edge when no verified public record references the bytes. A known or derivable CID is therefore fetchable between upload and apply; validation, authorization, CAS, connectivity, process failure, or abandonment can leave the edge indefinitely, and re-uploading identical content recreates the public edge after prior promotion. PermissionedBlobRepositoryReachabilityTests explicitly demonstrate that same-CID re-upload restores anonymous reachability until another permissioned update cleans it up. Successful apply atomically removes the edge, but those tests prove only eventual isolation after promotion, not confidentiality during staging. Raw SHA-256 CIDs are generally hard to guess, yet known, shared, leaked, low-entropy, or otherwise predictable content CIDs suffice and the never-public invariant is violated. Additional ordered discovery: The authenticated com.atproto.repo.uploadBlob handler stores every upload with BlobNamespace.public, which immediately inserts a public namespace edge. Anonymous sync.getBlob deliberately skips repository-generation admission and serves any CAS payload with that edge. The permissioned workflow itself uses uploadBlob and removes the
```
