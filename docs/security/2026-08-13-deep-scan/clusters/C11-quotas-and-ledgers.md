# Cluster C11-quotas-and-ledgers

---

## F20 [MEDIUM] `resource-exhaustion`
**Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.**
finding id: `csf_6254accba7a7afce29bcae57`

### Locations
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950`  
- `Sources/SwanSpaces/SwanSpaces.swift:1605-1661`  
- `Sources/SwanSQLite/SwanSQLite.swift:3531-3571`  
- `Sources/SwanSQLite/SwanSQLite.swift:3410-3475`  
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:850-860`  
- `Sources/SwanSQLite/SwanSQLite.swift:3418-3432`  
- `Sources/SwanSpaces/SwanSpaces.swift:1605-1660`  
- `Sources/SwanSQLite/SwanSQLite.swift:3531-3572`  
- `Sources/SwanSQLite/SwanSQLite.swift:3648-3660`  
- `Sources/SwanSQLite/SwanSQLite.swift:3682-3710`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:3531-3571`
- outcome: Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Only an authenticated author with the applicable OAuth write grant can reach the sink, and per-request/body plus blob admissions exist. No cumulative live permissioned-record quota was found; deployment/account storage quotas remain unknown. Additional context: writes require self-authorized account OAuth, canonical DAG-CBOR and CID validation, exact space and author binding, revision CAS, and bounded batches. Replacements keep live record cardinality stable, but unique creates grow current records and can cross the export boundary; external filesystem quotas remain unknown.

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Only an authenticated author with the applicable OAuth write grant can reach the sink, and per-request/body plus blob admissions exist. No cumulative live permissioned-record quota was found; deployment/account storage quotas remain unknown. Additional context: writes require self-authorized account OAuth, canonical DAG-CBOR and CID validation, exact space and author binding, revision CAS, and bounded batches. Replacements keep live record cardinality stable, but unique creates grow current records and can cross the export boundary; external filesystem quotas remain unknown.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. An OAuth-authorized repository author can create unbounded distinct collection/rkey records in successive requests. Each request is limited to roughly 1 MiB and the oplog is pruned, but current permissioned_space_records values persist without an aggregate live-record count or byte ceiling, allowing disk exhaustion through valid writes. Additional ordered discovery: a repository author with valid account OAuth can repeatedly create unique permissioned collection and rkey paths. SpaceWriteLimits caps one batch at 4,096 operations and 1 MiB of values, but the transaction checks neither cumulative live-record count nor total stored value bytes before inserting current records. Full-CAR production separately refuses repositories above 100,000 records or its metadata and body budgets, so writes accepted by the mutation path can make required full recovery unavailable before eventual disk exhaustion. Each unique mutation also leaves a request-receipt row, compounding storage; that independently retained receipt table remains represented by its separate canonical candidate.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950; root_control Sources/SwanSpaces/SwanSpaces.swift:1605-1661; sink Sources/SwanSQLite/SwanSQLite.swift:3531-3571 An OAuth-authorized repository author can create unbounded distinct collection/rkey records in successive requests. Each request is limited to roughly 1 MiB and the oplog is pruned, but current permissioned_space_records values persist without an aggregate live-record count or byte ceiling, allowing disk exhaustion through valid writes. Additional ordered discovery: a repository author with valid account OAuth can repeatedly create unique permissioned collection and rkey paths. SpaceWriteLimits caps one batch at 4,096 operations and 1 MiB of values, but the transaction checks neither cumulative live-record count nor total stored value bytes before inserting current records. Full-CAR production separately refuses repositories above 100,000 records or its metadata and body budgets, so writes accepted by the mutation path can make required full recovery unavailable before eventual disk exhaustion. Each unique mutation also leaves a request-receipt row, compounding storage; that independently retained receipt table remains represented by its separate canonical candidate."
}
```

---

## F21 [MEDIUM] `resource-exhaustion`
**Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.**
finding id: `csf_74868870b916061658de0714`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189`  
- `Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32`  
- `Sources/SwanSQLite/PublicRepositoryStore.swift:551-571`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:23-23`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188`  
- `Sources/SwanSQLite/PublicRepositoryStore.swift:551-689`  
- `Sources/SwanSQLite/PublicFirehoseOutboxStore.swift:234-266`  
- `Sources/SwanSQLite/SwanSQLite.swift:2479-2495`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-188`  
- `Sources/SwanSQLite/SwanSQLite.swift:434-437`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189`
- sink: `Sources/SwanSQLite/PublicRepositoryStore.swift:551-571`
- outcome: Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: JSON and commit sizes are bounded per request and the path requires an authenticated account principal; account deletion removes the database. No per-account repository-byte quota or block garbage collector was found, while deployment filesystem quotas remain unknown. The added source requires a hosted account with valid account OAuth and public mutations enabled; impact can cross accounts that share a filesystem. A complete fix must cover both unreachable repository blocks and completed firehose history material. Additional context: Requires a valid writable hosted account and public mutations enabled. Record, write-count and CAR limits bound each request; blob quota governs different table

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
JSON and commit sizes are bounded per request and the path requires an authenticated account principal; account deletion removes the database. No per-account repository-byte quota or block garbage collector was found, while deployment filesystem quotas remain unknown. The added source requires a hosted account with valid account OAuth and public mutations enabled; impact can cross accounts that share a filesystem. A complete fix must cover both unreachable repository blocks and completed firehose history material. Additional context: Requires a valid writable hosted account and public mutations enabled. Record, write-count and CAR limits bound each request; blob quota governs different tables; whole-account deletion is the only observed coarse reclamation. Additional context: Requires a valid writable account and firehose-enabled composition. Source-key uniqueness blocks exact duplicates, and global retention bounds the separate global log, but neither bounds distinct completed account-local anchors. Additional context: An authenticated account can issue an unlimited sequence of unique commits and grow its account database independently of global firehose retention. Additional cont

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Repeated authorized create/apply operations can generate unique record, MST, and commit blocks. Every new content-addressed block is inserted into public_repository_blocks, while the reviewed runtime sources contain no pruning of blocks made unreachable as heads advance. An account principal can therefore grow its SQLite database across individually valid bounded mutations until shared storage is exhausted. Added ordered discovery traces the same repeated near-limit authorized mutation stream through fresh immutable repository blocks, committed mutation projection, and enqueued CAR/payload material. Completion explicitly retains public-event outbox payloads and CARs indefinitely as idempotence anchors; updates and deletes alter only the current record index. Per-request limits, CAS, blob quotas, and account deletion do not bound cumulative non-blob history. Additional ordered discovery: Each authorized create, update or applyWrites operation is individually bounded, but every newly prepared record, MST and commit block is inserted by CID into public_repository_blocks. That table has no generation, reachability or expiry metadata and the reviewed implementation has no deletion path for blocks made unreachable by later updates or deletes. Replacing one record repeatedly with unique near-limit values keeps the live projection small while permanently growing the account database. Additional ordered discovery: Successful repository publication constructs payload and diff/commit CAR bytes and inserts them into public_event_outbox. Sequencing completion only sets completed=1 and deliberately retains the public material for exact replay. Global firehose age, row and byte pruning does not compact this account-local table. A writable account can issue unbounded distinct commits a

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189; root_control Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32; sink Sources/SwanSQLite/PublicRepositoryStore.swift:551-571 Repeated authorized create/apply operations can generate unique record, MST, and commit blocks. Every new content-addressed block is inserted into public_repository_blocks, while the reviewed runtime sources contain no pruning of blocks made unreachable as heads advance. An account principal can therefore grow its SQLite database across individually valid bounded mutations until shared storage is exhausted. Added ordered discovery traces the same repeated near-limit authorized mutation stream through fresh immutable repository blocks, committed mutation projection, and enqueued CAR/payload material. Completion explicitly retains public-event outbox payloads and CARs indefinitely as idempotence anchors; updates and deletes alter only the current record index. Per-request limits, CAS, blob quotas, and account deletion do not bound cumulative non-blob history. Additional ordered discovery: Each authorized create, update or applyWrites operation is individually bounded, but every newly prepared record, MST and commit block is inserted by CID into public_repository_blocks. That table has no generation, reachability or expiry metadata and the reviewed implementation has no deletion path for blocks made unreachable by later updates or deletes. Replacing one record repeatedly with unique near-limit values keeps the live projection small while permanently growing the account database. Additional ordered discovery: Successful repository publication constructs payload a
```

---

## F23 [MEDIUM] `resource-exhaustion`
**Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.**
finding id: `csf_8ede63211c6d944c55b570f8`

### Locations
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171`  
- `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:893-932`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:139-139`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-80`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-170`  
- `Sources/SwanHTTP/SwanHTTP.swift:696-700`  
- `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:109-110`  
- `Sources/SwanStorage/PublicRepositoryReadDirectory.swift:876-880`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80`
- sink: `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171`
- outcome: Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Exploitation requires a valid space credential or matching account OAuth principal and slow or stalled response consumption. Existing admission bounds memory and concurrent damage but makes over-reservation an efficient availability primitive. Additional context: Public blob reads demonstrate the available size-aware control by reserving the metadata-reported length. Exploitation requires valid OAuth or space authorization, readable blob targets, and clients able to retain response streams; the finite budgets bound total use but make starvation attainable with very few requests.

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Exploitation requires a valid space credential or matching account OAuth principal and slow or stalled response consumption. Existing admission bounds memory and concurrent damage but makes over-reservation an efficient availability primitive. Additional context: Public blob reads demonstrate the available size-aware control by reserving the metadata-reported length. Exploitation requires valid OAuth or space authorization, readable blob targets, and clients able to retain response streams; the finite budgets bound total use but make starvation attainable with very few requests.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. AuthenticatedGetSpaceBlobHandler reserves maximumPermissionedBlobTransferBytes before querying the directory or learning blob.body.contentLength and holds the lease until streaming terminates. The default admission permits 1 GiB globally and 512 MiB per account, making two requests against one author or four across authors sufficient to consume byte admission even for tiny blobs. The public blob route instead obtains metadata and reserves the true size to avoid the same starvation condition. Additional ordered discovery: Production wires this handler to `directory.publicRepositorySpoolAdmission`, whose defaults are 1 GiB globally and 512 MiB per account. The fixed reservation is retained for the response lifetime and adjusted only after the actual content length is known. Two stalled tiny-blob reads can consume one author's allowance, while reads spanning four authors can reserve the global pool and deny unrelated public CAR and blob streams despite transferring little data. The added trace also establishes that a member reading across multiple writer repositories can span per-account allowances and consume the global pool shared not only with public CAR and blob reads but also uploads.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80; root_control Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82; sink Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171 AuthenticatedGetSpaceBlobHandler reserves maximumPermissionedBlobTransferBytes before querying the directory or learning blob.body.contentLength and holds the lease until streaming terminates. The default admission permits 1 GiB globally and 512 MiB per account, making two requests against one author or four across authors sufficient to consume byte admission even for tiny blobs. The public blob route instead obtains metadata and reserves the true size to avoid the same starvation condition. Additional ordered discovery: Production wires this handler to `directory.publicRepositorySpoolAdmission`, whose defaults are 1 GiB globally and 512 MiB per account. The fixed reservation is retained for the response lifetime and adjusted only after the actual content length is known. Two stalled tiny-blob reads can consume one author's allowance, while reads spanning four authors can reserve the global pool and deny unrelated public CAR and blob streams despite transferring little data. The added trace also establishes that a member reading across multiple writer repositories can span per-account allowances and consume the global pool shared not only with public CAR and blob reads but also uploads."
}
```

---

## F24 [MEDIUM] `resource-exhaustion`
**Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.**
finding id: `csf_a83ada583257aa112b79f48e`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:229-251`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:263-320`  
- `Sources/SwanSQLite/PublicRepositoryStore.swift:308-419`  
- `Sources/SwanSQLite/SwanSQLite.swift:448-472`  
- `docs/superpowers/specs/2026-08-12-swan-read-after-write-design.md:223-227`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift:171-209`  
- `Sources/SwanSQLite/PublicRepositoryStore.swift:699-734`  
- `Sources/SwanSQLite/PublicRepositoryStore.swift:308-413`  
- `Sources/SwanSQLite/SwanSQLite.swift:448-472`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:448-472`
- outcome: Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires valid account OAuth and successful mutations. Request/body concurrency limits bound instantaneous work, not cumulative durable rows. Additional context: Requires public writes and valid account OAuth. Per-request body limits, UUID uniqueness and integrity checks prevent corruption but do not bound cumulative ledger rows. The added source requires an active hosted account and valid OAuth/DPoP write authority. Per-request body and operation limits, account database separation, and blob quotas bound individual work but not cumulative request-ledger bytes on the shared host volume; deployment filesystem or account quotas remain a validation question.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Requires valid account OAuth and successful mutations. Request/body concurrency limits bound instantaneous work, not cumulative durable rows. Additional context: Requires public writes and valid account OAuth. Per-request body limits, UUID uniqueness and integrity checks prevent corruption but do not bound cumulative ledger rows. The added source requires an active hosted account and valid OAuth/DPoP write authority. Per-request body and operation limits, account database separation, and blob quotas bound individual work but not cumulative request-ledger bytes on the shared host volume; deployment filesystem or account quotas remain a validation question.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Every apply/create/put/delete HTTP operation supplies a fresh server-generated UUID. Reservation inserts a new public_repository_mutation_requests row, while the schema has no timestamp, expiry, quota, or retention field and repository-wide source contains no deletion from this table. The design document explicitly states that the table grows unbounded. A malicious hosted account can sustain successful mutations until SQLite/disk growth degrades the service. Additional ordered discovery: The coordinator reserves a revision before preparing and applying a mutation. Each reservation inserts a fresh public_repository_mutation_requests row keyed by an HTTP-generated UUID. A request with an intentionally wrong expected record CID reaches reservation and then fails state validation; the catch path only updates the row to abandoned. Neither abandoned nor committed rows have a cardinality ceiling, expiry or deletion path, so repeated authenticated failures grow durable state without publishing records. Added ordered discovery establishes that authenticated create, put, and applyWrites requests accept JSON bodies up to 1,000,000 bytes, generate a fresh UUID request ID, and retain committed_projection bytes in the permanent public_repository_mutation_requests row. No row or byte quota or deletion path exists, the design documentation explicitly states that nothing prunes the table, and the supplied RSS fixture demonstrates accumulation by committing 300 unique 900,000-byte records.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188; root_control Sources/SwanSQLite/PublicRepositoryStore.swift:308-419; sink Sources/SwanSQLite/SwanSQLite.swift:448-472 Every apply/create/put/delete HTTP operation supplies a fresh server-generated UUID. Reservation inserts a new public_repository_mutation_requests row, while the schema has no timestamp, expiry, quota, or retention field and repository-wide source contains no deletion from this table. The design document explicitly states that the table grows unbounded. A malicious hosted account can sustain successful mutations until SQLite/disk growth degrades the service. Additional ordered discovery: The coordinator reserves a revision before preparing and applying a mutation. Each reservation inserts a fresh public_repository_mutation_requests row keyed by an HTTP-generated UUID. A request with an intentionally wrong expected record CID reaches reservation and then fails state validation; the catch path only updates the row to abandoned. Neither abandoned nor committed rows have a cardinality ceiling, expiry or deletion path, so repeated authenticated failures grow durable state without publishing records. Added ordered discovery establishes that authenticated create, put, and applyWrites requests accept JSON bodies up to 1,000,000 bytes, generate a fresh UUID request ID, and retain committed_projection bytes in the permanent public_repository_mutation_requests row. No row or byte quota or deletion path exists, the design documentation explicitly states that nothing prunes the table, and the supplied RSS fixture demonstrates accumulation by committing 300 unique 900,000-byte records."
}
```

---

## F26 [MEDIUM] `resource-exhaustion`
**Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.**
finding id: `csf_57a6f887f996653082e14b76`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:408-429`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363`  
- `Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733`  
- `Sources/SwanHTTP/SwanJSONWriteBody.swift:230-255`  
- `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift:329-374`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605`
- sink: `Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733`
- outcome: Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Public mutation routes must be enabled. The loopback management listener has a separate pool and is not affected.

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Public mutation routes must be enabled. The loopback management listener has a separate pool and is not affected.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Public JSON mutation routes reserve one of eight processShared leases and collect up to 1 MiB before authorizedTarget runs. uploadBlob authorizes first but deliberately drains a rejected body using the same pool. Each slow or incomplete anonymous body retains a lease until EOF or the 30-second absolute deadline. The pool is shared with authenticated public, permissioned, account-email, and preferences commands, so eight repeatedly renewed unauthenticated requests can make those routes fail unavailable. Deadlines, byte accounting, and the listener cap bound impact but do not isolate authenticated capacity.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605; root_control Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363; sink Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733 Public JSON mutation routes reserve one of eight processShared leases and collect up to 1 MiB before authorizedTarget runs. uploadBlob authorizes first but deliberately drains a rejected body using the same pool. Each slow or incomplete anonymous body retains a lease until EOF or the 30-second absolute deadline. The pool is shared with authenticated public, permissioned, account-email, and preferences commands, so eight repeatedly renewed unauthenticated requests can make those routes fail unavailable. Deadlines, byte accounting, and the listener cap bound impact but do not isolate authenticated capacity."
}
```

---

## F27 [MEDIUM] `secret-exposure`
**Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.**
finding id: `csf_9d883e24117ebfdb4499ab99`

### Locations
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860`  
- `Sources/SwanSQLite/SwanSQLite.swift:3474-3483`  
- `Sources/SwanSQLite/SwanSQLite.swift:3648-3659`  
- `Sources/SwanHTTP/SwanSpaceXRPC.swift:713-720`  
- `Sources/SwanSQLite/SwanSQLite.swift:991-998`  
- `Sources/SwanSQLite/SwanSQLite.swift:3682-3709`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:3648-3659`
- outcome: Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: the attacker must satisfy the route-specific authentication or configuration prerequisites

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
No material counterevidence beyond the stated preconditions and partial controls.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Authenticated permissioned create/put/delete/applyWrites are individually body/operation bounded and require write authorization and self-author identity. The durable apply transaction rejects duplicate request IDs using `permissioned_space_requests`, then inserts one permanent row for every successful unique request. The same transaction explicitly prunes `permissioned_space_oplog` by retention depth, but no analogous expiry, compaction, or cumulative quota is applied to the request ledger. An authorized writer can therefore submit sustained valid small writes with unique request IDs and grow this table without bound, consuming shared SQLite storage over time. Expected control is a bounded idempotency window or quota preserving required replay semantics; actual control is an indefinitely growing global primary-key ledger. Protected asset is PDS disk/database availability. Prerequisites are valid permissioned write credentials, current membership/write authority, and sustained requests. Strong counterevidence/proof gap: each receipt is small, account/space quotas or edge rate limits may exist outside this persistence path, and no load test quantified practical exhaustion. Authorization, operation bounds, revision CAS, and oplog retention remain effective; no credential confusion or permissioned disclosure was demonstrated.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

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
 "summary": "Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860; root_control Sources/SwanSQLite/SwanSQLite.swift:3474-3483; sink Sources/SwanSQLite/SwanSQLite.swift:3648-3659 Authenticated permissioned create/put/delete/applyWrites are individually body/operation bounded and require write authorization and self-author identity. The durable apply transaction rejects duplicate request IDs using `permissioned_space_requests`, then inserts one permanent row for every successful unique request. The same transaction explicitly prunes `permissioned_space_oplog` by retention depth, but no analogous expiry, compaction, or cumulative quota is applied to the request ledger. An authorized writer can therefore submit sustained valid small writes with unique request IDs and grow this table without bound, consuming shared SQLite storage over time. Expected control is a bounded idempotency window or quota preserving required replay semantics; actual control is an indefinitely growing global primary-key ledger. Protected asset is PDS disk/database availability. Prerequisites are valid permissioned write credentials, current membership/write authority, and sustained requests. Strong counterevidence/proof gap: each receipt is small, account/space quotas or edge rate limits may exist outside this persistence path, and no load test quantified practical exhaustion. Authorization, operation bounds, revision CAS, and oplog retention remain effective; no credential confusion or permissioned disclosure was demonstrated."
}
```

---

## F28 [MEDIUM] `resource-exhaustion`
**Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.**
finding id: `csf_143a6dc33a5b0d8cd39f1084`

### Locations
- `Sources/swan/SwanCommand.swift:5664-5711`  
- `Sources/SwanInterop/PublicRepositoryCARReplication.swift:374-450`  
- `Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453`  
- `Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543`  
- `Sources/SwanSQLite/PublicRepositoryImportStaging.swift:235-248`  
- `Sources/SwanPublicRepository/PublicRepositoryLimits.swift:17-24`  

### Attack path
- source: `Sources/swan/SwanCommand.swift:5664-5711`
- sink: `Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543`
- outcome: Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker must control a repository and valid signing key and induce an operator/replication import. Signature, CID, MST topology, record-size, CAR-byte, node-count, cancellation, and staging checks are strong countercontrols, and unverified state is not published; they do not bound aggregate decoded leaf count or sorting memory/CPU.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Attacker must control a repository and valid signing key and induce an operator/replication import. Signature, CID, MST topology, record-size, CAR-byte, node-count, cancellation, and staging checks are strong countercontrols, and unverified state is not published; they do not bound aggregate decoded leaf count or sorting memory/CPU.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The operator import command fetches an attacker-hosted com.atproto.sync.getRepo CAR and invokes validateProjection before publication. The validator caps MST nodes and entries per individual node, but appends every reconstructed leaf to an aggregate array and every record CID to a set without a repository-wide record/leaf cap; it then builds another CID-to-collection dictionary and sorts the entire leaf array. Standard policy permits a 512 MiB CAR, 500,000 MST nodes, and 4,096 entries per node, so a validly signed, structurally valid compact MST can expand into millions of Swift objects and attacker-controlled O(n log n) work before rejection or publication.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:5664-5711; root_control Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453; sink Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543 The operator import command fetches an attacker-hosted com.atproto.sync.getRepo CAR and invokes validateProjection before publication. The validator caps MST nodes and entries per individual node, but appends every reconstructed leaf to an aggregate array and every record CID to a set without a repository-wide record/leaf cap; it then builds another CID-to-collection dictionary and sorts the entire leaf array. Standard policy permits a 512 MiB CAR, 500,000 MST nodes, and 4,096 entries per node, so a validly signed, structurally valid compact MST can expand into millions of Swift objects and attacker-controlled O(n log n) work before rejection or publication."
}
```

---

## F29 [MEDIUM] `resource-exhaustion`
**Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.**
finding id: `csf_c2216232ce490cedb6931b5d`

### Locations
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129`  
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549`  
- `Sources/SwanSQLite/SwanSQLite.swift:4603-4613`  
- `Sources/SwanSpaces/SwanSpaces.swift:617-629`  
- `Sources/SwanSpaces/SwanSpaces.swift:645-705`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129`
- sink: `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549`
- outcome: Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: the attacker must satisfy the route-specific authentication or configuration prerequisites

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
No material counterevidence beyond the stated preconditions and partial controls.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Each full permissioned repository export reserves the worst-case working-spool allowance, about 384 MiB, before actual repository size is known and holds it through response streaming. A valid aggregate read credential for a multi-writer space can keep slow tiny exports open across authors and consume the default 1 GiB global budget, preventing further permissioned recovery/export operations. Authorization is exact and physical work is bounded, but worst-case logical reservation makes global starvation cheap relative to repository size.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

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
 "summary": "Tiny permissioned repository exports can monopolize the permissioned CAR spool budget. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; sink Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549 Each full permissioned repository export reserves the worst-case working-spool allowance, about 384 MiB, before actual repository size is known and holds it through response streaming. A valid aggregate read credential for a multi-writer space can keep slow tiny exports open across authors and consume the default 1 GiB global budget, preventing further permissioned recovery/export operations. Authorization is exact and physical work is bounded, but worst-case logical reservation makes global starvation cheap relative to repository size."
}
```
