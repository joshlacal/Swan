# Security Review: Swan

## Scope

Whole Swan repository at revision fc11540f4d3e9d62ace564dc4b01880aa1f47c6f, including 582 inventoried files across application source, tests, scripts, profiles, SwiftPM, Docker, Compose and interop material.

- Scan mode: deep_repository
- Target kind: git_worktree
- Target ID: target_sha256_6c9e671d113dcda773fd9a6c8e97b5b527923dc68aa3f89705c93103e6fa6f80
- Revision: fc11540f4d3e9d62ace564dc4b01880aa1f47c6f
- Snapshot digest: codex-security-snapshot/v1:sha256:8ea6cda30cac44c46b235fb1aba87ab9a5e3f5f522ca844f2060ab802eb9c899
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Runtime or test status: Read-only static validation with checked-in test and deployment evidence; no live adversarial probing and no repository implementation edits.
- Artifacts reviewed: Sources/\*\*, Tests/\*\*, Scripts/\*\*, Package.swift, Package.resolved, Dockerfile, Dockerfile.dockerignore, docker-compose\*.yml, interop/\*\*, Profiles/\*\*, configuration and deployment documentation

Limitations and exclusions:
- No disposable full-stack adversarial runtime was brought up during this scan.
- No active probes were sent to swan.place.
- Dependency advisory freshness and external PLC/AT Protocol behavior were not independently verified over the network.
- Three protocol/retention semantics remain deferred, so coverage is partial.
- Excluded https://swan.place adversarial runtime testing: The user supplied the live non-federated deployment as context but authorized offensive testing only on local/disposable systems; no active adversarial requests were sent to the public service.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable DSS findings | 46 |
| Report instances | 46 |
| Report severity mix | high: 3, medium: 28, low: 15 |
| Report confidence mix | high: 43, medium: 3 |
| Coverage | partial |
| Validation mode | Deep repeated discovery followed by centralized static source/control/sink validation and attack-path calibration. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Swan is an Internet-facing AT Protocol PDS with shared process and identity infrastructure but distinct public and permissioned data planes. Threat actors include unauthenticated clients, malicious authenticated accounts and space members, hostile/compromised PDS peers and identity authorities, stolen-capability holders, and malicious configuration/build infrastructure.

### Assets

- Permissioned records, blobs and metadata
- Account, OAuth, DPoP, service, delegation and space credentials
- Public and permissioned repository integrity
- PLC/DID key continuity and service routing
- SQLite durability and lifecycle authorization state
- Listener, memory, disk, spool, resolver and notification availability
- Production/laboratory and build/runtime secret separation

### Trust Boundaries

- Internet HTTP/XRPC to route handlers
- Authentication to per-object and per-operation authorization
- Public versus permissioned repository/blob/sync namespaces
- Lifecycle checks versus asynchronous signing, streaming and durable commits
- Local PDS versus remote PDS, PLC/DID, OAuth metadata, AppView and relay responses
- Parser/staging versus durable publication
- Production serve versus laboratory overlays and credentials
- Checkout versus Docker builder/cache and runtime

### Attacker Capabilities

- Send malformed, slow, replayed and concurrent Internet requests
- Operate an authenticated account or malicious space member/writer/authority
- Control a hostile or compromised remote PDS or identity/metadata response
- Steal a bearer credential or retain a formerly valid signing key
- Supply malicious operator configuration or use shared/remote build infrastructure

### Security Objectives

- Never make permissioned values anonymously public
- Keep credential classes and scopes non-interchangeable
- Keep read capabilities unable to mutate durable state
- Verify exact repository state before publication
- Fail closed on remote identity and endpoint resolution
- Linearize authorization with security-sensitive durable effects
- Bound attacker-controlled resource work and durable growth
- Keep lab relaxations structurally out of production

### Assumptions

- A hosting PDS can observe hosted permissioned plaintext and is trusted for confidentiality
- External PLC/DID and upstream protocol semantics remain residual trust dependencies
- No active adversarial testing of the live swan.place deployment was performed
- Static source traces and checked-in tests support findings, but operational exploitability depends on enabled configuration and infrastructure

## Findings

| Findings | Reports | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- | --- |
| A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM. | [permissioned-recovery-deniable-binding-forgery](#finding-1) | high | high | permissioned-recovery-deniable-binding-forgery: inline below |
| Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace. | [permissioned-blob-public-edge-window](#finding-2) | high | high | permissioned-blob-public-edge-window: inline below |
| Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential. | [member-removal-outstanding-space-credential](#finding-3) | high | high | member-removal-outstanding-space-credential: inline below |
| Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes. | [shared-write-admission](#finding-4) | medium | high | shared-write-admission: inline below |
| Tiny permissioned repository exports can monopolize the permissioned CAR spool budget. | [occ_10d528fc1033b1e295db2f2d](#finding-5) | medium | high | occ_10d528fc1033b1e295db2f2d: inline below |
| The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted. | [occ_12aea77fa129415e1ea69972](#finding-6) | medium | high | occ_12aea77fa129415e1ea69972: inline below |
| A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority | [occ_1357b7af217722c070a1c905](#finding-7) | medium | high | occ_1357b7af217722c070a1c905: inline below |
| The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary. | [interop-runtime-operator-secret-boundary](#finding-8) | medium | high | interop-runtime-operator-secret-boundary: inline below |
| Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned. | [permissioned-request-ledger-retention](#finding-9) | medium | high | permissioned-request-ledger-retention: inline below |
| Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity | [occ_4f1f34a4b2df229fac4967e0](#finding-10) | medium | high | occ_4f1f34a4b2df229fac4967e0: inline below |
| Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins. | [oauth-par-remote-fetch-starvation](#finding-11) | medium | high | oauth-par-remote-fetch-starvation: inline below |
| Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection. | [public-repository-retained-block-growth](#finding-12) | medium | high | public-repository-retained-block-growth: inline below |
| Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority. | [proxy-service-issuer-lifecycle-race](#finding-13) | medium | high | proxy-service-issuer-lifecycle-race: inline below |
| OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query. | [occ_70d393a9c951067011057863](#finding-14) | medium | high | occ_70d393a9c951067011057863: inline below |
| A read-only space credential can mutate, replace, and exhaust durable notification registrations. | [register-notify](#finding-15) | medium | high | register-notify: inline below |
| Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits. | [aggregate-mst-leaf-count](#finding-16) | medium | high | aggregate-mst-leaf-count: inline below |
| Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check. | [record-object-depth-not-counted-before-encoding](#finding-17) | medium | high | record-object-depth-not-counted-before-encoding: inline below |
| Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations. | [public-mutation-request-ledger](#finding-18) | medium | high | public-mutation-request-ledger: inline below |
| Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer. | [occ_852d29f30d160df1745a65f6](#finding-19) | medium | high | occ_852d29f30d160df1745a65f6: inline below |
| Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp. | [service-jwt-missing-iat-lifetime](#finding-20) | medium | high | service-jwt-missing-iat-lifetime: inline below |
| A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it | [post-deactivation-public-commit](#finding-21) | medium | high | post-deactivation-public-commit: inline below |
| Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification. | [occ_b90491c6ca4d4cfd1affffc3](#finding-22) | medium | medium | occ_b90491c6ca4d4cfd1affffc3: inline below |
| The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry. | [occ_d27478b01e502a45992483a1](#finding-23) | medium | high | occ_d27478b01e502a45992483a1: inline below |
| Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames. | [anonymous-firehose-inbound-frame-amplification](#finding-24) | medium | high | anonymous-firehose-inbound-frame-amplification: inline below |
| Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work. | [unauthenticated-websocket-subscriber-exhaustion](#finding-25) | medium | high | unauthenticated-websocket-subscriber-exhaustion: inline below |
| Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding | [failed-client-metadata-freshness-poisoning](#finding-26) | medium | high | failed-client-metadata-freshness-poisoning: inline below |
| Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority. | [authority-lifecycle-signing-race](#finding-27) | medium | high | authority-lifecycle-signing-race: inline below |
| Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget. | [occ_e85896d60562192099fa8c1e](#finding-28) | medium | high | occ_e85896d60562192099fa8c1e: inline below |
| The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public. | [oauth-ipv6-special-purpose-policy](#finding-29) | medium | high | oauth-ipv6-special-purpose-policy: inline below |
| Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint. | [occ_ed3b299096c6797831e5a0ae](#finding-30) | medium | high | occ_ed3b299096c6797831e5a0ae: inline below |
| Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage. | [permissioned-live-record-growth](#finding-31) | medium | high | permissioned-live-record-growth: inline below |
| Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup. | [deactivation-delegation-signing-race](#finding-32) | low | high | deactivation-delegation-signing-race: inline below |
| Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation. | [stale-lifecycle-sync-after-deactivation](#finding-33) | low | high | stale-lifecycle-sync-after-deactivation: inline below |
| Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache. | [docker-context-live-artifact-disclosure](#finding-34) | low | medium | docker-context-live-artifact-disclosure: inline below |
| The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin. | [proxied-location](#finding-35) | low | high | proxied-location: inline below |
| Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout. | [occ_476b6552925cea7304c4a309](#finding-36) | low | high | occ_476b6552925cea7304c4a309: inline below |
| Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity. | [proxy-dns-timeout-gap](#finding-37) | low | high | proxy-dns-timeout-gap: inline below |
| Notification delivery can mint a service JWT after concurrent issuer deactivation. | [notification-service-token-signing](#finding-38) | low | high | notification-service-token-signing: inline below |
| PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires. | [plc-space-credential-stale-key-window](#finding-39) | low | high | plc-space-credential-stale-key-window: inline below |
| Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery. | [occ_706ec604088934548b0ffdd2](#finding-40) | low | high | occ_706ec604088934548b0ffdd2: inline below |
| An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation. | [permissioned-repository-commit-signing](#finding-41) | low | high | permissioned-repository-commit-signing: inline below |
| Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write. | [permissioned-apply-rites-create-ecord-delete-ecord-put-ecord-deactivation-race](#finding-42) | low | high | permissioned-apply-rites-create-ecord-delete-ecord-put-ecord-deactivation-race: inline below |
| A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP. | [oauth-metadata-private-ip-exception](#finding-43) | low | medium | oauth-metadata-private-ip-exception: inline below |
| Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate. | [firehose-lifecycle-log-amplification](#finding-44) | low | high | firehose-lifecycle-log-amplification: inline below |
| Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses | [occ_d50428f46b3ba5e65b2bb1b5](#finding-45) | low | high | occ_d50428f46b3ba5e65b2bb1b5: inline below |
| A streaming public blob upload can commit after the account is deactivated. | [public-blob-deactivation-race](#finding-46) | low | high | public-blob-deactivation-race: inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297; root_control Sources/SwanSpaces/SwanSpaces.swift:518-527; sink Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821; no reviewed control closes the stated path. |
| Category | cryptographic-integrity |
| CWE | CWE-345, CWE-347 |
| Affected lines | Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297, Sources/SwanInterop/PermissionedRemoteReplicaHTTPProvider.swift:211-251, Sources/SwanSpaces/SwanSpaces.swift:518-527, Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821, Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:838-900, Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:335-360, Sources/SwanSpaces/SwanSpaces.swift:530-581, Tests/SwanSpacesTests/SwanSpacesTests.swift:181-231, Sources/SwanSpaces/SwanSpaces.swift:530-570, Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:347-360 |

#### Summary

A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. SpaceCommitCodec signs encodedContext(space, author, rev, ikm), excluding commitment. The content binding is HMAC(commitment) under a key derived entirely from the envelope's disclosed ikm, and verification accepts the unchanged context signature plus this recomputable MAC. A source that observed a legitimate envelope for the same space/author/revision can construct arbitrary canonical records and DRISL/LtHash commitment, recompute the MAC, and pass streaming signature, MAC, CID, index and LtHash checks; SQLite then marks and can publish the result. The separately fetched freshness witness uses the same signature/MAC construction and compares only revision+commitment, so a malicious source can return a consistent forged pair. Strongest counterevidence: this explicitly implements proposal-0016's deniable-MAC design; TLS/source configuration, CAR canonicality, limits, CAS, high-water and publication authorization are fail-closed; a passive attacker without a valid envelope and source control cannot exploit it. Additional ordered discovery: The context signature covers space, author, revision, and the 32-byte IKM but excludes the repository commitment. The content-binding key is deterministically derived from that IKM, which is transmitted in the envelope, so an observer of a valid signed context can calculate a valid MAC for any replacement commitment. Streaming and in-memory recovery accept the unchanged context signature plus this recomputed MAC and install records whose LtHash matches the attacker-selected commitment. Comments correctly describe the MAC as deniable and peer-pinned HTTPS may supply transport integrity, but the recovery boundary calls these checks authentication of the exact commit root; a malicious hosting peer or response substituter with one valid env

#### Validation

A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM. Static trace locations: entrypoint Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297; root_control Sources/SwanSpaces/SwanSpaces.swift:518-527; sink Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821 SpaceCommitCodec signs encodedContext(space, author, rev, ikm), excluding commitment. The content binding is HMAC(commitment) under a key derived entirely from the envelope's disclosed ikm, and verification accepts the unchanged context signature plus this recomputable MAC. A source that observed a legitimate envelope for the same space/author/revision can construct arbitrary canonical records and DRISL/LtHash commitment, recompute the MAC, and pass streaming signature, MAC, CID, index and LtHash checks; SQLite then marks and can publish the result. The separately fetched freshness witness uses the same signature/MAC construction and compares only revision+commitment, so a malicious source can return a consistent forged pair. Strongest counterevidence: this explicitly implements proposal-0016's deniable-MAC design; TLS/source configuration, CAR canonicality, limits, CAS, high-water and publication authorization are fail-closed; a passive attacker without a valid envelope and source control cannot exploit it. Additional ordered discovery: The context signature covers space, author, revision, and the 32-byte IKM but excludes the repository commitment. The content-binding key is deterministically derived from that IKM, which is transmitted in the envelope, so an observer of a valid signed context can calculate a valid MAC for any replacement commitment. Streaming and in-memory recovery accept the unchanged context signature plus this recomputed MAC and install records whose LtHash matches the attacker-selected commitment. Comments correctly describe the MAC as deniable and peer-pinned HTTPS may supply transport integrity, but the recovery boundary calls these checks authentication of the exact commit root; a malicious hosting peer or response subs

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297 reaches the incomplete control at Sources/SwanSpaces/SwanSpaces.swift:518-527 and then Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821. A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.

- **Source:** Sources/SwanSpaces/StreamingSpaceCARRecovery.swift:251-297

- **Sink:** Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:731-821

- **Outcome:** A captured valid permissioned commit-context signature can authenticate substituted repository contents because the signature excludes the commitment and its MAC is recomputable from public IKM.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Prerequisites are capture of a valid signed context for the exact tuple and control of the recovery/latest-commit source or authenticated transport boundary. The scan invariant requires cross-host writer identity and repository commits to be verified, but this verifies author context rather than writer-authenticated repository state. Additional context: Potential cross-host repository-authority failure. Later validation should determine whether the pinned protocol intentionally delegates all exact-content authenticity to the serving host and whether that trust is acceptable for the claimed author-verification invariant.

#### Severity

**High** — The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

Severity would fall if runtime evidence proved the public/permissioned edge, forged commit, or revoked credential cannot reach the recorded sink; it would rise only with broader cross-account automation or mass exploitation.

#### Remediation

Bind the exact commitment into the writer-authenticated signature (with domain separation) or explicitly treat the serving PDS as the sole integrity authority and stop describing the deniable MAC as writer authentication. Reject recovery envelopes whose signed binding does not cover the installed commitment.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-2"></a>

### [2] Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112; root_control Sources/SwanSQLite/SwanSQLite.swift:7446-7577; sink Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942; no reviewed control closes the stated path. |
| Category | permissioned-data-disclosure |
| CWE | CWE-200, CWE-668, CWE-284, CWE-862 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112, Sources/SwanSQLite/SwanSQLite.swift:7446-7577, Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942, Sources/SwanSQLite/SwanSQLite.swift:9889-9973, Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift:135-177, Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift:511-531, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:109-112, Sources/SwanSQLite/SwanSQLite.swift:9889-9973, Sources/SwanSQLite/SwanSQLite.swift:7234-7269, Sources/SwanSQLite/SwanSQLite.swift:7127-7179 |

#### Summary

Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The only authenticated production uploadBlob path stores every upload through namespace .public, and putBlobLocked immediately creates a durable public edge served by unauthenticated CID lookup and streaming without repository-record reachability. Only a later successful permissioned record transaction promotes referenced CIDs and removes the public edge when no verified public record references the bytes. A known or derivable CID is therefore fetchable between upload and apply; validation, authorization, CAS, connectivity, process failure, or abandonment can leave the edge indefinitely, and re-uploading identical content recreates the public edge after prior promotion. PermissionedBlobRepositoryReachabilityTests explicitly demonstrate that same-CID re-upload restores anonymous reachability until another permissioned update cleans it up. Successful apply atomically removes the edge, but those tests prove only eventual isolation after promotion, not confidentiality during staging. Raw SHA-256 CIDs are generally hard to guess, yet known, shared, leaked, low-entropy, or otherwise predictable content CIDs suffice and the never-public invariant is violated. Additional ordered discovery: The authenticated com.atproto.repo.uploadBlob handler stores every upload with BlobNamespace.public, which immediately inserts a public namespace edge. Anonymous sync.getBlob deliberately skips repository-generation admission and serves any CAS payload with that edge. The permissioned workflow itself uses uploadBlob and removes the public edge only inside a later successful permissioned-record transaction. A crash, network loss, validation/quota/CAS rejection, or deliberate omission leaves the blob public with no staged-edge expiry found. Additional ordered discovery: The only HTTP uploadBlob

#### Validation

Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112; root_control Sources/SwanSQLite/SwanSQLite.swift:7446-7577; sink Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942 The only authenticated production uploadBlob path stores every upload through namespace .public, and putBlobLocked immediately creates a durable public edge served by unauthenticated CID lookup and streaming without repository-record reachability. Only a later successful permissioned record transaction promotes referenced CIDs and removes the public edge when no verified public record references the bytes. A known or derivable CID is therefore fetchable between upload and apply; validation, authorization, CAS, connectivity, process failure, or abandonment can leave the edge indefinitely, and re-uploading identical content recreates the public edge after prior promotion. PermissionedBlobRepositoryReachabilityTests explicitly demonstrate that same-CID re-upload restores anonymous reachability until another permissioned update cleans it up. Successful apply atomically removes the edge, but those tests prove only eventual isolation after promotion, not confidentiality during staging. Raw SHA-256 CIDs are generally hard to guess, yet known, shared, leaked, low-entropy, or otherwise predictable content CIDs suffice and the never-public invariant is violated. Additional ordered discovery: The authenticated com.atproto.repo.uploadBlob handler stores every upload with BlobNamespace.public, which immediately inserts a public namespace edge. Anonymous sync.getBlob deliberately skips repository-generation admission and serves any CAS payload with that edge. The permissioned workflow itself uses uploadBlob and removes the public edge only inside a later successful permissioned-record transaction. A crash, network loss, validation/quota/CAS rejection, or deliberate omission leaves the blob public with no staged-edge expiry found. Additional ordered discovery: The only

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112 reaches the incomplete control at Sources/SwanSQLite/SwanSQLite.swift:7446-7577 and then Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942. Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:71-112

- **Sink:** Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:839-942

- **Outcome:** Permissioned blob uploads temporarily, after failed or abandoned applies indefinitely, and after same-CID re-upload again expose private-intended bytes through the anonymous public namespace.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Upload requires account authentication, and the blob is not formally permissioned until referenced. Anonymous reading requires the account DID and CID; CIDs are not enumerable here. Exploitation therefore requires CID knowledge or derivation plus timing before promotion, a failed or abandoned apply, or a later same-CID re-upload. CID opacity reduces discoverability but does not enforce namespace confidentiality. Additional context: An unauthenticated reader still needs the SHA-256 CID, which is difficult to guess for high-entropy content but predictable for known content or may be disclosed by the workflow. Successful promotion removes the edge transactionally unless a public record also ref

#### Severity

**High** — The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

Severity would fall if runtime evidence proved the public/permissioned edge, forged commit, or revoked credential cannot reach the recorded sink; it would rise only with broader cross-account automation or mass exploitation.

#### Remediation

Add a permissioned/staged upload namespace that is never served by anonymous `sync.getBlob`; promote it atomically to a space edge only within an authorized record commit, expire abandoned staging edges, and make same-CID re-upload preserve the private namespace.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-3"></a>

### [3] Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907; sink Sources/SwanSQLite/SwanSQLite.swift:10514-10520; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-613, CWE-863, CWE-284 |
| Affected lines | Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678, Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751, Sources/SwanOAuth/SwanOAuth.swift:343-375, Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907, Sources/SwanSpaces/SwanSpaces.swift:232-254, Sources/SwanSQLite/SwanSQLite.swift:10514-10520, Sources/SwanSQLite/SwanSQLite.swift:6403-6435, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:216-245, Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751, Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-908 |

#### Summary

Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. PermissionedDataJWT.spaceCredentialLifetime defaults to 2 hours, while SpaceCredentialClaims contains only iss/sub/iat/exp/jti and createSpaceCredential encodes no reader, client, membership revision, or revocation epoch. Issuance does authorize the exact user/client tuple, but verification later checks only signature, authority/space, time, and JTI. DurableSpaceCredentialVerifier then constructs a read grant whose subject is the authority issuer. SpaceAuthorizationPolicy accepts that grant for any read in the matching space without consulting membership. removeSimpleSpaceMember deletes the membership row and advances the space revision but does not revoke outstanding JTIs or advance a credential epoch. DurableSpaceRepository.record (representative sink; the same context is used by the broader permissioned read surface) authorizes via the space grant and reads the record without a current membership lookup. Consequently, a credential minted immediately before removal can continue reading permissioned records after removal. Added ordered discovery extends the same post-issuance revocation root from membership removal to managing-app or client-policy denial and traces the retained grant through permissioned blob, record, CAR, and operation-log reads. Issuance checks the current member and app-policy tuple once, but removal or denial records neither JTI revocation nor a credential-policy generation, while verification later checks only signature, space or authority binding, and time. A retained credential therefore continues authorizing the broader permissioned read surface until expiry.

#### Validation

Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907; sink Sources/SwanSQLite/SwanSQLite.swift:10514-10520 PermissionedDataJWT.spaceCredentialLifetime defaults to 2 hours, while SpaceCredentialClaims contains only iss/sub/iat/exp/jti and createSpaceCredential encodes no reader, client, membership revision, or revocation epoch. Issuance does authorize the exact user/client tuple, but verification later checks only signature, authority/space, time, and JTI. DurableSpaceCredentialVerifier then constructs a read grant whose subject is the authority issuer. SpaceAuthorizationPolicy accepts that grant for any read in the matching space without consulting membership. removeSimpleSpaceMember deletes the membership row and advances the space revision but does not revoke outstanding JTIs or advance a credential epoch. DurableSpaceRepository.record (representative sink; the same context is used by the broader permissioned read surface) authorizes via the space grant and reads the record without a current membership lookup. Consequently, a credential minted immediately before removal can continue reading permissioned records after removal. Added ordered discovery extends the same post-issuance revocation root from membership removal to managing-app or client-policy denial and traces the retained grant through permissioned blob, record, CAR, and operation-log reads. Issuance checks the current member and app-policy tuple once, but removal or denial records neither JTI revocation nor a credential-policy generation, while verification later checks only signature, space or authority binding, and time. A retained credential therefore continues authorizing the broader permissioned read surface until expiry.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678 reaches the incomplete control at Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-907 and then Sources/SwanSQLite/SwanSQLite.swift:10514-10520. Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.

- **Source:** Sources/SwanHTTP/SwanSpaceXRPC.swift:643-678

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:10514-10520

- **Outcome:** Removing a space member or denying its app policy does not invalidate that principal's previously issued whole-space read credential.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A legitimate space member (or any party holding that member's bearer credential) obtains a space credential before the owner removes the member or changes the client policy. The credential remains usable against local or cross-host permissioned read endpoints until its default two-hour expiry (plus accepted clock skew). This is especially relevant to cross-host access because the compact credential intentionally omits reader and client identity, and the repository host therefore cannot re-check the removed member or policy tuple. The strongest counterevidence is that proposal-shaped credentials are intentionally transferable read capabilities, issuance does check the current member/client po

#### Severity

**High** — The path crosses a core permissioned confidentiality, repository-integrity, or membership-revocation boundary with a realistic in-scope actor and concrete protected data impact.

Severity would fall if runtime evidence proved the public/permissioned edge, forged commit, or revoked credential cannot reach the recorded sink; it would rise only with broader cross-account automation or mass exploitation.

#### Remediation

Bind space credentials to a membership/client-policy generation or revocation epoch and check it on every read; alternatively shorten leases to an explicitly accepted revocation window and provide durable JTI revocation propagated to repository hosts.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-4"></a>

### [4] Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605; root_control Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363; sink Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:408-429, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363, Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733, Sources/SwanHTTP/SwanJSONWriteBody.swift:230-255, Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift:329-374 |

#### Summary

Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Public JSON mutation routes reserve one of eight processShared leases and collect up to 1 MiB before authorizedTarget runs. uploadBlob authorizes first but deliberately drains a rejected body using the same pool. Each slow or incomplete anonymous body retains a lease until EOF or the 30-second absolute deadline. The pool is shared with authenticated public, permissioned, account-email, and preferences commands, so eight repeatedly renewed unauthenticated requests can make those routes fail unavailable. Deadlines, byte accounting, and the listener cap bound impact but do not isolate authenticated capacity.

#### Validation

Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605; root_control Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363; sink Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733 Public JSON mutation routes reserve one of eight processShared leases and collect up to 1 MiB before authorizedTarget runs. uploadBlob authorizes first but deliberately drains a rejected body using the same pool. Each slow or incomplete anonymous body retains a lease until EOF or the 30-second absolute deadline. The pool is shared with authenticated public, permissioned, account-email, and preferences commands, so eight repeatedly renewed unauthenticated requests can make those routes fail unavailable. Deadlines, byte accounting, and the listener cap bound impact but do not isolate authenticated capacity.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605 reaches the incomplete control at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-363 and then Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733. Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:565-605

- **Sink:** Sources/SwanStorage/PublicRepositoryReadDirectory.swift:670-733

- **Outcome:** Unauthenticated slow public-mutation bodies can monopolize the shared JSON-write admission pool and deny authenticated writes.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Public mutation routes must be enabled. The loopback management listener has a separate pool and is not affected.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-5"></a>

### [5] Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; sink Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129, Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549, Sources/SwanSQLite/SwanSQLite.swift:4603-4613, Sources/SwanSpaces/SwanSpaces.swift:617-629, Sources/SwanSpaces/SwanSpaces.swift:645-705 |

#### Summary

Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Each full permissioned repository export reserves the worst-case working-spool allowance, about 384 MiB, before actual repository size is known and holds it through response streaming. A valid aggregate read credential for a multi-writer space can keep slow tiny exports open across authors and consume the default 1 GiB global budget, preventing further permissioned recovery/export operations. Authorization is exact and physical work is bounded, but worst-case logical reservation makes global starvation cheap relative to repository size.

#### Validation

Tiny permissioned repository exports can monopolize the permissioned CAR spool budget. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; sink Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549 Each full permissioned repository export reserves the worst-case working-spool allowance, about 384 MiB, before actual repository size is known and holds it through response streaming. A valid aggregate read credential for a multi-writer space can keep slow tiny exports open across authors and consume the default 1 GiB global budget, preventing further permissioned recovery/export operations. Authorization is exact and physical work is bounded, but worst-case logical reservation makes global starvation cheap relative to repository size.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129 reaches the incomplete control at the candidate's recorded source location and then Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549. Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.

- **Source:** Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129

- **Sink:** Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:518-549

- **Outcome:** Tiny permissioned repository exports can monopolize the permissioned CAR spool budget.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: the attacker must satisfy the route-specific authentication or configuration prerequisites

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-6"></a>

### [6] The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440; root_control Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234; sink Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580; no reviewed control closes the stated path. |
| Category | identity-and-ssrf |
| CWE | CWE-287, CWE-613, CWE-672, CWE-863 |
| Affected lines | Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234, Sources/SwanOAuth/SpaceServiceAuthentication.swift:67-89, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580, Sources/SwanOAuth/SpaceCredentialAuthority.swift:246-318, Sources/SwanOAuth/SpaceCredentialAuthority.swift:340-411, Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440, Sources/SwanOAuth/SpaceServiceAuthentication.swift:76-83, Sources/SwanOAuth/PermissionedResolverComposition.swift:200-215, Sources/SwanOAuth/SpaceServiceAuthentication.swift:76-88, Sources/SwanOAuth/PermissionedResolverComposition.swift:200-215 |

#### Summary

The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. For service authentication, LocalAccountSpaceServicePublicKeyResolver returns nil not only for a genuinely unmanaged DID but also when a local account is missing, inactive, lacks a service reference/key, or lookup fails. CompositeSpaceServicePublicKeyResolver treats nil as permission to use the configured pinned key. Thus, if an operator has a pin for a DID that is also managed locally, a holder of that pinned private key can continue producing service JWTs after local deactivation/deletion and reach notification verification. Expected lifecycle behavior is terminal failure for an inactive managed identity. The credential and delegation resolvers demonstrate that control by distinguishing proven local absence from inactive/corrupt/racy local state and throwing instead of falling through. Prerequisites are the overlapping pin and possession of its private key; startup preflight and all JWT claim/signature checks still apply. Impact is a configuration-dependent lifecycle revocation bypass. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil not only for an unmanaged issuer, but also when the managed account is suspended, has missing key references, or lacks public-key metadata. CompositeSpaceServicePublicKeyResolver interprets nil as permission to use the configured pin. If a pin overlaps a local issuer while active, startup accepts it when key material matches; after suspension or local metadata failure, the same old pin becomes authoritative and verifies service JWTs used by the notification path. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil both when an issuer is absent and when its managed account is inactive or its key references/public projection are unavailable. CompositeSpaceServicePublicKeyRes

#### Validation

The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440; root_control Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234; sink Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580 For service authentication, LocalAccountSpaceServicePublicKeyResolver returns nil not only for a genuinely unmanaged DID but also when a local account is missing, inactive, lacks a service reference/key, or lookup fails. CompositeSpaceServicePublicKeyResolver treats nil as permission to use the configured pinned key. Thus, if an operator has a pin for a DID that is also managed locally, a holder of that pinned private key can continue producing service JWTs after local deactivation/deletion and reach notification verification. Expected lifecycle behavior is terminal failure for an inactive managed identity. The credential and delegation resolvers demonstrate that control by distinguishing proven local absence from inactive/corrupt/racy local state and throwing instead of falling through. Prerequisites are the overlapping pin and possession of its private key; startup preflight and all JWT claim/signature checks still apply. Impact is a configuration-dependent lifecycle revocation bypass. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil not only for an unmanaged issuer, but also when the managed account is suspended, has missing key references, or lacks public-key metadata. CompositeSpaceServicePublicKeyResolver interprets nil as permission to use the configured pin. If a pin overlaps a local issuer while active, startup accepts it when key material matches; after suspension or local metadata failure, the same old pin becomes authoritative and verifies service JWTs used by the notification path. Additional ordered discovery: LocalAccountSpaceServicePublicKeyResolver returns nil both when an issuer is absent and when its managed account is inactive or its key references/public projection are unavailable. CompositeSpaceServicePublicKeyRes

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440 reaches the incomplete control at Sources/SwanOAuth/PermissionedResolverComposition.swift:175-234 and then Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580. The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.

- **Source:** Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440

- **Sink:** Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-580

- **Outcome:** The composite service-key resolver can fall through to a configured pin when a managed local service DID is inactive or deleted.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Additional context: Strongest counterevidence/proof gap: service JWTs remain signature-, audience-, method-, expiry-, and JTI-bound, and an overlapping operator pin must have been explicitly configured. Confirm production permits local/pinned issuer overlap and that account suspension is intended to revoke service-auth immediately. Unlike the credential and delegation local resolvers, this resolver has no typed terminal local-negative error, despite those adjacent resolvers explicitly preventing pin/remote fallback. Additional context: Construction rejects conflicting simultaneous local and pinned keys. It does not retain a terminal local-authority result after lifecycle changes; credential

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-7"></a>

### [7] A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299; sink Sources/SwanSQLite/SwanSQLite.swift:6948-7023; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230, Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299, Sources/SwanOAuth/SpaceServiceAuthentication.swift:456-466, Sources/SwanSQLite/SwanSQLite.swift:6948-7023, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:722-740 |

#### Summary

A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. notifySpaceDeleted authenticates a JWT using only its issuer, audience, lxm, jti, and time claims. The handler then accepts any request-body SpaceURI whose authority equals the JWT issuer; neither the token nor verifier binds the JWT to the body space. The same valid Bearer token can therefore be paired with a different space URI under the same authority. The selected local audience database records a terminal recipient tombstone for that request-selected space and deletes its outbox rows atomically. Receipt uniqueness includes space_uri, so reusing the same issuer/JTI against another space is not treated as a duplicate. Signature verification, method binding, recipient binding, authority equality, and local-account preopening are strong controls, but none supplies the missing per-space authorization context.

#### Validation

A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299; sink Sources/SwanSQLite/SwanSQLite.swift:6948-7023 notifySpaceDeleted authenticates a JWT using only its issuer, audience, lxm, jti, and time claims. The handler then accepts any request-body SpaceURI whose authority equals the JWT issuer; neither the token nor verifier binds the JWT to the body space. The same valid Bearer token can therefore be paired with a different space URI under the same authority. The selected local audience database records a terminal recipient tombstone for that request-selected space and deletes its outbox rows atomically. Receipt uniqueness includes space_uri, so reusing the same issuer/JTI against another space is not treated as a duplicate. Signature verification, method binding, recipient binding, authority equality, and local-account preopening are strong controls, but none supplies the missing per-space authorization context.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230 reaches the incomplete control at Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299 and then Sources/SwanSQLite/SwanSQLite.swift:6948-7023. A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority

- **Source:** Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:190-230

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:6948-7023

- **Outcome:** A deletion service JWT is not bound to a space and can be replayed across spaces under the same authority

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: observe/obtain one valid notifySpaceDeleted Bearer JWT issued by an authority to a hosted recipient, then submit it before expiry (or longer if combined with the separate missing-iat condition). Entry point: POST /xrpc/com.atproto.space.notifySpaceDeleted. Controlled value: JSON body `space`, changed to another SpaceURI with the same authority DID. Control flow: handler verifies the unchanged JWT, checks issuer == request-selected space.authority, resolves the audience to a local account, and passes the selected space into persistence. Asset/impact: a different permissioned repository can receive a terminal deletion tombstone and have pending outbound notifications remov

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Include the exact space URI in the signed service JWT and require equality with the request body before writing any deletion tombstone or clearing outbox state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-8"></a>

### [8] The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at source interop/prepare-interop-secrets.sh:35-42; root_control interop/prepare-interop-secrets.sh:39-42; sink interop/docker-compose.reference-relay.yml:29-36; no reviewed control closes the stated path. |
| Category | secrets-and-deployment |
| CWE | CWE-250, CWE-522, CWE-668 |
| Affected lines | interop/prepare-interop-secrets.sh:39-42, interop/docker-compose.reference-relay.yml:29-36, docker-compose.yml:119-120, README.md:248-252, Scripts/verify-interop-lab.sh:540-542, interop/prepare-interop-secrets.sh:35-42, Scripts/verify-interop-lab.sh:531-543, docker-compose.yml:66-120 |

#### Summary

The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The secret initializer copies operator-secret into the same swan-runtime-secrets directory as ordinary runtime keys, and base Compose mounts that entire volume into Swan. The verifier only checks that the service definition does not spell the filename, while README and its own diagnostic claim the runtime must not receive it. The optional relay topology enables management PLC provisioning and firehose sync using this mounted operator secret, so compromise or arbitrary file read of the ordinary runtime obtains a separate operator capability. The secret-preparation script explicitly copies operator-secret into swan-runtime-secrets, while verify-interop-lab.sh only searches the Swan YAML block for the literal filename and therefore falsely passes despite the mounted volume's contents.

#### Validation

The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary. Static trace locations: source interop/prepare-interop-secrets.sh:35-42; root_control interop/prepare-interop-secrets.sh:39-42; sink interop/docker-compose.reference-relay.yml:29-36 The secret initializer copies operator-secret into the same swan-runtime-secrets directory as ordinary runtime keys, and base Compose mounts that entire volume into Swan. The verifier only checks that the service definition does not spell the filename, while README and its own diagnostic claim the runtime must not receive it. The optional relay topology enables management PLC provisioning and firehose sync using this mounted operator secret, so compromise or arbitrary file read of the ordinary runtime obtains a separate operator capability. The secret-preparation script explicitly copies operator-secret into swan-runtime-secrets, while verify-interop-lab.sh only searches the Swan YAML block for the literal filename and therefore falsely passes despite the mounted volume's contents.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at interop/prepare-interop-secrets.sh:35-42 reaches the incomplete control at interop/prepare-interop-secrets.sh:39-42 and then interop/docker-compose.reference-relay.yml:29-36. The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.

- **Source:** interop/prepare-interop-secrets.sh:35-42

- **Sink:** interop/docker-compose.reference-relay.yml:29-36

- **Outcome:** The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The checked-in topology is loopback laboratory infrastructure; base Swan does not expose management, files are mode 0400, and the mount is read-only. These reduce deployment impact but do not preserve the asserted credential separation. The base Compose laboratory is loopback-published and does not enable the management listener, so no direct production extraction was shown; the boundary failure still widens the impact of compromise of the Internet-facing runtime process.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Remove the secret from the long-running/runtime or build context, use narrowly scoped secret mounts/files with owner-only permissions, exclude all live-artifact trees from Docker context and cache, and add a build-context regression check.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-9"></a>

### [9] Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860; root_control Sources/SwanSQLite/SwanSQLite.swift:3474-3483; sink Sources/SwanSQLite/SwanSQLite.swift:3648-3659; no reviewed control closes the stated path. |
| Category | secrets-and-deployment |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860, Sources/SwanSQLite/SwanSQLite.swift:3474-3483, Sources/SwanSQLite/SwanSQLite.swift:3648-3659, Sources/SwanHTTP/SwanSpaceXRPC.swift:713-720, Sources/SwanSQLite/SwanSQLite.swift:991-998, Sources/SwanSQLite/SwanSQLite.swift:3682-3709 |

#### Summary

Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Authenticated permissioned create/put/delete/applyWrites are individually body/operation bounded and require write authorization and self-author identity. The durable apply transaction rejects duplicate request IDs using `permissioned_space_requests`, then inserts one permanent row for every successful unique request. The same transaction explicitly prunes `permissioned_space_oplog` by retention depth, but no analogous expiry, compaction, or cumulative quota is applied to the request ledger. An authorized writer can therefore submit sustained valid small writes with unique request IDs and grow this table without bound, consuming shared SQLite storage over time. Expected control is a bounded idempotency window or quota preserving required replay semantics; actual control is an indefinitely growing global primary-key ledger. Protected asset is PDS disk/database availability. Prerequisites are valid permissioned write credentials, current membership/write authority, and sustained requests. Strong counterevidence/proof gap: each receipt is small, account/space quotas or edge rate limits may exist outside this persistence path, and no load test quantified practical exhaustion. Authorization, operation bounds, revision CAS, and oplog retention remain effective; no credential confusion or permissioned disclosure was demonstrated.

#### Validation

Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860; root_control Sources/SwanSQLite/SwanSQLite.swift:3474-3483; sink Sources/SwanSQLite/SwanSQLite.swift:3648-3659 Authenticated permissioned create/put/delete/applyWrites are individually body/operation bounded and require write authorization and self-author identity. The durable apply transaction rejects duplicate request IDs using `permissioned_space_requests`, then inserts one permanent row for every successful unique request. The same transaction explicitly prunes `permissioned_space_oplog` by retention depth, but no analogous expiry, compaction, or cumulative quota is applied to the request ledger. An authorized writer can therefore submit sustained valid small writes with unique request IDs and grow this table without bound, consuming shared SQLite storage over time. Expected control is a bounded idempotency window or quota preserving required replay semantics; actual control is an indefinitely growing global primary-key ledger. Protected asset is PDS disk/database availability. Prerequisites are valid permissioned write credentials, current membership/write authority, and sustained requests. Strong counterevidence/proof gap: each receipt is small, account/space quotas or edge rate limits may exist outside this persistence path, and no load test quantified practical exhaustion. Authorization, operation bounds, revision CAS, and oplog retention remain effective; no credential confusion or permissioned disclosure was demonstrated.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860 reaches the incomplete control at Sources/SwanSQLite/SwanSQLite.swift:3474-3483 and then Sources/SwanSQLite/SwanSQLite.swift:3648-3659. Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.

- **Source:** Sources/SwanHTTP/SwanSpaceXRPC.swift:816-860

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:3648-3659

- **Outcome:** Every successful authenticated permissioned write permanently adds a unique request receipt even though the adjacent permissioned operation log is explicitly pruned.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: the attacker must satisfy the route-specific authentication or configuration prerequisites

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-10"></a>

### [10] Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268; root_control Sources/SwanOAuth/OAuthProofValidation.swift:68-125; sink Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936; no reviewed control closes the stated path. |
| Category | security-control-bypass |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268, Sources/SwanOAuth/OAuthProofValidation.swift:68-125, Sources/SwanSQLite/OAuthControlStore.swift:1741-1797, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-275, Sources/SwanOAuth/OAuthProofValidation.swift:68-120, Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936 |

#### Summary

Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The PAR handler validates and durably claims a DPoP jti before loading or validating client metadata, redirect binding, scope, or client assertion. OAuthDPoPProofValidator accepts an embedded attacker-generated ES256 JWK, a fresh attacker jti, and a stateless server nonce, then calls claimDPoP. A nonce is reusable within its short MAC lifetime, so no account, registered OAuth client, or access token is required to allocate replay rows. The global table is bounded at 131,072 rows and fails new insertions at capacity, which would make legitimate DPoP validation unavailable across PAR/token/resource routes until expiry. Strongest counterevidence: each proof requires real ES256 verification, valid htm/htu/nonce/iat, throughput admissions apply, and entries expire after about five minutes. Feasibility therefore requires a high sustained signed-proof rate and remains a validation-phase proof gap. This allocation occurs even when the attacker-selected client_id is invalid because client metadata and identity validation follow the durable claim.

#### Validation

Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268; root_control Sources/SwanOAuth/OAuthProofValidation.swift:68-125; sink Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936 The PAR handler validates and durably claims a DPoP jti before loading or validating client metadata, redirect binding, scope, or client assertion. OAuthDPoPProofValidator accepts an embedded attacker-generated ES256 JWK, a fresh attacker jti, and a stateless server nonce, then calls claimDPoP. A nonce is reusable within its short MAC lifetime, so no account, registered OAuth client, or access token is required to allocate replay rows. The global table is bounded at 131,072 rows and fails new insertions at capacity, which would make legitimate DPoP validation unavailable across PAR/token/resource routes until expiry. Strongest counterevidence: each proof requires real ES256 verification, valid htm/htu/nonce/iat, throughput admissions apply, and entries expire after about five minutes. Feasibility therefore requires a high sustained signed-proof rate and remains a validation-phase proof gap. This allocation occurs even when the attacker-selected client_id is invalid because client metadata and identity validation follow the durable claim.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268 reaches the incomplete control at Sources/SwanOAuth/OAuthProofValidation.swift:68-125 and then Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936. Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity

- **Source:** Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268

- **Sink:** Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936

- **Outcome:** Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Internet-reachable high-rate availability issue. The table is capped at 131,072 rows and proofs expire after roughly five minutes; body/connection bounds, proof verification cost, expiry cleanup, and metadata-fetch concurrency constrain throughput, but no per-peer PAR/JTI allocation limit or pre-client-validation replay namespace was identified.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-11"></a>

### [11] Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87, Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:129-164, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:174-275, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233, Sources/SwanOAuth/OAuthRemoteFetch.swift:470-505, Sources/SwanOAuth/OAuthRemoteFetch.swift:558-637, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:174-300 |

#### Summary

Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. After the public attacker-generatable DPoP nonce flow, PAR accepts attacker-selected client_id values and synchronously loads remote client metadata before any account token or validated client identity is required and before persisting the PAR. Distinct slow but policy-valid HTTPS origins bypass exact-URL flight sharing and can occupy all eight loader and process-wide fetch admission leases across DNS, metadata retrieval, and optional JWKS retrieval for full timeout intervals. Legitimate metadata validation, PAR, token revalidation, and DID or other security-critical remote fetches sharing the pool then fail immediately; repeated requests can sustain cross-tenant starvation. Additional ordered discovery: A remote caller can obtain a nonce, create its own valid DPoP key/proof, and submit distinct attacker-controlled HTTPS client_id values. PAR then loads remote metadata before establishing a client identity. Eight distinct slow loads consume the process-wide flight budget; detached loads intentionally survive caller cancellation, so repeated attacker-controlled slow hosts can keep legitimate PAR requests at temporarily_unavailable. Added ordered discovery confirms that eight distinct attacker-controlled metadata flights hold the process-global non-queueing document-operation leases across metadata and optional JWKS retrieval. Token redemption, refresh, and revoke deliberately bypass cache and revalidate remotely, so saturation denies those flows as well as PAR and other shared document consumers.

#### Validation

Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575 After the public attacker-generatable DPoP nonce flow, PAR accepts attacker-selected client_id values and synchronously loads remote client metadata before any account token or validated client identity is required and before persisting the PAR. Distinct slow but policy-valid HTTPS origins bypass exact-URL flight sharing and can occupy all eight loader and process-wide fetch admission leases across DNS, metadata retrieval, and optional JWKS retrieval for full timeout intervals. Legitimate metadata validation, PAR, token revalidation, and DID or other security-critical remote fetches sharing the pool then fail immediately; repeated requests can sustain cross-tenant starvation. Additional ordered discovery: A remote caller can obtain a nonce, create its own valid DPoP key/proof, and submit distinct attacker-controlled HTTPS client_id values. PAR then loads remote metadata before establishing a client identity. Eight distinct slow loads consume the process-wide flight budget; detached loads intentionally survive caller cancellation, so repeated attacker-controlled slow hosts can keep legitimate PAR requests at temporarily_unavailable. Added ordered discovery confirms that eight distinct attacker-controlled metadata flights hold the process-global non-queueing document-operation leases across metadata and optional JWKS retrieval. Token redemption, refresh, and revoke deliberately bypass cache and revalidate remotely, so saturation denies those flows as well as PAR and other shared document consumers.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168 reaches the incomplete control at Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87 and then Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575. Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.

- **Source:** Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168

- **Sink:** Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575

- **Outcome:** Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: DNS and transport operations, bodies, and peers are bounded; redirects are rejected; and the eight-slot gate prevents unbounded socket growth. Saturation yields fail-fast unavailability rather than a crash. The issue is starvation of a shared security-critical pool by unauthenticated clients, not unbounded allocation. Additional context: Fetches are peer-pinned, SSRF-filtered, size/time bounded, capped at eight, and DPoP-replay protected. Those controls limit each fetch but DPoP only proves possession of a caller-generated key and there is no per-peer or established-client admission before the shared budget. Deployment rate limiting remains a proof gap. The added source narrows the impact to

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-12"></a>

### [12] Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189; root_control Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32; sink Sources/SwanSQLite/PublicRepositoryStore.swift:551-571; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189, Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32, Sources/SwanSQLite/PublicRepositoryStore.swift:551-571, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:23, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188, Sources/SwanSQLite/PublicRepositoryStore.swift:551-689, Sources/SwanSQLite/PublicFirehoseOutboxStore.swift:234-266, Sources/SwanSQLite/SwanSQLite.swift:2479-2495, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-188, Sources/SwanSQLite/SwanSQLite.swift:434-437 |

#### Summary

Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Repeated authorized create/apply operations can generate unique record, MST, and commit blocks. Every new content-addressed block is inserted into public_repository_blocks, while the reviewed runtime sources contain no pruning of blocks made unreachable as heads advance. An account principal can therefore grow its SQLite database across individually valid bounded mutations until shared storage is exhausted. Added ordered discovery traces the same repeated near-limit authorized mutation stream through fresh immutable repository blocks, committed mutation projection, and enqueued CAR/payload material. Completion explicitly retains public-event outbox payloads and CARs indefinitely as idempotence anchors; updates and deletes alter only the current record index. Per-request limits, CAS, blob quotas, and account deletion do not bound cumulative non-blob history. Additional ordered discovery: Each authorized create, update or applyWrites operation is individually bounded, but every newly prepared record, MST and commit block is inserted by CID into public_repository_blocks. That table has no generation, reachability or expiry metadata and the reviewed implementation has no deletion path for blocks made unreachable by later updates or deletes. Replacing one record repeatedly with unique near-limit values keeps the live projection small while permanently growing the account database. Additional ordered discovery: Successful repository publication constructs payload and diff/commit CAR bytes and inserts them into public_event_outbox. Sequencing completion only sets completed=1 and deliberately retains the public material for exact replay. Global firehose age, row and byte pruning does not compact this account-local table. A writable account can issue unbounded distinct commits a

#### Validation

Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189; root_control Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32; sink Sources/SwanSQLite/PublicRepositoryStore.swift:551-571 Repeated authorized create/apply operations can generate unique record, MST, and commit blocks. Every new content-addressed block is inserted into public_repository_blocks, while the reviewed runtime sources contain no pruning of blocks made unreachable as heads advance. An account principal can therefore grow its SQLite database across individually valid bounded mutations until shared storage is exhausted. Added ordered discovery traces the same repeated near-limit authorized mutation stream through fresh immutable repository blocks, committed mutation projection, and enqueued CAR/payload material. Completion explicitly retains public-event outbox payloads and CARs indefinitely as idempotence anchors; updates and deletes alter only the current record index. Per-request limits, CAS, blob quotas, and account deletion do not bound cumulative non-blob history. Additional ordered discovery: Each authorized create, update or applyWrites operation is individually bounded, but every newly prepared record, MST and commit block is inserted by CID into public_repository_blocks. That table has no generation, reachability or expiry metadata and the reviewed implementation has no deletion path for blocks made unreachable by later updates or deletes. Replacing one record repeatedly with unique near-limit values keeps the live projection small while permanently growing the account database. Additional ordered discovery: Successful repository publication constructs payload and diff/commit CAR bytes and inserts them into public_event_outbox. Sequencing completion only sets completed=1 and deliberately retains the public material for exact replay. Global firehose age, row and byte pruning does not compact this account-loc

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189 reaches the incomplete control at Sources/SwanPublicRepository/PublicRepositoryLimits.swift:7-32 and then Sources/SwanSQLite/PublicRepositoryStore.swift:551-571. Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-189

- **Sink:** Sources/SwanSQLite/PublicRepositoryStore.swift:551-571

- **Outcome:** Authenticated public mutations can exhaust shared storage because cumulative immutable repository history, committed mutation receipts, and completed firehose payload or CAR material have no effective quota or garbage collection.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: JSON and commit sizes are bounded per request and the path requires an authenticated account principal; account deletion removes the database. No per-account repository-byte quota or block garbage collector was found, while deployment filesystem quotas remain unknown. The added source requires a hosted account with valid account OAuth and public mutations enabled; impact can cross accounts that share a filesystem. A complete fix must cover both unreachable repository blocks and completed firehose history material. Additional context: Requires a valid writable hosted account and public mutations enabled. Record, write-count and CAR limits bound each request; blob quota governs different table

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-13"></a>

### [13] Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364; root_control Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159; sink Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-367, CWE-613, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364, Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-440, Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159, Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169, Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-147, Sources/SwanOAuth/ProxyServiceAuthentication.swift:149-169, Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-431, Sources/SwanOAuth/ProxyServiceAuthentication.swift:120-169, Sources/SwanAccounts/AccountOperatorService.swift:325-338, Sources/SwanHTTP/SwanXRPCPipethrough.swift:409-417 |

#### Summary

Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The authenticated wildcard XRPC proxy validates the user's OAuth request, may buffer a body and resolve a remote service, then requests a service JWT. LocalAccountProxyServiceTokenIssuer reads the account lifecycle and key references at lines 143-145, awaits keyStore.key at line 152, and signs at lines 159-169 without a post-read lifecycle/generation check. Deactivation, permanent deletion, password-recovery revocation, or key rotation can complete during that await while the request still emits and forwards a fresh 60-second service token to the remote audience. The service token is correctly bound to audience and NSID and the proxy is peer-pinned; those controls do not fence issuer lifecycle. issueProxyServiceToken authorizes the issuer and captures signing references at lines 142-146, then suspends at keyStore.key(for:) on line 152 before issuing the service JWT at lines 159-169. The source comment states no await occurs after the lifecycle decision, but line 152 is awaited. No account status, generation, or current reference is revalidated afterward. Additional ordered discovery: LocalAccountProxyServiceTokenIssuer checks active status and key references, then awaits keyStore.key and signs without a final lifecycle/reference check. Its comment claims there is no await after the checks, but the key read is async. A deactivation that wins during this suspension still leaves the in-flight request able to mint a fresh, method/audience-bound service token for the outbound proxy request. Additional ordered discovery: An authenticated pipethrough request reaches issueProxyServiceToken with a route-bound audience and method. The issuer reads active account state and signing-key references at lines 143-145, then suspends at keyStore.key on line 152 despite a comment assertin

#### Validation

Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364; root_control Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159; sink Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169 The authenticated wildcard XRPC proxy validates the user's OAuth request, may buffer a body and resolve a remote service, then requests a service JWT. LocalAccountProxyServiceTokenIssuer reads the account lifecycle and key references at lines 143-145, awaits keyStore.key at line 152, and signs at lines 159-169 without a post-read lifecycle/generation check. Deactivation, permanent deletion, password-recovery revocation, or key rotation can complete during that await while the request still emits and forwards a fresh 60-second service token to the remote audience. The service token is correctly bound to audience and NSID and the proxy is peer-pinned; those controls do not fence issuer lifecycle. issueProxyServiceToken authorizes the issuer and captures signing references at lines 142-146, then suspends at keyStore.key(for:) on line 152 before issuing the service JWT at lines 159-169. The source comment states no await occurs after the lifecycle decision, but line 152 is awaited. No account status, generation, or current reference is revalidated afterward. Additional ordered discovery: LocalAccountProxyServiceTokenIssuer checks active status and key references, then awaits keyStore.key and signs without a final lifecycle/reference check. Its comment claims there is no await after the checks, but the key read is async. A deactivation that wins during this suspension still leaves the in-flight request able to mint a fresh, method/audience-bound service token for the outbound proxy request. Additional ordered discovery: An authenticated pipethrough request reaches issueProxyServiceToken with a route-bound audience and method. The issuer reads active account state and signing-key references at lines 143-145, then suspends at keyStore.key on line 152 despite a comment assertin

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364 reaches the incomplete control at Sources/SwanOAuth/ProxyServiceAuthentication.swift:136-159 and then Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169. Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.

- **Source:** Sources/SwanHTTP/SwanXRPCPipethrough.swift:358-364

- **Sink:** Sources/SwanOAuth/ProxyServiceAuthentication.swift:159-169

- **Outcome:** Revoked or rotated accounts can race AppView proxy service-token signing after authorization and mint a fresh audience-and-method-bound credential with stale authority.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The attacker begins with a valid OAuth/DPoP request and must win the concurrent transition. The protected privilege is the account's inter-service identity at an AppView/labeler/feed service after local revocation. The caller must first have an authenticated OAuth subject; proxy routing, method allowlists, audience/lxm binding, a fresh jti, and a 60-second lifetime constrain impact. Parent validation should establish whether a lifecycle transition can interleave and whether a remote service can accept the old PLC identity before rotation or tombstone propagation. Additional context: The token remains narrowly bound and short-lived, limiting impact to a raced request, but revocation does not

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-14"></a>

### [14] OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66; root_control Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135; no reviewed control closes the stated path. |
| Category | identity-and-ssrf |
| CWE | CWE-180 |
| Affected lines | Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66, Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251, Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135, Sources/SwanOAuth/OAuthClientMetadata.swift:238-245, Sources/SwanOAuth/SwanProxyHTTPTransport.swift:215-225 |

#### Summary

OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. NIOPeerPinnedOAuthDocumentTransport constructs the origin-form target from url.path and url.query. SwanProxyHTTPTransport separately documents that URL.path percent-decodes and therefore uses percentEncodedPath and percentEncodedQuery. The response handler reports responseURL as the original requestURL rather than the emitted target, so the later exact URL check cannot detect a rewrite. Encoded separators or query delimiters in attacker-selected client_id or jwks_uri values can request a different same-origin resource than the identity that passed policy.

#### Validation

OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query. Static trace locations: entrypoint Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66; root_control Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135 NIOPeerPinnedOAuthDocumentTransport constructs the origin-form target from url.path and url.query. SwanProxyHTTPTransport separately documents that URL.path percent-decodes and therefore uses percentEncodedPath and percentEncodedQuery. The response handler reports responseURL as the original requestURL rather than the emitted target, so the later exact URL check cannot detect a rewrite. Encoded separators or query delimiters in attacker-selected client_id or jwks_uri values can request a different same-origin resource than the identity that passed policy.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66 reaches the incomplete control at Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251 and then Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135. OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.

- **Source:** Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66

- **Sink:** Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135

- **Outcome:** OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: TLS hostname verification, peer pinning, and redirect refusal prevent cross-host redirection. The proof gap is a realistic same-origin endpoint that returns usable metadata or JWKS under the rewritten target.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Use one canonical URL representation for validation, request-target construction, DPoP identity, caching and transport; reject encodings whose decoded path/query changes the validated identity.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-15"></a>

### [15] A read-only space credential can mutate, replace, and exhaust durable notification registrations.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278; root_control Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132; sink Sources/SwanSQLite/SwanSQLite.swift:6716-6776; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-284, CWE-862, CWE-269, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:523-543, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132, Sources/SwanSQLite/SwanSQLite.swift:6716-6776, Sources/SwanSpaces/SwanSpaces.swift:245-254, Tests/SwanSQLiteTests/SpaceNotificationSQLiteTests.swift:299-363, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-136, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:385-410, Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-905, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:523-543 |

#### Summary

A read-only space credential can mutate, replace, and exhaust durable notification registrations.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. POST registerNotify accepts any bearer space credential for the requested space and passes it directly to SQLite registration. The store explicitly permits a read grant, then INSERTs or overwrites the authority-owned (space, endpoint) registration and its repository filter. Elsewhere SpaceAuthorizationPolicy rejects space-credential writes, but this control-plane mutation bypasses that policy. A reader who knows a legitimate endpoint can replace its filter/expiry, or create 1,024 unique endpoints and deny new registrations for up to 24 hours. The explicit cap, expiry, and outbound endpoint allowlist bound storage and SSRF but do not preserve the claimed read-only capability invariant. Added ordered discovery traces the same boundary from DurableSpaceCredentialVerifier's read-only SpaceGrant through credentialAuthorization to registerNotify storage, where the read credential inserts or replaces attacker-selected endpoint and optional repository registration state for up to 24 hours without account OAuth or a distinct write-capable principal. Additional ordered discovery: POST com.atproto.space.registerNotify authenticates solely through credentialAuthorization, which accepts a bearer space credential for the requested space, then passes the attacker-selected endpoint and optional repository to durable registration. The SQLite implementation explicitly requires a spaceCredential whose grant allows read and nevertheless inserts or upserts permissioned_space_notification_registrations. A holder of the claimed read capability can therefore create or replace durable control-plane state and influence later deletion fanout to an operator-allowlisted destination.

#### Validation

A read-only space credential can mutate, replace, and exhaust durable notification registrations. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278; root_control Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132; sink Sources/SwanSQLite/SwanSQLite.swift:6716-6776 POST registerNotify accepts any bearer space credential for the requested space and passes it directly to SQLite registration. The store explicitly permits a read grant, then INSERTs or overwrites the authority-owned (space, endpoint) registration and its repository filter. Elsewhere SpaceAuthorizationPolicy rejects space-credential writes, but this control-plane mutation bypasses that policy. A reader who knows a legitimate endpoint can replace its filter/expiry, or create 1,024 unique endpoints and deny new registrations for up to 24 hours. The explicit cap, expiry, and outbound endpoint allowlist bound storage and SSRF but do not preserve the claimed read-only capability invariant. Added ordered discovery traces the same boundary from DurableSpaceCredentialVerifier's read-only SpaceGrant through credentialAuthorization to registerNotify storage, where the read credential inserts or replaces attacker-selected endpoint and optional repository registration state for up to 24 hours without account OAuth or a distinct write-capable principal. Additional ordered discovery: POST com.atproto.space.registerNotify authenticates solely through credentialAuthorization, which accepts a bearer space credential for the requested space, then passes the attacker-selected endpoint and optional repository to durable registration. The SQLite implementation explicitly requires a spaceCredential whose grant allows read and nevertheless inserts or upserts permissioned_space_notification_registrations. A holder of the claimed read capability can therefore create or replace durable control-plane state and influence later deletion fanout to an operator-allowlisted destination.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278 reaches the incomplete control at Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132 and then Sources/SwanSQLite/SwanSQLite.swift:6716-6776. A read-only space credential can mutate, replace, and exhaust durable notification registrations.

- **Source:** Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:6716-6776

- **Outcome:** A read-only space credential can mutate, replace, and exhaust durable notification registrations.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires permissioned notification routes and one valid read credential for the target space. No repository-content write or permissioned-data disclosure was demonstrated. The added source emphasizes the stated invariant that space credentials are read capabilities. Static destination resolution limits immediate arbitrary-URL SSRF, and proposal credentials carry no reader subject with which to bind the optional repository, but neither control authorizes the durable registration write. Additional context: exploitation requires a valid unexpired credential for the target space. Outbound notification destinations are independently operator-allowlisted, so this is not arbitrary SSRF; the issue i

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Require an account/authority write-capable credential for `registerNotify`, bind the registration to the authorized repository/client, and keep space credentials read-only at the route and storage layers.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-16"></a>

### [16] Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/swan/SwanCommand.swift:5664-5711; root_control Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453; sink Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/swan/SwanCommand.swift:5664-5711, Sources/SwanInterop/PublicRepositoryCARReplication.swift:374-450, Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453, Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543, Sources/SwanSQLite/PublicRepositoryImportStaging.swift:235-248, Sources/SwanPublicRepository/PublicRepositoryLimits.swift:17-24 |

#### Summary

Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The operator import command fetches an attacker-hosted com.atproto.sync.getRepo CAR and invokes validateProjection before publication. The validator caps MST nodes and entries per individual node, but appends every reconstructed leaf to an aggregate array and every record CID to a set without a repository-wide record/leaf cap; it then builds another CID-to-collection dictionary and sorts the entire leaf array. Standard policy permits a 512 MiB CAR, 500,000 MST nodes, and 4,096 entries per node, so a validly signed, structurally valid compact MST can expand into millions of Swift objects and attacker-controlled O(n log n) work before rejection or publication.

#### Validation

Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:5664-5711; root_control Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453; sink Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543 The operator import command fetches an attacker-hosted com.atproto.sync.getRepo CAR and invokes validateProjection before publication. The validator caps MST nodes and entries per individual node, but appends every reconstructed leaf to an aggregate array and every record CID to a set without a repository-wide record/leaf cap; it then builds another CID-to-collection dictionary and sorts the entire leaf array. Standard policy permits a 512 MiB CAR, 500,000 MST nodes, and 4,096 entries per node, so a validly signed, structurally valid compact MST can expand into millions of Swift objects and attacker-controlled O(n log n) work before rejection or publication.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/swan/SwanCommand.swift:5664-5711 reaches the incomplete control at Sources/SwanPublicRepository/RepositoryMSTValidation.swift:359-453 and then Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543. Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.

- **Source:** Sources/swan/SwanCommand.swift:5664-5711

- **Sink:** Sources/SwanPublicRepository/RepositoryMSTValidation.swift:487-543

- **Outcome:** Public repository import retains and sorts an unbounded aggregate MST leaf set despite per-node and CAR-byte limits.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker must control a repository and valid signing key and induce an operator/replication import. Signature, CID, MST topology, record-size, CAR-byte, node-count, cancellation, and staging checks are strong countercontrols, and unverified state is not published; they do not bound aggregate decoded leaf count or sorting memory/CPU.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-17"></a>

### [17] Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint/wrapper Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177; root_control Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112; no reviewed control closes the stated path. |
| Category | security-control-bypass |
| CWE | CWE-674, CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:115-135, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:172-215, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:349-400, Tests/SwanPublicRepositoryTests/PublicRepositoryDomainTests.swift:289-312, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-177, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-108, Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:130 |

#### Summary

Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. convertObject passes the same depth to each child, convert(.object) calls convertObject with unchanged depth, and convertCBOR recurses through OrderedCBORMap and dictionary values without incrementing or checking depth; only arrays advance depth. The later prepare/encode phase correctly advances object depth, but it runs after conversion has already recursively traversed the attacker-controlled graph. Authenticated createRecord, putRecord, and applyWrites call publicRecord on request values. Additional ordered discovery: convertObject checks depth but passes the same depth to convert, whose .object branch calls convertObject with that unchanged value. convertCBOR likewise recursively visits OrderedCBORMap and \[String: Any\] children with unchanged depth; only arrays increment it. The applyWrites/createRecord/putRecord HTTP paths invoke publicRecord directly on request-decoded records. Although later record preparation increments object depth correctly, conversion and recursive blob-reference projection happen first, so sufficiently deep object nesting can exhaust the Swift stack or CPU instead of returning recordNestingTooDeep. Existing depth coverage exercises mixed array/object nesting, not object-only nesting.

#### Validation

Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check. Static trace locations: entrypoint/wrapper Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177; root_control Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112 convertObject passes the same depth to each child, convert(.object) calls convertObject with unchanged depth, and convertCBOR recurses through OrderedCBORMap and dictionary values without incrementing or checking depth; only arrays advance depth. The later prepare/encode phase correctly advances object depth, but it runs after conversion has already recursively traversed the attacker-controlled graph. Authenticated createRecord, putRecord, and applyWrites call publicRecord on request values. Additional ordered discovery: convertObject checks depth but passes the same depth to convert, whose .object branch calls convertObject with that unchanged value. convertCBOR likewise recursively visits OrderedCBORMap and \[String: Any\] children with unchanged depth; only arrays increment it. The applyWrites/createRecord/putRecord HTTP paths invoke publicRecord directly on request-decoded records. Although later record preparation increments object depth correctly, conversion and recursive blob-reference projection happen first, so sufficiently deep object nesting can exhaust the Swift stack or CPU instead of returning recordNestingTooDeep. Existing depth coverage exercises mixed array/object nesting, not object-only nesting.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177 reaches the incomplete control at Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112 and then the candidate's recorded source location. Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177

- **Sink:** recorded protected operation

- **Outcome:** Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Prerequisite: an authenticated account submits a deeply object-nested value that survives the Petrel/Foundation request decoder and 1 MiB HTTP body limit. Potential impact is excessive recursion/CPU or stack exhaustion before the intended maximumCBORNestingDepth control. Upstream decoding may impose its own depth ceiling and prepare rejects excessive depth before persistence; the existing depth test covers the later encoder and an array/object mixture, not object-only pre-encoding conversion.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-18"></a>

### [18] Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188; root_control Sources/SwanSQLite/PublicRepositoryStore.swift:308-419; sink Sources/SwanSQLite/SwanSQLite.swift:448-472; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:229-251, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:263-320, Sources/SwanSQLite/PublicRepositoryStore.swift:308-419, Sources/SwanSQLite/SwanSQLite.swift:448-472, docs/superpowers/specs/2026-08-12-swan-read-after-write-design.md:223-227, Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift:171-209, Sources/SwanSQLite/PublicRepositoryStore.swift:699-734, Sources/SwanSQLite/PublicRepositoryStore.swift:308-413, Sources/SwanSQLite/SwanSQLite.swift:448-472 |

#### Summary

Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Every apply/create/put/delete HTTP operation supplies a fresh server-generated UUID. Reservation inserts a new public_repository_mutation_requests row, while the schema has no timestamp, expiry, quota, or retention field and repository-wide source contains no deletion from this table. The design document explicitly states that the table grows unbounded. A malicious hosted account can sustain successful mutations until SQLite/disk growth degrades the service. Additional ordered discovery: The coordinator reserves a revision before preparing and applying a mutation. Each reservation inserts a fresh public_repository_mutation_requests row keyed by an HTTP-generated UUID. A request with an intentionally wrong expected record CID reaches reservation and then fails state validation; the catch path only updates the row to abandoned. Neither abandoned nor committed rows have a cardinality ceiling, expiry or deletion path, so repeated authenticated failures grow durable state without publishing records. Added ordered discovery establishes that authenticated create, put, and applyWrites requests accept JSON bodies up to 1,000,000 bytes, generate a fresh UUID request ID, and retain committed_projection bytes in the permanent public_repository_mutation_requests row. No row or byte quota or deletion path exists, the design documentation explicitly states that nothing prunes the table, and the supplied RSS fixture demonstrates accumulation by committing 300 unique 900,000-byte records.

#### Validation

Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188; root_control Sources/SwanSQLite/PublicRepositoryStore.swift:308-419; sink Sources/SwanSQLite/SwanSQLite.swift:448-472 Every apply/create/put/delete HTTP operation supplies a fresh server-generated UUID. Reservation inserts a new public_repository_mutation_requests row, while the schema has no timestamp, expiry, quota, or retention field and repository-wide source contains no deletion from this table. The design document explicitly states that the table grows unbounded. A malicious hosted account can sustain successful mutations until SQLite/disk growth degrades the service. Additional ordered discovery: The coordinator reserves a revision before preparing and applying a mutation. Each reservation inserts a fresh public_repository_mutation_requests row keyed by an HTTP-generated UUID. A request with an intentionally wrong expected record CID reaches reservation and then fails state validation; the catch path only updates the row to abandoned. Neither abandoned nor committed rows have a cardinality ceiling, expiry or deletion path, so repeated authenticated failures grow durable state without publishing records. Added ordered discovery establishes that authenticated create, put, and applyWrites requests accept JSON bodies up to 1,000,000 bytes, generate a fresh UUID request ID, and retain committed_projection bytes in the permanent public_repository_mutation_requests row. No row or byte quota or deletion path exists, the design documentation explicitly states that nothing prunes the table, and the supplied RSS fixture demonstrates accumulation by committing 300 unique 900,000-byte records.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188 reaches the incomplete control at Sources/SwanSQLite/PublicRepositoryStore.swift:308-419 and then Sources/SwanSQLite/SwanSQLite.swift:448-472. Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:184-188

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:448-472

- **Outcome:** Authenticated successful and failed public mutations permanently grow an unbounded durable request ledger, including full committed projections and abandoned wrong-CID reservations.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires valid account OAuth and successful mutations. Request/body concurrency limits bound instantaneous work, not cumulative durable rows. Additional context: Requires public writes and valid account OAuth. Per-request body limits, UUID uniqueness and integrity checks prevent corruption but do not bound cumulative ledger rows. The added source requires an active hosted account and valid OAuth/DPoP write authority. Per-request body and operation limits, account database separation, and blob quotas bound individual work but not cumulative request-ledger bytes on the shared host volume; deployment filesystem or account quotas remain a validation question.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-19"></a>

### [19] Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140, Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751, Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:609-638, Sources/SwanStorage/AuthorizedSimpleSpaceDirectory.swift:439-455, Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140, Sources/SwanOAuth/SpaceCredentialAuthority.swift:732-744, Sources/SwanOAuth/SpaceCredentialAuthority.swift:744-751, Sources/SwanSQLite/SwanSQLite.swift:7033-7074, Sources/SwanSQLite/SwanSQLite.swift:6403-6434 |

#### Summary

Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. A remote holder of a valid single-use delegation reaches getSpaceCredential, passes client-attestation verification, and receives a transactional authorizeSimpleSpaceCredentialRead decision covering current space lifecycle, app allow-list, member-list or managing-app membership. That read transaction ends before the issuer separately awaits signingKeys.signingKey and signs a fresh two-hour space credential without carrying a policy revision or rechecking policy. Concurrent removeMember, client allow-list removal, managing-app denial, space update, or deletion can therefore commit after authorization and before signing while issuance still returns a bearer the post-change policy would deny. The later verifier checks signature, space, and time rather than current membership or policy. Transactional reads, single-use delegation JTI, bounded lifetime, and sequential policy tests are counterevidence, but they do not close the post-transaction async signing window. The latest ordered discovery isolates member removal or whole-space deletion committing during the asynchronous signing-key lookup: issueSpaceCredential can then mint the same two-hour read bearer without a policy version, CAS, or second membership check, and later verification does not consult current membership. Additional ordered discovery: A credential exchange passes durable membership/managing-app policy at lines 732-737, then suspends while resolving the authority signing key. The local resolver reads active account state and key references at lines 207-213 and suspends again for key-store access. Neither the space policy nor authority lifecycle/generation is revalidated before createSpaceCredential signs at lines 744-750, so concurrent member/app revocation, authority deactivation, deletion, or key rotation

#### Validation

Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223 A remote holder of a valid single-use delegation reaches getSpaceCredential, passes client-attestation verification, and receives a transactional authorizeSimpleSpaceCredentialRead decision covering current space lifecycle, app allow-list, member-list or managing-app membership. That read transaction ends before the issuer separately awaits signingKeys.signingKey and signs a fresh two-hour space credential without carrying a policy revision or rechecking policy. Concurrent removeMember, client allow-list removal, managing-app denial, space update, or deletion can therefore commit after authorization and before signing while issuance still returns a bearer the post-change policy would deny. The later verifier checks signature, space, and time rather than current membership or policy. Transactional reads, single-use delegation JTI, bounded lifetime, and sequential policy tests are counterevidence, but they do not close the post-transaction async signing window. The latest ordered discovery isolates member removal or whole-space deletion committing during the asynchronous signing-key lookup: issueSpaceCredential can then mint the same two-hour read bearer without a policy version, CAS, or second membership check, and later verification does not consult current membership. Additional ordered discovery: A credential exchange passes durable membership/managing-app policy at lines 732-737, then suspends while resolving the authority signing key. The local resolver reads active account state and key references at lines 207-213 and suspends again for key-store access. Neither the space policy nor authority lifecycle/generation is revalidated before createSpaceCredential signs at lines 744-750, so concurrent member/app revocation, authority deactivation, deletion, or key rotation

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140 reaches the incomplete control at Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751 and then Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223. Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.

- **Source:** Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:107-140

- **Sink:** Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223

- **Outcome:** Space lifecycle, membership, managing-app, or client-policy revocation can race credential signing and still produce a fresh read bearer.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The caller must hold a valid delegation and be authorized under membership and app policy when the initial transaction runs, then win a concurrent authority-policy transition or prolong the signing-key read. The protected asset is permissioned repository read authority after revocation or policy tightening. The added source preserves the narrower currently authorized member racing removal or deletion; accepting ordinary validity of already-issued tokens does not explain issuance that linearizes after revocation. Additional context: The route is remotely reachable after delegation verification; a requester can keep exchanges in flight while a concurrent authorized lifecycle or policy operatio

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-20"></a>

### [20] Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint/wrapper Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381; sink Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420; no reviewed control closes the stated path. |
| Category | security-control-bypass |
| CWE | CWE-287, CWE-613, CWE-345, CWE-294 |
| Affected lines | Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223, Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-299, Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381, Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:556-570, Sources/SwanOAuth/SpaceServiceAuthentication.swift:456-465, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:147-183, Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:197-225, Sources/SwanOAuth/SpaceServiceAuthentication.swift:288-298, Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-420 |

#### Summary

Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. SpaceServiceJWT.Claims decodes iat as optional, and validateShape requires issuer, audience, method, and event ID but not iat. The verifier always checks exp, but its future-issued-at and exp-minus-iat maximumLifetime checks execute only inside if let issuedAt. A correctly signed token without iat and with an arbitrarily distant exp therefore skips both lifetime controls and is accepted after signature, issuer, audience, method, route-shape, expiry, and event-id checks. DurableSpaceServiceAuthenticationVerifier passes a five-minute maximum, accepts the token for service-authenticated notification and control routes, and returns the distant expiry, so notifyWrite, deletion, or check-access authority and credential exposure can persist far beyond the configured window. Route-specific discovery further confirms that notifyWrite binds issuer to input.repo and audience to the space authority, while notifySpaceDeleted binds issuer to space.authority and maps its audience through the configured recipient binding; both then rely on the same verifier whose lifetime checks execute only when iat is present. These controls prevent unsigned, cross-authority, or cross-method use but do not enforce freshness for a valid no-iat bearer. Existing tests cover extreme present iat but not absent iat. Additional ordered discovery: SpaceServiceJWT.Claims declares iat optional. verify() enforces expiration relative to now, but performs the exp-minus-iat maximumLifetime check only inside `if let issuedAt`. A signer accepted by the configured resolver can therefore omit iat and choose an arbitrarily distant exp; DurableSpaceServiceAuthenticationVerifier then returns the token as authenticated after exact audience and method checks. The added discovery independently traces absent iat through Spac

#### Validation

Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp. Static trace locations: entrypoint/wrapper Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381; sink Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420 SpaceServiceJWT.Claims decodes iat as optional, and validateShape requires issuer, audience, method, and event ID but not iat. The verifier always checks exp, but its future-issued-at and exp-minus-iat maximumLifetime checks execute only inside if let issuedAt. A correctly signed token without iat and with an arbitrarily distant exp therefore skips both lifetime controls and is accepted after signature, issuer, audience, method, route-shape, expiry, and event-id checks. DurableSpaceServiceAuthenticationVerifier passes a five-minute maximum, accepts the token for service-authenticated notification and control routes, and returns the distant expiry, so notifyWrite, deletion, or check-access authority and credential exposure can persist far beyond the configured window. Route-specific discovery further confirms that notifyWrite binds issuer to input.repo and audience to the space authority, while notifySpaceDeleted binds issuer to space.authority and maps its audience through the configured recipient binding; both then rely on the same verifier whose lifetime checks execute only when iat is present. These controls prevent unsigned, cross-authority, or cross-method use but do not enforce freshness for a valid no-iat bearer. Existing tests cover extreme present iat but not absent iat. Additional ordered discovery: SpaceServiceJWT.Claims declares iat optional. verify() enforces expiration relative to now, but performs the exp-minus-iat maximumLifetime check only inside `if let issuedAt`. A signer accepted by the configured resolver can therefore omit iat and choose an arbitrarily distant exp; DurableSpaceServiceAuthenticationVerifier then returns the token as authenticated after exact audience and method checks. The adde

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223 reaches the incomplete control at Sources/SwanOAuth/SpaceServiceAuthentication.swift:371-381 and then Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420. Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.

- **Source:** Sources/SwanOAuth/SpaceServiceAuthentication.swift:193-223

- **Sink:** Sources/SwanOAuth/SpaceServiceAuthentication.swift:405-420

- **Outcome:** Correctly signed service JWTs that omit optional iat bypass the configured maximum lifetime on independently reachable notifyWrite and notifySpaceDeleted routes and may remain valid until an arbitrarily distant exp.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A network attacker cannot remove iat without invalidating the signature. Exploitation requires a trusted or pinned allowed issuer that emits the optional shape, a currently accepted service-key holder that pre-mints unique-jti long-lived tokens, disclosure of such a token, or misuse or compromise of its signing key. Exact-event replay is durably idempotent and method, audience where supplied, issuer, signature, expiration, JTI, and bounded event-id controls still apply. Swan's own issuer and the checked-in TypeScript fixture include iat; no reviewed compatibility evidence requires accepting absent iat. The independently reachable write and deletion notification instances preserve their narro

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Require `iat` for service JWTs and enforce `exp <= now + maximumLifetime` independently of `iat`; add absent-`iat`, distant-`exp`, replay, audience, method, and issuer negative tests.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-21"></a>

### [21] A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342; root_control Sources/SwanSQLite/AccountControlStore.swift:2488-2515; sink Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342, Sources/SwanSQLite/AccountControlStore.swift:2488-2515, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2633-2662, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730, Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift:218-250, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:229-320, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-343, Sources/SwanSQLite/AccountControlStore.swift:2492-2515 |

#### Summary

A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Authenticated public mutation routes resolve a target and check that its status is active before preparing the write. The final SQLite control-plane fence then rechecks active status and signing generation in a transaction, but PublicFirehoseCommitFence catches AccountControlStoreError.invalidTransition and invokes the durable mutation closure again with a nil firehose context. Consequently, a request admitted while active can be prepared, lose a race to deactivation, and still commit signed repository state after revocation. The inactive state hides the new commit and suppresses firehose emission, but reactivation or later cold public-read admission can expose the post-deactivation state. The strongest counterevidence is the initial active check, inactive-login rejection, cache eviction, and comments saying non-emitting post-deactivation commits are intentional; those controls do not preserve the documented final authorization fence, and the focused fence tests cover stale signing generation rather than the inactive-race fallback. Additional ordered discovery: The HTTP handler checks that the target is active, but the durable commit occurs later. PublicFirehoseCommitFence detects an inactive account through invalidTransition and then explicitly invokes mutate(nil), allowing the record mutation to commit without a firehose event after deactivation rather than rejecting the stale request. Reactivation can subsequently expose the post-revocation repository state.

#### Validation

A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342; root_control Sources/SwanSQLite/AccountControlStore.swift:2488-2515; sink Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730 Authenticated public mutation routes resolve a target and check that its status is active before preparing the write. The final SQLite control-plane fence then rechecks active status and signing generation in a transaction, but PublicFirehoseCommitFence catches AccountControlStoreError.invalidTransition and invokes the durable mutation closure again with a nil firehose context. Consequently, a request admitted while active can be prepared, lose a race to deactivation, and still commit signed repository state after revocation. The inactive state hides the new commit and suppresses firehose emission, but reactivation or later cold public-read admission can expose the post-deactivation state. The strongest counterevidence is the initial active check, inactive-login rejection, cache eviction, and comments saying non-emitting post-deactivation commits are intentional; those controls do not preserve the documented final authorization fence, and the focused fence tests cover stale signing generation rather than the inactive-race fallback. Additional ordered discovery: The HTTP handler checks that the target is active, but the durable commit occurs later. PublicFirehoseCommitFence detects an inactive account through invalidTransition and then explicitly invokes mutate(nil), allowing the record mutation to commit without a firehose event after deactivation rather than rejecting the stale request. Reactivation can subsequently expose the post-revocation repository state.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342 reaches the incomplete control at Sources/SwanSQLite/AccountControlStore.swift:2488-2515 and then Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730. A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:329-342

- **Sink:** Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2730

- **Outcome:** A public repository mutation that races account deactivation is deliberately committed after the final active-account authorization fence rejects it

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: an account holder with a valid OAuth/DPoP request concurrent with an operator or lifecycle deactivation. Protected asset: the account's durable public repository integrity and revocation boundary. This is source-demonstrated but was not dynamically exercised during read-only discovery. Additional context: The fallback is documented as intentional for pre/post-deactivation commits, but it conflicts with the adversarial scan invariant that lifecycle races must not bypass authorization/state transitions.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-22"></a>

### [22] Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | medium |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at source Dockerfile:21-30; root_control Sources/swan/SwanCommand.swift:130-180; sink Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-16, CWE-345 |
| Affected lines | Dockerfile:21-30, Sources/swan/SwanCommand.swift:130-180, docker-compose.yml:66-107, interop/notification-config.json:15-18, Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:299-320, Sources/swan/SwanCommand.swift:2547-2565, Sources/swan/SwanCommand.swift:78-88, Sources/SwanAccounts/PLCClient.swift:249-263, Sources/swan/SwanCommand.swift:160-225, Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545 |

#### Summary

Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The runtime Dockerfile copies the checked-in interop notification configuration and helpers into every image. That configuration selects an HTTP reference-plc origin with laboratory=true and an allowlisted private service hostname. SwanCommand's ordinary notification-config loader selects PLCClientConfiguration.laboratory solely from the file boolean; it does not require a separate laboratory serve mode or reject laboratory resolution for a public HTTPS issuer. The checked-in Compose service demonstrates activation through --notification-config on a 0.0.0.0 listener alongside live routes. Additional ordered discovery: Notification JSON directly controls `credentialKeyPLC.laboratory` and `delegationKeyPLC.laboratory`. When true, the ordinary `serve` command constructs `PLCClientConfiguration.laboratory`, which permits literal-loopback or an arbitrary explicitly allowlisted hostname over HTTP; there is no process-wide production/laboratory gate. The resulting remote resolvers are composed into space-credential and repository-credential verification. A bearer credential on repository-sync routes causes key resolution for its configured, allowed issuer. The PLC resolver fetches state and audit over that transport, checks state/audit/CID consistency, and advances continuity, but the shown boundary does not independently authenticate the first observed PLC history. An on-path attacker or compromised allowlisted lab service could therefore substitute the initial authority key and supply a credential signed by that key.

#### Validation

Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification. Static trace locations: source Dockerfile:21-30; root_control Sources/swan/SwanCommand.swift:130-180; sink Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545 The runtime Dockerfile copies the checked-in interop notification configuration and helpers into every image. That configuration selects an HTTP reference-plc origin with laboratory=true and an allowlisted private service hostname. SwanCommand's ordinary notification-config loader selects PLCClientConfiguration.laboratory solely from the file boolean; it does not require a separate laboratory serve mode or reject laboratory resolution for a public HTTPS issuer. The checked-in Compose service demonstrates activation through --notification-config on a 0.0.0.0 listener alongside live routes. Additional ordered discovery: Notification JSON directly controls `credentialKeyPLC.laboratory` and `delegationKeyPLC.laboratory`. When true, the ordinary `serve` command constructs `PLCClientConfiguration.laboratory`, which permits literal-loopback or an arbitrary explicitly allowlisted hostname over HTTP; there is no process-wide production/laboratory gate. The resulting remote resolvers are composed into space-credential and repository-credential verification. A bearer credential on repository-sync routes causes key resolution for its configured, allowed issuer. The PLC resolver fetches state and audit over that transport, checks state/audit/CID consistency, and advances continuity, but the shown boundary does not independently authenticate the first observed PLC history. An on-path attacker or compromised allowlisted lab service could therefore substitute the initial authority key and supply a credential signed by that key.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Dockerfile:21-30 reaches the incomplete control at Sources/swan/SwanCommand.swift:130-180 and then Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545. Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.

- **Source:** Dockerfile:21-30

- **Sink:** Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545

- **Outcome:** Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker input is not request-selected: activation requires an operator to deploy the embedded configuration. The risk is accidental production reachability of a lab trust relaxation and private HTTP PLC resolver. The Compose topology publishes Caddy only on loopback, destinations and PLC hosts are static allowlists, and the embedded file is inactive unless --notification-config is supplied. No attacker-directed SSRF or live swan.place exposure was demonstrated. Additional context: Prerequisites are substantial: an operator must explicitly install a notification config with `laboratory: true`, the targeted issuer must be on the static authority/delegation allowlist, and the attacker must con

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-23"></a>

### [23] The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/swan/SwanCommand.swift:1799-1800; root_control Sources/SwanHTTP/SwanHTTP.swift:869-875; sink Sources/SwanHTTP/SwanHTTP.swift:875-980; no reviewed control closes the stated path. |
| Category | configuration-boundary |
| CWE | CWE-16, CWE-284, CWE-436, CWE-840 |
| Affected lines | Sources/SwanHTTP/SwanHTTP.swift:869-875, Sources/SwanHTTP/SwanHTTP.swift:875-980, docs/superpowers/records/2026-08-12-swan-production-readiness/README.md:35-43, Sources/swan/SwanCommand.swift:1799-1800, Sources/swan/SwanCommand.swift:2295, Sources/SwanHTTP/SwanHTTP.swift:875-980, Profiles/permissioned-data-0016-2026-07-03.json:1-20, docs/superpowers/records/2026-08-12-swan-production-readiness/task-10-report.md:300-303, Sources/swan/SwanCommand.swift:2295-2301, Sources/SwanCore/SwanCore.swift:55-107 |

#### Summary

The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. SwanHTTP advertises the loaded profile id but installs permissioned handlers by iterating the build-wide PermissionedData0016.methods registry, not the selected ProtocolProfile's method inventory. The production-readiness execution record explicitly marks this mismatch as still open. A valid narrower profile can therefore express or attest a reduced method set while the Internet-facing router continues to answer every compiled permissioned NSID whose capability is configured, leaving endpoint authentication as the only control rather than honoring the operator-selected surface. Additional ordered discovery: The serve command loads --profile and describeServer reports that profile ID, but SwanHTTP always iterates PermissionedData0016.methods. The assigned production-readiness report explicitly records that selecting the 07-03 profile still installs the 07-30 permissioned surface. The two current profiles list the same NSIDs, so an immediate authorization bypass is not established, but the control becomes unsafe when profile method sets diverge. The new ordered source independently traces the operator-decoded profile endpoints through serve composition to route construction, where every build-wide PermissionedData0016 method is registered as either an available handler or a 503 gate regardless of the selected profile.endpoints. Production-readiness records still identify the mismatch as open. Additional ordered discovery: describeServer returns the operator-loaded profile.id, but buildRouter iterates the hardcoded PermissionedData0016.methods registry. The checked-in production-readiness report explicitly records this as unfixed. A divergent older, future, or narrowed profile can therefore be attested on the wire while a different endpoint surface is served. Additional or

#### Validation

The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:1799-1800; root_control Sources/SwanHTTP/SwanHTTP.swift:869-875; sink Sources/SwanHTTP/SwanHTTP.swift:875-980 SwanHTTP advertises the loaded profile id but installs permissioned handlers by iterating the build-wide PermissionedData0016.methods registry, not the selected ProtocolProfile's method inventory. The production-readiness execution record explicitly marks this mismatch as still open. A valid narrower profile can therefore express or attest a reduced method set while the Internet-facing router continues to answer every compiled permissioned NSID whose capability is configured, leaving endpoint authentication as the only control rather than honoring the operator-selected surface. Additional ordered discovery: The serve command loads --profile and describeServer reports that profile ID, but SwanHTTP always iterates PermissionedData0016.methods. The assigned production-readiness report explicitly records that selecting the 07-03 profile still installs the 07-30 permissioned surface. The two current profiles list the same NSIDs, so an immediate authorization bypass is not established, but the control becomes unsafe when profile method sets diverge. The new ordered source independently traces the operator-decoded profile endpoints through serve composition to route construction, where every build-wide PermissionedData0016 method is registered as either an available handler or a 503 gate regardless of the selected profile.endpoints. Production-readiness records still identify the mismatch as open. Additional ordered discovery: describeServer returns the operator-loaded profile.id, but buildRouter iterates the hardcoded PermissionedData0016.methods registry. The checked-in production-readiness report explicitly records this as unfixed. A divergent older, future, or narrowed profile can therefore be attested on the wire while a different endpoint surface is served. Additional or

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/swan/SwanCommand.swift:1799-1800 reaches the incomplete control at Sources/SwanHTTP/SwanHTTP.swift:869-875 and then Sources/SwanHTTP/SwanHTTP.swift:875-980. The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.

- **Source:** Sources/swan/SwanCommand.swift:1799-1800

- **Sink:** Sources/SwanHTTP/SwanHTTP.swift:875-980

- **Outcome:** The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Both currently checked-in permissioned profiles contain the same method inventory and endpoint-level authorization remains in place, so no present unauthenticated bypass is demonstrated. The risk becomes concrete for a valid narrowed or future profile used to disable a method or feature in production. Additional context: Configuration/schema-version confusion at the production route boundary; currently documented as unfixed backlog. The added source confirms that both checked-in profiles currently contain the same 25 methods and each live handler retains capability and authentication checks, so the concrete risk remains a narrowed or future custom profile rather than a present credential byp

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Make the selected profile constrain the installed parser/routes and make lab trust material structurally unavailable to ordinary production composition; reject mixed production/lab configuration at startup.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-24"></a>

### [24] Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/SwanHTTP.swift:1159-1175; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163, Sources/SwanHTTP/SwanHTTP.swift:1159-1175, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367, Sources/SwanHTTP/SwanHTTP.swift:1125-1156, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:330-350, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:136-163, Sources/SwanHTTP/SwanHTTP.swift:1125-1155, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:330-359 |

#### Summary

Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. subscribeRepos upgrades anonymous clients without an inbound-message rate or aggregate-byte budget. Each accepted connection creates multiple tasks and database/tailer state, and its inbound drain task repeatedly accepts, copies, and discards attacker-controlled frames up to 5,000,000 bytes. Even within any route-level connection allowance, admitted clients can continuously send maximum frames to consume memory-copy, event-loop, and parsing/drain work; enough sessions also occupy the listener-wide allowance and deny unrelated HTTP and OAuth traffic. The added discovery clarifies that the 5,000,000-byte maximum exists for outbound commit frames but applies symmetrically inbound, where subscribeRepos defines no client-data protocol; the task fully iterates and discards every such frame without count, byte, or rate budgets. The new ordered source independently traces the anonymous upgrade, the symmetric 5,000,000-byte frame ceiling selected for outbound commits, and the inbound task that continuously drains and discards every client message without message-type, cumulative-byte, rate, or per-peer limits.

#### Validation

Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/SwanHTTP.swift:1159-1175; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367 subscribeRepos upgrades anonymous clients without an inbound-message rate or aggregate-byte budget. Each accepted connection creates multiple tasks and database/tailer state, and its inbound drain task repeatedly accepts, copies, and discards attacker-controlled frames up to 5,000,000 bytes. Even within any route-level connection allowance, admitted clients can continuously send maximum frames to consume memory-copy, event-loop, and parsing/drain work; enough sessions also occupy the listener-wide allowance and deny unrelated HTTP and OAuth traffic. The added discovery clarifies that the 5,000,000-byte maximum exists for outbound commit frames but applies symmetrically inbound, where subscribeRepos defines no client-data protocol; the task fully iterates and discards every such frame without count, byte, or rate budgets. The new ordered source independently traces the anonymous upgrade, the symmetric 5,000,000-byte frame ceiling selected for outbound commits, and the inbound task that continuously drains and discards every client message without message-type, cumulative-byte, rate, or per-peer limits.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163 reaches the incomplete control at Sources/SwanHTTP/SwanHTTP.swift:1159-1175 and then Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367. Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.

- **Source:** Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163

- **Sink:** Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367

- **Outcome:** Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The listener has a default 256-connection global bound, ping and close timeouts, and outbound slow-consumer controls. Those controls bound simultaneous sessions and outbound stalls but do not limit inbound frame rate, per-session bytes, or aggregate inbound work. Route-level subscriber admission addresses listener monopolization but does not by itself stop abusive frames from admitted clients. This preserves the oversized-inbound-firehose-frames subcase and its CPU, memory, event-loop, network, and shared-pool pressure across parallel admitted sessions. The added source retains uncertainty about Hummingbird buffering and backpressure and notes the global 256-connection cap, ping/close timeou

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-25"></a>

### [25] Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18; sink Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163, Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18, Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:312-367, Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:58-73, Sources/SwanHTTP/SwanHTTP.swift:1125-1151, Sources/SwanHTTP/SwanHTTP.swift:1125-1136, Sources/SwanHTTP/PublicFirehoseStreaming.swift:173-247, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:235-367, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:145-162 |

#### Summary

Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The public subscribeRepos upgrader accepts every syntactically valid unauthenticated request. Each accepted responsive connection occupies one of the listener-wide 256 default connection slots, creates an inbound drain task, wakeup subscription/forwarder, repeatedly polling SQLite tailer, and outbound writer, and remains live indefinitely if it answers automatic pings. The hub subscriber dictionary has no capacity check and every append/retention signal iterates and yields to every subscriber. Cursor, lag, per-write, and slow-consumer controls bound some individual work but do not evict idle responsive clients; maximumWriteDuration is evaluated only after a write returns rather than enforcing a deadline. Enough compliant WebSockets can therefore deny unrelated public reads, OAuth, repository, account, and XRPC traffic and make each repository event O(attacker subscribers). Existing tests exercise individual lag/write behavior but not endpoint-specific concurrent admission. The idle tailer performs roughly two SQLite reads per 250 ms polling interval per responsive connection, so even subscribers that are not lagging or slow-writing amplify steady database work. Additional discovery identifies the concrete cross-route effect: roughly the default 256 responsive firehose sockets can occupy the listener-wide MaximumAvailableConnections budget shared with login, OAuth, public repository, and permissioned routes. Each accepted session resolves cursors, registers a hub subscriber, starts forwarding, drain, writer, and tailer work, and an idle tailer repeatedly queries retainedFromSeq/events about every 250 ms. Auto-ping, close timeout, per-stream lag, and write-deadline policies constrain dead or slow consumers but do not evict responsive idle subscribers or reserve listener c

#### Validation

Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18; sink Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30 The public subscribeRepos upgrader accepts every syntactically valid unauthenticated request. Each accepted responsive connection occupies one of the listener-wide 256 default connection slots, creates an inbound drain task, wakeup subscription/forwarder, repeatedly polling SQLite tailer, and outbound writer, and remains live indefinitely if it answers automatic pings. The hub subscriber dictionary has no capacity check and every append/retention signal iterates and yields to every subscriber. Cursor, lag, per-write, and slow-consumer controls bound some individual work but do not evict idle responsive clients; maximumWriteDuration is evaluated only after a write returns rather than enforcing a deadline. Enough compliant WebSockets can therefore deny unrelated public reads, OAuth, repository, account, and XRPC traffic and make each repository event O(attacker subscribers). Existing tests exercise individual lag/write behavior but not endpoint-specific concurrent admission. The idle tailer performs roughly two SQLite reads per 250 ms polling interval per responsive connection, so even subscribers that are not lagging or slow-writing amplify steady database work. Additional discovery identifies the concrete cross-route effect: roughly the default 256 responsive firehose sockets can occupy the listener-wide MaximumAvailableConnections budget shared with login, OAuth, public repository, and permissioned routes. Each accepted session resolves cursors, registers a hub subscriber, starts forwarding, drain, writer, and tailer work, and an idle tailer repeatedly queries retainedFromSeq/events about every 250 ms. Auto-ping, close timeout, per-stream lag, and write-deadline policies constrain dead or slow consumers but do not evict

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163 reaches the incomplete control at Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18 and then Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30. Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.

- **Source:** Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163

- **Sink:** Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30

- **Outcome:** Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Internet reachable when the public firehose runtime and subscribeRepos profile surface are enabled. An external proxy may impose quotas, but neither the in-process route nor the checked-in lab proxy supplies a firehose-specific aggregate or per-client bound. The listener-wide ceiling bounds process growth while enabling cross-route starvation. The feature is opt-in and the listener ceiling bounds simultaneous growth; those are countercontrols but turn the issue into deterministic shared-listener starvation rather than preventing it. Attacker capability: anonymous Internet TCP/WebSocket access. Entry point: /xrpc/com.atproto.sync.subscribeRepos. Protected asset: availability of all routes sha

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-26"></a>

### [26] Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335; sink Sources/SwanSQLite/OAuthControlStore.swift:1225-1289; no reviewed control closes the stated path. |
| Category | security-control-bypass |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-234, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335, Sources/SwanSQLite/OAuthControlStore.swift:1225-1289, Sources/SwanSQLite/OAuthControlStore.swift:399-415, Sources/SwanSQLite/OAuthControlStore.swift:102-129, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-233, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:115-164, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:235-299, Sources/SwanSQLite/OAuthControlStore.swift:1197-1275 |

#### Summary

Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The unauthenticated production PAR endpoint accepts an attacker-selected client_id after DPoP proof-of-key and nonce validation; those checks do not authorize a pre-registered client. OAuthClientMetadataLoader calls beginClientMetadataFetch before any remote document, JSON, client profile, or JWKS validation. The SQLite store immediately inserts or refreshes a distinct client_id in oauth_control_client_metadata_freshness with retain_until one hour in the future, under a global production cap of 8,192 rows. Failure of fetch or validation has no cleanup/abandon operation. An attacker controlling a public HTTPS origin can therefore rotate 8,192 URL paths and return small invalid documents sequentially, filling the durable capacity; subsequent legitimate previously unseen clients receive capacity exhaustion until rows expire and batched cleanup drains them. Eight concurrent remote-fetch permits, strict SSRF policy, and the hard row cap bound resource use but do not prevent this low-cost durable capacity poisoning; already cached clients remain usable. Added ordered discovery confirms ticket issuance inserts or refreshes the per-client one-hour row before DNS or HTTP, that invalid or failed remote documents do not roll it back, cleanup removes only expired orphan rows in bounded batches, and 8,192 attacker-chosen client IDs can block unseen legitimate clients while existing cached clients remain usable.

#### Validation

Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335; sink Sources/SwanSQLite/OAuthControlStore.swift:1225-1289 The unauthenticated production PAR endpoint accepts an attacker-selected client_id after DPoP proof-of-key and nonce validation; those checks do not authorize a pre-registered client. OAuthClientMetadataLoader calls beginClientMetadataFetch before any remote document, JSON, client profile, or JWKS validation. The SQLite store immediately inserts or refreshes a distinct client_id in oauth_control_client_metadata_freshness with retain_until one hour in the future, under a global production cap of 8,192 rows. Failure of fetch or validation has no cleanup/abandon operation. An attacker controlling a public HTTPS origin can therefore rotate 8,192 URL paths and return small invalid documents sequentially, filling the durable capacity; subsequent legitimate previously unseen clients receive capacity exhaustion until rows expire and batched cleanup drains them. Eight concurrent remote-fetch permits, strict SSRF policy, and the hard row cap bound resource use but do not prevent this low-cost durable capacity poisoning; already cached clients remain usable. Added ordered discovery confirms ticket issuance inserts or refreshes the per-client one-hour row before DNS or HTTP, that invalid or failed remote documents do not roll it back, cleanup removes only expired orphan rows in bounded batches, and 8,192 attacker-chosen client IDs can block unseen legitimate clients while existing cached clients remain usable.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180 reaches the incomplete control at Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335 and then Sources/SwanSQLite/OAuthControlStore.swift:1225-1289. Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding

- **Source:** Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180

- **Sink:** Sources/SwanSQLite/OAuthControlStore.swift:1225-1289

- **Outcome:** Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: create valid self-signed DPoP proofs and serve attacker-controlled HTTPS metadata URLs. Protected asset: OAuth PAR availability for new clients. No network validation was performed. The added source preserves the bounded conditions: thousands of public PAR attempts, attacker-controlled HTTPS responses, a globally shared 8,192-row cap, and at most one hour of retention.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-27"></a>

### [27] Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-367, CWE-613 |
| Affected lines | Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140, Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223, Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751, Sources/SwanOAuth/SpaceCredentialAuthority.swift:695-751 |

#### Summary

Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The credential endpoint invokes the durable issuer, which resolves its local authority key through LocalAccountSpaceCredentialSigningKeyResolver. That resolver reads an authorizing account row and key references at lines 207-209, then awaits keyStore.key at line 213 and returns the private key without re-reading the account lifecycle or generation. The caller immediately signs a two-hour space credential at lines 744-751. Account deactivation, permanent-deletion revocation, or key rotation can therefore interleave after the authorizing snapshot and before signature creation. The verification-only resolver elsewhere explicitly re-reads the account after its external metadata read, which is strong counterevidence for verification but highlights the missing equivalent fence on this signing path. LocalAccountSpaceCredentialSigningKeyResolver checks account status and obtains key references at lines 207-212, then awaits keyStore.key(for:) at line 213 and returns without re-reading account lifecycle or generation. DurableSpaceCredentialAuthority performs policy authorization, awaits this resolver at lines 738-742, and signs at lines 744-751. Concurrent deactivation or rotation can therefore yield a key authorized only by stale facts. Verification resolvers in the same file deliberately re-read the complete account after key access (lines 304-317 and 397-410), providing internal evidence for the missing fence.

#### Validation

Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140; root_control Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751 The credential endpoint invokes the durable issuer, which resolves its local authority key through LocalAccountSpaceCredentialSigningKeyResolver. That resolver reads an authorizing account row and key references at lines 207-209, then awaits keyStore.key at line 213 and returns the private key without re-reading the account lifecycle or generation. The caller immediately signs a two-hour space credential at lines 744-751. Account deactivation, permanent-deletion revocation, or key rotation can therefore interleave after the authorizing snapshot and before signature creation. The verification-only resolver elsewhere explicitly re-reads the account after its external metadata read, which is strong counterevidence for verification but highlights the missing equivalent fence on this signing path. LocalAccountSpaceCredentialSigningKeyResolver checks account status and obtains key references at lines 207-212, then awaits keyStore.key(for:) at line 213 and returns without re-reading account lifecycle or generation. DurableSpaceCredentialAuthority performs policy authorization, awaits this resolver at lines 738-742, and signs at lines 744-751. Concurrent deactivation or rotation can therefore yield a key authorized only by stale facts. Verification resolvers in the same file deliberately re-read the complete account after key access (lines 304-317 and 397-410), providing internal evidence for the missing fence.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140 reaches the incomplete control at Sources/SwanOAuth/SpaceCredentialAuthority.swift:204-223 and then Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751. Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.

- **Source:** Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:134-140

- **Sink:** Sources/SwanOAuth/SpaceCredentialAuthority.swift:738-751

- **Outcome:** Authority lifecycle and signing-key generation can change during async space-credential key resolution, allowing a fresh credential to be signed with stale authority.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: A valid delegation is still required. Local verification may reject a token after a completed lifecycle/key transition, but a cross-host verifier with an accepted prior PLC/pinned key can accept a token minted after local authority was revoked unless the transition and signer are fenced. Exact requester/user/space matching, delegation or OAuth context, durable reader policy, dedicated kid, and short lifetime are strong controls; local managed-key verification also fails closed after deactivation. Parent validation should determine whether cross-host verification can accept the old PLC or dedicated key during propagation and whether an outer lifecycle transaction prevents the interleaving.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-28"></a>

### [28] Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80; root_control Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82; sink Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171, Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:893-932, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:139, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-80, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-170, Sources/SwanHTTP/SwanHTTP.swift:696-700, Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:109-110, Sources/SwanStorage/PublicRepositoryReadDirectory.swift:876-880 |

#### Summary

Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. AuthenticatedGetSpaceBlobHandler reserves maximumPermissionedBlobTransferBytes before querying the directory or learning blob.body.contentLength and holds the lease until streaming terminates. The default admission permits 1 GiB globally and 512 MiB per account, making two requests against one author or four across authors sufficient to consume byte admission even for tiny blobs. The public blob route instead obtains metadata and reserves the true size to avoid the same starvation condition. Additional ordered discovery: Production wires this handler to `directory.publicRepositorySpoolAdmission`, whose defaults are 1 GiB globally and 512 MiB per account. The fixed reservation is retained for the response lifetime and adjusted only after the actual content length is known. Two stalled tiny-blob reads can consume one author's allowance, while reads spanning four authors can reserve the global pool and deny unrelated public CAR and blob streams despite transferring little data. The added trace also establishes that a member reading across multiple writer repositories can span per-account allowances and consume the global pool shared not only with public CAR and blob reads but also uploads.

#### Validation

Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80; root_control Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82; sink Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171 AuthenticatedGetSpaceBlobHandler reserves maximumPermissionedBlobTransferBytes before querying the directory or learning blob.body.contentLength and holds the lease until streaming terminates. The default admission permits 1 GiB globally and 512 MiB per account, making two requests against one author or four across authors sufficient to consume byte admission even for tiny blobs. The public blob route instead obtains metadata and reserves the true size to avoid the same starvation condition. Additional ordered discovery: Production wires this handler to `directory.publicRepositorySpoolAdmission`, whose defaults are 1 GiB globally and 512 MiB per account. The fixed reservation is retained for the response lifetime and adjusted only after the actual content length is known. Two stalled tiny-blob reads can consume one author's allowance, while reads spanning four authors can reserve the global pool and deny unrelated public CAR and blob streams despite transferring little data. The added trace also establishes that a member reading across multiple writer repositories can span per-account allowances and consume the global pool shared not only with public CAR and blob reads but also uploads.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80 reaches the incomplete control at Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:77-82 and then Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171. Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.

- **Source:** Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:65-80

- **Sink:** Sources/SwanHTTP/SwanSpaceBlobXRPC.swift:164-171

- **Outcome:** Permissioned blob reads reserve a fixed 256 MiB before metadata lookup, so a few authorized stalled small reads can exhaust the production process-wide spool budget.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Exploitation requires a valid space credential or matching account OAuth principal and slow or stalled response consumption. Existing admission bounds memory and concurrent damage but makes over-reservation an efficient availability primitive. Additional context: Public blob reads demonstrate the available size-aware control by reserving the metadata-reported length. Exploitation requires valid OAuth or space authorization, readable blob targets, and clients able to retain response streams; the finite budgets bound total use but make starvation attainable with very few requests.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-29"></a>

### [29] The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101; sink Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72; no reviewed control closes the stated path. |
| Category | identity-and-ssrf |
| CWE | CWE-918 |
| Affected lines | Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233, Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:129-164, Sources/SwanAccounts/ATHandleVerification.swift:105-118, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:232-234, Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72, Sources/SwanOAuth/OAuthRemoteFetch.swift:137-169, Sources/SwanAccounts/ATHandleVerification.swift:100-113, Sources/SwanOAuth/OAuthRemoteFetch.swift:351-366 |

#### Summary

The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. OAuthIPAddress accepts all 2000::/3 except 2001:db8::/32 and a small portion of 2001::/32. Special-purpose prefixes including 2002::/16 6to4, 2001:20::/28 ORCHIDv2, and 3fff::/20 documentation therefore pass, while the parallel AT-handle classifier explicitly rejects these classes. Public PAR can select metadata client IDs that reach this policy. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts nearly all 2000::/3 addresses and does not reject 2002::/16, so literals such as 2002:7f00:1:: and DNS answers in that range pass URL and resolved-address checks and are supplied as approved peer pins to outbound transports. Public PAR loads attacker-selected HTTPS client metadata through this policy. Swan's independent handle-fetch classifier explicitly rejects 2002::/16, demonstrating the missing special-purpose check. Added ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts 2002::/16 within its broad 2000::/3 allowance. A 6to4 address can embed an IPv4 destination that the same policy rejects directly, and resolved OAuth metadata or JWKS, did:web, and authenticated proxy service hosts are policy-checked with this classifier before a peer-pinned connection. The parallel ATHandleIPAddress classifier explicitly rejects 2002::/16, confirming inconsistent special-purpose handling. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts any IPv6 address in 2000::/3 except 2001:db8::/32 and approximately 2001::/20. This leaves at least 2002::/16 (6to4) and 3fff::/20 (documentation) classified as public. The repository's AT-handle policy rejects both ranges in Sources/SwanAccounts/ATHandleVerification.swift:101-113. An attacker-selected OAuth metadata or JWKS hostname can therefore place one of these addresses in the appr

#### Validation

The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101; sink Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72 OAuthIPAddress accepts all 2000::/3 except 2001:db8::/32 and a small portion of 2001::/32. Special-purpose prefixes including 2002::/16 6to4, 2001:20::/28 ORCHIDv2, and 3fff::/20 documentation therefore pass, while the parallel AT-handle classifier explicitly rejects these classes. Public PAR can select metadata client IDs that reach this policy. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts nearly all 2000::/3 addresses and does not reject 2002::/16, so literals such as 2002:7f00:1:: and DNS answers in that range pass URL and resolved-address checks and are supplied as approved peer pins to outbound transports. Public PAR loads attacker-selected HTTPS client metadata through this policy. Swan's independent handle-fetch classifier explicitly rejects 2002::/16, demonstrating the missing special-purpose check. Added ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts 2002::/16 within its broad 2000::/3 allowance. A 6to4 address can embed an IPv4 destination that the same policy rejects directly, and resolved OAuth metadata or JWKS, did:web, and authenticated proxy service hosts are policy-checked with this classifier before a peer-pinned connection. The parallel ATHandleIPAddress classifier explicitly rejects 2002::/16, confirming inconsistent special-purpose handling. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts any IPv6 address in 2000::/3 except 2001:db8::/32 and approximately 2001::/20. This leaves at least 2002::/16 (6to4) and 3fff::/20 (documentation) classified as public. The repository's AT-handle policy rejects both ranges in Sources/SwanAccounts/ATHandleVerification.swift:101-113. An attacker-selected OAuth metadata or JWKS hostname can therefore place one of these addresses in t

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168 reaches the incomplete control at Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101 and then Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72. The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.

- **Source:** Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168

- **Sink:** Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72

- **Outcome:** The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Peer pinning, TLS hostname validation, redirect rejection, and deployment routing constrain exploitability; practical internal response retrieval was not demonstrated. Additional context: Practical exploitation depends on functional 6to4 routing and compatible TLS/target behavior; exact peer pinning and hostname certificate validation limit ordinary deployments. Where 6to4 is routed, the policy can permit blind internal reachability or side effects that the stated SSRF boundary intends to reject. Additional context: Practical exploitation is conditional on usable 6to4 routing and a TLS endpoint valid for the attacker-selected hostname or relevant laboratory trust. Modern deployments often la

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-30"></a>

### [30] Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at source Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119; root_control Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56; sink Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432; no reviewed control closes the stated path. |
| Category | identity-and-ssrf |
| CWE | CWE-345, CWE-441, CWE-346, CWE-200 |
| Affected lines | Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119, Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56, Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432, Sources/SwanHTTP/SwanXRPCPipethrough.swift:400-445, Sources/SwanOAuth/SwanServiceEndpointResolver.swift:71-95, Sources/SwanOAuth/SwanServiceEndpointResolver.swift:36-56, Sources/SwanAccounts/PLCClient.swift:395-417, Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-440, Sources/SwanOAuth/SwanServiceEndpointResolver.swift:92-119, Sources/SwanOAuth/SwanServiceEndpointResolver.swift:36-55 |

#### Summary

Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. SwanServiceEndpointResolver's decoded Document omits the top-level id, so it does not require the returned document identity to equal the requested DID; it selects a matching service fragment using the caller-supplied DID and returns its endpoint. For did:plc, SwanPeerPinnedDIDDocumentFetcher derives the configured PLC directory URL and accepts fetchJSON bytes with transport, redirect, address, and size controls, but it does not verify the PLC audit chain or bind the returned id, services, keys, and aliases to verified terminal PLC state. The authenticated XRPC pipethrough then mints an account service JWT whose audience is the requested DID and whose method is bound to the request, and sends the token and proxied request to the selected endpoint. The separate PLCDirectoryClient.fetchState demonstrates the stronger available control by fetching the audit chain and comparing terminal rotation keys, verification methods, aliases, and services. A compromised, malicious, stale, misbound, or incorrectly served external identity-authority response can therefore substitute a public HTTPS endpoint and receive the signed service JWT and body, including when the document claims the requested id but its PLC state is unverified. Counterevidence is substantial: document URLs are canonically derived; peer pinning blocks private-address SSRF, redirects, and DNS rebinding; the source directory is normally authoritative; audience and lxm binding limit token reuse; and account DPoP authorization precedes resolution, so ordinary unauthenticated callers cannot trigger the path. Additional ordered discovery: SwanPeerPinnedDIDDocumentFetcher maps did:plc directly to the configured PLC origin and returns the generic peer-pinned JSON response. SwanServiceEndpointResolver decodes only the servi

#### Validation

Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint. Static trace locations: source Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119; root_control Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56; sink Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432 SwanServiceEndpointResolver's decoded Document omits the top-level id, so it does not require the returned document identity to equal the requested DID; it selects a matching service fragment using the caller-supplied DID and returns its endpoint. For did:plc, SwanPeerPinnedDIDDocumentFetcher derives the configured PLC directory URL and accepts fetchJSON bytes with transport, redirect, address, and size controls, but it does not verify the PLC audit chain or bind the returned id, services, keys, and aliases to verified terminal PLC state. The authenticated XRPC pipethrough then mints an account service JWT whose audience is the requested DID and whose method is bound to the request, and sends the token and proxied request to the selected endpoint. The separate PLCDirectoryClient.fetchState demonstrates the stronger available control by fetching the audit chain and comparing terminal rotation keys, verification methods, aliases, and services. A compromised, malicious, stale, misbound, or incorrectly served external identity-authority response can therefore substitute a public HTTPS endpoint and receive the signed service JWT and body, including when the document claims the requested id but its PLC state is unverified. Counterevidence is substantial: document URLs are canonically derived; peer pinning blocks private-address SSRF, redirects, and DNS rebinding; the source directory is normally authoritative; audience and lxm binding limit token reuse; and account DPoP authorization precedes resolution, so ordinary unauthenticated callers cannot trigger the path. Additional ordered discovery: SwanPeerPinnedDIDDocumentFetcher maps did:plc directly to the configured PLC origin and returns the generic peer-pinned JSON response. SwanServiceEndpointResolver decodes

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119 reaches the incomplete control at Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56 and then Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432. Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.

- **Source:** Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119

- **Sink:** Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432

- **Outcome:** Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Identity and authenticity binding gap at the boundary between remote DID resolution and authenticated service proxying. Exploitation requires resolver misbinding or control, compromise, or misbehavior of the configured external identity authority while retaining an accepted transport identity. The PLC subcase is confused-deputy routing to a substituted public endpoint, not private-network SSRF; non-PLC DID methods still require returned-document id equality. Additional context: Strongest counterevidence/proof gap: HTTPS, DNS/peer pinning, no redirects, public-address policy, exact service-fragment matching, and downstream JWT aud/lxm binding prevent ordinary SSRF and cross-method token reuse

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-31"></a>

### [31] Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950; root_control Sources/SwanSpaces/SwanSpaces.swift:1605-1661; sink Sources/SwanSQLite/SwanSQLite.swift:3531-3571; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950, Sources/SwanSpaces/SwanSpaces.swift:1605-1661, Sources/SwanSQLite/SwanSQLite.swift:3531-3571, Sources/SwanSQLite/SwanSQLite.swift:3410-3475, Sources/SwanHTTP/SwanSpaceXRPC.swift:850-860, Sources/SwanSQLite/SwanSQLite.swift:3418-3432, Sources/SwanSpaces/SwanSpaces.swift:1605-1660, Sources/SwanSQLite/SwanSQLite.swift:3531-3572, Sources/SwanSQLite/SwanSQLite.swift:3648-3660, Sources/SwanSQLite/SwanSQLite.swift:3682-3710 |

#### Summary

Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. An OAuth-authorized repository author can create unbounded distinct collection/rkey records in successive requests. Each request is limited to roughly 1 MiB and the oplog is pruned, but current permissioned_space_records values persist without an aggregate live-record count or byte ceiling, allowing disk exhaustion through valid writes. Additional ordered discovery: a repository author with valid account OAuth can repeatedly create unique permissioned collection and rkey paths. SpaceWriteLimits caps one batch at 4,096 operations and 1 MiB of values, but the transaction checks neither cumulative live-record count nor total stored value bytes before inserting current records. Full-CAR production separately refuses repositories above 100,000 records or its metadata and body budgets, so writes accepted by the mutation path can make required full recovery unavailable before eventual disk exhaustion. Each unique mutation also leaves a request-receipt row, compounding storage; that independently retained receipt table remains represented by its separate canonical candidate.

#### Validation

Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950; root_control Sources/SwanSpaces/SwanSpaces.swift:1605-1661; sink Sources/SwanSQLite/SwanSQLite.swift:3531-3571 An OAuth-authorized repository author can create unbounded distinct collection/rkey records in successive requests. Each request is limited to roughly 1 MiB and the oplog is pruned, but current permissioned_space_records values persist without an aggregate live-record count or byte ceiling, allowing disk exhaustion through valid writes. Additional ordered discovery: a repository author with valid account OAuth can repeatedly create unique permissioned collection and rkey paths. SpaceWriteLimits caps one batch at 4,096 operations and 1 MiB of values, but the transaction checks neither cumulative live-record count nor total stored value bytes before inserting current records. Full-CAR production separately refuses repositories above 100,000 records or its metadata and body budgets, so writes accepted by the mutation path can make required full recovery unavailable before eventual disk exhaustion. Each unique mutation also leaves a request-receipt row, compounding storage; that independently retained receipt table remains represented by its separate canonical candidate.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950 reaches the incomplete control at Sources/SwanSpaces/SwanSpaces.swift:1605-1661 and then Sources/SwanSQLite/SwanSQLite.swift:3531-3571. Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.

- **Source:** Sources/SwanHTTP/SwanSpaceXRPC.swift:908-950

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:3531-3571

- **Outcome:** Authenticated permissioned writes have per-batch limits but no cumulative live-record count or byte quota, allowing repositories to exceed full-recovery bounds and exhaust storage.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Only an authenticated author with the applicable OAuth write grant can reach the sink, and per-request/body plus blob admissions exist. No cumulative live permissioned-record quota was found; deployment/account storage quotas remain unknown. Additional context: writes require self-authorized account OAuth, canonical DAG-CBOR and CID validation, exact space and author binding, revision CAS, and bounded batches. Replacements keep live record cardinality stable, but unique creates grow current records and can cross the export boundary; external filesystem quotas remain unknown.

#### Severity

**Medium** — The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

Severity rises with unauthenticated cross-account exploitation or demonstrated durable data compromise, and falls if deployment disables the route or an unreviewed outer control closes the path.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-32"></a>

### [32] Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110; root_control Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64; sink Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-367, CWE-863, CWE-613 |
| Affected lines | Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64, Sources/SwanSQLite/AccountControlStore.swift:2320-2373, Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:93-107, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-58, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:58-65, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-45, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:48-64, Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:36-64 |

#### Summary

Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The authenticated getSpaceDelegationToken path first passes sender-constrained OAuth, whole-space-read scope, and active-account checks. LocalAccountSpaceDelegationTokenIssuer then reads an authorizing account and current key references, but—despite a nearby comment claiming no await follows the status check—awaits keyStore.key before signing a fresh one-minute delegation without re-reading lifecycle or reference generation. Deactivation transactionally revokes OAuth families but does not synchronize already-running signer operations. Concurrent deactivation, permanent deletion, or key rotation can therefore complete during key lookup while the in-flight request still returns a newly signed cross-host delegation. Existing tests cover inactive accounts and missing envelopes sequentially, not a suspended key read concurrent with lifecycle or generation transition. issueDelegation checks account lifecycle and reads key references at lines 41-45, then suspends at keyStore.key(for:) on line 51 before signing at lines 58-64. Contrary to the comment that there is no await after authorization, that key-store call is awaited. Concurrent deactivation or rotation can invalidate the lifecycle/reference facts while suspended, yet the resumed task signs with the previously selected reference. LocalAccountSpaceDelegationPublicKeyResolver re-reads the complete account after external key metadata access (SpaceCredentialAuthority.swift:397-410), showing the anti-TOCTOU fence absent here. Additional ordered discovery: The route authorizes the OAuth subject and active preopened account, then the issuer independently reads active account status and key references, awaits keyStore.key, and signs a 60-second delegation with those references. No lifecycle-generation lease or compare-and-set re

#### Validation

Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110; root_control Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64; sink Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64 The authenticated getSpaceDelegationToken path first passes sender-constrained OAuth, whole-space-read scope, and active-account checks. LocalAccountSpaceDelegationTokenIssuer then reads an authorizing account and current key references, but—despite a nearby comment claiming no await follows the status check—awaits keyStore.key before signing a fresh one-minute delegation without re-reading lifecycle or reference generation. Deactivation transactionally revokes OAuth families but does not synchronize already-running signer operations. Concurrent deactivation, permanent deletion, or key rotation can therefore complete during key lookup while the in-flight request still returns a newly signed cross-host delegation. Existing tests cover inactive accounts and missing envelopes sequentially, not a suspended key read concurrent with lifecycle or generation transition. issueDelegation checks account lifecycle and reads key references at lines 41-45, then suspends at keyStore.key(for:) on line 51 before signing at lines 58-64. Contrary to the comment that there is no await after authorization, that key-store call is awaited. Concurrent deactivation or rotation can invalidate the lifecycle/reference facts while suspended, yet the resumed task signs with the previously selected reference. LocalAccountSpaceDelegationPublicKeyResolver re-reads the complete account after external key metadata access (SpaceCredentialAuthority.swift:397-410), showing the anti-TOCTOU fence absent here. Additional ordered discovery: The route authorizes the OAuth subject and active preopened account, then the issuer independently reads active account status and key references, awaits keyStore.key, and signs a 60-second delegation with those references. No lifecycle-generation lease or compare-and-set re

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110 reaches the incomplete control at Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:42-64 and then Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64. Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.

- **Source:** Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:61-110

- **Sink:** Sources/SwanOAuth/SpaceDelegationTokenIssuer.swift:51-64

- **Outcome:** Account deactivation, permanent deletion, or key rotation can race delegation-token signing because lifecycle and key generation are not fenced across asynchronous key lookup.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an initially active account, a valid sender-constrained OAuth token with whole-space-read scope, and winning the concurrent lifecycle or key transition. Requests begun after deactivation are rejected. Cross-host impact is material where the authority still accepts a published or pinned old account key independently of the user PDS lifecycle. Requires an authenticated account concurrently minting a delegation while an account lifecycle or key-rotation transition occurs. Audience, space, and lifetime binding are strong controls, and a local Swan verifier rechecks managed account status. Parent validation should determine whether a remote authority can still accept the old PLC key duri

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-33"></a>

### [33] Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78; root_control Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175; sink Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-362, CWE-367 |
| Affected lines | Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78, Sources/SwanSQLite/PublicLifecycleEmitter.swift:99-107, Sources/SwanAccounts/AccountOperatorService.swift:341-364, Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175, Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177, Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift:375-408, Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift:451-477 |

#### Summary

Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. emitReactivationSync reads the lifecycle generation and later performs account-database reads and an independent outbox insert without withActiveAccountFirehoseAuthorization. emitActivation likewise commits its control-side lifecycle batch before independently inserting sync. Concurrent deactivation can advance and drain generation N+1 before delayed generation-N sync insertion. The sequencer then selects the account event when no lifecycle batch remains without rejecting a generation older than durable current generation, allowing sync after the inactive event. Existing deterministic race coverage applies to manual sync, while reactivation coverage is uncontended.

#### Validation

Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation. Static trace locations: entrypoint Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78; root_control Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175; sink Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177 emitReactivationSync reads the lifecycle generation and later performs account-database reads and an independent outbox insert without withActiveAccountFirehoseAuthorization. emitActivation likewise commits its control-side lifecycle batch before independently inserting sync. Concurrent deactivation can advance and drain generation N+1 before delayed generation-N sync insertion. The sequencer then selects the account event when no lifecycle batch remains without rejecting a generation older than durable current generation, allowing sync after the inactive event. Existing deterministic race coverage applies to manual sync, while reactivation coverage is uncontended.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78 reaches the incomplete control at Sources/SwanSQLite/PublicLifecycleEmitter.swift:134-175 and then Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177. Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.

- **Source:** Sources/SwanSQLite/PublicLifecycleEmitter.swift:48-78

- **Sink:** Sources/SwanSQLite/PublicFirehoseSequencer.swift:145-177

- **Outcome:** Activation/reactivation sync emission is not fenced against a concurrent lifecycle transition, allowing stale-generation repository sync to be sequenced after deactivation.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an authorized lifecycle operation racing the sequencer; impact is public lifecycle ordering and possible repository reannouncement after deactivation.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-34"></a>

### [34] Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at source Scripts/run-forum-live-demo.sh:21-23; root_control Dockerfile.dockerignore:1-7; sink Dockerfile:10-14; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-200, CWE-538, CWE-668 |
| Affected lines | Scripts/run-forum-live-demo.sh:21-23, Scripts/run-forum-live-demo.sh:229-256, Scripts/run-forum-live-demo.sh:737-751, Scripts/run-forum-live-demo.sh:867-868, Dockerfile.dockerignore:1-7, Dockerfile.dockerignore:31-62, Dockerfile:10-14, .gitignore:4-8, Sources/SwanInterop/ForumThreadMerger.swift:310-348, Scripts/run-first-write-notification-loss-acceptance.sh:109-125 |

#### Summary

Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Dockerfile.dockerignore excludes everything and then re-includes Swan paths, but its later exclusions omit Swan/artifacts/\*\* and Swan/.interop-live/\*\* even though Git ignores both as runtime and evidence material. Lab and acceptance runners create owner-only work directories there containing post text, temporary JSON record bodies, access, delegation, and space credentials, and other private permissioned values. Cleanup depends on normal shell traps, so crash, SIGKILL, stale residue, or concurrent builds can leave sensitive files present when a later Compose or CI build sends the context to the Docker daemon or remote BuildKit builder. Narrow final-stage or COPY selections do not prevent context transfer or builder-side caching. Added ordered discovery: Dockerfile.dockerignore re-includes the Swan tree but omits exclusions for Swan/.interop-live/\*\* and Swan/artifacts/\*\*; Compose uses the parent directory as build context and Dockerfile COPYs the admitted Swan tree into the build stage. Current ignored .interop-live JSON demonstrates that raw permissioned write bodies can occupy the omitted directory, so a build from a stale or concurrent live workspace transmits those values to a local, remote, or shared builder and retains them in an intermediate COPY layer or cache even though the final runtime stage does not copy the JSON. Additional ordered discovery: Lab scripts also install private-body and permissioned recovery or fault artifacts under the ignored Swan/.interop-live and Swan/artifacts trees. The Docker-specific ignore re-admits those trees, and JSON private bodies evade its secret-extension filters, so ordinary release builds transmit them to the builder and retain them in intermediate COPY layers or cache. Additional ordered discovery: The Docker ignore file beg

#### Validation

Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache. Static trace locations: source Scripts/run-forum-live-demo.sh:21-23; root_control Dockerfile.dockerignore:1-7; sink Dockerfile:10-14 Dockerfile.dockerignore excludes everything and then re-includes Swan paths, but its later exclusions omit Swan/artifacts/\*\* and Swan/.interop-live/\*\* even though Git ignores both as runtime and evidence material. Lab and acceptance runners create owner-only work directories there containing post text, temporary JSON record bodies, access, delegation, and space credentials, and other private permissioned values. Cleanup depends on normal shell traps, so crash, SIGKILL, stale residue, or concurrent builds can leave sensitive files present when a later Compose or CI build sends the context to the Docker daemon or remote BuildKit builder. Narrow final-stage or COPY selections do not prevent context transfer or builder-side caching. Added ordered discovery: Dockerfile.dockerignore re-includes the Swan tree but omits exclusions for Swan/.interop-live/\*\* and Swan/artifacts/\*\*; Compose uses the parent directory as build context and Dockerfile COPYs the admitted Swan tree into the build stage. Current ignored .interop-live JSON demonstrates that raw permissioned write bodies can occupy the omitted directory, so a build from a stale or concurrent live workspace transmits those values to a local, remote, or shared builder and retains them in an intermediate COPY layer or cache even though the final runtime stage does not copy the JSON. Additional ordered discovery: Lab scripts also install private-body and permissioned recovery or fault artifacts under the ignored Swan/.interop-live and Swan/artifacts trees. The Docker-specific ignore re-admits those trees, and JSON private bodies evade its secret-extension filters, so ordinary release builds transmit them to the builder and retain them in intermediate COPY layers or cache. Additional ordered discovery: The Docker ignore file beg

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Scripts/run-forum-live-demo.sh:21-23 reaches the incomplete control at Dockerfile.dockerignore:1-7 and then Dockerfile:10-14. Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.

- **Source:** Scripts/run-forum-live-demo.sh:21-23

- **Sink:** Dockerfile:10-14

- **Outcome:** Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Normal EXIT, INT, TERM, and HUP traps remove many temporary directories; most persisted artifacts are sanitized and mode 0600; and a common local builder remains on the developer host. The final runtime stage copies only selected outputs. These controls reduce ordinary exposure but do not cover crash residue, concurrency, remote or shared builders, context upload, or cache retention. Additional context: This concrete instance requires a prior live or interop run leaving raw artifacts plus access to the daemon, remote/shared builder, exported cache, or provenance. Gitignore and owner-only file modes reduce casual local exposure but do not control context transmission. Additional context: The

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Require `iat` for service JWTs and enforce `exp <= now + maximumLifetime` independently of `iat`; add absent-`iat`, distant-`exp`, replay, audience, method, and issuer negative tests.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-35"></a>

### [35] The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447; root_control Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737; no reviewed control closes the stated path. |
| Category | redirect-validation |
| CWE | CWE-601 |
| Affected lines | Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447, Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737 |

#### Summary

The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. After an account-OAuth-authorized request is routed through the peer-pinned sender, pipethroughResponse allow-lists the upstream Location header and copies its sole printable value of at most 256 bytes verbatim. It does not parse the value or restrict scheme, host, or origin. A malicious or compromised configured/resolved service can therefore return a 3xx that directs a following client to an attacker-selected destination.

#### Validation

The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447; root_control Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737 After an account-OAuth-authorized request is routed through the peer-pinned sender, pipethroughResponse allow-lists the upstream Location header and copies its sole printable value of at most 256 bytes verbatim. It does not parse the value or restrict scheme, host, or origin. A malicious or compromised configured/resolved service can therefore return a 3xx that directs a following client to an attacker-selected destination.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447 reaches the incomplete control at Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737 and then the candidate's recorded source location. The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.

- **Source:** Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447

- **Sink:** recorded protected operation

- **Outcome:** The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Authentication and peer pinning constrain who reaches the proxy and prevent server-side SSRF; they do not constrain the client-visible redirect. Practical impact depends on AT Protocol client redirect behavior.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Do not relay arbitrary upstream `Location` values under Swan's origin; reject them or allow only same-origin/same-service canonical destinations.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-36"></a>

### [36] Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375; root_control Sources/SwanAccounts/AccountLoginAdmission.swift:24-46; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-307 |
| Affected lines | Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375, Sources/SwanAccounts/AccountLoginAdmission.swift:24-46, Sources/SwanAccounts/AccountLoginAdmission.swift:95-162 |

#### Summary

Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. After a valid PAR/browser session and CSRF check, the public OAuth login handler calls admitLogin(handle:directPeer:) before password authentication. Admission canonicalizes the supplied handle and consumes handle, peer, and pair buckets for every attempt. The default handle-wide limit is ten attempts per five minutes, so an attacker can submit ten bad passwords for a known victim handle and make subsequent correct-password attempts fail at admission until the window rolls, then repeat.

#### Validation

Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375; root_control Sources/SwanAccounts/AccountLoginAdmission.swift:24-46 After a valid PAR/browser session and CSRF check, the public OAuth login handler calls admitLogin(handle:directPeer:) before password authentication. Admission canonicalizes the supplied handle and consumes handle, peer, and pair buckets for every attempt. The default handle-wide limit is ten attempts per five minutes, so an attacker can submit ten bad passwords for a known victim handle and make subsequent correct-password attempts fail at admission until the window rolls, then repeat.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375 reaches the incomplete control at Sources/SwanAccounts/AccountLoginAdmission.swift:24-46 and then the candidate's recorded source location. Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.

- **Source:** Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375

- **Sink:** recorded protected operation

- **Outcome:** Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires the complete OAuth authorization server and the ability to establish valid authorization sessions. Peer and pair buckets constrain each source, durable/process bounds prevent table exhaustion, and the five-minute handle bucket is an intentional brute-force defense; the candidate is the resulting cross-client targeted denial.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-37"></a>

### [37] Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint/wrapper Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42; root_control Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366; no reviewed control closes the stated path. |
| Category | identity-and-ssrf |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42, Sources/SwanHTTP/SwanXRPCPipethrough.swift:385-445, Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72, Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366, Sources/swan/SwanCommand.swift:2774-2822, Sources/SwanOAuth/OAuthRemoteFetch.swift:303-341, Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-445, Sources/SwanOAuth/OAuthRemoteFetch.swift:192-214 |

#### Summary

Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The public authenticated pipethrough acquires one of 32 leases before resolving and sending to a request-selected DID service. SwanProxyHTTPTransport awaits resolver.resolve before entering the timed peer-pinned transport. SystemOAuthHostnameResolver dispatches blocking getaddrinfo without a caller deadline even though OAuthRemoteFetch contains a separate private deadline helper. An attacker-controlled serviceEndpoint hostname with slow DNS can therefore retain leases beyond the advertised 10-second request timeout. Added ordered discovery: An authenticated account OAuth/DPoP caller with atproto scope can select a DID service hostname through atproto-proxy. SwanPeerPinnedProxySender validates the URL but awaits resolver.resolve(host:) before the timeout-bounded transport. Production resolution runs blocking getaddrinfo on a serial queue and holds one of four process-wide DNS leases until libc returns, while the broader pipethrough admission remains held; attacker-controlled authoritative DNS can therefore stall the queue and shared DNS capacity and degrade proxy, OAuth metadata, and DID resolution beyond the configured request timeout.

#### Validation

Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity. Static trace locations: entrypoint/wrapper Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42; root_control Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366 The public authenticated pipethrough acquires one of 32 leases before resolving and sending to a request-selected DID service. SwanProxyHTTPTransport awaits resolver.resolve before entering the timed peer-pinned transport. SystemOAuthHostnameResolver dispatches blocking getaddrinfo without a caller deadline even though OAuthRemoteFetch contains a separate private deadline helper. An attacker-controlled serviceEndpoint hostname with slow DNS can therefore retain leases beyond the advertised 10-second request timeout. Added ordered discovery: An authenticated account OAuth/DPoP caller with atproto scope can select a DID service hostname through atproto-proxy. SwanPeerPinnedProxySender validates the URL but awaits resolver.resolve(host:) before the timeout-bounded transport. Production resolution runs blocking getaddrinfo on a serial queue and holds one of four process-wide DNS leases until libc returns, while the broader pipethrough admission remains held; attacker-controlled authoritative DNS can therefore stall the queue and shared DNS capacity and degrade proxy, OAuth metadata, and DID resolution beyond the configured request timeout.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42 reaches the incomplete control at Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72 and then Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366. Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.

- **Source:** Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42

- **Sink:** Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366

- **Outcome:** Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker needs a valid account/atproto scope and a peer-pinned DID document that selects an attacker-controlled service endpoint. Four-outstanding/serial DNS admission and the DID fetch deadline limit amplification, and the OS resolver may eventually return, but one blocked serial getaddrinfo can stall queued callers while leases remain held. Practical resolver duration requires later validation. Additional context: The newly traced instance requires an authenticated account and control of a resolvable DID service hostname and its authoritative DNS behavior. The four-entry DNS gate, 32-slot proxy admission, and eventual OS resolver timeout bound concurrency but do not make the advertised req

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Move the missing security check to the closest shared control, fail closed before the sensitive operation, inspect sibling routes using the same helper, and add a focused negative regression test for the exact candidate input and state transition.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-38"></a>

### [38] Notification delivery can mint a service JWT after concurrent issuer deactivation.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171, Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:215-241, Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269, Sources/SwanAccounts/AccountOperatorService.swift:325-338 |

#### Summary

Notification delivery can mint a service JWT after concurrent issuer deactivation.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. LocalAccountSpaceServiceAuthenticationIssuer checks active account status and signing reference, then awaits key retrieval and signs without a lifecycle/reference recheck. Writer and deletion notification transports immediately place this newly minted token in an outbound Authorization header, so a deactivation race can authorize one post-revocation delivery.

#### Validation

Notification delivery can mint a service JWT after concurrent issuer deactivation. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171; root_control Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269 LocalAccountSpaceServiceAuthenticationIssuer checks active account status and signing reference, then awaits key retrieval and signs without a lifecycle/reference recheck. Writer and deletion notification transports immediately place this newly minted token in an outbound Authorization header, so a deactivation race can authorize one post-revocation delivery.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171 reaches the incomplete control at Sources/SwanOAuth/SpaceServiceAuthentication.swift:227-269 and then the candidate's recorded source location. Notification delivery can mint a service JWT after concurrent issuer deactivation.

- **Source:** Sources/SwanHTTP/SwanSpaceNotificationDelivery.swift:145-171

- **Sink:** recorded protected operation

- **Outcome:** Notification delivery can mint a service JWT after concurrent issuer deactivation.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Destinations, audience, method, and event ID remain constrained; the candidate concerns lifecycle revocation of the signing account.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-39"></a>

### [39] PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380; root_control Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-347 |
| Affected lines | Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380, Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:386-392, Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173, Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899, Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:466-475 |

#### Summary

PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The remote resolver caches an authenticated PLC document for 60 seconds by default and permits values up to 300 seconds. publicKey returns the cached state immediately while expiresAt remains in the future, without refreshing PLC state. DurableSpaceCredentialVerifier then uses that key to verify a bearer credential. If an authority rotates a compromised #atproto_space/#atproto key after the cache is populated, an attacker retaining the old private key can mint newly signed credentials that remain accepted until the cache expires.

#### Validation

PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires. Static trace locations: entrypoint Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380; root_control Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173; sink Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899 The remote resolver caches an authenticated PLC document for 60 seconds by default and permits values up to 300 seconds. publicKey returns the cached state immediately while expiresAt remains in the future, without refreshing PLC state. DurableSpaceCredentialVerifier then uses that key to verify a bearer credential. If an authority rotates a compromised #atproto_space/#atproto key after the cache is populated, an attacker retaining the old private key can mint newly signed credentials that remain accepted until the cache expires.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380 reaches the incomplete control at Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:150-173 and then Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899. PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.

- **Source:** Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:340-380

- **Sink:** Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-899

- **Outcome:** PLC-backed space-credential verification accepts a cached pre-rotation authority key until its configurable TTL expires.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Refreshes verify current PLC state, audit CIDs, and durable continuity, and the stale window is bounded; after refresh the old signature stops verifying. This candidate requires compromise of a formerly valid authority key and a populated pre-rotation cache. It is a revocation-latency/stale-key candidate, not demonstrated rollback or key substitution.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Bind every fetched document to the requested DID, verify authenticated PLC audit-chain terminal state and durable continuity, reject duplicate/ambiguous service IDs, and keep public-address peer pinning through the connected socket.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-40"></a>

### [40] Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201 |

#### Summary

Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The public requestPasswordReset route accepts an attacker-supplied canonical email and consumes durable admission before invoking blind recovery. The default policy shares a five-per-hour and fifteen-per-day bucket keyed solely by that email. An attacker who knows a victim's address can spend the victim-wide quota with five anonymous requests; later legitimate reset requests are rejected with rate limiting, and repeated requests can maintain the daily denial while causing reset-email spam.

#### Validation

Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery. Static trace locations: entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201 The public requestPasswordReset route accepts an attacker-supplied canonical email and consumes durable admission before invoking blind recovery. The default policy shares a five-per-hour and fifteen-per-day bucket keyed solely by that email. An attacker who knows a victim's address can spend the victim-wide quota with five anonymous requests; later legitimate reset requests are rejected with rate limiting, and repeated requests can maintain the daily denial while causing reset-email spam.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695 reaches the incomplete control at Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201 and then the candidate's recorded source location. Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.

- **Source:** Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695

- **Sink:** recorded protected operation

- **Outcome:** Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The route must be enabled and the victim email known. Direct-peer limits cap one source at 15/hour and 50/day, responses avoid account enumeration, and the email bucket protects delivery infrastructure; the security tradeoff is a targeted temporary recovery lockout rather than account takeover.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-41"></a>

### [41] An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; root_control Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70; sink Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129, Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:347-410, Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70, Sources/SwanAccounts/AccountOperatorService.swift:325-338, Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:95-113, Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:45-58, Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70 |

#### Summary

An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. LocalAccountSpaceRepositoryCommitSigner checks account status and key references, then suspends again while reading the signing key and signs without rechecking lifecycle or reference generation. If deactivation commits after the status check but before the key read/signature, the still-present key produces a valid reader-bound signature after revocation, contradicting the file's stated stale-request invariant. Additional ordered discovery: The sync route obtains an authorized repository snapshot and asks for a reader-specific signed commit. The signer repeats an active-author and key-reference check at lines 49-51, but then awaits keyStore.key at line 58 without a final lifecycle/generation check. A concurrent deactivation, deletion, or rotation can therefore occur before createReaderEnvelope signs at lines 65-70, contrary to the stated guarantee that a stale request cannot sign after deactivation or key-reference removal.

#### Validation

An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129; root_control Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70; sink Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70 LocalAccountSpaceRepositoryCommitSigner checks account status and key references, then suspends again while reading the signing key and signs without rechecking lifecycle or reference generation. If deactivation commits after the status check but before the key read/signature, the still-present key produces a valid reader-bound signature after revocation, contradicting the file's stated stale-request invariant. Additional ordered discovery: The sync route obtains an authorized repository snapshot and asks for a reader-specific signed commit. The signer repeats an active-author and key-reference check at lines 49-51, but then awaits keyStore.key at line 58 without a final lifecycle/generation check. A concurrent deactivation, deletion, or rotation can therefore occur before createReaderEnvelope signs at lines 65-70, contrary to the stated guarantee that a stale request cannot sign after deactivation or key-reference removal.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129 reaches the incomplete control at Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:39-70 and then Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70. An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.

- **Source:** Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:65-129

- **Sink:** Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift:65-70

- **Outcome:** An in-flight permissioned sync request can sign a repository envelope after concurrent account deactivation.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an already-authorized sync request racing an operator lifecycle transition. Permanent deletion has broader quiescence, but ordinary deactivation is a separate reachable transition. Additional context: A remote credentialed reader can hold the sync request across the signing-key suspension and receive repository state authenticated after the author's local signing authority was revoked.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-42"></a>

### [42] Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082; sink Sources/SwanSQLite/SwanSQLite.swift:10725-10732; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082, Sources/SwanSQLite/SwanSQLite.swift:10725-10732, Sources/SwanSQLite/AccountControlStore.swift:2433-2454, Sources/SwanHTTP/SwanSpaceXRPC.swift:735-764, Sources/SwanHTTP/SwanSpaceXRPC.swift:798-813, Sources/SwanHTTP/SwanSpaceXRPC.swift:771-791 |

#### Summary

Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. Each authenticated OAuth/DPoP handler checks a self-write and routes applyWrites, createRecord, deleteRecord, or putRecord through SQLitePreMigratedAccountDirectory.apply. That shared method selects the preopened account database and awaits applyAuthorizedWrites, which durably commits record, oplog, and outbox state through database.apply, before checking isActiveAccount. A lifecycle transition can therefore linearize after initial admission but before the account-local commit; the post-commit Unauthorized result cannot roll back the mutation. AccountControlStore.withActiveAccountAuthorization already provides the relevant pattern for holding the control-plane write transaction across a staged network-free mutation, but this permissioned publication path does not use it. All four independently reachable XRPC entrypoints share this same root control and durable sink.

#### Validation

Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082; sink Sources/SwanSQLite/SwanSQLite.swift:10725-10732 Each authenticated OAuth/DPoP handler checks a self-write and routes applyWrites, createRecord, deleteRecord, or putRecord through SQLitePreMigratedAccountDirectory.apply. That shared method selects the preopened account database and awaits applyAuthorizedWrites, which durably commits record, oplog, and outbox state through database.apply, before checking isActiveAccount. A lifecycle transition can therefore linearize after initial admission but before the account-local commit; the post-commit Unauthorized result cannot roll back the mutation. AccountControlStore.withActiveAccountAuthorization already provides the relevant pattern for holding the control-plane write transaction across a staged network-free mutation, but this permissioned publication path does not use it. All four independently reachable XRPC entrypoints share this same root control and durable sink.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870 reaches the incomplete control at Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1049-1082 and then Sources/SwanSQLite/SwanSQLite.swift:10725-10732. Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.

- **Source:** Sources/SwanHTTP/SwanSpaceXRPC.swift:820-870

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:10725-10732

- **Outcome:** Permissioned applyWrites, createRecord, deleteRecord, and putRecord can durably commit after concurrent account deactivation because lifecycle authorization is not linearized with the shared account-local SQLite write.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker prerequisite: a still-valid OAuth/DPoP request for one of the four permissioned write operations already in flight while an operator or lifecycle workflow suspends or deactivates the same account. Requests begun after deactivation fail, the directory performs a post-write active check, and public-repository publication has a lifecycle fence; none prevents or rolls back these permissioned commits. The four entrypoints and their operation-specific effects remain preserved as independently reachable instances.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-43"></a>

### [43] A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/swan/SwanCommand.swift:1848-1861; root_control Sources/swan/SwanCommand.swift:2442-2471; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130; no reviewed control closes the stated path. |
| Category | authorization |
| CWE | CWE-918, CWE-1188, CWE-16 |
| Affected lines | Sources/swan/SwanCommand.swift:1848-1861, Sources/swan/SwanCommand.swift:2442-2471, Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130, Sources/SwanOAuth/OAuthRemoteFetch.swift:106-169, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-234, Sources/swan/SwanCommand.swift:1860-1861, Sources/swan/SwanCommand.swift:2442-2461, Sources/SwanOAuth/OAuthRemoteFetch.swift:137-169, Sources/SwanOAuth/OAuthClientMetadataLoader.swift:111-161, Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-184 |

#### Summary

A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The production serve CLI exposes --oauth-allow-metadata-ip as a laboratory option but accepts literal IPv4/IPv6 exceptions in the same complete Internet-facing authorization-server or local-space-interop composition. OAuthRemoteNetworkAllowlist approves an allowlisted private/loopback address regardless of the requested hostname. A remote PAR client controls client_id and, after supplying a self-generated valid DPoP proof, can trigger peer-pinned HTTPS client-metadata and possible JWKS retrieval at an attacker hostname resolving to that internal address. Counterevidence: explicit operator opt-in is required; destinations are exact literal IPs; redirects, bodies, and content types are bounded; the connected peer is checked; and TLS must validate the attacker hostname. Checked-in deployment configuration does not use the option, but no separate lab-mode, loopback-listener, or hostname-plus-IP binding prevents production composition. Additional ordered discovery: `--oauth-allow-metadata-ip` is described as laboratory-only, but serve accepts it whenever either the full OAuth server or local-space interop is enabled and does not require a loopback listener or separate laboratory mode. The CLI regression test demonstrates startup with the full OAuth server and `127.0.0.1` allowlisted. `/oauth/par` parses attacker-supplied `client_id`, requires only a self-generated DPoP nonce/proof, and calls the metadata loader. `OAuthRemoteFetchPolicy.permits` unconditionally treats an allowlisted address as permitted, after which the peer-pinned transport performs the outbound GET. Thus an Internet client can select an HTTPS client metadata URL resolving to an operator-allowlisted internal address and produce a blind SSRF request. Additional ordered discovery: serve exposes --oauth-allow-m

#### Validation

A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:1848-1861; root_control Sources/swan/SwanCommand.swift:2442-2471; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130 The production serve CLI exposes --oauth-allow-metadata-ip as a laboratory option but accepts literal IPv4/IPv6 exceptions in the same complete Internet-facing authorization-server or local-space-interop composition. OAuthRemoteNetworkAllowlist approves an allowlisted private/loopback address regardless of the requested hostname. A remote PAR client controls client_id and, after supplying a self-generated valid DPoP proof, can trigger peer-pinned HTTPS client-metadata and possible JWKS retrieval at an attacker hostname resolving to that internal address. Counterevidence: explicit operator opt-in is required; destinations are exact literal IPs; redirects, bodies, and content types are bounded; the connected peer is checked; and TLS must validate the attacker hostname. Checked-in deployment configuration does not use the option, but no separate lab-mode, loopback-listener, or hostname-plus-IP binding prevents production composition. Additional ordered discovery: `--oauth-allow-metadata-ip` is described as laboratory-only, but serve accepts it whenever either the full OAuth server or local-space interop is enabled and does not require a loopback listener or separate laboratory mode. The CLI regression test demonstrates startup with the full OAuth server and `127.0.0.1` allowlisted. `/oauth/par` parses attacker-supplied `client_id`, requires only a self-generated DPoP nonce/proof, and calls the metadata loader. `OAuthRemoteFetchPolicy.permits` unconditionally treats an allowlisted address as permitted, after which the peer-pinned transport performs the outbound GET. Thus an Internet client can select an HTTPS client metadata URL resolving to an operator-allowlisted internal address and produce a blind SSRF request. Additional ordered discovery: serve exposes --oauth-allow-m

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/swan/SwanCommand.swift:1848-1861 reaches the incomplete control at Sources/swan/SwanCommand.swift:2442-2471 and then Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130. A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.

- **Source:** Sources/swan/SwanCommand.swift:1848-1861

- **Sink:** Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130

- **Outcome:** A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Production-reachable configuration hazard and laboratory relaxation, not a default SSRF bypass or a demonstrated live-service exploit. Additional context: Prerequisite: deployment must set the explicitly documented laboratory allowlist. Default configuration is fail-closed; RemoteOAuthAuthorizationServerHTTPTests.testUnsafeRemoteMetadataNeverActivatesAClientOrContactsTransport proves private addresses are rejected when the allowlist is empty. DNS is checked before and after, redirects are forbidden, TLS hostname verification and response bounds remain in force. The proof gap is whether any intended production deployment sets this flag; no live service was tested. Additional context: A mistak

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Make the selected profile constrain the installed parser/routes and make lab trust material structurally unavailable to ordinary production composition; reject mixed production/lab configuration at startup.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-44"></a>

### [44] Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-400 |
| Affected lines | Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374, Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259 |

#### Summary

Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. The default public subscription observer emits one info-level opened record for every successful anonymous firehose upgrade and another closed record for every termination. Each session receives a fresh UUID, and there is no sampling, per-peer rate limit, aggregate rollup, deduplication, logging admission, or bounded journal. A remote actor can repeatedly upgrade and disconnect to produce two durable lifecycle events per cycle and sustain log, ingestion, disk, or journal pressure. The throttled public-read diagnostic logger provides a repository-local example of the missing analogous rate control, while credential and payload omission limits the issue to availability rather than disclosure.

#### Validation

Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99 The default public subscription observer emits one info-level opened record for every successful anonymous firehose upgrade and another closed record for every termination. Each session receives a fresh UUID, and there is no sampling, per-peer rate limit, aggregate rollup, deduplication, logging admission, or bounded journal. A remote actor can repeatedly upgrade and disconnect to produce two durable lifecycle events per cycle and sustain log, ingestion, disk, or journal pressure. The throttled public-read diagnostic logger provides a repository-local example of the missing analogous rate control, while credential and payload omission limits the issue to availability rather than disclosure.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163 reaches the incomplete control at Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131 and then Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99. Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.

- **Source:** Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163

- **Sink:** Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99

- **Outcome:** Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The listener connection cap bounds simultaneous sockets but not connection churn or accumulated log volume over time. Logged fields are server-generated or bounded and omit request headers, tokens, peer identifiers, and event values, so the concern is rate-driven resource exhaustion rather than injection or credential disclosure.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-45"></a>

### [45] Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145; sink Sources/SwanSQLite/AccountControlStore.swift:1557-1573; no reviewed control closes the stated path. |
| Category | denial-of-service |
| CWE | CWE-400, CWE-770 |
| Affected lines | Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145, Sources/SwanSQLite/AccountControlStore.swift:1499-1587, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:159-205, Tests/SwanHTTPTests/AccountEmailXRPCTests.swift:525-547, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:124-145, Sources/SwanSQLite/AccountControlStore.swift:1557-1573, Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201, Sources/SwanSQLite/AccountControlStore.swift:17-22 |

#### Summary

Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. requestPasswordReset is unauthenticated and admits an attacker-chosen canonical email plus direct peer. The consume-all limiter deliberately evaluates and consumes every applicable rule after a rule reports limited; its password-reset email/hour and email/day rules allocate globally keyed durable rows before the reused peer rules reject the request. Consequently, after one peer exhausts its 15/hour bucket, the same peer can continue submitting fresh valid email strings and allocate two long-lived email-scope rows per request. Roughly 2,047 varied emails plus peer rows reach the shared 4,096-row cap, where AccountControlStore returns .limited for every absent key and denies creation of legitimate fresh-address recovery keys. The storage test explicitly fills the table with hostile fresh email digests and proves a new digest is denied. Existing size, peer, purge, expiry, and table bounds prevent unbounded disk growth but neither partition capacity nor stop post-peer-limit email allocation.

#### Validation

Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses Static trace locations: entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145; sink Sources/SwanSQLite/AccountControlStore.swift:1557-1573 requestPasswordReset is unauthenticated and admits an attacker-chosen canonical email plus direct peer. The consume-all limiter deliberately evaluates and consumes every applicable rule after a rule reports limited; its password-reset email/hour and email/day rules allocate globally keyed durable rows before the reused peer rules reject the request. Consequently, after one peer exhausts its 15/hour bucket, the same peer can continue submitting fresh valid email strings and allocate two long-lived email-scope rows per request. Roughly 2,047 varied emails plus peer rows reach the shared 4,096-row cap, where AccountControlStore returns .limited for every absent key and denies creation of legitimate fresh-address recovery keys. The storage test explicitly fills the table with hostile fresh email digests and proves a new digest is denied. Existing size, peer, purge, expiry, and table bounds prevent unbounded disk growth but neither partition capacity nor stop post-peer-limit email allocation.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678 reaches the incomplete control at Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145 and then Sources/SwanSQLite/AccountControlStore.swift:1557-1573. Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses

- **Source:** Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678

- **Sink:** Sources/SwanSQLite/AccountControlStore.swift:1557-1573

- **Outcome:** Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker needs only remote access to POST /xrpc/com.atproto.server.requestPasswordReset and distinct syntactically valid email strings; no account or distributed IPs are required. Opaque success behavior limits enumeration, and body, peer, purge, expiry, and 4,096-row bounds prevent unbounded growth, but they do not prevent deterministic collateral denial of fresh recovery addresses for up to the 24-hour window.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Add the missing per-principal and global admission quota at the earliest unauthenticated boundary, charge actual bytes/work rather than worst-case fixed reservations where applicable, enforce deadlines/backpressure, prune durable ledgers, and test concurrent slow/churn/oversize clients.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

<a id="finding-46"></a>

### [46] A streaming public blob upload can commit after the account is deactivated.

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Exact source, closest-control, and security sink tuple established at entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795; sink Sources/SwanSQLite/SwanSQLite.swift:7122-7180; no reviewed control closes the stated path. |
| Category | authorization-race |
| CWE | CWE-367, CWE-863 |
| Affected lines | Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2715-2735, Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-130, Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2760-2795, Sources/SwanSQLite/SwanSQLite.swift:7122-7180, Sources/SwanAccounts/AccountOperatorService.swift:325-338 |

#### Summary

A streaming public blob upload can commit after the account is deactivated.

#### Root Cause

The violated invariant is enforced incompletely at the recorded root control. uploadBlob checks OAuth subject and target.status == active only before streaming a body of up to 256 MiB. The directory's streaming wrapper delegates directly to the account database after generation refresh, while the lifecycle/firehose authorization fence is used for repository mutations but not blob streaming. Deactivation after preflight therefore can race with completion and leave a new public-namespace blob written outside the active lifecycle. Additional ordered discovery: uploadBlob verifies OAuth and active target only before streaming up to 256 MiB. The generation-refreshing wrapper delegates putStreaming directly to the account database; unlike record commits, no control-plane lifecycle fence or final active-state check covers adoption. An in-flight request can therefore continue across deactivation and create a durable public namespace reference.

#### Validation

A streaming public blob upload can commit after the account is deactivated. Static trace locations: entrypoint Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135; root_control Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795; sink Sources/SwanSQLite/SwanSQLite.swift:7122-7180 uploadBlob checks OAuth subject and target.status == active only before streaming a body of up to 256 MiB. The directory's streaming wrapper delegates directly to the account database after generation refresh, while the lifecycle/firehose authorization fence is used for repository mutations but not blob streaming. Deactivation after preflight therefore can race with completion and leave a new public-namespace blob written outside the active lifecycle. Additional ordered discovery: uploadBlob verifies OAuth and active target only before streaming up to 256 MiB. The generation-refreshing wrapper delegates putStreaming directly to the account database; unlike record commits, no control-plane lifecycle fence or final active-state check covers adoption. An in-flight request can therefore continue across deactivation and create a durable public namespace reference.

Validation method: static source/control/sink trace with adjacent tests and deployment/config evidence

#### Dataflow

Attacker or hostile-peer input at Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135 reaches the incomplete control at Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2763-2795 and then Sources/SwanSQLite/SwanSQLite.swift:7122-7180. A streaming public blob upload can commit after the account is deactivated.

- **Source:** Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:48-135

- **Sink:** Sources/SwanSQLite/SwanSQLite.swift:7122-7180

- **Outcome:** A streaming public blob upload can commit after the account is deactivated.

#### Reachability

The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires an already authenticated account and a concurrent deactivation; the blob remains content-addressed and becomes anonymously retrievable by CID if the account is later active/readable. Additional context: Public read routing may hide an inactive account until reactivation, but the write and disk consumption have already occurred under a revoked lifecycle state.

#### Severity

**Low** — The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

Severity rises if the path is enabled by default, remotely triggerable without the stated preconditions, or produces durable cross-account compromise; it falls if a complete outer control is demonstrated.

#### Remediation

Linearize lifecycle/generation authorization with the signing, streaming-adoption, or SQLite commit point using the existing active-account authorization transaction/lease pattern; re-read the generation after every suspension and fail without publishing stale state.

Tests:
- Exercise the exact negative input/state transition through the smallest reachable handler and assert rejection before durable or externally visible effects.
- Run the affected package tests and a sibling-route regression covering the same shared control.

Preventive controls:
- Centralize the invariant in the shared authorization, resolver, parser, lifecycle fence, or resource-admission layer.
- Record a fail-closed regression for every independently reachable sibling operation.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| HTTP/XRPC public and authenticated route surface | Authentication, method binding, request admission, streaming and error/resource behavior | Reported | Reviewed route registration and handlers; retained public firehose, OAuth/login/recovery, proxy, mutation and streaming findings. |
| OAuth, DPoP, session and service JWT enforcement | Credential type, freshness, replay, scope, audience and lifecycle binding | Reported | Reviewed issuance and verification; retained lifetime, replay-capacity, metadata-fetch, login-admission and lifecycle-race findings. |
| Permissioned authorization and capability enforcement | Space membership, read/write separation, delegation, notification and cross-space binding | Reported | Retained read-credential registration mutation, cross-space deletion replay, post-revocation credential use and signing-race findings. |
| Public and permissioned blob isolation | Anonymous namespace reachability, staging, promotion, streaming and spool budgets | Reported | Demonstrated by source and checked-in tests that permissioned-intended uploads enter the public namespace before promotion; retained streaming and reservation findings. |
| Repository, CAR, MST, CID and recovery verification | Exact-content authentication, import bounds, CAS and durable key continuity | Needs follow-up | Retained deniable-binding and MST resource findings; PLC key-continuity semantics remain deferred. |
| DID, PLC, DNS and outbound request resolution | Document identity, PLC audit state, URL/IP canonicalization, DNS pinning and timeouts | Reported | Retained document-binding, IPv6 classification, URL canonicalization and proxy DNS findings; operator-only configured-origin candidate was rejected. |
| SQLite durability, lifecycle and concurrency | Linearization, retries, durable ledgers, publication and account/space transitions | Reported | Retained public/permissioned write, signing, sync and blob lifecycle races plus unbounded durable-ledger growth. |
| Notifications and outbound delivery | Service authentication, space binding, registration authority, retries and deletion state | Reported | Retained service-JWT freshness, deletion-token scope and read-capability registration findings. |
| Parser, serialization and resource exhaustion | Nesting, aggregate work, body/frame rates, spool, disk, memory and response deadlines | Reported | Retained object-depth, WebSocket, CAR/MST, remote-fetch and admission-budget findings; lab-only parser tools were rejected. |
| Production versus laboratory configuration | Lab trust material, profile selection, SMTP/HTTP exceptions and reference overlays | Reported | Retained production-composable lab trust/profile findings; explicitly invoked lab CLI, Mailpit and reference-relay candidates were rejected. |
| Secrets, Docker, Compose and build/deployment boundary | Runtime operator secrets, build context/cache and local artifact custody | Reported | Retained runtime-secret and Docker-context findings; same-UID disposable credential observations were rejected. |
| SwiftPM dependencies, generated profiles and scripts | Pins, generated-wire integrity, script quoting and artifact verification | No issue found | Package manifests, lockfile, profiles, checksums and scripts were inventoried. No source-supported dependency-substitution or remote code-execution path survived. |

## Open Questions And Follow Up

- Does Proposal 0016 intentionally define removed-member space credentials as non-revocable leases until expiry, or must Swan enforce a membership/client-policy epoch on every read?
  - Follow-up prompt: Define and test Swan space-credential revocation semantics across member removal and managing-app policy denial.
- Must permissioned blob readability track live record reachability, or are blobs intentionally retained at space scope after the last record reference is removed?
  - Follow-up prompt: Specify permissioned blob retention semantics and add update/delete/last-reference tests.
- Is fallback from `#atproto_space` to the ordinary `#atproto` repository key an accepted production protocol rule, and what compromise blast radius is accepted?
  - Follow-up prompt: Review Proposal 0016 key-purpose compatibility and decide whether Swan production must require a dedicated space key.
- A protocol/retention decision and focused interoperability or lifecycle test are required.
  - Follow-up prompt: Review deferred unit candidate-a8b1cf9933918fd3 and close its stated proof gap. Paths: Sources/SwanSQLite/SwanSQLite.swift.
- A protocol/retention decision and focused interoperability or lifecycle test are required.
  - Follow-up prompt: Review deferred unit candidate-cb95fe2176260086 and close its stated proof gap. Paths: Sources/SwanInterop/PublicRepositoryCARReplication.swift, Sources/SwanAccounts/PLCClient.swift, Sources/SwanInterop/PublicRepositoryDIDResolver.swift, Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift.
- A protocol/retention decision and focused interoperability or lifecycle test are required.
  - Follow-up prompt: Review deferred unit candidate-cb8b526aaa85b738 and close its stated proof gap. Paths: Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift, Sources/SwanOAuth/SpaceCredentialAuthority.swift, Tests/SwanOAuthTests/PLCSpaceCredentialPublicKeyResolverTests.swift, Tests/SwanOAuthTests/SpaceCredentialAuthorityTests.swift.
