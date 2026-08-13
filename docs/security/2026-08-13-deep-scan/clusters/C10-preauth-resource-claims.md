# Cluster C10-preauth-resource-claims

---

## F06 [MEDIUM] `security-control-bypass`
**Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity**
finding id: `csf_45a162d50762f3e25b15edfa`

### Locations
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268`  
- `Sources/SwanOAuth/OAuthProofValidation.swift:68-125`  
- `Sources/SwanSQLite/OAuthControlStore.swift:1741-1797`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-275`  
- `Sources/SwanOAuth/OAuthProofValidation.swift:68-120`  
- `Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936`  

### Attack path
- source: `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268`
- sink: `Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936`
- outcome: Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Internet-reachable high-rate availability issue. The table is capped at 131,072 rows and proofs expire after roughly five minutes; body/connection bounds, proof verification cost, expiry cleanup, and metadata-fetch concurrency constrain throughput, but no per-peer PAR/JTI allocation limit or pre-client-validation replay namespace was identified.

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Internet-reachable high-rate availability issue. The table is capped at 131,072 rows and proofs expire after roughly five minutes; body/connection bounds, proof verification cost, expiry cleanup, and metadata-fetch concurrency constrain throughput, but no per-peer PAR/JTI allocation limit or pre-client-validation replay namespace was identified.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The PAR handler validates and durably claims a DPoP jti before loading or validating client metadata, redirect binding, scope, or client assertion. OAuthDPoPProofValidator accepts an embedded attacker-generated ES256 JWK, a fresh attacker jti, and a stateless server nonce, then calls claimDPoP. A nonce is reusable within its short MAC lifetime, so no account, registered OAuth client, or access token is required to allocate replay rows. The global table is bounded at 131,072 rows and fails new insertions at capacity, which would make legitimate DPoP validation unavailable across PAR/token/resource routes until expiry. Strongest counterevidence: each proof requires real ES256 verification, valid htm/htu/nonce/iat, throughput admissions apply, and entries expire after about five minutes. Feasibility therefore requires a high sustained signed-proof rate and remains a validation-phase proof gap. This allocation occurs even when the attacker-selected client_id is invalid because client metadata and identity validation follow the durable claim.

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
 "summary": "Public OAuth PAR claims global durable DPoP replay capacity for attacker-generated proofs before validating any client identity Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-268; root_control Sources/SwanOAuth/OAuthProofValidation.swift:68-125; sink Sources/SwanOAuth/DurableOAuthTokenService.swift:920-936 The PAR handler validates and durably claims a DPoP jti before loading or validating client metadata, redirect binding, scope, or client assertion. OAuthDPoPProofValidator accepts an embedded attacker-generated ES256 JWK, a fresh attacker jti, and a stateless server nonce, then calls claimDPoP. A nonce is reusable within its short MAC lifetime, so no account, registered OAuth client, or access token is required to allocate replay rows. The global table is bounded at 131,072 rows and fails new insertions at capacity, which would make legitimate DPoP validation unavailable across PAR/token/resource routes until expiry. Strongest counterevidence: each proof requires real ES256 verification, valid htm/htu/nonce/iat, throughput admissions apply, and entries expire after about five minutes. Feasibility therefore requires a high sustained signed-proof rate and remains a validation-phase proof gap. This allocation occurs even when the attacker-selected client_id is invalid because client metadata and identity validation follow the durable claim."
}
```

---

## F09 [MEDIUM] `resource-exhaustion`
**Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.**
finding id: `csf_86a849919be0db7549a397ec`

### Locations
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:129-164`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:174-275`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:470-505`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:558-637`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:174-300`  

### Attack path
- source: `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168`
- sink: `Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575`
- outcome: Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: DNS and transport operations, bodies, and peers are bounded; redirects are rejected; and the eight-slot gate prevents unbounded socket growth. Saturation yields fail-fast unavailability rather than a crash. The issue is starvation of a shared security-critical pool by unauthenticated clients, not unbounded allocation. Additional context: Fetches are peer-pinned, SSRF-filtered, size/time bounded, capped at eight, and DPoP-replay protected. Those controls limit each fetch but DPoP only proves possession of a caller-generated key and there is no per-peer or established-client admission before the shared budget. Deployment rate limiting remains a proof gap. The added source narrows the impact to

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
DNS and transport operations, bodies, and peers are bounded; redirects are rejected; and the eight-slot gate prevents unbounded socket growth. Saturation yields fail-fast unavailability rather than a crash. The issue is starvation of a shared security-critical pool by unauthenticated clients, not unbounded allocation. Additional context: Fetches are peer-pinned, SSRF-filtered, size/time bounded, capped at eight, and DPoP-replay protected. Those controls limit each fetch but DPoP only proves possession of a caller-generated key and there is no per-peer or established-client admission before the shared budget. Deployment rate limiting remains a proof gap. The added source narrows the impact to bounded cross-client availability: peer pinning, response limits, five-second default timeouts, exact-URL singleflight, and prompt rejection limit each operation but do not partition the shared pool.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. After the public attacker-generatable DPoP nonce flow, PAR accepts attacker-selected client_id values and synchronously loads remote client metadata before any account token or validated client identity is required and before persisting the PAR. Distinct slow but policy-valid HTTPS origins bypass exact-URL flight sharing and can occupy all eight loader and process-wide fetch admission leases across DNS, metadata retrieval, and optional JWKS retrieval for full timeout intervals. Legitimate metadata validation, PAR, token revalidation, and DID or other security-critical remote fetches sharing the pool then fail immediately; repeated requests can sustain cross-tenant starvation. Additional ordered discovery: A remote caller can obtain a nonce, create its own valid DPoP key/proof, and submit distinct attacker-controlled HTTPS client_id values. PAR then loads remote metadata before establishing a client identity. Eight distinct slow loads consume the process-wide flight budget; detached loads intentionally survive caller cancellation, so repeated attacker-controlled slow hosts can keep legitimate PAR requests at temporarily_unavailable. Added ordered discovery confirms that eight distinct attacker-controlled metadata flights hold the process-global non-queueing document-operation leases across metadata and optional JWKS retrieval. Token redemption, refresh, and revoke deliberately bypass cache and revalidate remotely, so saturation denies those flows as well as PAR and other shared document consumers.

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
 "summary": "Public PAR clients can monopolize the process-wide remote-document budget with distinct attacker-controlled slow metadata origins. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:86-87; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:470-575 After the public attacker-generatable DPoP nonce flow, PAR accepts attacker-selected client_id values and synchronously loads remote client metadata before any account token or validated client identity is required and before persisting the PAR. Distinct slow but policy-valid HTTPS origins bypass exact-URL flight sharing and can occupy all eight loader and process-wide fetch admission leases across DNS, metadata retrieval, and optional JWKS retrieval for full timeout intervals. Legitimate metadata validation, PAR, token revalidation, and DID or other security-critical remote fetches sharing the pool then fail immediately; repeated requests can sustain cross-tenant starvation. Additional ordered discovery: A remote caller can obtain a nonce, create its own valid DPoP key/proof, and submit distinct attacker-controlled HTTPS client_id values. PAR then loads remote metadata before establishing a client identity. Eight distinct slow loads consume the process-wide flight budget; detached loads intentionally survive caller cancellation, so repeated attacker-controlled slow hosts can keep legitimate PAR requests at temporarily_unavailable. Added ordered discovery confirms that eight distinct attacker-controlled metadata flights hold the process-global non-queueing document-operation leases across metadata and optional JWKS retrieval. Token redemption, refresh, and revoke deliberately bypass cache and revalidate remotely, so saturation denies those flows as well as PAR and other shared document consumers."
}
```

---

## F19 [MEDIUM] `security-control-bypass`
**Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding**
finding id: `csf_2816c4731d54fbc431b0cfd2`

### Locations
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-234`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335`  
- `Sources/SwanSQLite/OAuthControlStore.swift:1225-1289`  
- `Sources/SwanSQLite/OAuthControlStore.swift:399-415`  
- `Sources/SwanSQLite/OAuthControlStore.swift:102-129`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-233`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:115-164`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:235-299`  
- `Sources/SwanSQLite/OAuthControlStore.swift:1197-1275`  

### Attack path
- source: `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180`
- sink: `Sources/SwanSQLite/OAuthControlStore.swift:1225-1289`
- outcome: Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker capability: create valid self-signed DPoP proofs and serve attacker-controlled HTTPS metadata URLs. Protected asset: OAuth PAR availability for new clients. No network validation was performed. The added source preserves the bounded conditions: thousands of public PAR attempts, attacker-controlled HTTPS responses, a globally shared 8,192-row cap, and at most one hour of retention.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Attacker capability: create valid self-signed DPoP proofs and serve attacker-controlled HTTPS metadata URLs. Protected asset: OAuth PAR availability for new clients. No network validation was performed. The added source preserves the bounded conditions: thousands of public PAR attempts, attacker-controlled HTTPS responses, a globally shared 8,192-row cap, and at most one hour of retention.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The unauthenticated production PAR endpoint accepts an attacker-selected client_id after DPoP proof-of-key and nonce validation; those checks do not authorize a pre-registered client. OAuthClientMetadataLoader calls beginClientMetadataFetch before any remote document, JSON, client profile, or JWKS validation. The SQLite store immediately inserts or refreshes a distinct client_id in oauth_control_client_metadata_freshness with retain_until one hour in the future, under a global production cap of 8,192 rows. Failure of fetch or validation has no cleanup/abandon operation. An attacker controlling a public HTTPS origin can therefore rotate 8,192 URL paths and return small invalid documents sequentially, filling the durable capacity; subsequent legitimate previously unseen clients receive capacity exhaustion until rows expire and batched cleanup drains them. Eight concurrent remote-fetch permits, strict SSRF policy, and the hard row cap bound resource use but do not prevent this low-cost durable capacity poisoning; already cached clients remain usable. Added ordered discovery confirms ticket issuance inserts or refreshes the per-client one-hour row before DNS or HTTP, that invalid or failed remote documents do not roll it back, cleanup removes only expired orphan rows in bounded batches, and 8,192 attacker-chosen client IDs can block unseen legitimate clients while existing cached clients remain usable.

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
 "summary": "Failed attacker-selected OAuth client metadata fetches retain one-hour freshness rows and can block all new client onboarding Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:158-180; root_control Sources/SwanOAuth/OAuthClientMetadataLoader.swift:283-335; sink Sources/SwanSQLite/OAuthControlStore.swift:1225-1289 The unauthenticated production PAR endpoint accepts an attacker-selected client_id after DPoP proof-of-key and nonce validation; those checks do not authorize a pre-registered client. OAuthClientMetadataLoader calls beginClientMetadataFetch before any remote document, JSON, client profile, or JWKS validation. The SQLite store immediately inserts or refreshes a distinct client_id in oauth_control_client_metadata_freshness with retain_until one hour in the future, under a global production cap of 8,192 rows. Failure of fetch or validation has no cleanup/abandon operation. An attacker controlling a public HTTPS origin can therefore rotate 8,192 URL paths and return small invalid documents sequentially, filling the durable capacity; subsequent legitimate previously unseen clients receive capacity exhaustion until rows expire and batched cleanup drains them. Eight concurrent remote-fetch permits, strict SSRF policy, and the hard row cap bound resource use but do not prevent this low-cost durable capacity poisoning; already cached clients remain usable. Added ordered discovery confirms ticket issuance inserts or refreshes the per-client one-hour row before DNS or HTTP, that invalid or failed remote documents do not roll it back, cleanup removes only expired orphan rows in bounded batches, and 8,192 attacker-chosen client IDs can block unseen legitimate clients while existing cached clients remain usable."
}
```

---

## F41 [LOW] `resource-exhaustion`
**Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.**
finding id: `csf_42745998fc1addc3d94c982d`

### Locations
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375`  
- `Sources/SwanAccounts/AccountLoginAdmission.swift:24-46`  
- `Sources/SwanAccounts/AccountLoginAdmission.swift:95-162`  

### Attack path
- source: `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375`
- sink: `recorded protected operation`
- outcome: Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires the complete OAuth authorization server and the ability to establish valid authorization sessions. Peer and pair buckets constrain each source, durable/process bounds prevent table exhaustion, and the five-minute handle bucket is an intentional brute-force defense; the candidate is the resulting cross-client targeted denial.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Requires the complete OAuth authorization server and the ability to establish valid authorization sessions. Peer and pair buckets constrain each source, durable/process bounds prevent table exhaustion, and the five-minute handle bucket is an intentional brute-force defense; the candidate is the resulting cross-client targeted denial.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. After a valid PAR/browser session and CSRF check, the public OAuth login handler calls admitLogin(handle:directPeer:) before password authentication. Admission canonicalizes the supplied handle and consumes handle, peer, and pair buckets for every attempt. The default handle-wide limit is ten attempts per five minutes, so an attacker can submit ten bad passwords for a known victim handle and make subsequent correct-password attempts fail at admission until the window rolls, then repeat.

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
 "summary": "Pre-authentication OAuth login admission lets invalid-password attempts consume a victim handle's global bucket and cause repeatable login lockout. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:335-375; root_control Sources/SwanAccounts/AccountLoginAdmission.swift:24-46 After a valid PAR/browser session and CSRF check, the public OAuth login handler calls admitLogin(handle:directPeer:) before password authentication. Admission canonicalizes the supplied handle and consumes handle, peer, and pair buckets for every attempt. The default handle-wide limit is ten attempts per five minutes, so an attacker can submit ten bad passwords for a known victim handle and make subsequent correct-password attempts fail at admission until the window rolls, then repeat."
}
```

---

## F34 [LOW] `resource-exhaustion`
**Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses**
finding id: `csf_1262f8f96d6a9ee8ab663a0f`

### Locations
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145`  
- `Sources/SwanSQLite/AccountControlStore.swift:1499-1587`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:159-205`  
- `Tests/SwanHTTPTests/AccountEmailXRPCTests.swift:525-547`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:124-145`  
- `Sources/SwanSQLite/AccountControlStore.swift:1557-1573`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201`  
- `Sources/SwanSQLite/AccountControlStore.swift:17-22`  

### Attack path
- source: `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678`
- sink: `Sources/SwanSQLite/AccountControlStore.swift:1557-1573`
- outcome: Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker needs only remote access to POST /xrpc/com.atproto.server.requestPasswordReset and distinct syntactically valid email strings; no account or distributed IPs are required. Opaque success behavior limits enumeration, and body, peer, purge, expiry, and 4,096-row bounds prevent unbounded growth, but they do not prevent deterministic collateral denial of fresh recovery addresses for up to the 24-hour window.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Attacker needs only remote access to POST /xrpc/com.atproto.server.requestPasswordReset and distinct syntactically valid email strings; no account or distributed IPs are required. Opaque success behavior limits enumeration, and body, peer, purge, expiry, and 4,096-row bounds prevent unbounded growth, but they do not prevent deterministic collateral denial of fresh recovery addresses for up to the 24-hour window.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. requestPasswordReset is unauthenticated and admits an attacker-chosen canonical email plus direct peer. The consume-all limiter deliberately evaluates and consumes every applicable rule after a rule reports limited; its password-reset email/hour and email/day rules allocate globally keyed durable rows before the reused peer rules reject the request. Consequently, after one peer exhausts its 15/hour bucket, the same peer can continue submitting fresh valid email strings and allocate two long-lived email-scope rows per request. Roughly 2,047 varied emails plus peer rows reach the shared 4,096-row cap, where AccountControlStore returns .limited for every absent key and denies creation of legitimate fresh-address recovery keys. The storage test explicitly fills the table with hostile fresh email digests and proves a new digest is denied. Existing size, peer, purge, expiry, and table bounds prevent unbounded disk growth but neither partition capacity nor stop post-peer-limit email allocation.

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
 "summary": "Unauthenticated password-reset requests can exhaust shared durable email rate-limit capacity after their source IP is limited and deny recovery for fresh legitimate addresses Static trace locations: entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-678; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:117-145; sink Sources/SwanSQLite/AccountControlStore.swift:1557-1573 requestPasswordReset is unauthenticated and admits an attacker-chosen canonical email plus direct peer. The consume-all limiter deliberately evaluates and consumes every applicable rule after a rule reports limited; its password-reset email/hour and email/day rules allocate globally keyed durable rows before the reused peer rules reject the request. Consequently, after one peer exhausts its 15/hour bucket, the same peer can continue submitting fresh valid email strings and allocate two long-lived email-scope rows per request. Roughly 2,047 varied emails plus peer rows reach the shared 4,096-row cap, where AccountControlStore returns .limited for every absent key and denies creation of legitimate fresh-address recovery keys. The storage test explicitly fills the table with hostile fresh email digests and proves a new digest is denied. Existing size, peer, purge, expiry, and table bounds prevent unbounded disk growth but neither partition capacity nor stop post-peer-limit email allocation."
}
```

---

## F42 [LOW] `resource-exhaustion`
**Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.**
finding id: `csf_3878986a06ffa683e8cc574b`

### Locations
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695`  
- `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201`  

### Attack path
- source: `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695`
- sink: `recorded protected operation`
- outcome: Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The route must be enabled and the victim email known. Direct-peer limits cap one source at 15/hour and 50/day, responses avoid account enumeration, and the email bucket protects delivery infrastructure; the security tradeoff is a targeted temporary recovery lockout rather than account takeover.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
The route must be enabled and the victim email known. Direct-peer limits cap one source at 15/hour and 50/day, responses avoid account enumeration, and the email bucket protects delivery infrastructure; the security tradeoff is a targeted temporary recovery lockout rather than account takeover.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The public requestPasswordReset route accepts an attacker-supplied canonical email and consumes durable admission before invoking blind recovery. The default policy shares a five-per-hour and fifteen-per-day bucket keyed solely by that email. An attacker who knows a victim's address can spend the victim-wide quota with five anonymous requests; later legitimate reset requests are rejected with rate limiting, and repeated requests can maintain the daily denial while causing reset-email spam.

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
 "summary": "Anonymous password-reset requests can exhaust a victim email's shared bucket and temporarily deny legitimate account recovery. Static trace locations: entrypoint Sources/SwanHTTP/SwanAccountEmailXRPC.swift:647-695; root_control Sources/SwanHTTP/SwanAccountEmailXRPC.swift:195-201 The public requestPasswordReset route accepts an attacker-supplied canonical email and consumes durable admission before invoking blind recovery. The default policy shares a five-per-hour and fifteen-per-day bucket keyed solely by that email. An attacker who knows a victim's address can spend the victim-wide quota with five anonymous requests; later legitimate reset requests are rejected with rate limiting, and repeated requests can maintain the daily denial while causing reset-email spam."
}
```
