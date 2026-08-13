# Cluster C8-lab-production-separation

---

## F12 [MEDIUM] `secret-exposure`
**The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.**
finding id: `csf_9f9ceea99fbaf78cb942b050`

### Locations
- `interop/prepare-interop-secrets.sh:39-42`  
- `interop/docker-compose.reference-relay.yml:29-36`  
- `docker-compose.yml:119-120`  
- `README.md:248-252`  
- `Scripts/verify-interop-lab.sh:540-542`  
- `interop/prepare-interop-secrets.sh:35-42`  
- `Scripts/verify-interop-lab.sh:531-543`  
- `docker-compose.yml:66-120`  

### Attack path
- source: `interop/prepare-interop-secrets.sh:35-42`
- sink: `interop/docker-compose.reference-relay.yml:29-36`
- outcome: The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The checked-in topology is loopback laboratory infrastructure; base Swan does not expose management, files are mode 0400, and the mount is read-only. These reduce deployment impact but do not preserve the asserted credential separation. The base Compose laboratory is loopback-published and does not enable the management listener, so no direct production extraction was shown; the boundary failure still widens the impact of compromise of the Internet-facing runtime process.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
The checked-in topology is loopback laboratory infrastructure; base Swan does not expose management, files are mode 0400, and the mount is read-only. These reduce deployment impact but do not preserve the asserted credential separation. The base Compose laboratory is loopback-published and does not enable the management listener, so no direct production extraction was shown; the boundary failure still widens the impact of compromise of the Internet-facing runtime process.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The secret initializer copies operator-secret into the same swan-runtime-secrets directory as ordinary runtime keys, and base Compose mounts that entire volume into Swan. The verifier only checks that the service definition does not spell the filename, while README and its own diagnostic claim the runtime must not receive it. The optional relay topology enables management PLC provisioning and firehose sync using this mounted operator secret, so compromise or arbitrary file read of the ordinary runtime obtains a separate operator capability. The secret-preparation script explicitly copies operator-secret into swan-runtime-secrets, while verify-interop-lab.sh only searches the Swan YAML block for the literal filename and therefore falsely passes despite the mounted volume's contents.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Remove the secret from the long-running/runtime or build context, use narrowly scoped secret mounts/files with owner-only permissions, exclude all live-artifact trees from Docker context and cache, and add a build-context regression check.

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
 "summary": "The ordinary long-running Swan container receives the operator management secret despite the documented and checked runtime-secret separation boundary. Static trace locations: source interop/prepare-interop-secrets.sh:35-42; root_control interop/prepare-interop-secrets.sh:39-42; sink interop/docker-compose.reference-relay.yml:29-36 The secret initializer copies operator-secret into the same swan-runtime-secrets directory as ordinary runtime keys, and base Compose mounts that entire volume into Swan. The verifier only checks that the service definition does not spell the filename, while README and its own diagnostic claim the runtime must not receive it. The optional relay topology enables management PLC provisioning and firehose sync using this mounted operator secret, so compromise or arbitrary file read of the ordinary runtime obtains a separate operator capability. The secret-preparation script explicitly copies operator-secret into swan-runtime-secrets, while verify-interop-lab.sh only searches the Swan YAML block for the literal filename and therefore falsely passes despite the mounted volume's contents."
}
```

---

## F13 [MEDIUM] `unsafe-production-configuration`
**The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.**
finding id: `csf_9116e1581dacedff2c7e41e4`

### Locations
- `Sources/SwanHTTP/SwanHTTP.swift:869-875`  
- `Sources/SwanHTTP/SwanHTTP.swift:875-980`  
- `docs/superpowers/records/2026-08-12-swan-production-readiness/README.md:35-43`  
- `Sources/swan/SwanCommand.swift:1799-1800`  
- `Sources/swan/SwanCommand.swift:2295-2295`  
- `Sources/SwanHTTP/SwanHTTP.swift:875-980`  
- `Profiles/permissioned-data-0016-2026-07-03.json:1-20`  
- `docs/superpowers/records/2026-08-12-swan-production-readiness/task-10-report.md:300-303`  
- `Sources/swan/SwanCommand.swift:2295-2301`  
- `Sources/SwanCore/SwanCore.swift:55-107`  

### Attack path
- source: `Sources/swan/SwanCommand.swift:1799-1800`
- sink: `Sources/SwanHTTP/SwanHTTP.swift:875-980`
- outcome: The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Both currently checked-in permissioned profiles contain the same method inventory and endpoint-level authorization remains in place, so no present unauthenticated bypass is demonstrated. The risk becomes concrete for a valid narrowed or future profile used to disable a method or feature in production. Additional context: Configuration/schema-version confusion at the production route boundary; currently documented as unfixed backlog. The added source confirms that both checked-in profiles currently contain the same 25 methods and each live handler retains capability and authentication checks, so the concrete risk remains a narrowed or future custom profile rather than a present credential byp

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Both currently checked-in permissioned profiles contain the same method inventory and endpoint-level authorization remains in place, so no present unauthenticated bypass is demonstrated. The risk becomes concrete for a valid narrowed or future profile used to disable a method or feature in production. Additional context: Configuration/schema-version confusion at the production route boundary; currently documented as unfixed backlog. The added source confirms that both checked-in profiles currently contain the same 25 methods and each live handler retains capability and authentication checks, so the concrete risk remains a narrowed or future custom profile rather than a present credential bypass. Additional context: The currently checked-in permissioned profiles expose the same NSIDs, so present endpoint widening is not demonstrated; impact becomes concrete when profile registries diverge. Additional context: Because profile identity is advertised and used for other runtime semantics, this is a security-relevant configuration and authorization-surface mismatch rather than cosmetic metadata drift. Exploitation still requires the omitted method to have a live configured capability and

### Root cause
The violated invariant is enforced incompletely at the recorded root control. SwanHTTP advertises the loaded profile id but installs permissioned handlers by iterating the build-wide PermissionedData0016.methods registry, not the selected ProtocolProfile's method inventory. The production-readiness execution record explicitly marks this mismatch as still open. A valid narrower profile can therefore express or attest a reduced method set while the Internet-facing router continues to answer every compiled permissioned NSID whose capability is configured, leaving endpoint authentication as the only control rather than honoring the operator-selected surface. Additional ordered discovery: The serve command loads --profile and describeServer reports that profile ID, but SwanHTTP always iterates PermissionedData0016.methods. The assigned production-readiness report explicitly records that selecting the 07-03 profile still installs the 07-30 permissioned surface. The two current profiles list the same NSIDs, so an immediate authorization bypass is not established, but the control becomes unsafe when profile method sets diverge. The new ordered source independently traces the operator-decoded profile endpoints through serve composition to route construction, where every build-wide PermissionedData0016 method is registered as either an available handler or a 503 gate regardless of the selected profile.endpoints. Production-readiness records still identify the mismatch as open. Additional ordered discovery: describeServer returns the operator-loaded profile.id, but buildRouter iterates the hardcoded PermissionedData0016.methods registry. The checked-in production-readiness report explicitly records this as unfixed. A divergent older, future, or narrowed profile can therefore be attested on the wire while a different endpoint surface is served. Additional or

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Make the selected profile constrain the installed parser/routes and make lab trust material structurally unavailable to ordinary production composition; reject mixed production/lab configuration at startup.

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
 "summary": "The loaded operator-selected permissioned profile is advertised but does not constrain the installed permissioned route, parser, and generated-wire contract, which remains tied to the latest build-wide registry. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:1799-1800; root_control Sources/SwanHTTP/SwanHTTP.swift:869-875; sink Sources/SwanHTTP/SwanHTTP.swift:875-980 SwanHTTP advertises the loaded profile id but installs permissioned handlers by iterating the build-wide PermissionedData0016.methods registry, not the selected ProtocolProfile's method inventory. The production-readiness execution record explicitly marks this mismatch as still open. A valid narrower profile can therefore express or attest a reduced method set while the Internet-facing router continues to answer every compiled permissioned NSID whose capability is configured, leaving endpoint authentication as the only control rather than honoring the operator-selected surface. Additional ordered discovery: The serve command loads --profile and describeServer reports that profile ID, but SwanHTTP always iterates PermissionedData0016.methods. The assigned production-readiness report explicitly records that selecting the 07-03 profile still installs the 07-30 permissioned surface. The two current profiles list the same NSIDs, so an immediate authorization bypass is not established, but the control becomes unsafe when profile method sets diverge. The new ordered source independently traces the operator-decoded profile endpoints through serve composition to route construction, where every build-wide PermissionedData0016 method is registered as either an available handler or a 503 gate regardless of the selected profile.endpoints. Production-readiness records still identify the mismatch as open. Additional ordered discovery: describeServer returns the operator-loaded profile.id, but buildRouter iterates the hardcoded PermissionedData0016.met
```

---

## F17 [MEDIUM] `authorization-capability-confusion`
**Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.**
finding id: `csf_7c032afaa6cd05b77adb86f4`

### Locations
- `Dockerfile:21-30`  
- `Sources/swan/SwanCommand.swift:130-180`  
- `docker-compose.yml:66-107`  
- `interop/notification-config.json:15-18`  
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:299-320`  
- `Sources/swan/SwanCommand.swift:2547-2565`  
- `Sources/swan/SwanCommand.swift:78-88`  
- `Sources/SwanAccounts/PLCClient.swift:249-263`  
- `Sources/swan/SwanCommand.swift:160-225`  
- `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545`  

### Attack path
- source: `Dockerfile:21-30`
- sink: `Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545`
- outcome: Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker input is not request-selected: activation requires an operator to deploy the embedded configuration. The risk is accidental production reachability of a lab trust relaxation and private HTTP PLC resolver. The Compose topology publishes Caddy only on loopback, destinations and PLC hosts are static allowlists, and the embedded file is inactive unless --notification-config is supplied. No attacker-directed SSRF or live swan.place exposure was demonstrated. Additional context: Prerequisites are substantial: an operator must explicitly install a notification config with `laboratory: true`, the targeted issuer must be on the static authority/delegation allowlist, and the attacker must con

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Attacker input is not request-selected: activation requires an operator to deploy the embedded configuration. The risk is accidental production reachability of a lab trust relaxation and private HTTP PLC resolver. The Compose topology publishes Caddy only on loopback, destinations and PLC hosts are static allowlists, and the embedded file is inactive unless --notification-config is supplied. No attacker-directed SSRF or live swan.place exposure was demonstrated. Additional context: Prerequisites are substantial: an operator must explicitly install a notification config with `laboratory: true`, the targeted issuer must be on the static authority/delegation allowlist, and the attacker must control or intercept the configured HTTP lab origin. Durable continuity resists later rollback, audit CIDs are recomputed, and issuer/space claims are still checked. The remaining proof gap is a focused forged-first-audit regression demonstrating end-to-end credential acceptance; discovery remained read-only.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The runtime Dockerfile copies the checked-in interop notification configuration and helpers into every image. That configuration selects an HTTP reference-plc origin with laboratory=true and an allowlisted private service hostname. SwanCommand's ordinary notification-config loader selects PLCClientConfiguration.laboratory solely from the file boolean; it does not require a separate laboratory serve mode or reject laboratory resolution for a public HTTPS issuer. The checked-in Compose service demonstrates activation through --notification-config on a 0.0.0.0 listener alongside live routes. Additional ordered discovery: Notification JSON directly controls `credentialKeyPLC.laboratory` and `delegationKeyPLC.laboratory`. When true, the ordinary `serve` command constructs `PLCClientConfiguration.laboratory`, which permits literal-loopback or an arbitrary explicitly allowlisted hostname over HTTP; there is no process-wide production/laboratory gate. The resulting remote resolvers are composed into space-credential and repository-credential verification. A bearer credential on repository-sync routes causes key resolution for its configured, allowed issuer. The PLC resolver fetches state and audit over that transport, checks state/audit/CID consistency, and advances continuity, but the shown boundary does not independently authenticate the first observed PLC history. An on-path attacker or compromised allowlisted lab service could therefore substitute the initial authority key and supply a credential signed by that key.

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
 "summary": "Ordinary public serve composition can activate laboratory notification and HTTP PLC key-resolution material, permitting an explicit lab trust downgrade to reach permissioned credential verification. Static trace locations: source Dockerfile:21-30; root_control Sources/swan/SwanCommand.swift:130-180; sink Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:503-545 The runtime Dockerfile copies the checked-in interop notification configuration and helpers into every image. That configuration selects an HTTP reference-plc origin with laboratory=true and an allowlisted private service hostname. SwanCommand's ordinary notification-config loader selects PLCClientConfiguration.laboratory solely from the file boolean; it does not require a separate laboratory serve mode or reject laboratory resolution for a public HTTPS issuer. The checked-in Compose service demonstrates activation through --notification-config on a 0.0.0.0 listener alongside live routes. Additional ordered discovery: Notification JSON directly controls `credentialKeyPLC.laboratory` and `delegationKeyPLC.laboratory`. When true, the ordinary `serve` command constructs `PLCClientConfiguration.laboratory`, which permits literal-loopback or an arbitrary explicitly allowlisted hostname over HTTP; there is no process-wide production/laboratory gate. The resulting remote resolvers are composed into space-credential and repository-credential verification. A bearer credential on repository-sync routes causes key resolution for its configured, allowed issuer. The PLC resolver fetches state and audit over that transport, checks state/audit/CID consistency, and advances continuity, but the shown boundary does not independently authenticate the first observed PLC history. An on-path attacker or compromised allowlisted lab service could therefore substitute the initial authority key and supply a credential signed by that key."
}
```

---

## F36 [LOW] `authorization-capability-confusion`
**A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.**
finding id: `csf_b237a3b3355b11752d4d30fe`

### Locations
- `Sources/swan/SwanCommand.swift:1848-1861`  
- `Sources/swan/SwanCommand.swift:2442-2471`  
- `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:106-169`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-234`  
- `Sources/swan/SwanCommand.swift:1860-1861`  
- `Sources/swan/SwanCommand.swift:2442-2461`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:137-169`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:111-161`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-184`  

### Attack path
- source: `Sources/swan/SwanCommand.swift:1848-1861`
- sink: `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130`
- outcome: A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Production-reachable configuration hazard and laboratory relaxation, not a default SSRF bypass or a demonstrated live-service exploit. Additional context: Prerequisite: deployment must set the explicitly documented laboratory allowlist. Default configuration is fail-closed; RemoteOAuthAuthorizationServerHTTPTests.testUnsafeRemoteMetadataNeverActivatesAClientOrContactsTransport proves private addresses are rejected when the allowlist is empty. DNS is checked before and after, redirects are forbidden, TLS hostname verification and response bounds remain in force. The proof gap is whether any intended production deployment sets this flag; no live service was tested. Additional context: A mistak

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Production-reachable configuration hazard and laboratory relaxation, not a default SSRF bypass or a demonstrated live-service exploit. Additional context: Prerequisite: deployment must set the explicitly documented laboratory allowlist. Default configuration is fail-closed; RemoteOAuthAuthorizationServerHTTPTests.testUnsafeRemoteMetadataNeverActivatesAClientOrContactsTransport proves private addresses are rejected when the allowlist is empty. DNS is checked before and after, redirects are forbidden, TLS hostname verification and response bounds remain in force. The proof gap is whether any intended production deployment sets this flag; no live service was tested. Additional context: A mistaken production configuration can allow attacker-selected OAuth metadata/JWKS URLs to reach an explicitly allowlisted internal service. The added source preserves that this is explicit, exact-IP, configuration-dependent behavior rather than default SSRF: HTTPS and peer pinning, redirect and rebinding defenses, a 256 KiB response limit, and a five-second timeout remain enforced. No checked-in production configuration enabling the exception was found. Redirect, size, JSON, status, DNS/peer, and TLS 

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The production serve CLI exposes --oauth-allow-metadata-ip as a laboratory option but accepts literal IPv4/IPv6 exceptions in the same complete Internet-facing authorization-server or local-space-interop composition. OAuthRemoteNetworkAllowlist approves an allowlisted private/loopback address regardless of the requested hostname. A remote PAR client controls client_id and, after supplying a self-generated valid DPoP proof, can trigger peer-pinned HTTPS client-metadata and possible JWKS retrieval at an attacker hostname resolving to that internal address. Counterevidence: explicit operator opt-in is required; destinations are exact literal IPs; redirects, bodies, and content types are bounded; the connected peer is checked; and TLS must validate the attacker hostname. Checked-in deployment configuration does not use the option, but no separate lab-mode, loopback-listener, or hostname-plus-IP binding prevents production composition. Additional ordered discovery: `--oauth-allow-metadata-ip` is described as laboratory-only, but serve accepts it whenever either the full OAuth server or local-space interop is enabled and does not require a loopback listener or separate laboratory mode. The CLI regression test demonstrates startup with the full OAuth server and `127.0.0.1` allowlisted. `/oauth/par` parses attacker-supplied `client_id`, requires only a self-generated DPoP nonce/proof, and calls the metadata loader. `OAuthRemoteFetchPolicy.permits` unconditionally treats an allowlisted address as permitted, after which the peer-pinned transport performs the outbound GET. Thus an Internet client can select an HTTPS client metadata URL resolving to an operator-allowlisted internal address and produce a blind SSRF request. Additional ordered discovery: serve exposes --oauth-allow-m

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Make the selected profile constrain the installed parser/routes and make lab trust material structurally unavailable to ordinary production composition; reject mixed production/lab configuration at startup.

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
 "summary": "A laboratory OAuth metadata IP exception is composable with the public authorization server and applies to every hostname resolving to that IP. Static trace locations: entrypoint Sources/swan/SwanCommand.swift:1848-1861; root_control Sources/swan/SwanCommand.swift:2442-2471; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:60-130 The production serve CLI exposes --oauth-allow-metadata-ip as a laboratory option but accepts literal IPv4/IPv6 exceptions in the same complete Internet-facing authorization-server or local-space-interop composition. OAuthRemoteNetworkAllowlist approves an allowlisted private/loopback address regardless of the requested hostname. A remote PAR client controls client_id and, after supplying a self-generated valid DPoP proof, can trigger peer-pinned HTTPS client-metadata and possible JWKS retrieval at an attacker hostname resolving to that internal address. Counterevidence: explicit operator opt-in is required; destinations are exact literal IPs; redirects, bodies, and content types are bounded; the connected peer is checked; and TLS must validate the attacker hostname. Checked-in deployment configuration does not use the option, but no separate lab-mode, loopback-listener, or hostname-plus-IP binding prevents production composition. Additional ordered discovery: `--oauth-allow-metadata-ip` is described as laboratory-only, but serve accepts it whenever either the full OAuth server or local-space interop is enabled and does not require a loopback listener or separate laboratory mode. The CLI regression test demonstrates startup with the full OAuth server and `127.0.0.1` allowlisted. `/oauth/par` parses attacker-supplied `client_id`, requires only a self-generated DPoP nonce/proof, and calls the metadata loader. `OAuthRemoteFetchPolicy.permits` unconditionally treats an allowlisted address as permitted, after which the peer-pinned transport performs the outbound GET. Thus an Inter
```

---

## F38 [LOW] `authorization-capability-confusion`
**Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.**
finding id: `csf_22d567bab466e73f94bf4cec`

### Locations
- `Scripts/run-forum-live-demo.sh:21-23`  
- `Scripts/run-forum-live-demo.sh:229-256`  
- `Scripts/run-forum-live-demo.sh:737-751`  
- `Scripts/run-forum-live-demo.sh:867-868`  
- `Dockerfile.dockerignore:1-7`  
- `Dockerfile.dockerignore:31-62`  
- `Dockerfile:10-14`  
- `.gitignore:4-8`  
- `Sources/SwanInterop/ForumThreadMerger.swift:310-348`  
- `Scripts/run-first-write-notification-loss-acceptance.sh:109-125`  

### Attack path
- source: `Scripts/run-forum-live-demo.sh:21-23`
- sink: `Dockerfile:10-14`
- outcome: Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Normal EXIT, INT, TERM, and HUP traps remove many temporary directories; most persisted artifacts are sanitized and mode 0600; and a common local builder remains on the developer host. The final runtime stage copies only selected outputs. These controls reduce ordinary exposure but do not cover crash residue, concurrency, remote or shared builders, context upload, or cache retention. Additional context: This concrete instance requires a prior live or interop run leaving raw artifacts plus access to the daemon, remote/shared builder, exported cache, or provenance. Gitignore and owner-only file modes reduce casual local exposure but do not control context transmission. Additional context: The 

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Normal EXIT, INT, TERM, and HUP traps remove many temporary directories; most persisted artifacts are sanitized and mode 0600; and a common local builder remains on the developer host. The final runtime stage copies only selected outputs. These controls reduce ordinary exposure but do not cover crash residue, concurrency, remote or shared builders, context upload, or cache retention. Additional context: This concrete instance requires a prior live or interop run leaving raw artifacts plus access to the daemon, remote/shared builder, exported cache, or provenance. Gitignore and owner-only file modes reduce casual local exposure but do not control context transmission. Additional context: The final runtime stage still contains only the binary and selected public resources; this source confirms builder, intermediate-image, and cache exposure rather than final-image or anonymous HTTP disclosure. Additional context: The final multi-stage runtime image copies only selected binaries, profiles, and scripts, explicit secret/key patterns are excluded, and many artifacts are intended to be sanitized and owner-only. Exposure is limited to the build context/intermediate stage/cache and depends 

### Root cause
The violated invariant is enforced incompletely at the recorded root control. Dockerfile.dockerignore excludes everything and then re-includes Swan paths, but its later exclusions omit Swan/artifacts/** and Swan/.interop-live/** even though Git ignores both as runtime and evidence material. Lab and acceptance runners create owner-only work directories there containing post text, temporary JSON record bodies, access, delegation, and space credentials, and other private permissioned values. Cleanup depends on normal shell traps, so crash, SIGKILL, stale residue, or concurrent builds can leave sensitive files present when a later Compose or CI build sends the context to the Docker daemon or remote BuildKit builder. Narrow final-stage or COPY selections do not prevent context transfer or builder-side caching. Added ordered discovery: Dockerfile.dockerignore re-includes the Swan tree but omits exclusions for Swan/.interop-live/** and Swan/artifacts/**; Compose uses the parent directory as build context and Dockerfile COPYs the admitted Swan tree into the build stage. Current ignored .interop-live JSON demonstrates that raw permissioned write bodies can occupy the omitted directory, so a build from a stale or concurrent live workspace transmits those values to a local, remote, or shared builder and retains them in an intermediate COPY layer or cache even though the final runtime stage does not copy the JSON. Additional ordered discovery: Lab scripts also install private-body and permissioned recovery or fault artifacts under the ignored Swan/.interop-live and Swan/artifacts trees. The Docker-specific ignore re-admits those trees, and JSON private bodies evade its secret-extension filters, so ordinary release builds transmit them to the builder and retain them in intermediate COPY layers or cache. Additional ordered discovery: The Docker ignore file beg

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
 "summary": "Docker build context includes ignored live artifacts, raw permissioned write bodies, temporary permissioned values, and lab credentials, exposing stale or concurrent residue to the configured builder, intermediate COPY layers, and cache. Static trace locations: source Scripts/run-forum-live-demo.sh:21-23; root_control Dockerfile.dockerignore:1-7; sink Dockerfile:10-14 Dockerfile.dockerignore excludes everything and then re-includes Swan paths, but its later exclusions omit Swan/artifacts/** and Swan/.interop-live/** even though Git ignores both as runtime and evidence material. Lab and acceptance runners create owner-only work directories there containing post text, temporary JSON record bodies, access, delegation, and space credentials, and other private permissioned values. Cleanup depends on normal shell traps, so crash, SIGKILL, stale residue, or concurrent builds can leave sensitive files present when a later Compose or CI build sends the context to the Docker daemon or remote BuildKit builder. Narrow final-stage or COPY selections do not prevent context transfer or builder-side caching. Added ordered discovery: Dockerfile.dockerignore re-includes the Swan tree but omits exclusions for Swan/.interop-live/** and Swan/artifacts/**; Compose uses the parent directory as build context and Dockerfile COPYs the admitted Swan tree into the build stage. Current ignored .interop-live JSON demonstrates that raw permissioned write bodies can occupy the omitted directory, so a build from a stale or concurrent live workspace transmits those values to a local, remote, or shared builder and retains them in an intermediate COPY layer or cache even though the final runtime stage does not copy the JSON. Additional ordered discovery: Lab scripts also install private-body and permissioned recovery or fault artifacts under the ignored Swan/.interop-live and Swan/artifacts trees. The Docker-specific ignore re-admits those trees, and J
```
