# Cluster C6-identity-resolution

---

## F07 [MEDIUM] `identity-resolution-confusion`
**Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.**
finding id: `csf_192ba0375e308472bf8c8ee3`

### Locations
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119`  
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:400-445`  
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:71-95`  
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:36-56`  
- `Sources/SwanAccounts/PLCClient.swift:395-417`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-440`  
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:92-119`  
- `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:36-55`  

### Attack path
- source: `Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119`
- sink: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432`
- outcome: Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Identity and authenticity binding gap at the boundary between remote DID resolution and authenticated service proxying. Exploitation requires resolver misbinding or control, compromise, or misbehavior of the configured external identity authority while retaining an accepted transport identity. The PLC subcase is confused-deputy routing to a substituted public endpoint, not private-network SSRF; non-PLC DID methods still require returned-document id equality. Additional context: Strongest counterevidence/proof gap: HTTPS, DNS/peer pinning, no redirects, public-address policy, exact service-fragment matching, and downstream JWT aud/lxm binding prevent ordinary SSRF and cross-method token reuse

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Identity and authenticity binding gap at the boundary between remote DID resolution and authenticated service proxying. Exploitation requires resolver misbinding or control, compromise, or misbehavior of the configured external identity authority while retaining an accepted transport identity. The PLC subcase is confused-deputy routing to a substituted public endpoint, not private-network SSRF; non-PLC DID methods still require returned-document id equality. Additional context: Strongest counterevidence/proof gap: HTTPS, DNS/peer pinning, no redirects, public-address policy, exact service-fragment matching, and downstream JWT aud/lxm binding prevent ordinary SSRF and cross-method token reuse. Exploitation requires a compromised/misbehaving configured PLC response path or rollback-capable intermediary, unless the PLC JSON endpoint itself is intentionally the final trusted authority. Confirm the intended PLC trust boundary and whether proxy service endpoints require cryptographic audit-chain verification. This narrower subcase preserves the proof tuple in which a substituted, compromised, or erroneous DID/PLC response redirects an authenticated request and audience-bound token to end

### Root cause
The violated invariant is enforced incompletely at the recorded root control. SwanServiceEndpointResolver's decoded Document omits the top-level id, so it does not require the returned document identity to equal the requested DID; it selects a matching service fragment using the caller-supplied DID and returns its endpoint. For did:plc, SwanPeerPinnedDIDDocumentFetcher derives the configured PLC directory URL and accepts fetchJSON bytes with transport, redirect, address, and size controls, but it does not verify the PLC audit chain or bind the returned id, services, keys, and aliases to verified terminal PLC state. The authenticated XRPC pipethrough then mints an account service JWT whose audience is the requested DID and whose method is bound to the request, and sends the token and proxied request to the selected endpoint. The separate PLCDirectoryClient.fetchState demonstrates the stronger available control by fetching the audit chain and comparing terminal rotation keys, verification methods, aliases, and services. A compromised, malicious, stale, misbound, or incorrectly served external identity-authority response can therefore substitute a public HTTPS endpoint and receive the signed service JWT and body, including when the document claims the requested id but its PLC state is unverified. Counterevidence is substantial: document URLs are canonically derived; peer pinning blocks private-address SSRF, redirects, and DNS rebinding; the source directory is normally authoritative; audience and lxm binding limit token reuse; and account DPoP authorization precedes resolution, so ordinary unauthenticated callers cannot trigger the path. Additional ordered discovery: SwanPeerPinnedDIDDocumentFetcher maps did:plc directly to the configured PLC origin and returns the generic peer-pinned JSON response. SwanServiceEndpointResolver decodes only the servi

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
 "summary": "Production DID service resolution accepts a document without binding its identity or PLC state to the requested DID and can send an account-signed proxy request to a substituted service endpoint. Static trace locations: source Sources/SwanOAuth/SwanServiceEndpointResolver.swift:60-119; root_control Sources/SwanOAuth/SwanServiceEndpointResolver.swift:20-56; sink Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-432 SwanServiceEndpointResolver's decoded Document omits the top-level id, so it does not require the returned document identity to equal the requested DID; it selects a matching service fragment using the caller-supplied DID and returns its endpoint. For did:plc, SwanPeerPinnedDIDDocumentFetcher derives the configured PLC directory URL and accepts fetchJSON bytes with transport, redirect, address, and size controls, but it does not verify the PLC audit chain or bind the returned id, services, keys, and aliases to verified terminal PLC state. The authenticated XRPC pipethrough then mints an account service JWT whose audience is the requested DID and whose method is bound to the request, and sends the token and proxied request to the selected endpoint. The separate PLCDirectoryClient.fetchState demonstrates the stronger available control by fetching the audit chain and comparing terminal rotation keys, verification methods, aliases, and services. A compromised, malicious, stale, misbound, or incorrectly served external identity-authority response can therefore substitute a public HTTPS endpoint and receive the signed service JWT and body, including when the document claims the requested id but its PLC state is unverified. Counterevidence is substantial: document URLs are canonically derived; peer pinning blocks private-address SSRF, redirects, and DNS rebinding; the source directory is normally authoritative; audience and lxm binding limit token reuse; and account DPoP authorization precedes resolution, so ordinary
```

---

## F10 [MEDIUM] `identity-resolution-confusion`
**The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.**
finding id: `csf_7ddfb79181cf3beb166874b4`

### Locations
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:208-233`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101`  
- `Sources/SwanOAuth/OAuthClientMetadataLoader.swift:129-164`  
- `Sources/SwanAccounts/ATHandleVerification.swift:105-118`  
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:232-234`  
- `Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:137-169`  
- `Sources/SwanAccounts/ATHandleVerification.swift:100-113`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:351-366`  

### Attack path
- source: `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168`
- sink: `Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72`
- outcome: The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Peer pinning, TLS hostname validation, redirect rejection, and deployment routing constrain exploitability; practical internal response retrieval was not demonstrated. Additional context: Practical exploitation depends on functional 6to4 routing and compatible TLS/target behavior; exact peer pinning and hostname certificate validation limit ordinary deployments. Where 6to4 is routed, the policy can permit blind internal reachability or side effects that the stated SSRF boundary intends to reject. Additional context: Practical exploitation is conditional on usable 6to4 routing and a TLS endpoint valid for the attacker-selected hostname or relevant laboratory trust. Modern deployments often la

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Peer pinning, TLS hostname validation, redirect rejection, and deployment routing constrain exploitability; practical internal response retrieval was not demonstrated. Additional context: Practical exploitation depends on functional 6to4 routing and compatible TLS/target behavior; exact peer pinning and hostname certificate validation limit ordinary deployments. Where 6to4 is routed, the policy can permit blind internal reachability or side effects that the stated SSRF boundary intends to reject. Additional context: Practical exploitation is conditional on usable 6to4 routing and a TLS endpoint valid for the attacker-selected hostname or relevant laboratory trust. Modern deployments often lack 6to4, peer pinning and TLS remain enforced, and no private-service access was demonstrated. Additional context: Peer pinning, double DNS resolution, redirect denial, and body bounds are strong counterevidence. Later validation must establish whether an accepted special-purpose range can route to a protected destination in a supported deployment; otherwise this is a policy inconsistency without an SSRF asset. Additional context: Potential IPv4 destination-policy bypass through 6to4 routing; ex

### Root cause
The violated invariant is enforced incompletely at the recorded root control. OAuthIPAddress accepts all 2000::/3 except 2001:db8::/32 and a small portion of 2001::/32. Special-purpose prefixes including 2002::/16 6to4, 2001:20::/28 ORCHIDv2, and 3fff::/20 documentation therefore pass, while the parallel AT-handle classifier explicitly rejects these classes. Public PAR can select metadata client IDs that reach this policy. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts nearly all 2000::/3 addresses and does not reject 2002::/16, so literals such as 2002:7f00:1:: and DNS answers in that range pass URL and resolved-address checks and are supplied as approved peer pins to outbound transports. Public PAR loads attacker-selected HTTPS client metadata through this policy. Swan's independent handle-fetch classifier explicitly rejects 2002::/16, demonstrating the missing special-purpose check. Added ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts 2002::/16 within its broad 2000::/3 allowance. A 6to4 address can embed an IPv4 destination that the same policy rejects directly, and resolved OAuth metadata or JWKS, did:web, and authenticated proxy service hosts are policy-checked with this classifier before a peer-pinned connection. The parallel ATHandleIPAddress classifier explicitly rejects 2002::/16, confirming inconsistent special-purpose handling. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts any IPv6 address in 2000::/3 except 2001:db8::/32 and approximately 2001::/20. This leaves at least 2002::/16 (6to4) and 3fff::/20 (documentation) classified as public. The repository's AT-handle policy rejects both ranges in Sources/SwanAccounts/ATHandleVerification.swift:101-113. An attacker-selected OAuth metadata or JWKS hostname can therefore place one of these addresses in the appr

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
 "summary": "The shared OAuth, DID-fetch, and authenticated-proxy IP classifier treats special-purpose IPv6 ranges, including 6to4 addresses embedding otherwise rejected IPv4 destinations, as public. Static trace locations: entrypoint Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:164-168; root_control Sources/SwanOAuth/OAuthRemoteFetch.swift:85-101; sink Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72 OAuthIPAddress accepts all 2000::/3 except 2001:db8::/32 and a small portion of 2001::/32. Special-purpose prefixes including 2002::/16 6to4, 2001:20::/28 ORCHIDv2, and 3fff::/20 documentation therefore pass, while the parallel AT-handle classifier explicitly rejects these classes. Public PAR can select metadata client IDs that reach this policy. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts nearly all 2000::/3 addresses and does not reject 2002::/16, so literals such as 2002:7f00:1:: and DNS answers in that range pass URL and resolved-address checks and are supplied as approved peer pins to outbound transports. Public PAR loads attacker-selected HTTPS client metadata through this policy. Swan's independent handle-fetch classifier explicitly rejects 2002::/16, demonstrating the missing special-purpose check. Added ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts 2002::/16 within its broad 2000::/3 allowance. A 6to4 address can embed an IPv4 destination that the same policy rejects directly, and resolved OAuth metadata or JWKS, did:web, and authenticated proxy service hosts are policy-checked with this classifier before a peer-pinned connection. The parallel ATHandleIPAddress classifier explicitly rejects 2002::/16, confirming inconsistent special-purpose handling. Additional ordered discovery: OAuthIPAddress.isPublicInternetAddress accepts any IPv6 address in 2000::/3 except 2001:db8::/32 and approximately 2001::/20. This leaves at least 2002::/16 (6to4) and 3fff::/20 (d
```

---

## F22 [MEDIUM] `identity-resolution-confusion`
**OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.**
finding id: `csf_97f518310ca135ba282c573e`

### Locations
- `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66`  
- `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251`  
- `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135`  
- `Sources/SwanOAuth/OAuthClientMetadata.swift:238-245`  
- `Sources/SwanOAuth/SwanProxyHTTPTransport.swift:215-225`  

### Attack path
- source: `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66`
- sink: `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135`
- outcome: OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: TLS hostname verification, peer pinning, and redirect refusal prevent cross-host redirection. The proof gap is a realistic same-origin endpoint that returns usable metadata or JWKS under the rewritten target.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
TLS hostname verification, peer pinning, and redirect refusal prevent cross-host redirection. The proof gap is a realistic same-origin endpoint that returns usable metadata or JWKS under the rewritten target.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. NIOPeerPinnedOAuthDocumentTransport constructs the origin-form target from url.path and url.query. SwanProxyHTTPTransport separately documents that URL.path percent-decodes and therefore uses percentEncodedPath and percentEncodedQuery. The response handler reports responseURL as the original requestURL rather than the emitted target, so the later exact URL check cannot detect a rewrite. Encoded separators or query delimiters in attacker-selected client_id or jwks_uri values can request a different same-origin resource than the identity that passed policy.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Use one canonical URL representation for validation, request-target construction, DPoP identity, caching and transport; reject encodings whose decoded path/query changes the validated identity.

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
 "summary": "OAuth document fetching validates one percent-encoded URL identity but emits an HTTP target built from percent-decoded path and query. Static trace locations: entrypoint Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:32-66; root_control Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:248-251; sink Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:128-135 NIOPeerPinnedOAuthDocumentTransport constructs the origin-form target from url.path and url.query. SwanProxyHTTPTransport separately documents that URL.path percent-decodes and therefore uses percentEncodedPath and percentEncodedQuery. The response handler reports responseURL as the original requestURL rather than the emitted target, so the later exact URL check cannot detect a rewrite. Encoded separators or query delimiters in attacker-selected client_id or jwks_uri values can request a different same-origin resource than the identity that passed policy."
}
```
