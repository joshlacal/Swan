# Cluster C7-pipethrough

---

## F35 [LOW] `open-redirect`
**The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.**
finding id: `csf_8e4562c5f795d7f58d5c6801`

### Locations
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737`  

### Attack path
- source: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447`
- sink: `recorded protected operation`
- outcome: The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Authentication and peer pinning constrain who reaches the proxy and prevent server-side SSRF; they do not constrain the client-visible redirect. Practical impact depends on AT Protocol client redirect behavior.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Authentication and peer pinning constrain who reaches the proxy and prevent server-side SSRF; they do not constrain the client-visible redirect. Practical impact depends on AT Protocol client redirect behavior.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. After an account-OAuth-authorized request is routed through the peer-pinned sender, pipethroughResponse allow-lists the upstream Location header and copies its sole printable value of at most 256 bytes verbatim. It does not parse the value or restrict scheme, host, or origin. A malicious or compromised configured/resolved service can therefore return a 3xx that directs a following client to an attacker-selected destination.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Do not relay arbitrary upstream `Location` values under Swan's origin; reject them or allow only same-origin/same-service canonical destinations.

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
 "summary": "The authenticated XRPC pipethrough relays an upstream-controlled Location header without validating its destination, potentially exposing an open redirect through Swan's origin. Static trace locations: entrypoint Sources/SwanHTTP/SwanXRPCPipethrough.swift:302-447; root_control Sources/SwanHTTP/SwanXRPCPipethrough.swift:709-737 After an account-OAuth-authorized request is routed through the peer-pinned sender, pipethroughResponse allow-lists the upstream Location header and copies its sole printable value of at most 256 bytes verbatim. It does not parse the value or restrict scheme, host, or origin. A malicious or compromised configured/resolved service can therefore return a 3xx that directs a following client to an attacker-selected destination."
}
```

---

## F40 [LOW] `identity-resolution-confusion`
**Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.**
finding id: `csf_1a32ff0a51e6fd7d4f98e886`

### Locations
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:385-445`  
- `Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366`  
- `Sources/swan/SwanCommand.swift:2774-2822`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:303-341`  
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:390-445`  
- `Sources/SwanOAuth/OAuthRemoteFetch.swift:192-214`  

### Attack path
- source: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42`
- sink: `Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366`
- outcome: Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Attacker needs a valid account/atproto scope and a peer-pinned DID document that selects an attacker-controlled service endpoint. Four-outstanding/serial DNS admission and the DID fetch deadline limit amplification, and the OS resolver may eventually return, but one blocked serial getaddrinfo can stall queued callers while leases remain held. Practical resolver duration requires later validation. Additional context: The newly traced instance requires an authenticated account and control of a resolvable DID service hostname and its authoritative DNS behavior. The four-entry DNS gate, 32-slot proxy admission, and eventual OS resolver timeout bound concurrency but do not make the advertised req

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
Attacker needs a valid account/atproto scope and a peer-pinned DID document that selects an attacker-controlled service endpoint. Four-outstanding/serial DNS admission and the DID fetch deadline limit amplification, and the OS resolver may eventually return, but one blocked serial getaddrinfo can stall queued callers while leases remain held. Practical resolver duration requires later validation. Additional context: The newly traced instance requires an authenticated account and control of a resolvable DID service hostname and its authoritative DNS behavior. The four-entry DNS gate, 32-slot proxy admission, and eventual OS resolver timeout bound concurrency but do not make the advertised request deadline cover pre-transport DNS.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The public authenticated pipethrough acquires one of 32 leases before resolving and sending to a request-selected DID service. SwanProxyHTTPTransport awaits resolver.resolve before entering the timed peer-pinned transport. SystemOAuthHostnameResolver dispatches blocking getaddrinfo without a caller deadline even though OAuthRemoteFetch contains a separate private deadline helper. An attacker-controlled serviceEndpoint hostname with slow DNS can therefore retain leases beyond the advertised 10-second request timeout. Added ordered discovery: An authenticated account OAuth/DPoP caller with atproto scope can select a DID service hostname through atproto-proxy. SwanPeerPinnedProxySender validates the URL but awaits resolver.resolve(host:) before the timeout-bounded transport. Production resolution runs blocking getaddrinfo on a serial queue and holds one of four process-wide DNS leases until libc returns, while the broader pipethrough admission remains held; attacker-controlled authoritative DNS can therefore stall the queue and shared DNS capacity and degrade proxy, OAuth metadata, and DID resolution beyond the configured request timeout.

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
 "summary": "Authenticated AppView pipethrough performs attacker-influenced blocking DNS resolution outside the configured request timeout, retaining proxy admission and shared DNS capacity. Static trace locations: entrypoint/wrapper Sources/SwanHTTP/SwanXRPCPipethrough.swift:16-42; root_control Sources/SwanOAuth/SwanProxyHTTPTransport.swift:60-72; sink Sources/SwanOAuth/OAuthRemoteFetch.swift:346-366 The public authenticated pipethrough acquires one of 32 leases before resolving and sending to a request-selected DID service. SwanProxyHTTPTransport awaits resolver.resolve before entering the timed peer-pinned transport. SystemOAuthHostnameResolver dispatches blocking getaddrinfo without a caller deadline even though OAuthRemoteFetch contains a separate private deadline helper. An attacker-controlled serviceEndpoint hostname with slow DNS can therefore retain leases beyond the advertised 10-second request timeout. Added ordered discovery: An authenticated account OAuth/DPoP caller with atproto scope can select a DID service hostname through atproto-proxy. SwanPeerPinnedProxySender validates the URL but awaits resolver.resolve(host:) before the timeout-bounded transport. Production resolution runs blocking getaddrinfo on a serial queue and holds one of four process-wide DNS leases until libc returns, while the broader pipethrough admission remains held; attacker-controlled authoritative DNS can therefore stall the queue and shared DNS capacity and degrade proxy, OAuth metadata, and DID resolution beyond the configured request timeout."
}
```
