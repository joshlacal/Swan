# Cluster C9-firehose-admission

---

## F05 [MEDIUM] `resource-exhaustion`
**Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.**
finding id: `csf_b9a83fb32e60e2b3e07b4314`

### Locations
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`  
- `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18`  
- `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:312-367`  
- `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:58-73`  
- `Sources/SwanHTTP/SwanHTTP.swift:1125-1151`  
- `Sources/SwanHTTP/SwanHTTP.swift:1125-1136`  
- `Sources/SwanHTTP/PublicFirehoseStreaming.swift:173-247`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:235-367`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:145-162`  

### Attack path
- source: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`
- sink: `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30`
- outcome: Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Internet reachable when the public firehose runtime and subscribeRepos profile surface are enabled. An external proxy may impose quotas, but neither the in-process route nor the checked-in lab proxy supplies a firehose-specific aggregate or per-client bound. The listener-wide ceiling bounds process growth while enabling cross-route starvation. The feature is opt-in and the listener ceiling bounds simultaneous growth; those are countercontrols but turn the issue into deterministic shared-listener starvation rather than preventing it. Attacker capability: anonymous Internet TCP/WebSocket access. Entry point: /xrpc/com.atproto.sync.subscribeRepos. Protected asset: availability of all routes sha

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Internet reachable when the public firehose runtime and subscribeRepos profile surface are enabled. An external proxy may impose quotas, but neither the in-process route nor the checked-in lab proxy supplies a firehose-specific aggregate or per-client bound. The listener-wide ceiling bounds process growth while enabling cross-route starvation. The feature is opt-in and the listener ceiling bounds simultaneous growth; those are countercontrols but turn the issue into deterministic shared-listener starvation rather than preventing it. Attacker capability: anonymous Internet TCP/WebSocket access. Entry point: /xrpc/com.atproto.sync.subscribeRepos. Protected asset: availability of all routes sharing the listener. Additional context: Global connection limits, ping/close timeouts, frame bounds, and slow-writer eviction exist, but do not reject responsive idle subscribers or reserve listener capacity for other routes. Whether upgraded sockets remain charged and whether an external proxy imposes per-IP limits remain proof gaps. Additional context: Attacker capability: anonymous Internet client able to complete WebSocket upgrades and stop reading. Protected asset: public listener connection

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The public subscribeRepos upgrader accepts every syntactically valid unauthenticated request. Each accepted responsive connection occupies one of the listener-wide 256 default connection slots, creates an inbound drain task, wakeup subscription/forwarder, repeatedly polling SQLite tailer, and outbound writer, and remains live indefinitely if it answers automatic pings. The hub subscriber dictionary has no capacity check and every append/retention signal iterates and yields to every subscriber. Cursor, lag, per-write, and slow-consumer controls bound some individual work but do not evict idle responsive clients; maximumWriteDuration is evaluated only after a write returns rather than enforcing a deadline. Enough compliant WebSockets can therefore deny unrelated public reads, OAuth, repository, account, and XRPC traffic and make each repository event O(attacker subscribers). Existing tests exercise individual lag/write behavior but not endpoint-specific concurrent admission. The idle tailer performs roughly two SQLite reads per 250 ms polling interval per responsive connection, so even subscribers that are not lagging or slow-writing amplify steady database work. Additional discovery identifies the concrete cross-route effect: roughly the default 256 responsive firehose sockets can occupy the listener-wide MaximumAvailableConnections budget shared with login, OAuth, public repository, and permissioned routes. Each accepted session resolves cursors, registers a hub subscriber, starts forwarding, drain, writer, and tailer work, and an idle tailer repeatedly queries retainedFromSeq/events about every 250 ms. Auto-ping, close timeout, per-stream lag, and write-deadline policies constrain dead or slow consumers but do not evict responsive idle subscribers or reserve listener c

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
 "summary": "Unauthenticated responsive or non-reading firehose WebSockets lack route-level admission and an effective outbound-write deadline, allowing them to monopolize shared listener capacity while accumulating session and SQLite work. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-18; sink Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:25-30 The public subscribeRepos upgrader accepts every syntactically valid unauthenticated request. Each accepted responsive connection occupies one of the listener-wide 256 default connection slots, creates an inbound drain task, wakeup subscription/forwarder, repeatedly polling SQLite tailer, and outbound writer, and remains live indefinitely if it answers automatic pings. The hub subscriber dictionary has no capacity check and every append/retention signal iterates and yields to every subscriber. Cursor, lag, per-write, and slow-consumer controls bound some individual work but do not evict idle responsive clients; maximumWriteDuration is evaluated only after a write returns rather than enforcing a deadline. Enough compliant WebSockets can therefore deny unrelated public reads, OAuth, repository, account, and XRPC traffic and make each repository event O(attacker subscribers). Existing tests exercise individual lag/write behavior but not endpoint-specific concurrent admission. The idle tailer performs roughly two SQLite reads per 250 ms polling interval per responsive connection, so even subscribers that are not lagging or slow-writing amplify steady database work. Additional discovery identifies the concrete cross-route effect: roughly the default 256 responsive firehose sockets can occupy the listener-wide MaximumAvailableConnections budget shared with login, OAuth, public repository, and permissioned routes. Each accepted session resolves cursors, registers a hub subscriber, st
```

---

## F11 [MEDIUM] `resource-exhaustion`
**Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.**
finding id: `csf_671afbb6450fc805506d3d8b`

### Locations
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`  
- `Sources/SwanHTTP/SwanHTTP.swift:1159-1175`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367`  
- `Sources/SwanHTTP/SwanHTTP.swift:1125-1156`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:330-350`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:136-163`  
- `Sources/SwanHTTP/SwanHTTP.swift:1125-1155`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:330-359`  

### Attack path
- source: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`
- sink: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367`
- outcome: Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The listener has a default 256-connection global bound, ping and close timeouts, and outbound slow-consumer controls. Those controls bound simultaneous sessions and outbound stalls but do not limit inbound frame rate, per-session bytes, or aggregate inbound work. Route-level subscriber admission addresses listener monopolization but does not by itself stop abusive frames from admitted clients. This preserves the oversized-inbound-firehose-frames subcase and its CPU, memory, event-loop, network, and shared-pool pressure across parallel admitted sessions. The added source retains uncertainty about Hummingbird buffering and backpressure and notes the global 256-connection cap, ping/close timeou

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
The listener has a default 256-connection global bound, ping and close timeouts, and outbound slow-consumer controls. Those controls bound simultaneous sessions and outbound stalls but do not limit inbound frame rate, per-session bytes, or aggregate inbound work. Route-level subscriber admission addresses listener monopolization but does not by itself stop abusive frames from admitted clients. This preserves the oversized-inbound-firehose-frames subcase and its CPU, memory, event-loop, network, and shared-pool pressure across parallel admitted sessions. The added source retains uncertainty about Hummingbird buffering and backpressure and notes the global 256-connection cap, ping/close timeouts, prompt discard, and per-frame rejection as bounds that do not constrain sustained admitted inbound work.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. subscribeRepos upgrades anonymous clients without an inbound-message rate or aggregate-byte budget. Each accepted connection creates multiple tasks and database/tailer state, and its inbound drain task repeatedly accepts, copies, and discards attacker-controlled frames up to 5,000,000 bytes. Even within any route-level connection allowance, admitted clients can continuously send maximum frames to consume memory-copy, event-loop, and parsing/drain work; enough sessions also occupy the listener-wide allowance and deny unrelated HTTP and OAuth traffic. The added discovery clarifies that the 5,000,000-byte maximum exists for outbound commit frames but applies symmetrically inbound, where subscribeRepos defines no client-data protocol; the task fully iterates and discards every such frame without count, byte, or rate budgets. The new ordered source independently traces the anonymous upgrade, the symmetric 5,000,000-byte frame ceiling selected for outbound commits, and the inbound task that continuously drains and discards every client message without message-type, cumulative-byte, rate, or per-peer limits.

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
 "summary": "Accepted anonymous firehose sessions have no inbound frame-rate or aggregate-byte budget and can continuously force processing of maximum-size WebSocket frames. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/SwanHTTP.swift:1159-1175; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:240-367 subscribeRepos upgrades anonymous clients without an inbound-message rate or aggregate-byte budget. Each accepted connection creates multiple tasks and database/tailer state, and its inbound drain task repeatedly accepts, copies, and discards attacker-controlled frames up to 5,000,000 bytes. Even within any route-level connection allowance, admitted clients can continuously send maximum frames to consume memory-copy, event-loop, and parsing/drain work; enough sessions also occupy the listener-wide allowance and deny unrelated HTTP and OAuth traffic. The added discovery clarifies that the 5,000,000-byte maximum exists for outbound commit frames but applies symmetrically inbound, where subscribeRepos defines no client-data protocol; the task fully iterates and discards every such frame without count, byte, or rate budgets. The new ordered source independently traces the anonymous upgrade, the symmetric 5,000,000-byte frame ceiling selected for outbound commits, and the inbound task that continuously drains and discards every client message without message-type, cumulative-byte, rate, or per-peer limits."
}
```

---

## F33 [LOW] `authorization-state-race`
**Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.**
finding id: `csf_fa2454216b43db02aa76cb97`

### Locations
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:368-374`  
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:255-259`  

### Attack path
- source: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163`
- sink: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99`
- outcome: Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: The listener connection cap bounds simultaneous sockets but not connection churn or accumulated log volume over time. Logged fields are server-generated or bounded and omit request headers, tokens, peer identifiers, and event values, so the concern is rate-driven resource exhaustion rather than injection or credential disclosure.

### Impact (medium)
The defect is reachable and security-relevant, but impact is bounded, requires narrow timing/configuration/key-compromise preconditions, or provides only limited denial, stale authority, or redirect behavior.

### Likelihood (low)
The listener connection cap bounds simultaneous sockets but not connection churn or accumulated log volume over time. Logged fields are server-generated or bounded and omit request headers, tokens, peer identifiers, and event values, so the concern is rate-driven resource exhaustion rather than injection or credential disclosure.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. The default public subscription observer emits one info-level opened record for every successful anonymous firehose upgrade and another closed record for every termination. Each session receives a fresh UUID, and there is no sampling, per-peer rate limit, aggregate rollup, deduplication, logging admission, or bounded journal. A remote actor can repeatedly upgrade and disconnect to produce two durable lifecycle events per cycle and sustain log, ingestion, disk, or journal pressure. The throttled public-read diagnostic logger provides a repository-local example of the missing analogous rate control, while credential and payload omission limits the issue to availability rather than disclosure.

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
 "summary": "Unauthenticated firehose connection churn emits unthrottled info-level lifecycle records and can drive durable log or journal growth at attacker request rate. Static trace locations: entrypoint Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:141-163; root_control Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:113-131; sink Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:85-99 The default public subscription observer emits one info-level opened record for every successful anonymous firehose upgrade and another closed record for every termination. Each session receives a fresh UUID, and there is no sampling, per-peer rate limit, aggregate rollup, deduplication, logging admission, or bounded journal. A remote actor can repeatedly upgrade and disconnect to produce two durable lifecycle events per cycle and sustain log, ingestion, disk, or journal pressure. The throttled public-read diagnostic logger provides a repository-local example of the missing analogous rate control, while credential and payload omission limits the issue to availability rather than disclosure."
}
```
