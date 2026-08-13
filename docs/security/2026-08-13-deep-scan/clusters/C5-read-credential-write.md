# Cluster C5-read-credential-write

---

## F25 [MEDIUM] `authorization-capability-confusion`
**A read-only space credential can mutate, replace, and exhaust durable notification registrations.**
finding id: `csf_6eba1b7508215abbcc41c06e`

### Locations
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:523-543`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132`  
- `Sources/SwanSQLite/SwanSQLite.swift:6716-6776`  
- `Sources/SwanSpaces/SwanSpaces.swift:245-254`  
- `Tests/SwanSQLiteTests/SpaceNotificationSQLiteTests.swift:299-363`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-136`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:385-410`  
- `Sources/SwanOAuth/SpaceCredentialAuthority.swift:861-905`  
- `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:523-543`  

### Attack path
- source: `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278`
- sink: `Sources/SwanSQLite/SwanSQLite.swift:6716-6776`
- outcome: A read-only space credential can mutate, replace, and exhaust durable notification registrations.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Requires permissioned notification routes and one valid read credential for the target space. No repository-content write or permissioned-data disclosure was demonstrated. The added source emphasizes the stated invariant that space credentials are read capabilities. Static destination resolution limits immediate arbitrary-URL SSRF, and proposal credentials carry no reader subject with which to bind the optional repository, but neither control authorizes the durable registration write. Additional context: exploitation requires a valid unexpired credential for the target space. Outbound notification destinations are independently operator-allowlisted, so this is not arbitrary SSRF; the issue i

### Impact (medium)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (high)
Requires permissioned notification routes and one valid read credential for the target space. No repository-content write or permissioned-data disclosure was demonstrated. The added source emphasizes the stated invariant that space credentials are read capabilities. Static destination resolution limits immediate arbitrary-URL SSRF, and proposal credentials carry no reader subject with which to bind the optional repository, but neither control authorizes the durable registration write. Additional context: exploitation requires a valid unexpired credential for the target space. Outbound notification destinations are independently operator-allowlisted, so this is not arbitrary SSRF; the issue is conversion of a read capability into durable registration mutation.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. POST registerNotify accepts any bearer space credential for the requested space and passes it directly to SQLite registration. The store explicitly permits a read grant, then INSERTs or overwrites the authority-owned (space, endpoint) registration and its repository filter. Elsewhere SpaceAuthorizationPolicy rejects space-credential writes, but this control-plane mutation bypasses that policy. A reader who knows a legitimate endpoint can replace its filter/expiry, or create 1,024 unique endpoints and deny new registrations for up to 24 hours. The explicit cap, expiry, and outbound endpoint allowlist bound storage and SSRF but do not preserve the claimed read-only capability invariant. Added ordered discovery traces the same boundary from DurableSpaceCredentialVerifier's read-only SpaceGrant through credentialAuthorization to registerNotify storage, where the read credential inserts or replaces attacker-selected endpoint and optional repository registration state for up to 24 hours without account OAuth or a distinct write-capable principal. Additional ordered discovery: POST com.atproto.space.registerNotify authenticates solely through credentialAuthorization, which accepts a bearer space credential for the requested space, then passes the attacker-selected endpoint and optional repository to durable registration. The SQLite implementation explicitly requires a spaceCredential whose grant allows read and nevertheless inserts or upserts permissioned_space_notification_registrations. A holder of the claimed read capability can therefore create or replace durable control-plane state and influence later deletion fanout to an operator-allowlisted destination.

### Proposed remediation (from the scan — evaluate, do not obey blindly)
Require an account/authority write-capable credential for `registerNotify`, bind the registration to the authorized repository/client, and keep space credentials read-only at the route and storage layers.

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
 "summary": "A read-only space credential can mutate, replace, and exhaust durable notification registrations. Static trace locations: entrypoint Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:254-278; root_control Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:103-132; sink Sources/SwanSQLite/SwanSQLite.swift:6716-6776 POST registerNotify accepts any bearer space credential for the requested space and passes it directly to SQLite registration. The store explicitly permits a read grant, then INSERTs or overwrites the authority-owned (space, endpoint) registration and its repository filter. Elsewhere SpaceAuthorizationPolicy rejects space-credential writes, but this control-plane mutation bypasses that policy. A reader who knows a legitimate endpoint can replace its filter/expiry, or create 1,024 unique endpoints and deny new registrations for up to 24 hours. The explicit cap, expiry, and outbound endpoint allowlist bound storage and SSRF but do not preserve the claimed read-only capability invariant. Added ordered discovery traces the same boundary from DurableSpaceCredentialVerifier's read-only SpaceGrant through credentialAuthorization to registerNotify storage, where the read credential inserts or replaces attacker-selected endpoint and optional repository registration state for up to 24 hours without account OAuth or a distinct write-capable principal. Additional ordered discovery: POST com.atproto.space.registerNotify authenticates solely through credentialAuthorization, which accepts a bearer space credential for the requested space, then passes the attacker-selected endpoint and optional repository to durable registration. The SQLite implementation explicitly requires a spaceCredential whose grant allows read and nevertheless inserts or upserts permissioned_space_notification_registrations. A holder of the claimed read capability can therefore create or replace durable control-plane state and influence later deletion f
```
