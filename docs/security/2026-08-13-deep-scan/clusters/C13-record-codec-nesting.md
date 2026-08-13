# Cluster C13-record-codec-nesting

---

## F30 [MEDIUM] `security-control-bypass`
**Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.**
finding id: `csf_eb4385a12a956b467c112941`

### Locations
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:115-135`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:172-215`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:349-400`  
- `Tests/SwanPublicRepositoryTests/PublicRepositoryDomainTests.swift:289-312`  
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:158-177`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-108`  
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:130-130`  

### Attack path
- source: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177`
- sink: `recorded protected operation`
- outcome: Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check.

### Reachability
The path is in a production-capable HTTP/XRPC, credential, identity, persistence, parser, deployment, or resource-control surface. Preconditions and partial controls are preserved in validation: Prerequisite: an authenticated account submits a deeply object-nested value that survives the Petrel/Foundation request decoder and 1 MiB HTTP body limit. Potential impact is excessive recursion/CPU or stack exhaustion before the intended maximumCBORNestingDepth control. Upstream decoding may impose its own depth ceiling and prepare rejects excessive depth before persistence; the existing depth test covers the later encoder and an array/object mixture, not object-only pre-encoding conversion.

### Impact (high)
The path is source-supported and production-capable, but impact is bounded to a narrower object, authorization window, or service-availability boundary, or exploitation requires authentication, peer control, or a race.

### Likelihood (medium)
Prerequisite: an authenticated account submits a deeply object-nested value that survives the Petrel/Foundation request decoder and 1 MiB HTTP body limit. Potential impact is excessive recursion/CPU or stack exhaustion before the intended maximumCBORNestingDepth control. Upstream decoding may impose its own depth ceiling and prepare rejects excessive depth before persistence; the existing depth test covers the later encoder and an array/object mixture, not object-only pre-encoding conversion.

### Root cause
The violated invariant is enforced incompletely at the recorded root control. convertObject passes the same depth to each child, convert(.object) calls convertObject with unchanged depth, and convertCBOR recurses through OrderedCBORMap and dictionary values without incrementing or checking depth; only arrays advance depth. The later prepare/encode phase correctly advances object depth, but it runs after conversion has already recursively traversed the attacker-controlled graph. Authenticated createRecord, putRecord, and applyWrites call publicRecord on request values. Additional ordered discovery: convertObject checks depth but passes the same depth to convert, whose .object branch calls convertObject with that unchanged value. convertCBOR likewise recursively visits OrderedCBORMap and [String: Any] children with unchanged depth; only arrays increment it. The applyWrites/createRecord/putRecord HTTP paths invoke publicRecord directly on request-decoded records. Although later record preparation increments object depth correctly, conversion and recursive blob-reference projection happen first, so sufficiently deep object nesting can exhaust the Swift stack or CPU instead of returning recordNestingTooDeep. Existing depth coverage exercises mixed array/object nesting, not object-only nesting.

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
 "summary": "Public record conversion does not advance or consistently enforce the advertised 64-level nesting bound through objects and maps, allowing object-only recursive traversal before the later encoder check. Static trace locations: entrypoint/wrapper Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:163-177; root_control Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift:97-112 convertObject passes the same depth to each child, convert(.object) calls convertObject with unchanged depth, and convertCBOR recurses through OrderedCBORMap and dictionary values without incrementing or checking depth; only arrays advance depth. The later prepare/encode phase correctly advances object depth, but it runs after conversion has already recursively traversed the attacker-controlled graph. Authenticated createRecord, putRecord, and applyWrites call publicRecord on request values. Additional ordered discovery: convertObject checks depth but passes the same depth to convert, whose .object branch calls convertObject with that unchanged value. convertCBOR likewise recursively visits OrderedCBORMap and [String: Any] children with unchanged depth; only arrays increment it. The applyWrites/createRecord/putRecord HTTP paths invoke publicRecord directly on request-decoded records. Although later record preparation increments object depth correctly, conversion and recursive blob-reference projection happen first, so sufficiently deep object nesting can exhaust the Swift stack or CPU instead of returning recordNestingTooDeep. Existing depth coverage exercises mixed array/object nesting, not object-only nesting."
}
```
