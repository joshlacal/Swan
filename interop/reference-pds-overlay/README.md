# Reference PDS recovery overlay

This is a deterministic, disposable laboratory overlay for the immutable
TypeScript reference pinned by Swan's permissioned-data profile. It never
patches `Swan/.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`.
Instead, `apply-reference-pds-overlay.sh` verifies the reference archive,
copies the extracted cache to a fresh destination, verifies the patch checksum
from `profile.json`, and applies `reference-pds-recovery.patch` there.

Run the focused overlay-and-integrity proof with:

```sh
Swan/interop/reference-pds-overlay/test-reference-pds-overlay.sh
```

The source qualification applies the patch to a disposable source copy,
checks the expected changed surfaces, and proves that the pinned cache is
unchanged. It is not behavioral or interoperability evidence. A full
reference Jest/SQLite run belongs in the Node 24 reference image; a host run
is not portable across native-module ABIs. The default Compose service remains
the exact pinned image; this overlay is an explicit recovery qualification,
not an upstream mutation.

The patch is intentionally narrow:

- Qualifies `space_record_oplog.space` in `getRepoOplog`, so the value-bearing
  `listRepoOps` query remains unambiguous after it joins `space_record`.
- Implements the read-authorized `com.atproto.space.getRepo` handler using one
  actor-store SQLite read transaction. The handler keyset-reads index metadata
  in canonical DAG-CBOR order, then reads one current record at a time in
  lexical path order. It rejects a stored CID that does not match the record's
  canonical DAG-CBOR bytes.
- Spools the canonical index and pre-framed record blocks into an owner-only
  temporary directory. Index SHA-256/CID calculation is incremental, response
  streaming never materializes the complete index or repository, and cleanup
  runs on success, stream cancellation, and failure.
- Uses a disk-backed CID set while spooling records. Every indexed path is
  retained and validated, while paths sharing the same value CID emit exactly
  one CAR block frame for that CID.
- Emits exactly two ordered CAR roots: the freshly signed commit and the
  canonical DAG-CBOR DRISL mapping `collection/rkey` to record CID. The root
  blocks are followed by current record blocks in lexical path order.

It deliberately does not alter the pin, its archive, auth policy, or
notification semantics. A never-written repository has no signed LtHash state
and therefore returns `InvalidRequest` rather than emitting an unverifiable
recovery CAR.

For permissioned blob fixtures, the overlay also promotes typed blobs found in
accepted `space.createRecord`, `space.putRecord`, and `space.applyWrites`
records through the reference actor's existing permanent-blob path. This is a
laboratory compatibility shim: the pinned reference has one actor blob
namespace, while Swan maintains separate public and permissioned references.
