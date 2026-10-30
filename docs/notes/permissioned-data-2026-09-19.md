# Permissioned-data alignment, 2026-09-19

## Sources and immutable pins

Research checked the official proposal and TypeScript implementation on September 19, 2026. Proposal 0016 remains a draft; its initial proposal PR is merged, while the implementation PR remains open and marked draft.

| Source | Previous Swan pin | Researched revision |
| --- | --- | --- |
| [Proposal 0016](https://github.com/bluesky-social/proposals/blob/119fa6b63476d30c2516846c714319046e0422f3/0016-permissioned-data/README.md) | `1caad93dbb1f445396f6abf3b97eb4040345e78e` | `119fa6b63476d30c2516846c714319046e0422f3` (September 10) |
| [Reference implementation](https://github.com/bluesky-social/atproto/compare/9d787ebff231ff8f4e01c63717e9f5bcd6e1bc33...907f41a7b379a7e649a6c4842864946eef6eb757) | `9d787ebff231ff8f4e01c63717e9f5bcd6e1bc33` | `907f41a7b379a7e649a6c4842864946eef6eb757` (September 15) |

The new Swan profile is `permissioned-data-0016-2026-09-19`. Historical profiles are retained byte-for-byte. The September 10 reference pin was already newer than the proposal pin, so comparing only reference commits would miss behavioral gaps.

The implementation advanced by two commits:

- [September 13 CAR varint import repair](https://github.com/bluesky-social/atproto/commit/f4a1f5f8cfc9f4638c53a01445f5232ac4e1cdc3): fixes CommonJS/ESM module interoperability. It changes no CAR bytes or varint rules and requires no equivalent Swift import change.
- [September 15 public blob isolation repair](https://github.com/bluesky-social/atproto/commit/907f41a7b379a7e649a6c4842864946eef6eb757): public `sync.getBlob` requires a current public record reference. A blob used only in a space, including one whose last public reference was deleted, cannot be fetched anonymously.

All 29 permissioned lexicon files are unchanged from the September 10 pin. Petrel's compilation and generator revisions therefore stay pinned, and generated wire sources are unchanged. The registry's profile ID changes its artifact digest. The GitHub `/archive/<commit>.tar.gz` archive is pinned to SHA-256 `418f7213539e2c8f0945a9f8e6e22643073dc1c3f3248115bc626e4c29c1c579`.

## Behavior changes

The proposal comparison identified these compatibility requirements beyond the reference commit delta:

- Space credentials carry `cnf.jkt`. The exchange uses a Bearer delegation token plus a DPoP proof without `ath`; subsequent requests use the DPoP authorization scheme and proofs containing `ath`. Proofs bind the method and URL, expire, and cannot be replayed. This flow does not use OAuth server nonce challenges.
- Public blob visibility depends on current public record references, independently of whether the bytes must be retained for a space or another purpose.
- CAR record blocks follow their index entries in canonical DAG-CBOR order: shortest UTF-8 key first, then bytewise. Each indexed path has a record frame, including paths that share a CID; internal content storage remains deduplicated.
- A deleted space returns `SpaceDeleted` during credential renewal. Deletion removes the authority's own repository while retaining members' independently owned repositories. Deletion notifications remove synchronized copies; they do not revoke the member's own OAuth access to authored records.
- `read` and `read_self` ignore collection filters. Record mutations remain collection-scoped. Default collection declarations are re-resolved when existing OAuth sessions refresh, matching the reference implementation; issued access tokens retain their scope snapshot until then.
- Default collection declarations reject wildcards and malformed NSIDs. Collections from another NSID domain remain valid, as do longer display names. Explicitly requested collection grants stay unchanged when declarations change.

Independent read/write policies, member `read`/`write` flags, `putMember`, access-specific managing-app checks, and `listBlobs`/`unregisterNotify` were already present in Swan's September 10 implementation. Malformed dedicated `#atproto_space` keys already fail closed instead of falling back to `#atproto`.

Deletion tombstones also reject delayed replica imports and incremental updates. Outbound deletion notices retain their delivery registrations until acknowledgment; recreating the space cancels pending notices from its previous incarnation, including notices already held by a worker but not yet dispatched. An HTTP request already in flight remains a network boundary.

## Compatibility boundaries

Clients must obtain new DPoP-bound space credentials and retain their private proof key for the credential lifetime. Existing bearer space credentials no longer authorize production space routes. Account OAuth and space credential proofs remain separate flows.

CAR export and recovery now use the current reference's canonical per-path frame order. Previously exported CARs using lexical block order or omitting repeated-CID frames must be re-exported for the new verifier. Stored account repositories are retained.

The profile retains its documented notification fanout and retention-gap exceptions. Swan's direct writer-to-authority notification contract does not claim support for the reference's authority-signed cross-host fanout. The full-recovery CAR transport uses Swan's bounded spool implementation.

The new public blob visibility check scans the bounded public record projection when metadata or bytes are opened. It prioritizes correct revocation with the existing schema; a reverse-reference index would be a separate performance improvement.

The Docker interoperability laboratory has an independent historical reference pin. Updating source/profile verification does not update that laboratory or establish live federation interoperability. This change does not deploy a server or alter a running service.

## Validation

- `Scripts/verify-profile.sh` passes, including the 29 upstream lexicon checks and frozen historical profile checks.
- The compiled `swan verify --reference-directory .interop-cache/atproto-907f41a7b379a7e649a6c4842864946eef6eb757` passes.
- `Scripts/verify-interop-lab.sh` passes static and effective Compose invariants. This does not start the laboratory or test live federation.

Final integrated test results will be recorded after validation completes. An earlier run exposed a CLI test harness pipe deadlock; help-command capture now uses private temporary files and a bounded process timeout. That run also saw one `incompleteResponse` in the unchanged slow-drip HTTP deadline test; a focused rerun passed. The initial failure remains recorded in `/tmp/swan-permissioned-tests-20260919-pass3.log`, with the successful rerun in `/tmp/swan-socket-deadline-recheck-20260919.log`.
