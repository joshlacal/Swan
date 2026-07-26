# Swan Petrel Generator Prerequisite

## Boundary

This plan owns only the isolated `Petrel-swan-generator` jj workspace. It does
not modify the main Petrel checkout, publish a Petrel release, or change an
existing generated client manifest unless that manifest explicitly enables the
Swan server-contract feature.

## Deliverables

- Recognize primary Lexicon declarations whose type is `space`.
- Emit Swift and Kotlin `SpaceDeclarationDescriptor` data for a space NSID,
  key policy, localized name, and allowed collections.
- Emit `XRPCMethodDescriptor` data for query, procedure, and subscription
  declarations, and opt-in Swift asynchronous server-handler contracts.
- Preserve existing manifest output byte-for-byte when the opt-in flag is not
  present.
- Preserve required-plus-nullable Lexicon fields: a key must be present but
  may carry JSON/CBOR null.

## Evidence and gates

- Isolated changes: `d831c7eb` (`space` contracts) and `d011ccf0`
  (required-nullable fields).
- The synthetic required-nullable fixture proves that explicit null is accepted
  and re-emitted while an absent key fails decoding.
- Targeted generator tests pass. The full generator suite currently has one
  unrelated stale projection assertion; it must be reproduced in the main
  Petrel line before any release decision, but does not justify a workaround
  in Swan.
- Swan's checked-in `com.atproto.space.listRepoOps` output uses nullable `cid`
  and `prev` with required-key decoding. The aligned Swan wire change is
  `c7403e5b`.

## Remaining gate

CI must download only the pinned proposal source, verify the profile checksums,
run the generator, and require an empty Swan generated-source diff.
