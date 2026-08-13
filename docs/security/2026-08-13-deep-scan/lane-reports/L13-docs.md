# Lane L13 — docs and comments (F02, F39)

**Workspace:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-L13-docs`
**Base commit:** `c1a71eb38adf`
**Scratch/logs:** `/private/tmp/swan-lane-L13-docs/`
**Status:** DONE. No production behaviour changed — comments, one doc, two tests.

## Did I independently confirm the commitment is outside the signed bytes?

**Yes. The P1 finding stands, and it is slightly worse than the brief states.**

The signed bytes are produced by exactly one function,
`SpaceCommitCodec.encodedContext` (`Sources/SwanSpaces/SwanSpaces.swift:573-582`),
reached from both `sign` (`:524-525`) and the public
`contextSigningBytes` (`:542-544`). It emits:

```
"atproto-space-v1" || len16(space) || space
                  || len16(author) || author
                  || len16(rev)    || rev
                  || len16(ikm)    || ikm
```

The commitment is not one of the four fields. `verifyContextSignature`
(`:532-536`) verifies over `contextSigningBytes(envelope.context)` and nothing
else. The commitment is bound only by `contentBinding` (`:557-571`), an
HMAC-SHA256 whose PRK is the IKM.

**The additional finding: the IKM is not a secret on this path.**
`encodeCommit` (`:1476-1488`) writes `ikm` as a plaintext field of the wire
`com.atproto.space.defs#signedCommit` block, and `decodeCommit` (`:1490-1503`)
reads it straight back. So the adversary class is not "a party holding the
IKM" — it is **anyone who can serve, relay, or replay the commit block**,
because holding the block *is* holding the IKM. I widened the wording in the
comments and the threat-boundaries entry accordingly.

The same two checks, with the same limitation, are the entirety of the live
provider's commit authentication: `PermissionedRemoteReplicaHTTPProvider.swift`
`verifyLatestCommit` (`:240-247`) calls `contextSigningBytes` + `verifyContentBinding`
and nothing more.

Per the brief, this is the pinned upstream proposal-0016 trust model, not a
Swan bug. **No code fix attempted.**

## Brief citation check

| Brief citation | Verdict |
| --- | --- |
| `StreamingSpaceCARRecovery.swift:305-308` — the over-claiming comment | **Correct**, exact |
| `PermissionedRemoteReplicaHTTPProvider.swift:44-49` — provider doc comment | **Correct**, exact |
| `SQLitePermissionedRemoteReplicaRecovery.swift:1541-1548` — equivocation/high-water | **Correct**, exact. `:1541-1543` is the `wireRevision < highWater → .staleRecovery` branch; `:1544-1548` is `wireRevision == highWater && commitment != highWaterCommitment → .equivocation` |
| `PLCSpaceCredentialPublicKeyResolver.swift:105-106` — bounded staleness | **Correct**. "Cached state is used only until its short TTL ends; an expired entry is never used if PLC refresh fails." |
| `PLCSpaceCredentialPublicKeyResolver.swift:477-486` — eviction on refresh failure | **Correct**. The `.failure` branch does `cache.removeValue(forKey: issuer)` + `recordNegativeResult` |
| 60 s TTL | **Correct**. `lifetime: 60` default at `:138` and `:152`; validator ceiling 300 s at `:166` |

No citation in this brief was wrong.

## Changes

1. `Sources/SwanSpaces/StreamingSpaceCARRecovery.swift` — the `:305-308` comment
   no longer claims the checks "have authenticated the exact commit root". It
   now enumerates what each check does establish, states that the IKM is
   cleartext on the wire, names the pinned upstream model, and points at the
   downstream equivocation bound and at the new tests. The original
   staging-ordering rationale (a failed first frame leaves no provisional root
   state) is preserved — it was correct and is unrelated to the over-claim.
2. `Sources/SwanInterop/PermissionedRemoteReplicaHTTPProvider.swift` — the
   `:44-49` doc comment no longer says the provider "authenticates" the commit,
   and no longer implies the two requests are what "make a recovery install
   safe". Adds an explicit note that the freshness witness comes from the same
   configured origin that serves the CAR, so it is a freshness check and cannot
   corroborate that origin.
3. `docs/threat-boundaries.md` — two new bullets after the content-binding-MAC
   bullet (`:15-17`): the pinned HTTPS source origin as the exact-content
   integrity authority with the equivocation/high-water residual bound, and the
   F39 PLC cache staleness window.

## Regression tests

**Yes, the substitution envelope was buildable with zero production-code
changes.** `Tests/SwanSpacesTests/StreamingSpaceCARRecoveryTests.swift`:

- `testStreamingRecoveryAcceptsCommitmentSubstitutionUnderTheOriginalAuthorSignature`
  — pins the accepted behaviour. A `SubstitutedCommitmentFixture` builds a
  different record, computes its LtHash commitment, and assembles an envelope
  from (a) the honest envelope's **byte-identical** `contextSignature`, (b) the
  cleartext IKM, and (c) a MAC recomputed by the test's own restatement of the
  RFC 5869 one-block HKDF-Expand. The author's private key is never used.
  `verifyStreamingRecovery` accepts it; the test asserts the summary carries the
  substituted commitment at the author's unchanged wire revision — which is
  exactly the `(rev, commitment)` pair that `requireRemoteReplicaHighWater`
  adjudicates.
  The doc comment says in capitals not to "fix" it.
- `testStreamingRecoveryRejectsCommitmentSubstitutionWhenAnOutOfBandWitnessIsSupplied`
  — the mitigation that does work inside the verifier: an expected path/CID
  witness sourced independently of the CAR origin yields
  `.expectedWitnessMismatch`.

The MAC recomputation is deliberately reimplemented in the test rather than
called through `SpaceCommitCodec` (whose `contentBinding` is `private` and so
unreachable even under `@testable`). That is the stronger demonstration: an
outsider reproduces it from the public envelope and the published algorithm.

### The `.equivocation` half of the brief's item 4

I did **not** add a publish-path `.equivocation` assertion, because one already
exists and duplicating it would require editing a file this lane does not own.
`Tests/SwanSQLiteTests/PermissionedRemoteReplicaRecoverySQLiteTests.swift:697-730`
stages an archive at the same TID with a different commitment
(`requestID: "same-tid-equivocation"`), asserts
`PermissionedRemoteReplicaRecoveryError.equivocation` from
`publishVerifiedPermissionedRemoteReplicaRecovery`, and asserts the installed
head is unchanged. Its harness, `RemoteReplicaSQLiteFixture`, is declared
`private` inside that file, so it is unreachable from `SwanSpacesTests` even
though that target does depend on `SwanSQLite`. My new test cites it by name in
a comment instead.

## Verification actually run

All commands from `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-L13-docs`.

| Command | Result | Log |
| --- | --- | --- |
| `xcrun --toolchain XcodeDefault swift build --build-tests` | exit **0**, `Build complete!`, 0 `error:` | `/private/tmp/swan-lane-L13-docs/build.log` |
| `xcrun --toolchain XcodeDefault swift test --skip-build --filter StreamingSpaceCARRecoveryTests` | exit **0**, **11** passed (9 pre-existing + 2 new), both new tests named in the log as `passed` | `/private/tmp/swan-lane-L13-docs/filtered.log` |
| `xcrun --toolchain XcodeDefault swift test --skip-build` (full macOS suite) | exit **0**, `grep -cE "^Test Case .* passed"` = **1573**, `grep -c "Some test targets reported failures"` = **0**, `grep -cE "^Test Case .* failed"` = **0** | `/private/tmp/swan-lane-L13-docs/full-suite.log` |

`--build-tests` ran before both `--skip-build` runs, in that order, in this
session. No `swiftformat`, no `swiftlint`, no Docker, no bare `swift`. No
build or test output was piped through `tail`/`head`.
`grep -c '"identity"' Package.resolved` = **35**, unchanged.

## Client-visible changes

**None.** Comments, one Markdown doc, and two new test cases. No status code,
error name, wire field, or runtime path was touched.

## Disagreements / notes for the brief's author

1. The brief says "a party holding the IKM can substitute permissioned
   content". Correct but understated: the IKM is a cleartext field of the wire
   commit block, so the capability is available to anyone who can serve or
   relay the block — which is precisely the pinned HTTPS origin the model
   already trusts, plus anyone who can replay a captured block. The written
   comments and doc use the wider phrasing.
2. Brief item 4 asked for the `.equivocation` assertion in
   `Tests/SwanSpacesTests/StreamingSpaceCARRecoveryTests.swift`. It cannot go
   there — the fixture is `private` to the `SwanSQLiteTests` file — and the
   assertion already exists there. Recorded rather than duplicated.
3. Every line-number citation in this brief checked out. Noting it because the
   instruction implied a prior pattern of drift.
