# W1 Task 1 — Name the failing guard in logs

**Status:** DONE
**Plan:** `docs/superpowers/plans/2026-08-12-swan-production-readiness.md` § W1 Task 1
**Design:** `docs/superpowers/specs/2026-08-12-swan-production-readiness-design.md` § D4

Two commits:

| Commit | Scope |
|---|---|
| `3cbf43e8d2e3` | Initial implementation — `SwanSQLite: name the guard that fails public-read admission` |
| `27bcfeac3872` | Fix round 1 (F1–F6) — `SwanSQLite: split the last compound public-read guards and log every 503` |

> **This report file is not committed.** `.superpowers/sdd/.gitignore` is `*`, so
> everything under `sdd/` is ignored by this repo. The older
> `swan-spaces-interoperability-alpha` reports are tracked only because they were
> force-added before that rule existed. The file is on disk at the requested path;
> I did not edit the shared ignore file to change that.

---

## Why

On 2026-08-12 every public repository read for one account returned an identical
opaque `503 {"error":"temporarily_unavailable"}` for roughly three hours, and
`journalctl -u swan.service` recorded **nothing** across the entire outage.
`PublicRepositoryReadError.unavailable` carried no payload, so it erased which of
eight admission guards had fired, and six handler `catch` sites collapsed every
cause into the same response. Diagnosis required copying the production databases
to a laptop and rebuilding the admission path locally with the error uncollapsed.

This task makes the failed guard nameable server-side, without changing a single
byte of what a client sees.

---

## Changes, per file

### `Sources/SwanStorage/PublicRepositoryReadDirectory.swift`

Added `public enum PublicReadUnavailableReason: String, Sendable, Equatable, CaseIterable`
(29 cases) and changed the error case:

```swift
public enum PublicRepositoryReadError: Error, Sendable, Equatable {
    case invalidSelector
    case invalidLimit
    case invalidCursor
    case resourceLimitExceeded
    case unavailable(reason: PublicReadUnavailableReason)   // was: case unavailable
}

extension PublicRepositoryReadError {
    public var unavailableReason: PublicReadUnavailableReason? { … }
}
```

- `String`-backed so `rawValue` is the journal token.
- `CaseIterable` so the golden-token test can enumerate it.
- `Sendable` for Swift 6 strict concurrency.
- `unavailableReason` is the accessor Tasks 2–4 should match through; it returns
  `nil` for the four non-availability cases, so re-admission logic never has to
  re-destructure the error.

Its own 22 `throw` sites (value-type init invariants, admission-budget guards, CAR
spool descriptor/read failures) took specific reasons rather than a bucket.

### `Sources/SwanSQLite/PublicRepositoryReadStore.swift`

The admission path proper. Two compound `guard` statements were split — they are
the direct cause of the outage being undiagnosable:

1. `admitPublicRepositoryGeneration`'s identity guard chained journal row-count +
   stage + genesis CID + both key references into one condition. Now four guards:
   `.identityRowCount`, `.identityStageNotSubmitted`, `.genesisCIDMismatch`,
   `.missingKeyMaterial`.

2. `requirePublicRepositoryGenerationWithoutGate` — the one that runs on **every
   cached read** — chained control identity + `fileIdentity` + `PRAGMA data_version`
   + state load + state equality. Now five guards:
   `.generationIdentityMismatch`, `.fileIdentityMismatch`, `.generationPinStale`,
   `.repositoryStateMissing`, `.repositoryStateMismatch`.
   `recheckPublicRepositoryGenerationWithoutGate` and admission's own closing
   re-check got the same treatment.

**`generationPinStale` means `data_version` and only `data_version`.** This is the
distinction Task 2 depends on. `fileIdentity` and the exact
`public_repository_state` keep their hard-failure meanings, so re-admitting on
`.generationPinStale` cannot become a way to serve an account whose database file
was swapped or whose head moved unobserved.

**(F2)** The three row-reading helpers — `publicReadRequiredText`,
`publicReadRequiredInteger`, `publicReadCID` — now take an explicit
`reason:` parameter with no default. They are shared between the PLC preparation
journal and `public_repository_record_index`; before this, a malformed
`collection` / `rkey` / `record_cid` was journalled as an identity failure when the
fault was in the projection. Journal columns pass `.identityFactsMalformed`; index
columns pass the new `.recordIndexMalformed`. No default means no future call site
can silently inherit the wrong diagnosis.

### `Sources/SwanSQLite/PublicRepositoryStore.swift`

**(F6)** Projection verification split into two functions so one condition has one
classifier:

- `namedProjectionVerificationWithoutGate(state:)` does the work and reports which
  check failed: `.projectionMismatch` (index/MST disagreement),
  `.blockMaterializationFailed` (block corruption reached through the walk),
  `.recordIndexMalformed` / `.resourceLimitExceeded` (from the preflight),
  `.storageFailure` (anything else). **`CancellationError` is rethrown untouched** —
  a caller hanging up is not a repository fault, and it previously became
  `corruptRepository`.
- `verifyProjectionWithoutGate(state:)` is now a thin adapter that maps exactly
  `.projectionMismatch` / `.blockMaterializationFailed` / `.storageFailure` back to
  `PublicRepositoryMutationStoreError.corruptRepository`, preserving the historical
  contract for its direct maintenance caller (`verifyPublicRepositoryProjection()`)
  byte for byte, and passing everything else through unchanged as before.

Admission calls the named variant directly, so the previous over-capturing wrapper
in `PublicRepositoryReadStore.swift` is gone. Block corruption now reports
`.blockMaterializationFailed` whether it is reached through the projection walk or
through admission's direct commit-block read — the two-classifier inconsistency the
review flagged is resolved in favour of the block name.

### `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`

**(F1) The four-way split.** `refreshPublicReadGeneration`'s opening guard chained
four unrelated conditions under one name. This is the exact code path that failed
live. Final mapping:

| Condition | Reason |
|---|---|
| `!isClosed` | `.directoryClosed` |
| `account.status == .active` | `.accountNotActive` *(new case)* |
| `databases[account.did] === database` | `.accountNotPreopened` |
| `let identityVerifier = publicIdentityVerifier` | `.publicIdentityVerifierUnconfigured` *(new case)* |

`.accountNotActive` is new rather than reusing `.controlRowChanged`: nothing
changed, the account simply is not currently readable, and stretching
`controlRowChanged` over it would have re-created the misdescription the finding
was about. `.publicIdentityVerifierUnconfigured` is new because the condition is an
operator configuration state — the process was started without a verifier — and had
no representation at all.

All four now sit **inside** the `do` block, so the logging catch journals them.
Previously the compound guard was outside it, meaning the single most important
guard on the failing path produced no log line even after the reason type existed.

Three more compound lifecycle guards got the same treatment for consistency: the
pre-admission control re-read, the post-admission republication fence, and
`recheckPublicAccount` each now separate "the control row changed" from "the account
is not active", and the fence separates `.directoryClosed` and `.accountNotPreopened`.

**Reason preservation.** Five `catch { throw .unavailable }` sites would have erased
the reason the moment it was introduced. Each now rethrows
`PublicRepositoryReadError` unchanged and maps only genuinely foreign errors to
`.storageFailure`: `publicRepositoryStatus`, `publicRepositoryDescriptionOutcome`,
`publicRepositoryRecordOutcome`, `publicRepositoryRecordsOutcome`,
`publicRepositoryCAROutcome`.

**The directory log line**, at the `refreshPublicReadGeneration` catch the plan
cites as `:1456-1460`:

```
warning "public read admission refused"  did=<did> reason=<token>
```

Emitted through a file-private `SwanLog(label: "swan.public-read")`. Catch arms:
`CancellationError` rethrown without logging (not an admission refusal);
`PublicRepositoryReadError` logged and rethrown; `corruptRepository` named
`.blockMaterializationFailed`; anything else `.storageFailure`.

### `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`

**(F3)** Every 503 exit on these routes now logs. The brief's six `catch` sites were
not the full set; five more paths returned 503 silently.

New `PublicReadHandlerGuard: String` names the HTTP-layer causes that never reach
`PublicReadUnavailableReason` because they are decided above the directory, and
`PublicReadHandlerFailure.unavailable` now carries one:

| Guard token | Where |
|---|---|
| `pdsOriginMismatch` | `describeRepo` — admitted identity's `pdsOrigin` is not this service |
| `listRecordsOrderingInvariant` | `listRecords` — page violates its own ordering/cursor invariant |
| `unknownAccountStatus` | `getRepoStatus` — account status this build cannot render |
| `responseAdmissionExhausted` | all three `jsonReadAdmission.reserve` nil early-returns |
| `responseEncodingFailed` | `publicReadJSON` encode failure or over-budget body |

`publicReadResponse` now takes `method:`/`selector:` and routes its `.unavailable`
case through the logging helper, so the three thrown guards are journalled.
`publicReadJSON` gained `method:`/`selector:` parameters (defaulted, so the two
existing test call sites are unaffected) and logs on the encode-failure path.
The reserve early-returns call the logging helper directly.

All log lines share one shape:

```
warning "public read unavailable"  method=<nsid> selector=<did|handle> reason=<token>
```

The selector is logged only when it passes `AccountControlIdentifiers.isDID` or
`isCanonicalHandle`, so an arbitrary query value can never be reflected into the
journal. `CancellationError` classifies as `requestCancelled` rather than falling
into `unclassified`.

The doc comment claiming "the single collapse point for every public-read 503" was
false as written and now reads "Every public-read 503 on these routes leaves through
here", which is true.

### `Sources/SwanCore/SwanCore.swift`

`SwanLog` gained `warning(_:fields:)` beside `event(_:fields:)`. Same narrow
contract — stable identifiers only. `SwanSQLite` had no logging at all before this:
it has never imported `Logging`, and `SwanLog` only offered `info`. It reaches
`SwanCore` transitively through `SwanStorage`, so no `Package.swift` change was
needed.

### `Sources/SwanSQLite/PublicRepositoryBoundedExport.swift`, `Sources/SwanSQLite/SwanSQLite.swift`

Seven mechanical `throw` sites updated (`.projectionMismatch`,
`.blockMaterializationFailed`, `.storageFailure`, `.fileIdentityMismatch`).

### `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift` (new)

| Test | Asserts |
|---|---|
| `testAdmissionFailureNamesTheGuardThatFired` | journal stage `.submissionPending` → `.identityStageNotSubmitted` |
| `testDataVersionDriftIsDistinguishableFromIdentityFailure` | foreign-connection commit → `.generationPinStale`, **and** that it differs from the identity reason |
| `testJournalTokensMatchTheGoldenList` | the 29 journal tokens match a hand-written golden set, in both directions |

The drift test reproduces the live trigger shape directly: admit a generation, then
open a **second `SQLiteAccountDatabase` on the same file** and commit
`CREATE TABLE swan_diagnostics_scratch` plus one insert — touching no repository
state whatsoever — then read through the pinned generation.

**(F5)** The third test previously asserted uniqueness of compiler-derived raw
values, which the language already guarantees, so it could not fail. It is now a
golden list: the token is what an operator greps for during an incident and what any
saved query is written against, so a rename must fail loudly. Both directions are
checked — an added reason without a recorded token fails, and a renamed or removed
token fails with a message naming the consequence.

### Existing tests touched

- **(F4)** `Tests/SwanSQLiteTests/PublicRepositoryAdmissionIntegrityTests.swift:82`
  — `XCTAssertEqual(error, .unavailable)` had been weakened to
  `XCTAssertNotNil(error.unavailableReason)`, which pinned nothing. It exercises the
  nil-verifier branch from F1 and now asserts
  `.publicIdentityVerifierUnconfigured` exactly.
- `Tests/SwanSQLiteTests/PublicRepositoryReadDirectoryTests.swift` —
  `XCTAssertThrowsPublicReadUnavailable` is a shared helper across ~15 unrelated
  call sites, so it asserts `unavailableReason != nil`; pinning one reason there
  would be wrong for most of its callers.
- `Tests/SwanHTTPTests/PublicRepositoryReadHTTPTests.swift:561` — tightened to
  `.malformedProjectionValue` (it constructs an oversized `PublicRepositoryReadPage`
  directly, so the exact reason is knowable).
- Eight fixture-scaffolding `throw`s in tests took `.storageFailure`; they exist
  only to abort a `guard case let .reserved(…)` during setup.

Everything else survived untouched — `guard case .unavailable = error` and
`case .unavailable:` still match a case that gained a payload, so ~20 other
pattern-match sites needed no edit.

---

## Reason list and where each is thrown

| Case | Thrown at |
|---|---|
| `identityRowCount` | `admitPublicRepositoryGeneration`, journal row count ≠ 1 |
| `identityStageNotSubmitted` | same — journal `stage` ≠ `.submitted` |
| `genesisCIDMismatch` | same — control row's genesis CID ≠ journal's |
| `missingKeyMaterial` | same — `account.signingKey` / `rotationKey` nil |
| `keyReferenceMismatch` | same — empty-history branch, stored refs ≠ control refs |
| `historyVerifierUnavailable` | same — verifier is not `PublicPLCIdentityVerifying` |
| `terminalIdentityMismatch` | same — terminal PLC op disagrees with stored keys/genesis |
| `repositoryAuthenticatorUnavailable` | same — verifier is not `PublicPLCRepositoryAuthenticating` |
| `commitAuthenticationFailed` | same — signed head ≠ state; `PublicRepositoryCommitAuthentication.init` |
| `identityFactsMalformed` | `plc_account_preparation_journal` column reads |
| `recordIndexMalformed` | `public_repository_record_index` column reads (blob-CID walk, contains-CID walk, DISTINCT collections, projection preflight) |
| `projectionMismatch` | `namedProjectionVerificationWithoutGate` index/MST disagreement; `PublicRepositoryBoundedExport` index diff |
| `intentVerificationFailed` | `SQLitePreMigratedAccountDirectory.verifyPublicIdentityIntent` |
| `generationPinStale` | **`PRAGMA data_version` moved — nothing else.** `requirePublicRepositoryGenerationWithoutGate`, `recheckPublicRepositoryGenerationWithoutGate`, admission's closing re-check |
| `fileIdentityMismatch` | the same three helpers' `fileIdentity` pin; `publicRepositoryFileIdentityWithoutGate`; `publicRepositoryDatabaseDescriptorIdentity` |
| `repositoryStateMismatch` | exact `public_repository_state` pin; CAR-prep commit/state disagreement |
| `repositoryStateMissing` | no `public_repository_state` row |
| `generationIdentityMismatch` | pinned control account / DID / status / verification identity moved |
| `directoryClosed` | `isClosed` guards, including F1's first condition |
| `accountNotPreopened` | no startup-preopened database, or path no longer a regular owner-only file |
| `accountNotActive` | account lifecycle status is not `.active` |
| `controlRowChanged` | control row vanished or no longer equals the pinned row |
| `controlStoreFailure` | the control store itself threw |
| `publicIdentityVerifierUnconfigured` | process started without a public identity verifier |
| `blockMaterializationFailed` | block byte-count/length disagreement, MST `get`/`page` failure, block corruption inside or outside the projection walk |
| `admissionBudgetExhausted` | spool / JSON read / JSON write admission refused a lease |
| `malformedProjectionValue` | `PublicRepositoryReadDescription/Status/Record/Page/…Result` init invariants |
| `spoolStreamFailure` | `PublicRepositoryCARSpool` sizing, `pread`, drain failures |
| `storageFailure` | uncategorised underlying error at a directory or projection catch site |

Plus five HTTP-layer `PublicReadHandlerGuard` tokens (table above) and the synthetic
`requestCancelled` / `unclassified` tokens produced only by the HTTP classifier.

---

## Client-visible behaviour: unchanged

Every 503 path still returns `503 {"error":"temporarily_unavailable"}`. No reason,
DID, or CID reaches an unauthenticated caller. The three existing assertions on that
body in `Tests/SwanHTTPTests/PublicRepositoryReadHTTPTests.swift` (lines 326, 432,
442) pass untouched.

---

## Test commands and results

Counts are `Test Case '-[…]' passed` line counts. `Executed N tests` lines are not
summed — they nest and triple-count.

### Build

```
xcrun --toolchain XcodeDefault swift build --build-tests
```
Clean; pre-existing `SwanCommand.swift` warnings only.

### Reviewer-flagged suites

```
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "PublicRepositoryReadDirectoryTests|PublicRepositoryReadDiagnosticsTests|PublicRepositoryAdmissionIntegrityTests"
```

**29 passed, 0 failed.** Includes both tests the reviewer flagged as most likely to
be disturbed by the F6 wrapper — `testRepositoryTraversalRejectsOversizedMSTBlobBeforeMaterialization`
(`:574`) and `testGenerationAdmissionRejectsOversizedCommitBlobBeforeMaterialization`
(`:609`) — plus `testActivatedAccountAdmissionRejectsCorruptPublicProjectionBeforeExposure`
and `testBootstrapRejectsCorruptPublicProjectionBeforeDirectoryActivation`, which
exercise the projection path F6 restructured.

### Full suite

```
xcrun --toolchain XcodeDefault swift test --skip-build
```

**1420 passed, 0 failed, exit 0.** All 11 XCTest bundles reported `passed`:

| Bundle | Passed |
|---|---|
| SwanSQLiteTests | 377 |
| SwanHTTPTests | 310 |
| SwanOAuthTests | 136 |
| SwanInteropTests | 129 |
| SwanAccountsTests | 128 |
| SwanPublicRepositoryTests | 111 |
| SwanCLITests | 76 |
| SwanAccountExportTests | 55 |
| SwanPublicFirehoseTests | 54 |
| SwanSpacesTests | 38 |
| SwanCoreTests | 6 |
| **Total** | **1420** |

One intermediate full-suite run was terminated by SIGTERM at 1334 tests with two
bundles unreported. It was discarded, not counted, and re-run to completion — noted
here because a truncated run reports `0 failures` and could otherwise be mistaken for
a pass.

### Red phase (from the first commit, unchanged by this round)

I read the source before writing the tests, so rather than claim a red-green cycle I
did not have, I falsified the assertions explicitly: collapsing both guards to a
single shared reason produced 3 failures, including
`XCTAssertNotEqual failed: … a stale data_version pin and a failed identity guard
must not report the same reason` — the exact regression this task exists to prevent.
Source was restored and re-verified green before committing.

Constraints honoured: 4-space indentation in every file touched; `swiftformat` never
invoked; no bare `swift build` / `swift test`; `--build-tests` before every
`--skip-build`; no `git` mutation — `jj describe` + `jj new`; server untouched.

---

## Deliberately not done

- **The four deferred minor findings**, as instructed: `.admissionBudgetExhausted`
  on constructor validation (`PublicRepositoryReadDirectory.swift:439, :548, :699`),
  `.malformedProjectionValue` on aggregate-byte overflow (`:392`), `.storageFailure`
  on export column decodes (`PublicRepositoryBoundedExport.swift:433, :440, :451`),
  and the >100-column throw lines.
- **No re-admission, no eviction, no `data_version` demotion.** Tasks 2–4. This
  commit only names things.
- **Plan checkboxes left unticked** — other agents are active in this session and I
  did not want to write to the shared plan document unasked.
- **No live verification.** Task 5 owns deployment and production acceptance.

---

## Concerns

1. **A single failure can now produce two journal lines** — one from the directory
   (`did`, `reason`) and one from the HTTP catch site (`method`, `selector`,
   `reason`). That was already true before this round for storage-originated
   failures; F1 moving the four guards inside the logging `do` extends it to the
   configuration guards. It is more useful than harmful (the pair tells you both
   which account and which route), but it is a doubling an operator should expect,
   and it is worth a glance during Task 5 step 4 — which checks for the *absence*
   of warning lines — so a healthy service is not misread as a chatty one.

2. **`verifyProjectionWithoutGate`'s adapter is a behaviour-preserving mapping I
   verified by reading, not by a test.** Its only direct caller is
   `verifyPublicRepositoryProjection()`, and no test asserts on that API's error
   type, so nothing in the suite would catch a mistake in the mapping. The four
   projection tests that do pass exercise it through admission, which now takes the
   named path instead.

3. **`.projectionMismatch` and `.blockMaterializationFailed` are now decided inside
   the projection walk** by which error type the block source throws. If the block
   source ever starts reporting a genuine index disagreement as `corruptRepository`,
   the two would swap silently. That is a latent coupling, not a present bug.

4. **Blast radius remains 88 construction sites.** Swift has no defaulted-payload
   enum case, so adding the associated value meant visiting every one. 29 cases is a
   large enum; most of the extra ones exist because value-type init invariants in
   SwanStorage had nowhere accurate to go.

---

## Notes for Task 2

- Match on `error.unavailableReason == .generationPinStale`, not on the raw case.
- `.generationPinStale` is thrown from exactly three places, all in
  `Sources/SwanSQLite/PublicRepositoryReadStore.swift`, and all three mean *only*
  that `PRAGMA data_version` moved.
- `activePublicReadContext` does **not** catch — reasons propagate intact through
  all five outcome methods, so the re-admit-once decision can be placed wherever is
  cleanest.
- `refreshPublicReadGeneration` logs every failure arm, so a re-admission that fails
  produces a journal line for free.
- `CancellationError` now propagates untouched from the projection walk and from the
  admission boundary. Re-admission logic must not treat it as a retryable failure.
