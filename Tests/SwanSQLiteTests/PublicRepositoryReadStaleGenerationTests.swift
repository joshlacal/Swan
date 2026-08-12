import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicRepository
@testable import SwanSQLite
import SwanStorage
import Synchronization
import XCTest

/// Regression cover for the cause of the 2026-08-12 outage.
///
/// Every public read for one account returned `503` for roughly three hours
/// and recovered only when an unrelated record write ran the post-commit
/// refresh. The trigger was a commit from a **second connection** to the
/// account database: `PRAGMA data_version` is monotonic, moves on any commit
/// from any other connection to any table in that database, and never returns
/// to its prior value. Swan holds more than one descriptor per account
/// database in the live process, so nothing exotic is required — and nothing
/// on the read path replaced the pinned generation, so the refusal was
/// permanent.
///
/// These tests pin the fix and, just as importantly, its limits: re-admission
/// must not become a way to serve an account that genuinely does not verify,
/// and it must not turn one request into an unbounded retry loop.
final class PublicRepositoryReadStaleGenerationTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.example.com"

    // MARK: The outage

    func testForeignConnectionCommitDoesNotBreakPublicReads() async throws {
        let fixture = try await makeFixture()

        let before = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(before?.revision, fixture.revision)

        // A second connection commits something irrelevant — a scratch table.
        // This is what PRAGMA data_version observes, and it never returns.
        //
        // A third connection watches the pin across that commit. The whole
        // outage turned on this pragma moving, so the precondition is asserted
        // rather than assumed: if a future SQLite or schema change stopped the
        // scratch commit from moving it, every test below would pass while
        // testing nothing.
        let observer = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: did
        )
        let pinBefore: Int64
        let pinAfter: Int64
        do {
            pinBefore = try await observedDataVersion(observer)
            try await commitFromSecondConnection(root: fixture.root)
            pinAfter = try await observedDataVersion(observer)
        } catch {
            try? await observer.close()
            throw error
        }
        try await observer.close()
        XCTAssertNotEqual(
            pinBefore,
            pinAfter,
            "precondition: a foreign commit must move PRAGMA data_version"
        )

        let after = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(
            after?.revision,
            before?.revision,
            "A foreign commit that touches no repository state must not "
                + "make the account permanently unreadable."
        )

        // The pin is shared by every generation-validated read shape, so the
        // fix has to hold for all of them and not just for status.
        let description = try await fixture.directory.describePublicRepository(
            selector: did
        )
        XCTAssertEqual(description?.state.revision, fixture.revision)
        let page = try await fixture.directory.publicRepositoryRecordsOutcome(
            selector: did,
            collection: "app.bsky.feed.post",
            limit: 10,
            cursor: nil,
            reverse: false
        )
        guard case .active = page else {
            XCTFail("expected an active page after the foreign commit")
            return
        }
        let car = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        let spool = try XCTUnwrap(car?.spool)
        spool.cleanup()

        // A second foreign commit must not be a one-shot allowance either: the
        // re-admitted generation pins the new data_version, and the next drift
        // has to be re-admitted exactly the same way.
        try await commitFromSecondConnection(root: fixture.root)
        let third = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(third?.revision, before?.revision)
    }

    /// `data_version` is a hint that *something* committed, never a verdict on
    /// the repository — so drift on its own must re-admit and serve, and must
    /// leave the account in the same steady state it was in before.
    ///
    /// The sibling above proves the account is still readable. This one pins
    /// *how*: the repository state is independently observed to be byte-for-byte
    /// unchanged across the foreign commit, so the only thing that moved is the
    /// pin; the read then costs exactly one admission and replaces the cached
    /// generation. Zero admissions would mean the pin is no longer checked at
    /// all — the guard deleted rather than demoted — and a surviving generation
    /// ID would mean the drifted pin was served rather than re-admitted.
    func testDataVersionDriftAloneTriggersReAdmissionNotRejection() async throws {
        let fixture = try await makeFixture()

        let warm = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(warm?.revision, fixture.revision)
        let generationBefore = await fixture.directory
            .cachedPublicReadGenerationID(did: did)
        XCTAssertNotNil(
            generationBefore,
            "precondition: a warm read must leave a generation cached"
        )

        // Observe both pins from a third connection that is neither the
        // directory nor the writer, so the two claims this test rests on —
        // "data_version moved" and "repository state did not" — are measured,
        // not assumed. Without the first, everything below passes vacuously.
        let observer = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: did
        )
        let pinBefore: Int64
        let pinAfter: Int64
        let stateBefore: PublicRepositoryState?
        let stateAfter: PublicRepositoryState?
        do {
            pinBefore = try await observedDataVersion(observer)
            stateBefore = try await observer.loadPublicRepositoryState()
            try await commitFromSecondConnection(root: fixture.root)
            pinAfter = try await observedDataVersion(observer)
            stateAfter = try await observer.loadPublicRepositoryState()
        } catch {
            try? await observer.close()
            throw error
        }
        try await observer.close()
        XCTAssertNotEqual(
            pinBefore,
            pinAfter,
            "precondition: a foreign commit must move PRAGMA data_version"
        )
        XCTAssertEqual(
            stateBefore,
            stateAfter,
            "precondition: the foreign commit must touch no repository state, "
                + "so drift is the only thing this test changes"
        )

        let baseline = fixture.verifier.admissionCount
        let served = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(
            served?.revision,
            fixture.revision,
            "drift alone must be re-admitted and served, never refused"
        )
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "drift must cost exactly one re-admission — zero would mean the "
                + "pin is no longer checked at all"
        )
        let generationAfter = await fixture.directory
            .cachedPublicReadGenerationID(did: did)
        XCTAssertNotNil(generationAfter)
        XCTAssertNotEqual(
            generationAfter,
            generationBefore,
            "the drifted generation must be replaced, not served"
        )

        // Re-admission is recovery, not failure: nothing about drift may leave
        // a negative-cache entry behind, and the replacement generation pins
        // the new value, so steady state costs nothing.
        let backoff = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertFalse(
            backoff,
            "a drifted pin is change detection — it must never be recorded as "
                + "an admission failure"
        )
        let steady = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(steady?.revision, fixture.revision)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "the re-admitted generation must pin the new data_version, so the "
                + "next read re-admits nothing"
        )
    }

    /// A stale pin must never be written into the negative cache.
    ///
    /// `.generationPinStale` is the one reason the read path defines as
    /// "re-admit", and the negative cache means "refuse for 250 ms without
    /// admitting". Recording it therefore inverts its meaning and suppresses
    /// the exact admission that clears the staleness: the account goes dark for
    /// a backoff window on the strength of a pragma that says only that *some*
    /// connection committed *something*. That is a time-boxed replay of the
    /// 2026-08-12 outage, reached through the recovery path built to end it.
    ///
    /// The failing admission is driven through the injected verifier because
    /// that is the only seam that can make an *admission* refuse with a chosen
    /// reason; what matters is what the directory does with a
    /// `.generationPinStale` admission failure, not which line produced it.
    func testStalePinIsNeverRecordedAsAnAdmissionFailure() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything(with: .generationPinStale)

        let baseline = fixture.verifier.admissionCount
        let refused = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(refused, .generationPinStale)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "precondition: the read must have attempted a real re-admission"
        )
        let recordedStalePin = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertFalse(
            recordedStalePin,
            "a stale pin must not be recorded as evidence that the account "
                + "cannot be admitted"
        )

        // Immediately — well inside the 250 ms window a recorded entry would
        // have opened — the next read must do the work and serve.
        fixture.verifier.acceptEverything()
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(
            recovered?.revision,
            fixture.revision,
            "a stale pin must never make an admittable account dark for a "
                + "backoff window"
        )
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            2,
            "the recovering read must have run its own admission rather than "
                + "being suppressed"
        )

        // The exclusion is exactly one reason wide. A genuine identity failure
        // still records, or the demotion has quietly disabled the bound that
        // keeps an unadmittable account from costing a full record-index walk
        // and PLC verification on every anonymous read.
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything(with: .identityFactsMalformed)
        let identity = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(identity, .identityFactsMalformed)
        let recordedIdentityFailure = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertTrue(
            recordedIdentityFailure,
            "a real admission failure must still be recorded"
        )
    }

    /// An admission failure that carries no reason must still be named and
    /// still be bounded.
    ///
    /// `PublicRepositoryReadError.resourceLimitExceeded` has no associated
    /// ``PublicReadUnavailableReason``, and admission raises it: the projection
    /// preflight paginates the entire `public_repository_record_index` before
    /// refusing an account over `maximumGenerationIndexEntries` or over the
    /// `describeRepo` collection caps. Read through `unavailableReason` alone
    /// that refusal was invisible twice over — nothing journalled, which is the
    /// three-hour-blind failure mode this file exists to prevent, and nothing
    /// recorded, so an over-budget account stayed *permanently* unadmittable
    /// **and** unbounded: every anonymous read for that DID redid the full
    /// index walk, on endpoints a relay hammers.
    ///
    /// The refusal the caller sees must not change — this names an error, it
    /// does not reclassify one.
    func testReasonlessAdmissionFailureIsNamedAndBounded() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything(throwing: .resourceLimitExceeded)

        let baseline = fixture.verifier.admissionCount
        let refused = await captureRefusalError(fixture.directory, .status)
        XCTAssertEqual(
            refused,
            .resourceLimitExceeded,
            "the thrown error must reach the caller unchanged — this is a "
                + "diagnostic classification, not a reclassification"
        )
        XCTAssertNil(
            refused?.unavailableReason,
            "precondition: this refusal must be one that carries no reason, "
                + "or it exercises the already-covered path"
        )
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "precondition: the read must have attempted a real admission"
        )

        let recorded = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertTrue(
            recorded,
            "an admission failure that arrived without a reason is still an "
                + "admission failure, and the most permanent kind there is"
        )

        // The bound is what was missing. Inside the window every read shape
        // must refuse from the recorded entry and buy no further index walks.
        for shape in PublicReadShape.allCases {
            let reason = await captureRefusal(fixture.directory, shape)
            XCTAssertEqual(
                reason,
                .projectionBoundExceeded,
                "\(shape) must refuse with the name the reason-less failure "
                    + "was classified under"
            )
        }
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "reads inside the backoff window must add no admissions — an "
                + "unnamed refusal was the one failure that stayed unbounded"
        )

        // And the bound is still a window, not a wall: past it the account is
        // allowed to try again, exactly like every named failure.
        try await Task.sleep(for: .milliseconds(500))
        fixture.verifier.acceptEverything()
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(recovered?.revision, fixture.revision)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            2,
            "past the window the read must run its own admission"
        )
    }

    // MARK: The limits

    /// Re-admission must not become a way to serve a broken account.
    ///
    /// The account below is stale *and* genuinely unadmittable: the same
    /// foreign commit that moves `data_version` also regresses the durable PLC
    /// preparation journal below `.submitted`. The read must still refuse, and
    /// it must refuse with the identity guard that actually fired — not with
    /// `.generationPinStale`, and above all not by succeeding.
    func testGenuinelyUnadmittableAccountStill503sWithTheGuardThatFired() async throws {
        let fixture = try await makeFixture()

        let warm = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(warm?.revision, fixture.revision)

        try await regressPreparationStageFromSecondConnection(
            root: fixture.root
        )

        for shape in PublicReadShape.allCases {
            let reason = await captureRefusal(fixture.directory, shape)
            XCTAssertEqual(
                reason,
                .identityStageNotSubmitted,
                "\(shape) must surface the identity guard that fired, not a "
                    + "laundered success or a staleness reason"
            )
            XCTAssertNotEqual(
                reason,
                .generationPinStale,
                "re-admission must not report its own trigger as the outcome"
            )
        }

        // The refusal is durable: re-admission never publishes a generation
        // for an account that does not verify, so a later read cannot inherit
        // one.
        let repeated = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(repeated, .identityStageNotSubmitted)
    }

    /// A permanently-failing re-admit must not retry per read forever.
    ///
    /// The verifier counts every admission it is asked to perform. With the
    /// account pinned stale and the verifier rejecting, each read is allowed
    /// exactly one re-admission — never two, never a loop that only terminates
    /// because the failure happens to be deterministic.
    func testReAdmissionHappensOnceNotInALoop() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything()

        let baseline = fixture.verifier.admissionCount
        let first = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(first, .identityFactsMalformed)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "one read may re-admit exactly once — more means a retry loop, "
                + "fewer means the stale generation was served or skipped"
        )

        // Past the backoff window the next read is allowed its own attempt,
        // and it too gets exactly one. The bound is per read, permanently.
        try await Task.sleep(for: .milliseconds(500))
        let second = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(second, .identityFactsMalformed)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            2,
            "the second read must also cost exactly one admission"
        )
    }

    /// A failed re-admission must not make every subsequent anonymous read pay
    /// for a full record-index walk and PLC verification. Within the backoff
    /// window the reads still refuse, with the same reason — they just do not
    /// redo the work.
    func testFailedReAdmissionIsNotRepeatedWithinTheBackoffWindow()
        async throws
    {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything()

        let baseline = fixture.verifier.admissionCount
        let first = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(first, .identityFactsMalformed)
        XCTAssertEqual(fixture.verifier.admissionCount - baseline, 1)

        // Every read shape, immediately, well inside the window.
        for shape in PublicReadShape.allCases {
            let reason = await captureRefusal(fixture.directory, shape)
            XCTAssertEqual(
                reason,
                .identityFactsMalformed,
                "\(shape) must refuse with the same reason while the backoff "
                    + "window suppresses the work"
            )
        }
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "reads inside the backoff window must add no admissions"
        )
    }

    /// The backoff must not become a second way for an account to stay dark.
    /// Once the account is admittable again, the very next read past the
    /// window serves it — and the successful admission retires the negative
    /// entry, so the read after that costs nothing at all.
    func testBackoffDoesNotDelayRecovery() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything()
        let refused = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(refused, .identityFactsMalformed)

        fixture.verifier.acceptEverything()
        try await Task.sleep(for: .milliseconds(500))

        let baseline = fixture.verifier.admissionCount
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(
            recovered?.revision,
            fixture.revision,
            "an account that became admittable again must be served"
        )
        XCTAssertEqual(fixture.verifier.admissionCount - baseline, 1)

        // The published generation retired both the stale pin and the negative
        // entry, so steady state costs no admissions at all.
        let steady = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(steady?.revision, fixture.revision)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "a recovered account must not keep re-admitting"
        )
    }

    /// Many concurrent readers observe the same drifted pin at the same
    /// instant. Re-admission is single-flighted per DID, so they collapse onto
    /// one admission instead of stampeding a SQLite connection that would
    /// serialize them anyway.
    func testConcurrentReadersShareOneReAdmission() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)

        let baseline = fixture.verifier.admissionCount
        let directory = fixture.directory
        let selector = did
        let revisions = try await withThrowingTaskGroup(
            of: String?.self
        ) { group -> [String?] in
            for _ in 0 ..< 8 {
                group.addTask {
                    try await directory.publicRepositoryStatus(
                        selector: selector
                    )?.revision
                }
            }
            var collected: [String?] = []
            for try await revision in group {
                collected.append(revision)
            }
            return collected
        }
        XCTAssertEqual(revisions.count, 8)
        XCTAssertTrue(revisions.allSatisfy { $0 == fixture.revision })
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "eight concurrent readers of one drifted pin must cost one "
                + "admission, not eight"
        )
    }

    // MARK: The write side

    /// The commit is durable before the refresh runs. A refresh error must not
    /// fail a request whose write already succeeded.
    ///
    /// Asserted through the same seam HTTP uses — the mutation store returned
    /// by `generationRefreshingPublicMutationStore` — so this is the *request's*
    /// answer, not merely the absence of an internal throw. A client that is
    /// told its write failed retries it, and a repository write retried against
    /// a repository that already applied it is a duplicate record.
    func testFailedPostMutationRefreshDoesNotFailTheMutation() async throws {
        let fixture = try await makeFixture()

        let warm = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(warm?.revision, fixture.revision)

        // Every admission from here on refuses, so the post-commit refresh
        // cannot republish. The commit itself does not go through admission.
        fixture.verifier.rejectEverything()

        let committed = try await applyOneRecord(
            fixture, recordKey: "refresh-fails"
        )
        XCTAssertNotEqual(
            committed.state.revision,
            fixture.revision,
            "the mutation must have advanced the repository, not been a no-op"
        )
        XCTAssertEqual(committed.recordResults.count, 1)

        // And the write is durable: the account database agrees with what the
        // caller was told, independently of anything the read cache holds.
        let maybeStore = await fixture.directory
            .generationRefreshingPublicMutationStore(did: did)
        let store = try XCTUnwrap(maybeStore)
        let maybePersisted = try await store.loadPublicRepositoryState()
        let persisted = try XCTUnwrap(maybePersisted)
        XCTAssertEqual(persisted.revision, committed.state.revision)
    }

    /// A refresh that cannot republish must leave *nothing* cached, not a
    /// generation pinned to the pre-mutation state.
    ///
    /// The distinction is the whole point. A stale generation left in place
    /// still matches its `data_version` pin — the mutation committed on the
    /// directory's own connection, which `PRAGMA data_version` never reports —
    /// so it fails the *state* pin instead, with `.repositoryStateMismatch`.
    /// That reason earns no re-admission, so the account would be dark until
    /// some later write happened to succeed at refreshing: the 2026-08-12
    /// outage reached through the write path.
    func testFailedPostMutationRefreshEvictsRatherThanCachingStale()
        async throws
    {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        let cachedBefore = await fixture.directory.cachedPublicReadGenerationID(
            did: did
        )
        XCTAssertNotNil(
            cachedBefore,
            "precondition: a warm read must leave a generation cached"
        )

        fixture.verifier.rejectEverything()
        let committed = try await applyOneRecord(fixture, recordKey: "evicted")

        // Gone, not merely different. A replacement — even one pinned to the
        // new state — would still be a published generation, and this path
        // must never publish one it could not admit.
        let cachedAfter = await fixture.directory.cachedPublicReadGenerationID(
            did: did
        )
        XCTAssertNil(
            cachedAfter,
            "a failed post-mutation refresh must evict the generation, not "
                + "leave or replace one"
        )

        // The eviction must not have been recorded as an admission failure:
        // the cold read below goes through
        // `admitPublicReadGenerationForRequest`, which consults that negative
        // cache and refuses outright while an entry is live — see
        // `testColdCacheReadsAreBoundedByTheBackoff`, which pins that
        // suppression. An entry written here would make the account dark for
        // the whole window on the strength of a write-path failure.
        let backoff = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertFalse(
            backoff,
            "evicting the positive generation must not write a negative-cache "
                + "entry"
        )

        // So the next read admits from cold immediately, without waiting out a
        // 250 ms window it was never put into.
        fixture.verifier.acceptEverything()
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(
            recovered?.revision,
            committed.state.revision,
            "the next read must admit from cold and serve the state the "
                + "mutation committed"
        )
    }

    /// A successful post-mutation refresh must still publish. The eviction
    /// above is the failure path only; if it became the normal one, every
    /// write would cost the next read a full admission.
    func testSuccessfulPostMutationRefreshPublishesRatherThanEvicting()
        async throws
    {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        let before = await fixture.directory.cachedPublicReadGenerationID(
            did: did
        )
        let committed = try await applyOneRecord(fixture, recordKey: "healthy")

        let after = await fixture.directory.cachedPublicReadGenerationID(
            did: did
        )
        XCTAssertNotNil(after, "a successful refresh must publish")
        XCTAssertNotEqual(after, before, "and must publish a new generation")

        let baseline = fixture.verifier.admissionCount
        let served = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertEqual(served?.revision, committed.state.revision)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            0,
            "the published generation must serve the next read outright"
        )
    }

    /// Eviction must not open a hole in the backoff.
    ///
    /// The post-mutation eviction created a state nothing else in this file
    /// can produce: an open database with *no* cached generation. `bootstrap`
    /// admits every active account or fails startup, `installAccount` writes
    /// both maps together, and revoke/close remove the database as well — so
    /// before Task 3 the cold-cache branch of `activePublicReadContext` was
    /// reachable only via a control-row change. It is now a steady state for
    /// an account whose refresh keeps failing for a persistent reason, and
    /// every anonymous read lands on it.
    ///
    /// If that branch admitted bare, each of those reads would pay a full
    /// record-index walk, MST projection verify and PLC `verifyGenesis` —
    /// forever, on an endpoint the whole network can reach. The bound has to
    /// cover the cold path, not just re-admission after a stale pin.
    func testColdCacheReadsAreBoundedByTheBackoff() async throws {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)

        // Drive the account into "open database, nothing cached" through the
        // only door that produces it: a post-mutation refresh that fails.
        fixture.verifier.rejectEverything()
        _ = try await applyOneRecord(fixture, recordKey: "cold-backoff")
        let cached = await fixture.directory.cachedPublicReadGenerationID(
            did: did
        )
        XCTAssertNil(
            cached,
            "precondition: the failed refresh must have evicted the generation"
        )
        let evictionWroteBackoff = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertFalse(
            evictionWroteBackoff,
            "precondition: the write path must not have primed the negative "
                + "cache — otherwise the first read below is suppressed and "
                + "this test proves nothing about the cold path"
        )

        let baseline = fixture.verifier.admissionCount
        let first = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(first, .identityFactsMalformed)
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "the first cold read pays exactly one admission"
        )
        let recorded = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertTrue(
            recorded,
            "a failed cold admission must record the backoff entry, not only "
                + "a failed re-admission"
        )

        // Every read shape, immediately, well inside the window. Each one
        // takes the cold branch — there is still nothing cached — and each one
        // must be suppressed by the entry the first read wrote.
        for shape in PublicReadShape.allCases {
            let reason = await captureRefusal(fixture.directory, shape)
            XCTAssertEqual(
                reason,
                .identityFactsMalformed,
                "\(shape) must refuse with the same reason while the backoff "
                    + "window suppresses the work"
            )
        }
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            1,
            "cold reads inside the backoff window must add no admissions"
        )

        // And the bound must not become a second way to stay dark: past the
        // window the account is served again, from cold, with one admission.
        fixture.verifier.acceptEverything()
        try await Task.sleep(for: .milliseconds(500))
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertNotNil(
            recovered,
            "an account that became admittable again must be served"
        )
        XCTAssertEqual(
            fixture.verifier.admissionCount - baseline,
            2,
            "recovery costs exactly one further admission"
        )
    }

    /// The window bounds work; it must bound the journal by the same shape.
    ///
    /// Re-emitting the full admission line for every request the window
    /// suppresses makes journal volume a function of inbound request rate with
    /// no ceiling, and that rate is set by anonymous callers: one dark account
    /// plus a relay backfill retrying `getRepo` is a disk-fill path on the
    /// production box. Nothing is lost by counting instead — the failure that
    /// opened the window already journalled this DID and this reason in full —
    /// so each window costs the named failure that opened it plus one rollup
    /// naming how much traffic ran into it.
    func testSuppressedReadsAreCountedRatherThanJournalledPerRequest()
        async throws
    {
        let fixture = try await makeFixture()

        _ = try await fixture.directory.publicRepositoryStatus(selector: did)
        try await commitFromSecondConnection(root: fixture.root)
        fixture.verifier.rejectEverything()

        let baselineAdmissions = fixture.verifier.admissionCount
        let baselineLines = await fixture.directory
            .publicReadAdmissionJournalLineCount()
        let first = await captureRefusal(fixture.directory, .status)
        XCTAssertEqual(first, .identityFactsMalformed)
        let afterFirst = await fixture.directory
            .publicReadAdmissionJournalLineCount()
        XCTAssertEqual(
            afterFirst - baselineLines,
            1,
            "the admission that failed must still name itself, once"
        )

        for _ in 0 ..< 16 {
            let reason = await captureRefusal(fixture.directory, .status)
            XCTAssertEqual(reason, .identityFactsMalformed)
        }
        // Asserted so a window that expired mid-loop fails the test rather
        // than quietly making the line count below prove nothing.
        XCTAssertEqual(
            fixture.verifier.admissionCount - baselineAdmissions,
            1,
            "precondition: every read above ran inside one backoff window"
        )
        let afterSuppressed = await fixture.directory
            .publicReadAdmissionJournalLineCount()
        XCTAssertEqual(
            afterSuppressed - baselineLines,
            1,
            "reads suppressed by the window must not each write a warning"
        )

        // Retirement reports what the window absorbed — once, with a count,
        // rather than sixteen times.
        fixture.verifier.acceptEverything()
        try await Task.sleep(for: .milliseconds(500))
        let recovered = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        XCTAssertNotNil(recovered)
        let afterRetirement = await fixture.directory
            .publicReadAdmissionJournalLineCount()
        XCTAssertEqual(
            afterRetirement - baselineLines,
            2,
            "one rollup line for the whole window, not one per suppressed read"
        )
    }

    private enum MutationFixtureFailure: Error {
        /// The fixture's own write could not be set up. Reported as a fixture
        /// fault rather than folded into the assertions under test.
        case reservationWasNotFresh(String)
    }

    /// Drives one real record write through the same generation-refreshing
    /// store the HTTP mutation path uses, and returns what that request
    /// reports back to its caller.
    @discardableResult
    private func applyOneRecord(
        _ fixture: Fixture,
        recordKey: String
    ) async throws -> CommittedPublicRepositoryMutation {
        let maybeStore = await fixture.directory
            .generationRefreshingPublicMutationStore(did: did)
        let store = try XCTUnwrap(maybeStore)
        let maybeCurrent = try await store.loadPublicRepositoryState()
        let current = try XCTUnwrap(maybeCurrent)
        let collection = "app.bsky.feed.post"
        let request = try PublicRepositoryMutationRequest(
            id: "post-mutation-refresh-\(recordKey)",
            canonicalDigest: Data(
                SHA256.hash(data: Data(recordKey.utf8))
            ),
            baseCommitCID: current.commitCID
        )
        guard case let .reserved(reservation) = try await store
            .reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: nextWallClockMicroseconds()
            ) else {
            throw MutationFixtureFailure.reservationWasNotFresh(recordKey)
        }
        let record: PublicRecord = [
            "$type": .string(collection),
            "text": .string("post-mutation refresh \(recordKey)"),
            "createdAt": .string("2025-06-15T12:00:00.000Z"),
        ]
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: current,
            blocks: store,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [
                    .create(
                        path: try PublicRepositoryPath(
                            collection: collection, recordKey: recordKey
                        ),
                        record: record
                    ),
                ],
                expectedCommitCID: current.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(
                privateKey: fixture.signingKey
            )
        )
        return try await store.applyPublicRepositoryMutation(
            reservation: reservation, prepared: prepared
        )
    }

    private let wallClock = Mutex<UInt64>(1_750_000_002_000_000)

    private func nextWallClockMicroseconds() -> UInt64 {
        wallClock.withLock { current in
            current += 1_000_000
            return current
        }
    }

    // MARK: Read shapes

    private enum PublicReadShape: CaseIterable, CustomStringConvertible {
        case status
        case describe
        case record
        case listRecords
        case car

        var description: String {
            switch self {
            case .status: "getRepoStatus"
            case .describe: "describeRepo"
            case .record: "getRecord"
            case .listRecords: "listRecords"
            case .car: "getRepo"
            }
        }
    }

    private func captureRefusal(
        _ directory: SQLitePreMigratedAccountDirectory,
        _ shape: PublicReadShape
    ) async -> PublicReadUnavailableReason? {
        await captureRefusalError(directory, shape)?.unavailableReason
    }

    /// The whole refusal, not just its reason. A read error that carries no
    /// ``PublicReadUnavailableReason`` is exactly the case
    /// ``captureRefusal(_:_:)`` cannot distinguish from "did not refuse",
    /// and it is the case under test below.
    private func captureRefusalError(
        _ directory: SQLitePreMigratedAccountDirectory,
        _ shape: PublicReadShape
    ) async -> PublicRepositoryReadError? {
        do {
            switch shape {
            case .status:
                _ = try await directory.publicRepositoryStatus(selector: did)
            case .describe:
                _ = try await directory.describePublicRepository(selector: did)
            case .record:
                _ = try await directory.publicRepositoryRecord(
                    selector: did,
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post", recordKey: "one"
                    ),
                    expectedCID: nil
                )
            case .listRecords:
                _ = try await directory.publicRepositoryRecordsOutcome(
                    selector: did,
                    collection: "app.bsky.feed.post",
                    limit: 10,
                    cursor: nil,
                    reverse: false
                )
            case .car:
                let car = try await directory.publicRepositoryCAR(
                    selector: did
                )
                car?.spool.cleanup()
            }
            XCTFail("\(shape) must refuse an unadmittable account")
            return nil
        } catch let error as PublicRepositoryReadError {
            return error
        } catch {
            XCTFail("\(shape) threw an untyped error: \(error)")
            return nil
        }
    }

    // MARK: Foreign connections

    /// Commits from a second connection to the same account database. This is
    /// the minimal reproduction of the live trigger, so it deliberately writes
    /// to a scratch table and leaves repository state untouched.
    /// Reads the pin the outage turned on, from a connection that is not the
    /// writer. `PRAGMA data_version` only reports commits made by *other*
    /// connections, which is precisely the property under test.
    private func observedDataVersion(
        _ database: SQLiteAccountDatabase
    ) async throws -> Int64 {
        let rows = try await database.connection.query("PRAGMA data_version")
        let value = try XCTUnwrap(rows.first?.column("data_version")?.integer)
        return try XCTUnwrap(Int64(exactly: value))
    }

    private func commitFromSecondConnection(root: URL) async throws {
        let foreign = try await SQLiteAccountDatabase(
            dataDirectory: root, did: did
        )
        _ = try await foreign.connection.query(
            """
            CREATE TABLE IF NOT EXISTS swan_stale_generation_scratch(
                x INTEGER
            )
            """
        )
        _ = try await foreign.connection.query(
            "INSERT INTO swan_stale_generation_scratch(x) VALUES (1)"
        )
        try await foreign.close()
    }

    /// One foreign commit that both drifts the pin and makes the account
    /// genuinely unadmittable, by regressing the durable preparation journal
    /// below the stage admission requires.
    private func regressPreparationStageFromSecondConnection(
        root: URL
    ) async throws {
        let foreign = try await SQLiteAccountDatabase(
            dataDirectory: root, did: did
        )
        _ = try await foreign.connection.query(
            """
            UPDATE plc_account_preparation_journal
            SET stage = ?
            WHERE singleton = 1
            """,
            [
                .integer(
                    PLCAccountPreparationStage.submissionPending.rawValue
                ),
            ]
        )
        try await foreign.close()
    }

    // MARK: Fixture

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let directory: SQLitePreMigratedAccountDirectory
        let verifier: CountingPLCVerifier
        let revision: String
        /// The genesis signing key, retained so the write-side tests can sign
        /// a real commit against the repository this fixture installed.
        let signingKey: P256.Signing.PrivateKey
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanStaleGeneration-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: root.path
        )

        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root, did: did
        )
        let revision = "3jzfcijpj2z2a"
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: revision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let preparationRequestID = "public-read-stale-generation"
        let journal = try PLCAccountPreparationJournal(
            requestID: preparationRequestID,
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            repositoryRevision: revision,
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: CountingPLCVerifier.signingDIDKey,
                rotationDIDKey: CountingPLCVerifier.rotationDIDKey,
                signature: CountingPLCVerifier.signature
            ),
            signingKey: try AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await database.installPLCAccountPreparationJournal(journal)
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: genesis.commitCID.string
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        try await database.close()

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: genesis.commitCID.string,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        ))
        var intent = try PLCAccountPreparationIntent(
            requestID: preparationRequestID,
            did: did,
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            repositoryRevision: revision,
            operationCID: genesis.commitCID.string,
            stage: .keysStored
        )
        _ = try await control.reservePLCAccountPreparationIntent(intent)
        for next in [
            PLCAccountPreparationStage.repositoryInstalled,
            .submissionPending,
            .submitted,
        ] {
            intent = try await control.advancePLCAccountPreparationIntent(
                requestID: preparationRequestID,
                expectedStage: intent.stage,
                to: next
            )
        }

        let verifier = CountingPLCVerifier(
            operationCID: genesis.commitCID.string
        )
        let directory: SQLitePreMigratedAccountDirectory
        do {
            directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: verifier
            )
        } catch {
            try? await control.close()
            throw error
        }
        // Registered rather than deferred per test: a failing assertion aborts
        // the test body, and SQLiteNIO traps on a connection that deinitializes
        // unclosed — which would turn any future regression here into an opaque
        // signal 5 instead of a readable failure.
        addTeardownBlock {
            try? await directory.close()
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }
        return Fixture(
            root: root,
            control: control,
            directory: directory,
            verifier: verifier,
            revision: revision,
            signingKey: key
        )
    }
}

/// Counts admissions and can be told to reject every one of them.
///
/// `verifyGenesis` is the single call every full admission makes and no other
/// path makes, so its call count is the number of admissions performed.
private final class CountingPLCVerifier:
    PublicPLCGenesisVerifying,
    PublicPLCRepositoryAuthenticating,
    Sendable
{
    static let signingDIDKey =
        "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"
    static let rotationDIDKey =
        "did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA"
    static let signature =
        "9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg"

    private struct State {
        var admissions = 0
        /// The error every admission refuses with, or `nil` to accept.
        var rejection: PublicRepositoryReadError?
    }

    private let state = Mutex(State())
    let operationCID: String

    init(operationCID: String) {
        self.operationCID = operationCID
    }

    var admissionCount: Int {
        state.withLock { $0.admissions }
    }

    func rejectEverything() {
        rejectEverything(with: .identityFactsMalformed)
    }

    /// Refuses every admission with a chosen reason. Some tests care which
    /// reason an *admission* failed with — notably `.generationPinStale`, whose
    /// handling differs from every other refusal — and this is the only seam
    /// that can produce one on demand.
    func rejectEverything(with reason: PublicReadUnavailableReason) {
        rejectEverything(throwing: .unavailable(reason: reason))
    }

    /// Refuses every admission with a chosen `PublicRepositoryReadError`,
    /// including the cases that carry no reason at all. Admission's projection
    /// preflight really does throw `resourceLimitExceeded`, and how the
    /// directory journals and bounds an *unnamed* refusal is a distinct
    /// behaviour from how it handles a named one.
    func rejectEverything(throwing error: PublicRepositoryReadError) {
        state.withLock { $0.rejection = error }
    }

    func acceptEverything() {
        state.withLock { $0.rejection = nil }
    }

    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID _: String
    ) throws -> String {
        let rejection = state.withLock { current -> PublicRepositoryReadError? in
            current.admissions += 1
            return current.rejection
        }
        if let rejection {
            throw rejection
        }
        guard facts.signingDIDKey == Self.signingDIDKey,
              facts.rotationDIDKey == Self.rotationDIDKey,
              facts.signature == Self.signature else {
            throw PublicRepositoryReadError.unavailable(
                reason: .identityFactsMalformed
            )
        }
        return operationCID
    }

    func authenticateRepositoryCommit(
        signedCommitBytes: Data,
        expectedCommitCID: CID,
        expectedDID: String,
        signingDIDKey _: String
    ) async throws -> PublicRepositoryCommitAuthentication {
        let commit = try PublicRepositoryCommitCodec.structurallyValidate(
            signedCommitBytes: signedCommitBytes,
            expectedCommitCID: expectedCommitCID
        )
        guard commit.descriptor.did == expectedDID else {
            throw PublicRepositoryReadError.unavailable(
                reason: .commitAuthenticationFailed
            )
        }
        return try PublicRepositoryCommitAuthentication(
            descriptor: commit.descriptor,
            commitCID: commit.commitCID,
            verificationIdentity: "stale-generation-structural-verifier"
        )
    }
}
