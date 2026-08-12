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

        // The eviction must not have been recorded as a re-admission failure:
        // that negative entry answers refusals for the whole backoff window
        // and would suppress the cold admission this design depends on.
        let backoff = await fixture.directory
            .hasLivePublicReadReadmissionBackoff(did: did)
        XCTAssertFalse(
            backoff,
            "evicting the positive generation must not write a negative-cache "
                + "entry"
        )

        // With Task 2 in place, the next read re-admits — immediately, well
        // inside the 250 ms backoff window, because no entry was written.
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
            return error.unavailableReason
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
        var rejects = false
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
        state.withLock { $0.rejects = true }
    }

    func acceptEverything() {
        state.withLock { $0.rejects = false }
    }

    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID _: String
    ) throws -> String {
        let rejects = state.withLock { current -> Bool in
            current.admissions += 1
            return current.rejects
        }
        guard !rejects,
              facts.signingDIDKey == Self.signingDIDKey,
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
