import Crypto
import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanInterop
import SwanOAuth
import PetrelRepo
import SwanSQLite
import XCTest

/// Lane P2-G. **Adversarial** vectors against `SwanLexiconResolver`, written
/// against the resolver rather than with it: every artifact here is assembled
/// from `PublicRepositoryProofFixtureBuilder.encodeCAR` or from a deliberately
/// mis-wired harness, and none of them corresponds to a builder variant.
///
/// The companion file `SwanLexiconResolverTests` is the author's own vector
/// suite. These are the cases it does not reach, plus the non-vacuous
/// replacements for two of its assertions.
final class SwanLexiconResolverAdversarialTests: XCTestCase {
    // MARK: - Step ordering: isolating the `commit.did` equality

    /// The vector `SwanLexiconResolverTests` cannot construct.
    ///
    /// Its cross-repository test wires the authority to
    /// `documentPublicKeyX963` while the substituted commit is signed with a
    /// different key, so **two** checks reject that CAR (`commit.did` and the
    /// signature) and deleting either one leaves the other standing. That test
    /// pins the reported failure, which is real evidence of ordering — but it
    /// cannot show that the DID equality is load-bearing on its own.
    ///
    /// Here the authority names the key that actually signed the substituted
    /// commit, which is the shape a resolver that took its key from the
    /// response would produce. The signature verifies. Nothing but
    /// `commit.did == did` stands between this CAR and a resolved document,
    /// and the mutation recorded in the lane report confirms that: with the
    /// step-10 guard deleted, this vector RESOLVES an attacker-repo document.
    func testCrossRepositoryCARWhoseSignatureVerifiesIsStoppedByTheDIDEqualityAlone() async throws {
        let harness = try await AdversarialHarness(
            .crossRepositorySubstitution,
            authorityKey: .commit
        )
        // Positive control, in-test: under this harness's authority key the
        // commit signature really does verify, so a `.commitSignatureInvalid`
        // result would mean the fixture was simply broken.
        let verified = try await PublicRepositoryCommitCodec.verify(
            signedCommitBytes: harness.fixture.commitBytes,
            expectedCommitCID: harness.fixture.commitCID,
            verifier: harness.fixture.commitVerifier
        )
        XCTAssertEqual(verified.descriptor.did, harness.fixture.commitDID)
        XCTAssertNotEqual(harness.fixture.commitDID, harness.fixture.requestedDID)

        await harness.assertUnresolvable(.commitDIDMismatch)
    }

    // MARK: - Membership: the record CID the tree names is not in the CAR

    /// The inverse of `.recordPresentButUnlinked`, and the one framing case no
    /// builder variant produces: the record IS linked from `commit.data`, so
    /// the walk succeeds and returns a CID, but the block behind that CID was
    /// never sent. This is the only vector that exercises the second half of
    /// the step-12 guard (`blocks.block(for: recordCID)` returning nil).
    func testMSTNamesARecordWhoseBlockTheCARNeverCarried() async throws {
        let fixture = try await PublicRepositoryProofFixtureBuilder.build(.valid)
        var blocks: [PublicRepositoryBlock] = [
            .init(cid: fixture.commitCID, bytes: fixture.commitBytes),
        ]
        for cid in fixture.pathNodeCIDs {
            let nodeBytes = try await fixture.proofBlocks.block(for: cid)
            blocks.append(.init(cid: cid, bytes: try XCTUnwrap(nodeBytes)))
        }
        // Everything except the record block itself.
        let car = try PublicRepositoryProofFixtureBuilder.encodeCAR(
            roots: [fixture.commitCID], blocks: blocks
        )
        let harness = try await AdversarialHarness(fixture: fixture, carBytes: car)
        await harness.assertUnresolvable(.recordNotInProof)
    }

    // MARK: - CAR framing

    /// A block whose bytes do not hash to the CID that frames them. The parser
    /// refuses it, which is correct — but it is reported as
    /// `.carRootCountInvalid`, the same failure a two-root header produces.
    ///
    /// This is a **diagnostics-fidelity** vector, not a soundness one: the
    /// resolver funnels every `parseIncrementally` throw into one case
    /// (`SwanLexiconResolver.swift:472`), so an assertion of
    /// `.carRootCountInvalid` does not by itself establish that the root count
    /// was what rejected the artifact. In `SwanLexiconResolverTests` that
    /// assertion is still sound, because the happy path frames its CAR with
    /// the same encoder and only the extra root differs — but the failure name
    /// covers at least six distinct framing faults and this pins that fact so
    /// a future vector is not read as proving more than it does.
    func testABlockWhoseCIDDoesNotMatchItsBytesIsRefusedUnderTheRootCountFailure() async throws {
        let fixture = try await PublicRepositoryProofFixtureBuilder.build(.valid)
        var blocks: [PublicRepositoryBlock] = [
            .init(cid: fixture.commitCID, bytes: fixture.commitBytes),
        ]
        for cid in fixture.pathNodeCIDs {
            let nodeBytes = try await fixture.proofBlocks.block(for: cid)
            blocks.append(.init(cid: cid, bytes: try XCTUnwrap(nodeBytes)))
        }
        // The record's CID, framing bytes that are not the record.
        blocks.append(.init(cid: fixture.recordCID, bytes: Data([0xA0])))
        let car = try PublicRepositoryProofFixtureBuilder.encodeCAR(
            roots: [fixture.commitCID], blocks: blocks
        )
        let harness = try await AdversarialHarness(fixture: fixture, carBytes: car)
        await harness.assertUnresolvable(.carRootCountInvalid)
    }

    /// A CAR whose single root names the record block rather than a commit.
    /// Step 9 refuses it structurally, before any trust decision is taken on
    /// its contents.
    func testACARRootedAtTheRecordRatherThanACommitIsRefusedAtTheCommitDecode() async throws {
        let fixture = try await PublicRepositoryProofFixtureBuilder.build(.valid)
        var blocks: [PublicRepositoryBlock] = [
            .init(cid: fixture.commitCID, bytes: fixture.commitBytes),
            .init(cid: fixture.recordCID, bytes: fixture.recordBytes),
        ]
        for cid in fixture.pathNodeCIDs {
            let nodeBytes = try await fixture.proofBlocks.block(for: cid)
            blocks.append(.init(cid: cid, bytes: try XCTUnwrap(nodeBytes)))
        }
        let car = try PublicRepositoryProofFixtureBuilder.encodeCAR(
            roots: [fixture.recordCID], blocks: blocks
        )
        let harness = try await AdversarialHarness(fixture: fixture, carBytes: car)
        await harness.assertUnresolvable(.commitDecodeFailed)
    }

    /// Repeated blocks are legal CAR framing and must not escape the
    /// `SwanLexiconResolution` surface.
    ///
    /// `ProofCARSink.blocks` builds a `PublicRepositoryBlockMap` **outside any
    /// `do`/`catch`** (`SwanLexiconResolver.swift:474`), so anything it throws
    /// leaves `resolve` as a raw error rather than as `.unresolvable`. The map
    /// throws on a duplicate CID whose bytes differ and on a relevant-byte
    /// budget overrun; neither is reachable behind the parser's per-block CID
    /// verification and the 256 KiB body cap, and this vector is the executed
    /// check on the one an attacker can actually frame.
    func testARepeatedBlockIsToleratedRatherThanEscapingAsAThrownError() async throws {
        let fixture = try await PublicRepositoryProofFixtureBuilder.build(.valid)
        var blocks: [PublicRepositoryBlock] = [
            .init(cid: fixture.commitCID, bytes: fixture.commitBytes),
            .init(cid: fixture.commitCID, bytes: fixture.commitBytes),
        ]
        for cid in fixture.pathNodeCIDs {
            let nodeBytes = try await fixture.proofBlocks.block(for: cid)
            let bytes = try XCTUnwrap(nodeBytes)
            blocks.append(.init(cid: cid, bytes: bytes))
            blocks.append(.init(cid: cid, bytes: bytes))
        }
        blocks.append(.init(cid: fixture.recordCID, bytes: fixture.recordBytes))
        blocks.append(.init(cid: fixture.recordCID, bytes: fixture.recordBytes))
        let car = try PublicRepositoryProofFixtureBuilder.encodeCAR(
            roots: [fixture.commitCID], blocks: blocks
        )
        let harness = try await AdversarialHarness(fixture: fixture, carBytes: car)
        let resolution = try await harness.resolver.resolve(fixture.nsid)
        guard case let .resolved(_, _, verifiedCID) = resolution else {
            return XCTFail("a repeated block is legal framing, got \(resolution)")
        }
        XCTAssertEqual(verifiedCID, fixture.recordCID.string)
    }

    // MARK: - Cache integrity

    /// The sole pin on cached-row integrity. It replaced a vacuous test in
    /// `SwanLexiconResolverTests`, now deleted, which substituted
    /// `Data(repeating: 0xA1, count: 8)` — filler failing **both** the CID
    /// re-hash and `decodeDocument`, so it passed unchanged with the re-hash
    /// check deleted (mutation recorded in the lane report).
    ///
    /// This substitutes a *different, perfectly valid* lexicon document for the
    /// same NSID: it decodes, it satisfies `lexicon == 1` and `id == rkey`, and
    /// only the CID comparison can tell that these are not the bytes the proof
    /// chain terminated at. That is what makes storing canonical DAG-CBOR rather
    /// than re-serialised JSON an enforceable decision instead of an annotation.
    func testACachedRowHoldingAValidButDIFFERENTDocumentIsNotServed() async throws {
        let harness = try await AdversarialHarness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let storedRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let row = try XCTUnwrap(storedRow)

        // A second, independently built document for the SAME NSID. Different
        // bytes, different CID, and fully decodable.
        let other = try await PublicRepositoryProofFixtureBuilder.build(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(harness.fixture.nsid),
                "defs": .object(["main": .object([
                    "type": .string("permission-set"),
                    "permissions": .array([
                        .object([
                            "type": .string("permission"),
                            "resource": .string("repo"),
                            // A BROADER grant than the proved document names.
                            "collection": .array([.string("*")]),
                        ]),
                    ]),
                ])]),
            ])
        )
        XCTAssertNotEqual(other.recordCID, harness.fixture.recordCID)
        // Positive control: these substitute bytes really are a valid document
        // for this NSID, so a refusal below cannot be a decode failure.
        XCTAssertNoThrow(
            try SwanLexiconResolverAdversarialTests.decodeProbe(
                other.recordBytes, nsid: harness.fixture.nsid
            )
        )

        try await harness.store.storeLexicon(
            OAuthLexiconDocumentRow(
                nsid: row.nsid,
                document: other.recordBytes,
                sourceURI: row.sourceURI,
                verifiedCID: row.verifiedCID,
                createdAt: row.createdAt,
                updatedAt: row.updatedAt,
                lastSucceededAt: row.lastSucceededAt
            )
        )
        await harness.advance(by: 60)
        let served = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(
            served, .unresolvable,
            "bytes that do not hash to verified_cid must not be served"
        )
    }

    /// `decodeDocument` is `static` but not `public`, so the control above
    /// re-derives the same two checks it performs rather than reaching into it.
    private static func decodeProbe(_ bytes: Data, nsid: String) throws {
        struct Probe: Decodable, DAGCBORDecodable {
            let lexicon: Int
            let id: String
        }
        let probe: Probe = try DAGCBOR.decode(bytes)
        guard probe.lexicon == 1, probe.id == nsid else {
            throw SwanError.malformed("probe document is not valid for \(nsid)")
        }
    }

    // MARK: - `.unresolvable` reachability

    /// The attack this section exists for: `resolve`'s doc comment claims that
    /// "a cancellation, a storage fault, or any other error **propagates** —
    /// widening this to catch-all would convert a bug into a cached 'this
    /// lexicon doesn't exist' for five minutes." A cancelled resolution that
    /// instead wrote a negative row would let one slow authority in a
    /// `resolveAll` group negative-cache its three innocent siblings, because
    /// `SwanLexiconDeadline.run` calls `group.cancelAll()` on expiry.
    ///
    /// It holds, and for a non-obvious reason worth pinning: step 7's
    /// `catch is CancellationError` alone would NOT be enough, because
    /// `OAuthRemoteDocumentFetcher` re-wraps every non-`SwanError` transport
    /// throw as `SwanError.unavailable("OAuth remote fetch failed")`
    /// (`OAuthRemoteFetch.swift:674-677`) — a cancelled HTTP client's error is
    /// laundered before the resolver ever sees it. What saves the property is
    /// `SwanLexiconDeadline.run`: the sleeper task's `Task.sleep` throws
    /// `CancellationError` and that is what `group.next()` surfaces, ahead of
    /// the operation's laundered `SwanError`. The transport below blocks until
    /// cancelled and then throws its own error, exactly as a real client does.
    ///
    /// **Repeated deliberately.** Before `SwanLexiconResolver.classify` existed
    /// the outcome was a coin flip — measured at 5 laundered / 10 runs — so a
    /// single iteration would have been a flaky test that passed half the time
    /// on a broken resolver. Twenty iterations put that at 2^-20.
    func testARealCancellationMidFetchPropagatesAndWritesNoRow() async throws {
        for iteration in 0 ..< 20 {
            let harness = try await AdversarialHarness(
                .valid, transportBlocksUntilCancelled: true
            )
            let task = Task { try await harness.resolver.resolve(harness.fixture.nsid) }
            await harness.transport.waitUntilRequestObserved()
            task.cancel()

            switch await task.result {
            case let .success(resolution):
                XCTFail(
                    "run \(iteration): a cancelled resolution must not answer; "
                        + "got \(resolution)"
                )
            case let .failure(error):
                XCTAssertTrue(
                    error is CancellationError,
                    "run \(iteration): cancellation must reach the caller as a "
                        + "cancellation, got \(error)"
                )
            }
            // The property that actually matters: nothing was cached. A row here
            // would answer `.unresolvable` for five minutes for an NSID that
            // never failed.
            let row = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
            XCTAssertNil(row, "run \(iteration): a cancelled resolution left a cache row")
            XCTAssertNil(harness.diagnostics.last, "run \(iteration)")
        }
    }

    /// The boundary of the property above, recorded so the next reader does not
    /// over-read it: a `CancellationError` that the *transport* raises while
    /// the enclosing task is **not** cancelled is laundered by
    /// `OAuthRemoteFetch.swift:674-677` into a `SwanError` and classified as
    /// `.recordFetchFailed`, complete with a negative row.
    ///
    /// That is defensible — the resolver's own task is healthy and the fetch
    /// genuinely failed — and it is NOT the `resolveAll` hazard, which the
    /// vector above shows is closed. The two cases are separated in source by
    /// `classify`'s `Task.checkCancellation()`, which asks whether **this task**
    /// is cancelled rather than what type the error happens to be; before that
    /// existed they were told apart only by which task won the deadline race.
    ///
    /// **This expectation is coupled to the fetcher and moves with it.** The
    /// case lands on `.recordFetchFailed` precisely *because* the transport's
    /// `CancellationError` is re-wrapped — the same laundering that caused the
    /// bug the vector above pins is what makes this case come out right. If
    /// `OAuthRemoteFetch` ever stops re-wrapping, a bare `CancellationError`
    /// reaches `classify` first, this resolution starts propagating instead of
    /// caching, and **this test is supposed to fail**. It is the tripwire for
    /// that change, not a victim of it.
    func testATransportRaisedCancellationWithoutTaskCancellationIsAFetchFailure() async throws {
        let harness = try await AdversarialHarness(.valid, transportError: CancellationError())
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(resolution, .unresolvable)
        XCTAssertEqual(harness.diagnostics.last, .recordFetchFailed)

        let storedRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let row = try XCTUnwrap(storedRow)
        XCTAssertNil(row.document)
        XCTAssertNil(row.lastSucceededAt)
        XCTAssertFalse(row.isStale(now: harness.clock.currentDate.addingTimeInterval(299)))

        await harness.setTransportError(nil)
        await harness.advance(by: 60)
        let retried = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(retried, .unresolvable)
        let fetches = await harness.transport.requestedURLs.count
        XCTAssertEqual(fetches, 1, "the retry inside the window never reached the network")
    }

    // MARK: - Authority-cache keying

    /// The domain-keyed authority cache is keyed on the raw reversed authority,
    /// and `authorityDomain(ofNSID:)` does not case-fold. DNS is
    /// case-insensitive, so `com.example.foo.auth` and `com.Example.foo.auth`
    /// name the same TXT record but occupy two cache slots.
    ///
    /// Recorded as a **bounded** observation rather than a defect: the cache
    /// holds 256 entries and evicts oldest-first, the per-request populations
    /// are capped at 4 and 8, and every resolution re-runs the full proof
    /// against whatever key the document currently names — so the cost is
    /// duplicated DNS work, never a weakened trust decision. If `isValidNSID`
    /// refuses the mixed-case NSID outright the split does not exist at all,
    /// and this test records which of the two is true.
    func testMixedCaseAuthoritySegmentsDoNotShareAnAuthorityCacheSlot() async throws {
        let mixed = "com.Example.foo.auth"
        guard let domain = try? SwanLexiconResolver.authorityDomain(ofNSID: mixed) else {
            // `isValidNSID` refuses it; there is nothing to split.
            return
        }
        XCTAssertEqual(domain, "foo.Example.com")

        let harness = try await AdversarialHarness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        _ = try? await harness.resolver.resolve(mixed)
        let names = await harness.dns.queriedNames
        XCTAssertEqual(
            names, ["_lexicon.foo.example.com", "_lexicon.foo.Example.com"],
            "two DNS lookups for one DNS name"
        )
    }

    // MARK: - Negative-cache keying

    /// A failure must be written under the NSID that failed and nowhere else.
    /// Two sibling NSIDs share steps 1-6; only the second is made to fail.
    func testAFailureIsCachedUnderTheFailingNSIDAlone() async throws {
        let harness = try await AdversarialHarness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        await harness.setTransportError(SwanError.unavailable("stub"))
        _ = try await harness.resolver.resolve("com.example.foo.sibling")

        let siblingRow = try await harness.store.findLexicon(nsid: "com.example.foo.sibling")
        let sibling = try XCTUnwrap(siblingRow)
        XCTAssertNil(sibling.document)
        // The neighbour's positive row is untouched.
        let originalRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let original = try XCTUnwrap(originalRow)
        XCTAssertEqual(original.document, harness.fixture.recordBytes)
        XCTAssertEqual(original.verifiedCID, harness.fixture.recordCID.string)
    }

    /// An over-cap `resolveAll` must write nothing at all: the cap is a
    /// property of the request, not of any authority.
    func testAnOverCapResolveAllWritesNoRowForAnyNSID() async throws {
        let harness = try await AdversarialHarness(.valid)
        let five = (0 ..< 5).map { "com.example.foo.set\($0)" }
        do {
            _ = try await harness.resolver.resolveAll(five, population: .includes)
            XCTFail("expected the include cap to reject five distinct NSIDs")
        } catch let error as SwanLexiconResolutionBudgetError {
            XCTAssertEqual(error, .tooManyDistinctNSIDs(.includes, requested: 5))
        }
        for nsid in five {
            let row = try await harness.store.findLexicon(nsid: nsid)
            XCTAssertNil(row, "\(nsid) must not carry a row from a request-level refusal")
        }
        let fetches = await harness.transport.requestedURLs.count
        XCTAssertEqual(fetches, 0)
    }

    // MARK: - Task 12: Negative lexicon cache bounding and eviction

    func testNegativeLexiconCacheStopsAt4096AndEvictsExpiredRows() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("lexicon-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let store = try await SQLiteControlDatabase(dataDirectory: tempDir)
        defer {
            Task { try? await store.close() }
            try? FileManager.default.removeItem(at: tempDir)
        }
        let now = Date()

        // 1. Expired negative eviction with 512 batch limit
        for i in 0 ..< 1_000 {
            let updatedAt = now.addingTimeInterval(-7200 + Double(i) * 0.1)
            let row = OAuthLexiconDocumentRow(
                nsid: "com.example.expired\(i)",
                document: nil,
                sourceURI: nil,
                verifiedCID: nil,
                createdAt: updatedAt,
                updatedAt: updatedAt,
                lastSucceededAt: nil
            )
            try await store.storeLexicon(row)
        }
        let countAfterExpiredFill = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterExpiredFill, 1_000)

        // Inserting a row at `now` triggers eviction of up to 512 rows older than 1 hour
        let triggerRow = OAuthLexiconDocumentRow(
            nsid: "com.example.trigger",
            document: nil,
            sourceURI: nil,
            verifiedCID: nil,
            createdAt: now,
            updatedAt: now,
            lastSucceededAt: nil
        )
        try await store.storeLexicon(triggerRow)

        // Exactly 512 oldest rows are evicted (expired0..expired511), expired512..expired999 remain
        let evicted0 = try await store.findLexicon(nsid: "com.example.expired0")
        XCTAssertNil(evicted0, "expired negative row should be evicted")
        let evicted511 = try await store.findLexicon(nsid: "com.example.expired511")
        XCTAssertNil(evicted511, "expired negative row within batch bound should be evicted")
        let fresh512 = try await store.findLexicon(nsid: "com.example.expired512")
        XCTAssertNotNil(fresh512, "expired negative row beyond batch bound should remain until next batch")
        // 1000 - 512 expired + 1 trigger = 489
        let countAfterExpiredEviction = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterExpiredEviction, 489)

        // Clean up remaining expired rows to test full 4,096 fresh capacity
        for i in 512 ..< 1_000 {
            try await store.deleteLexicon(nsid: "com.example.expired\(i)")
        }
        try await store.deleteLexicon(nsid: "com.example.trigger")
        let countReset = try await store.countNegativeLexicons()
        XCTAssertEqual(countReset, 0)

        // 2. Fill negative cache to exactly 4,096 fresh rows (none expired)
        for i in 0 ..< 4_096 {
            let updatedAt = now.addingTimeInterval(-1800 + Double(i) * 0.1)
            let row = OAuthLexiconDocumentRow(
                nsid: "com.example.neg\(i)",
                document: nil,
                sourceURI: nil,
                verifiedCID: nil,
                createdAt: updatedAt,
                updatedAt: updatedAt,
                lastSucceededAt: nil
            )
            try await store.storeLexicon(row)
        }
        let countAfterFill = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterFill, 4_096)

        // Updating an existing negative NSID remains allowed without changing row count
        let updatedExisting = OAuthLexiconDocumentRow(
            nsid: "com.example.neg0",
            document: nil,
            sourceURI: nil,
            verifiedCID: nil,
            createdAt: now.addingTimeInterval(-1800),
            updatedAt: now.addingTimeInterval(-1800),
            lastSucceededAt: nil
        )
        try await store.storeLexicon(updatedExisting)
        let countAfterExistingUpdate = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterExistingUpdate, 4_096)

        // 3. Insert 4,097th negative row when no expired rows exist -> turns over oldest negative row
        let overCapNegative = OAuthLexiconDocumentRow(
            nsid: "com.example.neg.overflow",
            document: nil,
            sourceURI: nil,
            verifiedCID: nil,
            createdAt: now.addingTimeInterval(10),
            updatedAt: now.addingTimeInterval(10),
            lastSucceededAt: nil
        )
        try await store.storeLexicon(overCapNegative)
        let evictedOldest = try await store.findLexicon(nsid: "com.example.neg0")
        let preserved1 = try await store.findLexicon(nsid: "com.example.neg1")
        let admitted = try await store.findLexicon(nsid: overCapNegative.nsid)
        XCTAssertNil(evictedOldest)
        XCTAssertNotNil(preserved1)
        XCTAssertNotNil(admitted)
        let countAfterOverflow = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterOverflow, 4_096)

        // 4. Converting an actually-admitted negative NSID to positive frees a negative slot
        let positiveDoc = Data("valid-doc".utf8)
        let convertedPositive = OAuthLexiconDocumentRow(
            nsid: "com.example.neg1000",
            document: positiveDoc,
            sourceURI: "at://did:plc:test/com.atproto.lexicon.schema/com.example.neg1000",
            verifiedCID: "bafytestcid",
            createdAt: now,
            updatedAt: now,
            lastSucceededAt: now
        )
        try await store.storeLexicon(convertedPositive)
        let foundConverted = try await store.findLexicon(nsid: "com.example.neg1000")
        XCTAssertEqual(foundConverted?.document, positiveDoc)
        // Negative count dropped by 1 because neg1000 is now positive!
        let countAfterConversion = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterConversion, 4_095)

        // Now we can insert a fresh, distinct, never-before-stored negative NSID without evicting any negative row!
        let freshNegative = OAuthLexiconDocumentRow(
            nsid: "com.example.neg.fresh_after_conversion",
            document: nil,
            sourceURI: nil,
            verifiedCID: nil,
            createdAt: now.addingTimeInterval(20),
            updatedAt: now.addingTimeInterval(20),
            lastSucceededAt: nil
        )
        try await store.storeLexicon(freshNegative)
        let foundFreshNegative = try await store.findLexicon(nsid: "com.example.neg.fresh_after_conversion")
        XCTAssertNotNil(foundFreshNegative)
        let countAfterFreshNegative = try await store.countNegativeLexicons()
        XCTAssertEqual(countAfterFreshNegative, 4_096)

        // And verify that com.example.neg.overflow was NOT evicted when inserting into the freed slot!
        let foundOverCap = try await store.findLexicon(nsid: "com.example.neg.overflow")
        XCTAssertNotNil(foundOverCap)

        // 5. Positive rows are NEVER purged by negative cleanup
        let oldPositive = OAuthLexiconDocumentRow(
            nsid: "com.example.pos.old",
            document: positiveDoc,
            sourceURI: "at://did:plc:test/com.atproto.lexicon.schema/com.example.pos.old",
            verifiedCID: "bafytestcid",
            createdAt: now.addingTimeInterval(-7200),
            updatedAt: now.addingTimeInterval(-7200),
            lastSucceededAt: now.addingTimeInterval(-7200)
        )
        try await store.storeLexicon(oldPositive)

        // Trigger negative cleanup by storing another row
        let triggerPositiveRow = OAuthLexiconDocumentRow(
            nsid: "com.example.trigger.pos",
            document: positiveDoc,
            sourceURI: "at://did:plc:test/com.atproto.lexicon.schema/com.example.trigger.pos",
            verifiedCID: "bafytestcid",
            createdAt: now,
            updatedAt: now,
            lastSucceededAt: now
        )
        try await store.storeLexicon(triggerPositiveRow)

        let preservedPositive = try await store.findLexicon(nsid: "com.example.pos.old")
        XCTAssertNotNil(preservedPositive, "positive rows must never be deleted by negative eviction")
        let countFinal = try await store.countNegativeLexicons()
        XCTAssertLessThanOrEqual(countFinal, 4_096)
    }

    func testSaturatedNegativeCacheDoesNotFailUnresolvableLexicon() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("lexicon-store-sat-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let store = try await SQLiteControlDatabase(dataDirectory: tempDir)
        defer {
            Task { try? await store.close() }
            try? FileManager.default.removeItem(at: tempDir)
        }
        let now = Date()

        // 1. Fill negative cache to exactly 4,096 rows
        for i in 0 ..< 4_096 {
            let row = OAuthLexiconDocumentRow(
                nsid: "com.example.sat\(i)",
                document: nil,
                sourceURI: nil,
                verifiedCID: nil,
                createdAt: now,
                updatedAt: now,
                lastSucceededAt: nil
            )
            try await store.storeLexicon(row)
        }

        // Verify negative cache is full
        let overCapRow = OAuthLexiconDocumentRow(
            nsid: "com.example.sat.overflow",
            document: nil,
            sourceURI: nil,
            verifiedCID: nil,
            createdAt: now,
            updatedAt: now,
            lastSucceededAt: nil
        )
        // A 4,097th negative row turns over the oldest entry rather than
        // refusing admission.
        try await store.storeLexicon(overCapRow)

        // 2. Instantiate a SwanLexiconResolver using this saturated store and
        // a failing transport/DNS.
        let dns = AdversarialDNSResolver(records: [])
        let validKey = try await P256.Signing.PublicKey(
            x963Representation: PublicRepositoryProofFixtureBuilder.build(.valid).documentPublicKeyX963
        )
        let resolver = try SwanLexiconResolver(
            dns: dns,
            authorities: AdversarialAuthorityResolver(
                authority: SwanLexiconAuthority(
                    pdsEndpoint: URL(string: "https://pds.example.net")!,
                    commitVerifier: PermissionedDataPublicRepositoryCommitVerifier(
                        key: .p256(validKey)
                    )
                )
            ),
            fetcher: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: AdversarialHostnameResolver(),
                transport: AdversarialTransport(body: Data(), error: nil, blocksUntilCancelled: false)
            ),
            store: store,
            now: { now }
        )

        // 3. Resolving an unresolvable NSID must return .unresolvable, NOT throw SwanError.unavailable
        let resolution = try await resolver.resolve("com.example.unresolvable")
        XCTAssertEqual(resolution, SwanLexiconResolution.unresolvable)
    }

    func testSaturatedDNSGateDoesNotWriteNegativeLexiconCacheRow() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("lexicon-store-dns-sat-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let store = try await SQLiteControlDatabase(dataDirectory: tempDir)
        defer {
            Task { try? await store.close() }
            try? FileManager.default.removeItem(at: tempDir)
        }
        let now = Date()

        // Create a DNS resolver with a saturated admission gate
        let gate = HandleDNSAdmissionGate(maxActive: 1, maxQueued: 0)
        try await gate.acquire()
        let dns = SystemATHandleDNSResolver(gate: gate)

        let validKey = try await P256.Signing.PublicKey(
            x963Representation: PublicRepositoryProofFixtureBuilder.build(.valid).documentPublicKeyX963
        )
        let resolver = try SwanLexiconResolver(
            dns: dns,
            authorities: AdversarialAuthorityResolver(
                authority: SwanLexiconAuthority(
                    pdsEndpoint: URL(string: "https://pds.example.net")!,
                    commitVerifier: PermissionedDataPublicRepositoryCommitVerifier(
                        key: .p256(validKey)
                    )
                )
            ),
            fetcher: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: AdversarialHostnameResolver(),
                transport: AdversarialTransport(body: Data(), error: nil, blocksUntilCancelled: false)
            ),
            store: store,
            now: { now }
        )

        let testNSID = "com.example.transient.saturation"
        do {
            _ = try await resolver.resolve(testNSID)
            XCTFail("expected resolution to throw transient admission saturation error")
        } catch {
            // Transient local admission saturation must NOT create a negative lexicon cache row!
            let cached = try await store.findLexicon(nsid: testNSID)
            XCTAssertNil(cached, "DNS admission saturation must never write a negative lexicon cache row")
        }

        gate.release()
    }
}

// MARK: - Harness

/// Deliberately separate from `SwanLexiconResolverTests`' harness: this one can
/// serve arbitrary CAR bytes, can name either of the fixture's two keys as the
/// authority's, and can fail the transport with a chosen error.
private struct AdversarialHarness {
    enum AuthorityKey {
        /// What the requested DID's document names. The production shape.
        case document
        /// The key that actually signed the CAR's commit — the shape a resolver
        /// taking its key from the response would produce.
        case commit
    }

    let fixture: PublicRepositoryProofFixture
    let dns: AdversarialDNSResolver
    let transport: AdversarialTransport
    let store: any OAuthLexiconDocumentStore
    let resolver: SwanLexiconResolver
    let clock: AdversarialClock
    let diagnostics: AdversarialDiagnostics

    init(
        _ variant: PublicRepositoryProofFixtureVariant,
        authorityKey: AuthorityKey = .document,
        transportError: (any Error)? = nil,
        transportBlocksUntilCancelled: Bool = false
    ) async throws {
        try await self.init(
            fixture: try await PublicRepositoryProofFixtureBuilder.build(variant),
            carBytes: nil,
            authorityKey: authorityKey,
            transportError: transportError,
            transportBlocksUntilCancelled: transportBlocksUntilCancelled
        )
    }

    init(
        fixture: PublicRepositoryProofFixture,
        carBytes: Data?,
        authorityKey: AuthorityKey = .document,
        transportError: (any Error)? = nil,
        transportBlocksUntilCancelled: Bool = false
    ) async throws {
        self.fixture = fixture
        let x963: Data
        switch authorityKey {
        case .document: x963 = fixture.documentPublicKeyX963
        case .commit: x963 = fixture.commitPublicKeyX963
        }
        let key = try P256.Signing.PublicKey(x963Representation: x963)
        dns = AdversarialDNSResolver(records: ["did=\(fixture.requestedDID)"])
        transport = AdversarialTransport(
            body: carBytes ?? fixture.carBytes,
            error: transportError,
            blocksUntilCancelled: transportBlocksUntilCancelled
        )
        store = AdversarialLexiconStore()
        clock = AdversarialClock(now: Date(timeIntervalSince1970: 1_760_000_000))
        diagnostics = AdversarialDiagnostics()
        let capturedClock = clock
        let capturedDiagnostics = diagnostics
        resolver = try SwanLexiconResolver(
            dns: dns,
            authorities: AdversarialAuthorityResolver(
                authority: SwanLexiconAuthority(
                    pdsEndpoint: URL(string: "https://pds.example.net")!,
                    commitVerifier: PermissionedDataPublicRepositoryCommitVerifier(
                        key: .p256(key)
                    )
                )
            ),
            fetcher: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: AdversarialHostnameResolver(),
                transport: transport
            ),
            store: store,
            now: { capturedClock.currentDate },
            diagnostics: { _, failure in capturedDiagnostics.record(failure) }
        )
    }

    func advance(by seconds: TimeInterval) async { clock.advance(by: seconds) }

    func setTransportError(_ error: (any Error)?) async {
        await transport.setError(error)
    }

    func assertUnresolvable(
        _ expected: SwanLexiconResolverFailure,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            let resolution = try await resolver.resolve(fixture.nsid)
            XCTAssertEqual(resolution, .unresolvable, file: file, line: line)
        } catch {
            XCTFail("resolution threw instead of refusing: \(error)", file: file, line: line)
        }
        XCTAssertEqual(diagnostics.last, expected, file: file, line: line)
    }
}

private final class AdversarialClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(now: Date) { value = now }

    var currentDate: Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        value = value.addingTimeInterval(seconds)
    }
}

private final class AdversarialDiagnostics: @unchecked Sendable {
    private let lock = NSLock()
    private var failures: [SwanLexiconResolverFailure] = []

    func record(_ failure: SwanLexiconResolverFailure) {
        lock.lock()
        defer { lock.unlock() }
        failures.append(failure)
    }

    var last: SwanLexiconResolverFailure? {
        lock.lock()
        defer { lock.unlock() }
        return failures.last
    }
}

private actor AdversarialDNSResolver: ATHandleDNSResolving {
    private let records: [String]
    private(set) var queriedNames: [String] = []

    init(records: [String]) { self.records = records }

    func txtRecords(name: String) async throws -> [ATHandleTXTRecord] {
        queriedNames.append(name)
        return try records.map { try ATHandleTXTRecord(bytes: Data($0.utf8)) }
    }

    func addresses(host _: String) async throws -> [ATHandleIPAddress] { [] }
}

private actor AdversarialAuthorityResolver: SwanLexiconAuthorityResolving {
    private let authority: SwanLexiconAuthority

    init(authority: SwanLexiconAuthority) { self.authority = authority }

    func resolveAuthority(did _: String) async throws -> SwanLexiconAuthority {
        authority
    }
}

private struct AdversarialHostnameResolver: OAuthHostnameResolving {
    static let peer = OAuthIPAddress.ipv4(93 << 24 | 184 << 16 | 216 << 8 | 34)

    func resolve(host _: String) async throws -> [OAuthIPAddress] { [Self.peer] }
}

private actor AdversarialTransport: OAuthRemoteTransport {
    private let body: Data
    private var error: (any Error)?
    private let blocksUntilCancelled: Bool
    private(set) var requestedURLs: [URL] = []
    private var observers: [CheckedContinuation<Void, Never>] = []

    init(body: Data, error: (any Error)?, blocksUntilCancelled: Bool) {
        self.body = body
        self.error = error
        self.blocksUntilCancelled = blocksUntilCancelled
    }

    func setError(_ value: (any Error)?) { error = value }

    /// Lets a test cancel the enclosing task only once the fetch is genuinely
    /// in flight, so the cancellation lands inside the transport rather than at
    /// `withAdmission`'s entry `Task.checkCancellation()`.
    func waitUntilRequestObserved() async {
        if !requestedURLs.isEmpty { return }
        await withCheckedContinuation { observers.append($0) }
    }

    func get(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requestedURLs.append(url)
        for observer in observers { observer.resume() }
        observers.removeAll()
        if let error { throw error }
        if blocksUntilCancelled {
            // What a cancelled HTTP client does: notice the cancellation and
            // throw its OWN error rather than a bare `CancellationError`.
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000)
            }
            throw SwanError.unavailable("transport cancelled")
        }
        return OAuthRemoteHTTPResponse(
            status: 200,
            headers: ["content-type": ["application/vnd.ipld.car"]],
            body: body,
            responseURL: url,
            redirectCount: 0,
            connectedPeerAddress: AdversarialHostnameResolver.peer
        )
    }
}

private actor AdversarialLexiconStore: OAuthLexiconDocumentStore {
    private var rows: [String: OAuthLexiconDocumentRow] = [:]

    func findLexicon(nsid: String) async throws -> OAuthLexiconDocumentRow? {
        rows[nsid]
    }

    func storeLexicon(_ row: OAuthLexiconDocumentRow) async throws {
        guard (row.document == nil) == (row.verifiedCID == nil),
              (row.document == nil) == (row.sourceURI == nil),
              row.document == nil || row.lastSucceededAt != nil else {
            throw SwanError.malformed("half-populated lexicon cache row")
        }
        rows[row.nsid] = row
    }

    func deleteLexicon(nsid: String) async throws {
        rows[nsid] = nil
    }

    func countNegativeLexicons() async throws -> Int {
        rows.values.filter { $0.document == nil }.count
    }
}
