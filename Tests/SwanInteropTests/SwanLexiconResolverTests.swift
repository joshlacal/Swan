import Crypto
import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanInterop
import SwanOAuth
import SwanPublicRepository
import SwanPublicRepositoryTestSupport
import SwanSQLite
import XCTest

/// §5.7.4 / §5.7.6. These are predominantly **negative** vectors by design: a
/// resolver that passes every happy-path test and skips proof verification is
/// worse than no resolver, because it launders an attacker-controlled response
/// into a signed-looking grant.
final class SwanLexiconResolverTests: XCTestCase {
    // MARK: - Step 1

    func testAuthorityDomainIsTheReversedDomainAuthority() throws {
        // Upstream `NSID.authority`: every segment but the last, reversed.
        XCTAssertEqual(
            try SwanLexiconResolver.authorityDomain(ofNSID: "com.example.foo.auth"),
            "foo.example.com"
        )
        XCTAssertEqual(
            try SwanLexiconResolver.authorityDomain(ofNSID: "app.bsky.feed.post"),
            "feed.bsky.app"
        )
    }

    func testAuthorityDomainRejectsANonNSID() {
        for value in ["", "notannsid", "com.example", "com.exa mple.foo"] {
            XCTAssertThrowsError(
                try SwanLexiconResolver.authorityDomain(ofNSID: value)
            ) { error in
                XCTAssertEqual(
                    error as? SwanLexiconResolverFailure, .invalidNSID,
                    "\(value) should not yield an authority"
                )
            }
        }
    }

    // MARK: - Happy path

    func testWellFormedProofCARResolvesAndReportsTheWalkedCID() async throws {
        let harness = try await Harness(.valid)
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)

        guard case let .resolved(document, sourceURI, verifiedCID) = resolution else {
            return XCTFail("expected a resolution, got \(resolution)")
        }
        // `verifiedCID` is the CID the MST walk terminated at — the only value
        // in the result tying the returned bytes back to the signed commit.
        XCTAssertEqual(verifiedCID, harness.fixture.recordCID.string)
        XCTAssertEqual(
            sourceURI,
            "at://\(harness.fixture.requestedDID)/com.atproto.lexicon.schema/\(harness.fixture.nsid)"
        )
        guard case let .permissionSet(set) = document else {
            return XCTFail("expected a permission set, got \(document)")
        }
        XCTAssertEqual(set.type, "permission-set")
        XCTAssertEqual(set.permissions.count, 1)
        XCTAssertEqual(set.permissions.first?.resource, "repo")
    }

    func testHappyPathWritesAPositiveCacheRowCarryingTheProvedBytes() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)

        let row = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        XCTAssertEqual(row?.document, harness.fixture.recordBytes)
        XCTAssertEqual(row?.verifiedCID, harness.fixture.recordCID.string)
        XCTAssertNotNil(row?.lastSucceededAt)
        // The stored bytes still hash to the CID that was proved. That is the
        // property `verified_cid` exists for, and it is only achievable because
        // the row holds canonical DAG-CBOR rather than re-serialised JSON.
        XCTAssertEqual(CID.fromDAGCBOR(try XCTUnwrap(row?.document)), harness.fixture.recordCID)
    }

    // MARK: - Steps 2-3: DNS TXT

    func testZeroDIDLinesInTXTIsARefusal() async throws {
        let harness = try await Harness(.valid, txtRecords: ["nope=1", "hello"])
        await harness.assertUnresolvable(.noAuthorityDIDInTXT)
    }

    func testTwoDIDLinesInTXTIsARefusalAndNotFirstWins() async throws {
        // The attacker appends a second TXT record. Under "first wins" the
        // winner is decided by DNS answer ordering, which the attacker also
        // influences. Exactly one, or nothing.
        let harness = try await Harness(
            .valid,
            txtRecords: [
                "did=\(PublicRepositoryProofFixtureBuilder.defaultRequestedDID)",
                "did=\(PublicRepositoryProofFixtureBuilder.defaultSubstituteDID)",
            ]
        )
        await harness.assertUnresolvable(.multipleAuthorityDIDsInTXT)
    }

    func testTwoIdenticalDIDLinesAreStillTwoLines() async throws {
        let did = PublicRepositoryProofFixtureBuilder.defaultRequestedDID
        let harness = try await Harness(.valid, txtRecords: ["did=\(did)", "did=\(did)"])
        await harness.assertUnresolvable(.multipleAuthorityDIDsInTXT)
    }

    func testNonDIDTextAfterThePrefixIsARefusal() async throws {
        let harness = try await Harness(.valid, txtRecords: ["did=not-a-did"])
        await harness.assertUnresolvable(.invalidAuthorityDIDInTXT)
    }

    func testTheQueriedNameIsUnderscoreLexicon() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let names = await harness.dns.queriedNames
        XCTAssertEqual(names, ["_lexicon.foo.example.com"])
    }

    // MARK: - Steps 5-6: DID document

    func testAuthorityWithNoSigningKeyOrPDSIsARefusal() async throws {
        let harness = try await Harness(
            .valid, authorityError: .missingSigningKey
        )
        await harness.assertUnresolvable(.authorityDocumentIncomplete)

        let other = try await Harness(.valid, authorityError: .missingPDSEndpoint)
        await other.assertUnresolvable(.authorityDocumentIncomplete)
    }

    func testUnresolvableAuthorityDocumentIsARefusal() async throws {
        let harness = try await Harness(.valid, authorityError: .documentUnavailable)
        await harness.assertUnresolvable(.authorityDocumentUnavailable)
    }

    // MARK: - Step 7: fetch

    func testTheFetchTargetsTheResolvedPDSAndTheHardcodedCollection() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let urls = await harness.transport.requestedURLs
        let requested = try XCTUnwrap(urls.first)
        let components = try XCTUnwrap(
            URLComponents(url: requested, resolvingAgainstBaseURL: false)
        )
        XCTAssertEqual(components.host, "pds.example.net")
        XCTAssertEqual(components.path, "/xrpc/com.atproto.sync.getRecord")
        let items = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value) }
        )
        XCTAssertEqual(items["did"], harness.fixture.requestedDID)
        // Hardcoded, never caller-suppliable.
        XCTAssertEqual(items["collection"], "com.atproto.lexicon.schema")
        XCTAssertEqual(items["rkey"], harness.fixture.nsid)
    }

    func testAFailedFetchIsARefusal() async throws {
        let harness = try await Harness(.valid, transportFails: true)
        await harness.assertUnresolvable(.recordFetchFailed)
    }

    func testResolverRefusesAFetchPolicyWiderThan256KiB() async throws {
        let harness = try await Harness(.valid)
        XCTAssertThrowsError(
            try SwanLexiconResolver(
                dns: harness.dns,
                authorities: harness.authorities,
                fetcher: OAuthRemoteDocumentFetcher(
                    policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 512 * 1_024),
                    resolver: harness.hostnames,
                    transport: harness.transport
                ),
                store: harness.store
            )
        )
    }

    // MARK: - Steps 8-13: the six proofs

    func testCARWithTwoRootsIsARefusal() async throws {
        // Stops a second root smuggling an alternate commit past a caller that
        // naively reads `roots[0]`.
        let harness = try await Harness(.twoCARRoots)
        await harness.assertUnresolvable(.carRootCountInvalid)
    }

    /// **The single most important vector in Phase 2.** A correctly self-signed
    /// commit belonging to the *attacker's own* repo, presented as this DID's
    /// data. It is the one a proof-free implementation passes every other test
    /// while failing.
    func testCrossRepositorySubstitutionIsRefusedByTheDIDEqualityItself() async throws {
        let harness = try await Harness(.crossRepositorySubstitution)
        // `.commitDIDMismatch`, NOT `.commitSignatureInvalid`: the check that
        // catches this is `commit.did == the resolved DID`, and it runs first.
        // A resolver that took the key from the response would pass the
        // signature check on this exact CAR.
        await harness.assertUnresolvable(.commitDIDMismatch)
    }

    func testCrossRepositoryCARIsSelfConsistentUnderItsOwnRepositorysKey() async throws {
        // The positive control for the vector above: this CAR really is validly
        // signed — under the substitute repository's own key. Without this, the
        // test above could be passing because the artifact is simply broken.
        let fixture = try await PublicRepositoryProofFixtureBuilder
            .build(.crossRepositorySubstitution)
        let verified = try await PublicRepositoryCommitCodec.verify(
            signedCommitBytes: fixture.commitBytes,
            expectedCommitCID: fixture.commitCID,
            verifier: fixture.commitVerifier
        )
        XCTAssertEqual(verified.descriptor.did, fixture.commitDID)
        XCTAssertNotEqual(fixture.commitDID, fixture.requestedDID)
    }

    func testFlippedCommitSignatureByteIsARefusal() async throws {
        let harness = try await Harness(.flippedCommitSignatureByte)
        await harness.assertUnresolvable(.commitSignatureInvalid)
    }

    func testCommitSignedWithAKeyTheDocumentDoesNotNameIsARefusal() async throws {
        // Pins that the key comes from the DID document, not the response: this
        // signature is genuine and verifies perfectly — under the wrong key.
        let harness = try await Harness(.commitSignedWithUnnamedKey)
        await harness.assertUnresolvable(.commitSignatureInvalid)
    }

    func testRecordPresentInTheCARButNotInTheMSTIsARefusal() async throws {
        // Membership, not mere presence. An unlinked orphan block proves nothing.
        let harness = try await Harness(.recordPresentButUnlinked)
        await harness.assertUnresolvable(.recordNotInProof)
    }

    func testWithheldMSTPathNodeIsARefusal() async throws {
        // A withheld block must not read as "the authority does not declare
        // this" — an attacker choosing which blocks to omit must not be able to
        // steer that distinction into a different outcome.
        let harness = try await Harness(.omittedPathNode)
        await harness.assertUnresolvable(.recordNotInProof)
    }

    func testRecordTypeMismatchIsARefusal() async throws {
        let harness = try await Harness(.recordTypeMismatch("com.example.other.thing"))
        await harness.assertUnresolvable(.recordTypeMismatch)
    }

    // MARK: - Steps 14-15: document

    func testLexiconIDNamingADifferentNSIDIsARefusal() async throws {
        // Same-repo record substitution: a validly signed lexicon describing a
        // DIFFERENT NSID sitting at the expected rkey. Every proof above passes.
        let harness = try await Harness(.lexiconIDMismatch("com.example.foo.other"))
        await harness.assertUnresolvable(.documentIDMismatch)
    }

    func testDocumentFailingSchemaValidationIsARefusal() async throws {
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                // `lexicon` must be the literal 1.
                "lexicon": .integer(2),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object(["type": .string("permission-set"),
                                                  "permissions": .array([])])]),
            ])
        )
        await harness.assertUnresolvable(.documentSchemaInvalid)
    }

    func testSpaceDocumentResolvesToASpace() async throws {
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object([
                    "type": .string("space"),
                    "name": .string("Bulleted"),
                    "collections": .array([
                        .string("com.example.foo.item"),
                        .string("com.example.foo.list"),
                    ]),
                ])]),
            ])
        )
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case let .resolved(.space(space), _, _) = resolution else {
            return XCTFail("expected a space, got \(resolution)")
        }
        XCTAssertEqual(space.name, "Bulleted")
        XCTAssertEqual(space.collections, ["com.example.foo.item", "com.example.foo.list"])
    }

    func testSpaceDocumentCarryingNameLangStillDecodes() async throws {
        // `name:lang` (`lib/lexicon.ts:26` at the pinned corpus commit
        // `bddc99fb`) is a display-localisation map that contributes no
        // capability. Upstream declares it, so a real space from a localised
        // lexicon carries it, and refusing the document over it would reject a
        // legitimate authority. Same treatment `LexiconPermissionSet` already
        // gives `title:lang` / `detail:lang`.
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object([
                    "type": .string("space"),
                    "name": .string("Bulleted"),
                    "name:lang": .object([
                        "fr": .string("Puces"),
                        "ja": .string("ブレット"),
                    ]),
                    "collections": .array([.string("com.example.foo.item")]),
                    "description": .string("A bulleted space"),
                ])]),
            ])
        )
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case let .resolved(.space(space), _, _) = resolution else {
            return XCTFail("expected a space, got \(resolution)")
        }
        XCTAssertEqual(space.type, "space")
        XCTAssertEqual(space.name, "Bulleted")
        XCTAssertEqual(space.collections, ["com.example.foo.item"])
        XCTAssertEqual(space.description, "A bulleted space")
    }

    func testPermissionSetCarryingTitleLangStillDecodes() async throws {
        // The sibling control: the localisation maps upstream declares on a
        // permission set (`lexicon.ts:18`, `:20`) reach the resolver on the same
        // path and must not fail the document either.
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object([
                    "type": .string("permission-set"),
                    "title": .string("Bulleted"),
                    "title:lang": .object(["fr": .string("Puces")]),
                    "detail": .string("Read and write bulleted items"),
                    "detail:lang": .object(["fr": .string("Lire et écrire")]),
                    "permissions": .array([
                        .object([
                            "type": .string("permission"),
                            "resource": .string("repo"),
                            "collection": .array([.string("com.example.foo.item")]),
                        ]),
                    ]),
                ])]),
            ])
        )
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case let .resolved(.permissionSet(set), _, _) = resolution else {
            return XCTFail("expected a permission set, got \(resolution)")
        }
        XCTAssertEqual(set.title, "Bulleted")
        XCTAssertEqual(set.detail, "Read and write bulleted items")
        XCTAssertEqual(set.permissions.count, 1)
    }

    func testEmptySpaceCollectionListDecodesAsEmptyAndNotAsAbsent() async throws {
        // §5.7.5: an empty declared collection list is NOT an error; the bare
        // grant passes through. Materialisation treats `[]` and "unresolvable"
        // completely differently, so this must not decode to nil.
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object([
                    "type": .string("space"),
                    "name": .string("Empty"),
                    "collections": .array([]),
                ])]),
            ])
        )
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case let .resolved(.space(space), _, _) = resolution else {
            return XCTFail("expected a space, got \(resolution)")
        }
        XCTAssertEqual(space.collections, [])
    }

    func testDocumentWithAnUnrelatedMainIsResolvedAsOtherAndCachedPositively() async throws {
        // Proved and schema-valid but granting nothing. A SUCCESS, not a
        // failure: the document WAS established as the authority's, so
        // refetching it would prove the same thing. "Not a permission set" is
        // the consumer's rejection, not the resolver's.
        let harness = try await Harness(
            .valid,
            record: PublicRecord([
                "$type": .string("com.atproto.lexicon.schema"),
                "lexicon": .integer(1),
                "id": .string(PublicRepositoryProofFixtureBuilder.defaultNSID),
                "defs": .object(["main": .object(["type": .string("query")])]),
            ])
        )
        let resolution = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case .resolved(.other, _, _) = resolution else {
            return XCTFail("expected .other, got \(resolution)")
        }
        let row = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        XCTAssertNotNil(row?.document)
        XCTAssertNotNil(row?.lastSucceededAt)
    }

    // MARK: - Cache

    func testNegativeCachingPerformsNoNetworkIOAndNoMSTWalkOnTheSecondAttempt() async throws {
        let harness = try await Harness(.crossRepositorySubstitution)
        await harness.assertUnresolvable(.commitDIDMismatch)

        let dnsAfterFirst = await harness.dns.queryCount
        let fetchesAfterFirst = await harness.transport.requestedURLs.count
        XCTAssertEqual(dnsAfterFirst, 1)
        XCTAssertEqual(fetchesAfterFirst, 1)

        // Within the 5-minute refresh threshold.
        await harness.advance(by: 60)
        let second = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(second, .unresolvable)
        let dnsAfterSecond = await harness.dns.queryCount
        let fetchesAfterSecond = await harness.transport.requestedURLs.count
        XCTAssertEqual(dnsAfterSecond, dnsAfterFirst)
        XCTAssertEqual(fetchesAfterSecond, fetchesAfterFirst)
        // And no proof work: a negative row records nothing to walk.
        let row = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        XCTAssertNil(row?.document)
        XCTAssertNil(row?.verifiedCID)
        XCTAssertNil(row?.lastSucceededAt)
    }

    func testAStaleNegativeRowIsRetried() async throws {
        let harness = try await Harness(.crossRepositorySubstitution)
        await harness.assertUnresolvable(.commitDIDMismatch)
        await harness.advance(by: 301)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let queries = await harness.dns.queryCount
        XCTAssertEqual(queries, 2)
    }

    func testAFreshPositiveRowIsServedWithoutAnyIO() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        await harness.advance(by: 60)
        let again = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case .resolved = again else { return XCTFail("expected cached resolution") }
        let queries = await harness.dns.queryCount
        let fetches = await harness.transport.requestedURLs.count
        XCTAssertEqual(queries, 1)
        XCTAssertEqual(fetches, 1)
    }

    func testServeStaleOnFailureKeepsTheDocumentAndPreservesLastSucceededAt() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let firstRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let succeededAt = try XCTUnwrap(firstRow?.lastSucceededAt)

        await harness.setTransportFails(true)
        await harness.advance(by: 301)
        let stale = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case let .resolved(_, _, verifiedCID) = stale else {
            return XCTFail("expected the cached document to be served, got \(stale)")
        }
        XCTAssertEqual(verifiedCID, harness.fixture.recordCID.string)

        let staleRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let row = try XCTUnwrap(staleRow)
        XCTAssertEqual(row.lastSucceededAt, succeededAt, "last_succeeded_at is preserved")
        XCTAssertGreaterThan(row.updatedAt, succeededAt, "updated_at always advances")
    }

    func testHardExpiryAt24HoursStopsServingStale() async throws {
        // Swan's deliberate divergence: upstream serves stale FOREVER, so a
        // permission set narrowed at the authority would keep minting the wider
        // grant indefinitely whenever the resolver is unreachable.
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        await harness.setTransportFails(true)
        await harness.advance(by: 24 * 60 * 60 + 1)
        let expired = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(expired, .unresolvable)
    }

    func testACachedRowWhoseBytesDoNotHashToItsVerifiedCIDIsNotServed() async throws {
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        let storedRow = try await harness.store.findLexicon(nsid: harness.fixture.nsid)
        let row = try XCTUnwrap(storedRow)
        // A row whose document no longer hashes to the CID that was proved has
        // nothing vouching for it, so it is unservable rather than trusted.
        try await harness.store.storeLexicon(
            OAuthLexiconDocumentRow(
                nsid: row.nsid,
                document: Data(repeating: 0xA1, count: 8),
                sourceURI: row.sourceURI,
                verifiedCID: row.verifiedCID,
                createdAt: row.createdAt,
                updatedAt: row.updatedAt,
                lastSucceededAt: row.lastSucceededAt
            )
        )
        await harness.advance(by: 60)
        let unservable = try await harness.resolver.resolve(harness.fixture.nsid)
        XCTAssertEqual(unservable, .unresolvable)
    }

    func testStepsOneToSixAreCachedByDomainAcrossDistinctNSIDs() async throws {
        // Four includes under one authority share ONE DNS + DID resolution.
        let harness = try await Harness(.valid)
        _ = try await harness.resolver.resolve(harness.fixture.nsid)
        // A sibling NSID under the same authority. Its own fetch still happens
        // and its own proof still runs; only steps 1-6 are shared.
        _ = try? await harness.resolver.resolve("com.example.foo.other")
        let queries = await harness.dns.queryCount
        let authorityResolutions = await harness.authorities.resolveCount
        XCTAssertEqual(queries, 1)
        XCTAssertEqual(authorityResolutions, 1)
    }

    // MARK: - Budget

    func testDistinctIncludeNSIDsAreCappedAtFour() async throws {
        let harness = try await Harness(.valid)
        let five = (0 ..< 5).map { "com.example.foo.set\($0)" }
        do {
            _ = try await harness.resolver.resolveAll(five, population: .includes)
            XCTFail("expected the include cap to reject five distinct NSIDs")
        } catch let error as SwanLexiconResolutionBudgetError {
            XCTAssertEqual(error, .tooManyDistinctNSIDs(.includes, requested: 5))
        }
    }

    func testDuplicatesCollapseBeforeTheCapIsApplied() async throws {
        let harness = try await Harness(.valid)
        let nsids = Array(repeating: harness.fixture.nsid, count: 9)
        let results = try await harness.resolver.resolveAll(nsids, population: .includes)
        let fetches = await harness.transport.requestedURLs.count
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(fetches, 1)
    }

    func testSpaceTypesAreASecondSeparatelyBoundedPopulation() async throws {
        let harness = try await Harness(.valid)
        let nine = (0 ..< 9).map { "com.example.foo.space\($0)" }
        do {
            _ = try await harness.resolver.resolveAll(nine, population: .spaceTypes)
            XCTFail("expected the space-type cap to reject nine distinct NSIDs")
        } catch let error as SwanLexiconResolutionBudgetError {
            XCTAssertEqual(error, .tooManyDistinctNSIDs(.spaceTypes, requested: 9))
        }
        XCTAssertEqual(SwanLexiconResolutionPopulation.includes.maximumDistinctNSIDs, 4)
        XCTAssertEqual(SwanLexiconResolutionPopulation.spaceTypes.maximumDistinctNSIDs, 8)
    }

    // MARK: - Durable store

    func testSQLiteStoreRoundTripsPositiveAndNegativeRows() async throws {
        try await withControlDatabase { control in
        let absent = try await control.findLexicon(nsid: "com.example.foo.auth")
        XCTAssertNil(absent)

        let created = Date(timeIntervalSince1970: 1_760_000_000)
        let bytes = Data([0x01, 0x02, 0x03])
        try await control.storeLexicon(
            OAuthLexiconDocumentRow(
                nsid: "com.example.foo.auth",
                document: bytes,
                sourceURI: "at://did:plc:abc/com.atproto.lexicon.schema/com.example.foo.auth",
                verifiedCID: "bafyreih",
                createdAt: created,
                updatedAt: created,
                lastSucceededAt: created
            )
        )
        let positiveRow = try await control.findLexicon(nsid: "com.example.foo.auth")
        let positive = try XCTUnwrap(positiveRow)
        XCTAssertEqual(positive.document, bytes)
        XCTAssertEqual(positive.lastSucceededAt, created)

        // The negative-cache row: `document IS NULL` with `updated_at` still
        // advancing and `last_succeeded_at` preserved. Declaring the column NOT
        // NULL would make this row unrepresentable.
        let later = created.addingTimeInterval(600)
        try await control.storeLexicon(
            OAuthLexiconDocumentRow(
                nsid: "com.example.bar.auth",
                document: nil,
                sourceURI: nil,
                verifiedCID: nil,
                createdAt: later,
                updatedAt: later,
                lastSucceededAt: nil
            )
        )
        let negativeRow = try await control.findLexicon(nsid: "com.example.bar.auth")
        let negative = try XCTUnwrap(negativeRow)
        XCTAssertNil(negative.document)
        XCTAssertNil(negative.verifiedCID)
        XCTAssertTrue(negative.isHardExpired(now: later))
        XCTAssertFalse(negative.isStale(now: later.addingTimeInterval(60)))
        XCTAssertTrue(negative.isStale(now: later.addingTimeInterval(300)))

        try await control.deleteLexicon(nsid: "com.example.bar.auth")
        let deleted = try await control.findLexicon(nsid: "com.example.bar.auth")
        XCTAssertNil(deleted)
        }
    }

    func testSQLiteStoreRefusesAHalfPopulatedPositiveRow() async throws {
        try await withControlDatabase { control in
        // Bytes with no CID vouching for them is not a state the resolver can
        // produce, and admitting it would let a partial write read back as a
        // document nothing proved.
        do {
            try await control.storeLexicon(
                OAuthLexiconDocumentRow(
                    nsid: "com.example.foo.auth",
                    document: Data([0x01]),
                    sourceURI: nil,
                    verifiedCID: nil,
                    createdAt: Date(timeIntervalSince1970: 1),
                    updatedAt: Date(timeIntervalSince1970: 1),
                    lastSucceededAt: Date(timeIntervalSince1970: 1)
                )
            )
            XCTFail("expected a half-populated positive row to be refused")
        } catch {}
        }
    }

    func testResolverWorksAgainstTheDurableStore() async throws {
        try await withControlDatabase { control in
        let harness = try await Harness(.valid, store: control)

        let first = try await harness.resolver.resolve(harness.fixture.nsid)
        guard case .resolved = first else { return XCTFail("expected a resolution") }
        await harness.advance(by: 60)
        let second = try await harness.resolver.resolve(harness.fixture.nsid)
        let fetches = await harness.transport.requestedURLs.count
        XCTAssertEqual(first, second)
        XCTAssertEqual(fetches, 1)
        }
    }

    // MARK: - Helpers

    /// SQLiteNIO asserts in `deinit` if a connection was never closed, so the
    /// close has to survive a mid-test throw rather than sit in a trailing
    /// statement.
    private func withControlDatabase(
        _ body: (SQLiteControlDatabase) async throws -> Void
    ) async throws {
        let root = try Self.temporaryDirectory()
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await body(control)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
        try await control.close()
        try? FileManager.default.removeItem(at: root)
    }

    private static func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-lexicon-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return url
    }
}

// MARK: - Harness

private struct Harness {
    let fixture: PublicRepositoryProofFixture
    let dns: StubDNSResolver
    let authorities: StubAuthorityResolver
    let hostnames: StubHostnameResolver
    let transport: StubCARTransport
    let store: any OAuthLexiconDocumentStore
    let resolver: SwanLexiconResolver
    let clock: TestClock

    init(
        _ variant: PublicRepositoryProofFixtureVariant,
        txtRecords: [String]? = nil,
        authorityError: SwanLexiconAuthorityResolutionError? = nil,
        transportFails: Bool = false,
        record: PublicRecord? = nil,
        store: (any OAuthLexiconDocumentStore)? = nil
    ) async throws {
        fixture = try await PublicRepositoryProofFixtureBuilder.build(
            variant, record: record
        )
        let pds = URL(string: "https://pds.example.net")!
        let key = try P256.Signing.PublicKey(
            x963Representation: fixture.documentPublicKeyX963
        )
        dns = StubDNSResolver(
            records: txtRecords ?? ["did=\(fixture.requestedDID)"]
        )
        authorities = StubAuthorityResolver(
            authority: SwanLexiconAuthority(
                pdsEndpoint: pds,
                commitVerifier: PermissionedDataPublicRepositoryCommitVerifier(
                    key: .p256(key)
                )
            ),
            error: authorityError
        )
        hostnames = StubHostnameResolver()
        transport = StubCARTransport(body: fixture.carBytes, fails: transportFails)
        self.store = store ?? InMemoryLexiconStore()
        clock = TestClock(now: Date(timeIntervalSince1970: 1_760_000_000))
        let capturedClock = clock
        let capturedDiagnostics = DiagnosticsSink()
        diagnostics = capturedDiagnostics
        resolver = try SwanLexiconResolver(
            dns: dns,
            authorities: authorities,
            fetcher: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: hostnames,
                transport: transport
            ),
            store: self.store,
            now: { capturedClock.currentDate },
            diagnostics: { _, failure in capturedDiagnostics.record(failure) }
        )
    }

    let diagnostics: DiagnosticsSink

    func advance(by seconds: TimeInterval) async {
        clock.advance(by: seconds)
    }

    func setTransportFails(_ value: Bool) async {
        await transport.setFails(value)
    }

    /// Asserts the resolution refused AND that it refused for the stated reason.
    /// The reason matters: several vectors are only meaningful if the *right*
    /// check rejected them.
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

private final class TestClock: @unchecked Sendable {
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

private final class DiagnosticsSink: @unchecked Sendable {
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

private actor StubDNSResolver: ATHandleDNSResolving {
    private let records: [String]
    private(set) var queriedNames: [String] = []

    init(records: [String]) { self.records = records }

    var queryCount: Int { queriedNames.count }

    func txtRecords(name: String) async throws -> [ATHandleTXTRecord] {
        queriedNames.append(name)
        return try records.map { try ATHandleTXTRecord(bytes: Data($0.utf8)) }
    }

    func addresses(host _: String) async throws -> [ATHandleIPAddress] { [] }
}

private actor StubAuthorityResolver: SwanLexiconAuthorityResolving {
    private let authority: SwanLexiconAuthority
    private let error: SwanLexiconAuthorityResolutionError?
    private(set) var resolveCount = 0

    init(
        authority: SwanLexiconAuthority,
        error: SwanLexiconAuthorityResolutionError?
    ) {
        self.authority = authority
        self.error = error
    }

    func resolveAuthority(did _: String) async throws -> SwanLexiconAuthority {
        resolveCount += 1
        if let error { throw error }
        return authority
    }
}

private struct StubHostnameResolver: OAuthHostnameResolving {
    static let peer = OAuthIPAddress.ipv4(93 << 24 | 184 << 16 | 216 << 8 | 34)

    func resolve(host _: String) async throws -> [OAuthIPAddress] { [Self.peer] }
}

private actor StubCARTransport: OAuthRemoteTransport {
    private let body: Data
    private var fails: Bool
    private(set) var requestedURLs: [URL] = []

    init(body: Data, fails: Bool) {
        self.body = body
        self.fails = fails
    }

    func setFails(_ value: Bool) { fails = value }

    func get(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requestedURLs.append(url)
        if fails { throw SwanError.unavailable("stub transport failure") }
        return OAuthRemoteHTTPResponse(
            status: 200,
            headers: ["content-type": ["application/vnd.ipld.car"]],
            body: body,
            responseURL: url,
            redirectCount: 0,
            connectedPeerAddress: StubHostnameResolver.peer
        )
    }
}

private actor InMemoryLexiconStore: OAuthLexiconDocumentStore {
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
}
