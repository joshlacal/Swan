import Crypto
import Foundation
import NIOCore
import SQLiteNIO
import SwanAccounts
import SwanCore
@testable import SwanHTTP
@testable import SwanSQLite
import SwanStorage
import XCTest

/// Focused identity HTTP adapter tests against the real SQLite control
/// database. The step-up receipt rows are inserted directly because the MFA
/// lane owns receipt issuance; this lane only consumes them.
final class SwanDidWebIdentityHTTPTests: XCTestCase {
    private let pds = "https://pds.example.test"
    private let issuer = "https://swan.example.test"
    private let accountDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let did = "did:web:example.com"
    private let handle = "alice.example"

    // MARK: - Happy path

    func testReserveClaimReverifyAndAdmissionThroughAdapter() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "claim-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(reserve.targetDID, did)
        XCTAssertEqual(reserve.keyID, "#atproto")
        XCTAssertEqual(reserve.keyType, "Multikey")
        XCTAssertEqual(reserve.nonce.count, 43)
        XCTAssertTrue(reserve.claimServiceEndpoint.hasSuffix("/.well-known/swan/did-web-claim/\(reserve.nonce)"))

        let reservation = try await fixture.reservations.issuedReservation(requestID: "claim-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)

        let binding = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "claim-1"),
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(binding.state, "active")
        XCTAssertEqual(binding.identityDID, did)
        XCTAssertEqual(binding.method, "didWeb")

        let reverified = try await fixture.adapter.reverify(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(reverified.state, "active")

        let admission = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertTrue(admission.allowsRead)
        XCTAssertTrue(admission.allowsWrite)
        XCTAssertTrue(admission.allowsTokenIssuance)
    }

    // MARK: - Claim endpoint and exact consumption

    func testClaimEndpointServesCanonicalBytesThen404sAfterConsumption() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "claim-endpoint-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "claim-endpoint-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)

        let endpoint = fixture.adapter.claimEndpoint
        let before = try await endpoint.response(nonce: reserve.nonce, now: now)
        XCTAssertEqual(before.status, 200)
        XCTAssertEqual(before.contentType, "application/octet-stream")
        XCTAssertEqual(before.body, reservation.claimBytes)

        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "claim-endpoint-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        // The nonce is consumed atomically with the claim transaction: the
        // endpoint must 404 for the same nonce after commit.
        let after = try await endpoint.response(nonce: reserve.nonce, now: now)
        XCTAssertEqual(after.status, 404)
        let unknown = try await endpoint.response(nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now: now)
        XCTAssertEqual(unknown.status, 404)
    }

    func testClaimReplayWithSameRequestIDIsIdempotentAndForgedNonceIsRejected() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "replay-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "replay-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)

        let first = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "replay-1"),
            sessionValue: fixture.sessionValue, now: now
        )
        let retry = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "replay-1"),
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(first, retry)

        // A different request ID cannot mint a second binding from the same
        // nonce: the adapter's reservation lookup finds no issued reservation
        // for the forged request ID and refuses before any write.
        let forged = try SwanDidWebClaimReservation(
            requestID: "replay-2", accountDID: accountDID, targetDID: did,
            handle: handle, key: reservation.key, nonce: reservation.nonce,
            expiresAt: reservation.expiresAt, claimBytes: reservation.claimBytes,
            claimReceiptDigest: reservation.claimReceiptDigest,
            claimServiceEndpoint: reservation.claimServiceEndpoint
        )
        await XCTAssertThrowsIdentityError(.unprocessable("unknown claim reservation")) {
            _ = try await fixture.adapter.claim(
                SwanDidWebClaimRequest(requestID: "replay-2"),
                sessionValue: fixture.sessionValue, now: now
            )
        }
        _ = reserve
    }

    // MARK: - Replacement and removal require fresh step-up

    func testReplacementRequiresFreshStepUpAndConsumesReceiptExactlyOnce() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        // Initial claim (no existing binding, no step-up required).
        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "replace-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "replace-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "replace-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        // Reserve the replacement tuple first (idempotent on requestID) and
        // publish its temporary claim service document, so both the
        // missing-receipt refusal and the successful rotate reach the
        // step-up check rather than failing on document fetch.
        let newDID = "did:web:new.example"
        _ = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "replace-2", targetDID: newDID, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let newReservation = try await fixture.reservations.issuedReservation(requestID: "replace-2")
        guard let newReservation else { XCTFail("missing replacement reservation"); return }
        let newJSON = try DidWebDocumentFixture.json(
            did: newDID, handle: handle, pds: pds, key: newReservation.key,
            claimEndpoint: newReservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(newJSON, forDID: newDID)

        // Replacement without a fresh step-up receipt is refused.
        let rotate = SwanDidWebRotateRequest(
            requestID: "replace-2", targetDID: newDID, handle: handle,
            expiresAt: now.addingTimeInterval(300), stepUpReceipt: "missing"
        )
        await XCTAssertThrowsIdentityError(.stepUpRequired) {
            _ = try await fixture.adapter.rotate(rotate, sessionValue: fixture.sessionValue, now: now)
        }

        // With a valid receipt the replacement succeeds and consumes it.
        let receiptValue = "step-up-receipt-replace-1"
        try await fixture.insertReceipt(
            sessionID: fixture.sessionID, accountDID: accountDID,
            receiptValue: receiptValue, operation: "replace", now: now
        )
        let rotated = try await fixture.adapter.rotate(
            SwanDidWebRotateRequest(
                requestID: "replace-2", targetDID: newDID, handle: handle,
                expiresAt: now.addingTimeInterval(300), stepUpReceipt: receiptValue
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(rotated.identityDID, newDID)
        XCTAssertEqual(rotated.state, "active")

        // The receipt is consumed exactly once: the durable verifier now
        // rejects it, so a replay cannot reach the atomic store.
        let consumed = try await fixture.database.verifyIdentityStepUpReceipt(
            sessionID: fixture.sessionID, accountDID: accountDID,
            mfaStrength: "phishingResistant",
            receiptDigest: Data(SHA256.hash(data: Data(receiptValue.utf8))),
            now: now
        )
        XCTAssertFalse(consumed)
        // Publish a document for the replay target so the flow reaches the
        // authorizer pre-check, which must refuse the consumed receipt.
        let thirdDID = "did:web:third.example"
        _ = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "replace-3", targetDID: thirdDID, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let thirdReservation = try await fixture.reservations.issuedReservation(requestID: "replace-3")
        guard let thirdReservation else { XCTFail("missing replay reservation"); return }
        let thirdJSON = try DidWebDocumentFixture.json(
            did: thirdDID, handle: handle, pds: pds, key: thirdReservation.key,
            claimEndpoint: thirdReservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(thirdJSON, forDID: thirdDID)
        await XCTAssertThrowsIdentityError(.stepUpRequired) {
            _ = try await fixture.adapter.rotate(
                SwanDidWebRotateRequest(
                    requestID: "replace-3", targetDID: thirdDID,
                    handle: self.handle, expiresAt: now.addingTimeInterval(300),
                    stepUpReceipt: receiptValue
                ),
                sessionValue: fixture.sessionValue, now: now
            )
        }
    }

    func testRemoveRequiresFreshStepUpAndReleasesBinding() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "remove-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "remove-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "remove-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        await XCTAssertThrowsIdentityError(.stepUpRequired) {
            _ = try await fixture.adapter.remove(
                SwanDidWebRemoveRequest(stepUpReceipt: "missing"),
                sessionValue: fixture.sessionValue, now: now
            )
        }

        let receiptValue = "step-up-receipt-remove-1"
        try await fixture.insertReceipt(
            sessionID: fixture.sessionID, accountDID: accountDID,
            receiptValue: receiptValue, operation: "remove", now: now
        )
        let removed = try await fixture.adapter.remove(
            SwanDidWebRemoveRequest(stepUpReceipt: receiptValue),
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(removed.state, "released")
    }

    // MARK: - Suspension and grace

    func testSuspensionFencesWritesAndTokensButPreservesReads() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "suspend-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "suspend-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "suspend-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        // A document mismatch (subject change) suspends the binding.
        let mismatched = try DidWebDocumentFixture.json(
            did: "did:web:attacker.example", handle: handle, pds: pds,
            key: reservation.key, claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(mismatched, forDID: did)
        let suspended = try await fixture.adapter.reverify(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(suspended.state, "suspended")

        let admission = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertTrue(admission.allowsRead)
        XCTAssertFalse(admission.allowsWrite)
        XCTAssertFalse(admission.allowsTokenIssuance)
    }

    /// A did:web binding suspended by a document mismatch must return to
    /// active once the operator corrects the published document and reverify
    /// runs again — recovery is a revalidation outcome, not a new claim.
    func testMismatchSuspensionRecoversToActiveAfterDocumentCorrection() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "recover-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "recover-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "recover-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        // A document mismatch (subject change) suspends the binding.
        let mismatched = try DidWebDocumentFixture.json(
            did: "did:web:attacker.example", handle: handle, pds: pds,
            key: reservation.key, claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(mismatched, forDID: did)
        let suspended = try await fixture.adapter.reverify(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(suspended.state, "suspended")
        let fenced = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertTrue(fenced.allowsRead)
        XCTAssertFalse(fenced.allowsWrite)

        // The operator corrects the published document back to the exact
        // claimed subject/key/endpoint; reverify restores active.
        await fixture.fetcher.set(json, forDID: did)
        let recovered = try await fixture.adapter.reverify(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertEqual(recovered.state, "active")
        let admitted = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertTrue(admitted.allowsWrite)
        XCTAssertTrue(admitted.allowsTokenIssuance)
    }

    func testDefaultGraceIs24Hours() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        // The session must outlive the 24-hour grace window so admission
        // checks at +24h still authenticate.
        let fixture = try await makeFixture(
            now: now, idleLifetime: 48 * 60 * 60, absoluteLifetime: 48 * 60 * 60
        )
        defer { fixture.cleanup() }

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "grace-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "grace-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "grace-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        let withinGrace = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now.addingTimeInterval(86_399)
        )
        XCTAssertTrue(withinGrace.allowsWrite)
        XCTAssertTrue(withinGrace.allowsTokenIssuance)

        let expired = try await fixture.adapter.admission(
            sessionValue: fixture.sessionValue, now: now.addingTimeInterval(86_401)
        )
        XCTAssertTrue(expired.allowsRead)
        XCTAssertFalse(expired.allowsWrite)
        XCTAssertFalse(expired.allowsTokenIssuance)
    }

    // MARK: - Restart

    func testRestartPreservesBindingReservationAndConsumedNonce() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)

        let reserve = try await fixture.adapter.reserve(
            SwanDidWebReserveRequest(
                requestID: "restart-1", targetDID: did, handle: handle,
                expiresAt: now.addingTimeInterval(300)
            ),
            sessionValue: fixture.sessionValue, now: now
        )
        let reservation = try await fixture.reservations.issuedReservation(requestID: "restart-1")
        guard let reservation else { XCTFail("missing reservation"); return }
        let json = try DidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        await fixture.fetcher.set(json, forDID: did)
        _ = try await fixture.adapter.claim(
            SwanDidWebClaimRequest(requestID: "restart-1"),
            sessionValue: fixture.sessionValue, now: now
        )

        let root = fixture.root
        try await fixture.database.close()

        // Reopen the same data directory: binding, committed reservation, and
        // consumed nonce all survive the restart.
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task { try? await reopened.close() }
            try? FileManager.default.removeItem(at: root)
        }
        let reopenedReservations = SwanDurableSigningKeyReservationAdapter(
            store: reopened, provider: FixtureSigningKeyProvider()
        )
        let reopenedSessions = SwanManagementSessionRuntime(
            store: reopened, preAuthStore: reopened, csrfStore: reopened,
            preAuthSessionCoordinator: reopened
        )
        let reopenedService = SwanDidWebIdentityService(
            reservations: reopenedReservations, bindings: reopened,
            publicPDSURL: pds, publicURL: issuer,
            replacementAuthorizer: SwanDurableDidWebReplacementAuthorizer(verifier: reopened),
            stepUps: SwanDurableStepUpReceiptConsumer(store: reopened)
        )
        let reopenedAdapter = SwanDidWebIdentityHTTP(
            service: reopenedService, sessions: reopenedSessions,
            documents: fixture.fetcher, reservations: reopenedReservations,
            bindings: reopened
        )

        let binding = try await reopened.identityBinding(accountDID: accountDID)
        XCTAssertEqual(binding?.state, .active)
        XCTAssertEqual(binding?.identityDID, did)

        let committed = try await reopenedReservations.committedReservation(accountDID: accountDID)
        XCTAssertNotNil(committed)

        // The consumed nonce is not served after restart.
        let after = try await reopenedAdapter.claimEndpoint.response(nonce: reserve.nonce, now: now)
        XCTAssertEqual(after.status, 404)

        let admission = try await reopenedAdapter.admission(
            sessionValue: fixture.sessionValue, now: now
        )
        XCTAssertTrue(admission.allowsRead)
        XCTAssertTrue(admission.allowsWrite)
    }

    // MARK: - Durable authorizer

    /// Spec §3.3: storage/resolver/key-store outages are 503
    /// `service_unavailable`, never a field-safe 422. The adapter must not
    /// downgrade an infrastructure outage into a client-visible validation
    /// failure.
    func testUnavailableMapsToServiceUnavailable() {
        let mapped = SwanDidWebIdentityHTTP.map(SwanError.unavailable("key-store outage"))
        XCTAssertEqual(mapped, .serviceUnavailable)
        XCTAssertEqual(mapped.statusCode, 503)
        XCTAssertEqual(mapped.code, "service_unavailable")

        // Document/reservation mismatches stay field-safe 422s.
        let mismatch = SwanDidWebIdentityHTTP.map(
            SwanError.unauthorized("did:web document subject mismatch")
        )
        XCTAssertEqual(mismatch, .unprocessable("did:web document subject mismatch"))
        XCTAssertEqual(mismatch.statusCode, 422)

        // Replayed receipts are conflicts, not validation failures.
        let replayed = SwanDidWebIdentityHTTP.map(
            SwanError.unauthorized("invalid or replayed identity step-up receipt")
        )
        XCTAssertEqual(replayed, .conflict)
        XCTAssertEqual(replayed.statusCode, 409)
    }

    func testDurableAuthorizerVerifiesWithoutConsuming() async throws {
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let fixture = try await makeFixture(now: now)
        defer { fixture.cleanup() }

        let receiptValue = "step-up-receipt-authorizer-1"
        try await fixture.insertReceipt(
            sessionID: fixture.sessionID, accountDID: accountDID,
            receiptValue: receiptValue, operation: "replace", now: now
        )
        let digest = Data(SHA256.hash(data: Data(receiptValue.utf8)))
        let authorization = try SwanDidWebReplacementAuthorization(
            accountDID: accountDID, sessionAccountDID: accountDID,
            sessionID: fixture.sessionID, stepUpAt: now,
            stepUpReceiptDigest: digest, mfaStrength: .phishingResistant
        )
        let authorizer = SwanDurableDidWebReplacementAuthorizer(verifier: fixture.database)

        // The pre-check verifies without consuming.
        let allowed = try await authorizer.authorize(authorization, now: now)
        XCTAssertTrue(allowed)
        let stillPresent = try await fixture.database.verifyIdentityStepUpReceipt(
            sessionID: fixture.sessionID, accountDID: accountDID,
            mfaStrength: "phishingResistant", receiptDigest: digest, now: now
        )
        XCTAssertTrue(stillPresent)

        // The atomic store is the authoritative consumer.
        try await SwanDurableStepUpReceiptConsumer(store: fixture.database).consume(
            sessionID: fixture.sessionID, accountDID: accountDID,
            operation: .replace, receiptDigest: digest,
            verifiedAt: now, expiresAt: now.addingTimeInterval(300), now: now
        )
        let replayed = try await authorizer.authorize(authorization, now: now)
        XCTAssertFalse(replayed)

        // A stale step-up is refused.
        let stale = try SwanDidWebReplacementAuthorization(
            accountDID: accountDID, sessionAccountDID: accountDID,
            sessionID: fixture.sessionID, stepUpAt: now.addingTimeInterval(-301),
            stepUpReceiptDigest: digest, mfaStrength: .phishingResistant
        )
        let staleAllowed = try await authorizer.authorize(stale, now: now)
        XCTAssertFalse(staleAllowed)
    }

    // MARK: - Fixture

    private func makeFixture(now: Date, idleLifetime: TimeInterval = 12 * 60 * 60,
                             absoluteLifetime: TimeInterval = 30 * 24 * 60 * 60) async throws -> IdentityFixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-identity-http-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.migrateAccountPortalSessionSchema()
        _ = try await database.createAccount(try registration(now: now))

        let sessions = SwanManagementSessionRuntime(
            store: database, preAuthStore: database, csrfStore: database,
            preAuthSessionCoordinator: database,
            idleLifetime: idleLifetime, absoluteLifetime: absoluteLifetime
        )
        let issued = try await sessions.issue(accountDID: accountDID, strength: .password, now: now)
        // Promote the session to fresh step-up state, as the MFA lane's
        // step-up endpoint would after a successful re-authentication.
        _ = try await database.connection.query(
            """
            UPDATE management_sessions
            SET last_step_up_at = ?, strength = 'stepUpPassword'
            WHERE session_digest = ?
            """,
            [.integer(Int(now.timeIntervalSince1970 * 1_000_000)),
             .blob(ByteBuffer(data: Data(SHA256.hash(data: Data(issued.sessionValue.utf8)))))]
        )

        let fetcher = FixtureDocumentFetcher()
        let reservations = SwanDurableSigningKeyReservationAdapter(
            store: database, provider: FixtureSigningKeyProvider()
        )
        let service = SwanDidWebIdentityService(
            reservations: reservations, bindings: database,
            publicPDSURL: pds, publicURL: issuer,
            replacementAuthorizer: SwanDurableDidWebReplacementAuthorizer(verifier: database),
            stepUps: SwanDurableStepUpReceiptConsumer(store: database)
        )
        let adapter = SwanDidWebIdentityHTTP(
            service: service, sessions: sessions, documents: fetcher,
            reservations: reservations, bindings: database
        )
        return IdentityFixture(
            root: root, database: database, sessions: sessions,
            reservations: reservations, service: service, adapter: adapter,
            fetcher: fetcher, sessionValue: issued.sessionValue,
            sessionID: issued.metadata.sessionID.rawValue
        )
    }

    private func registration(now: Date) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: accountDID,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(purpose: .signing, generation: 1),
            rotationKey: .init(purpose: .rotation, generation: 1),
            createdAt: now
        )
    }
}

private struct IdentityFixture {
    let root: URL
    let database: SQLiteControlDatabase
    let sessions: SwanManagementSessionRuntime
    let reservations: SwanDurableSigningKeyReservationAdapter
    let service: SwanDidWebIdentityService
    let adapter: SwanDidWebIdentityHTTP
    let fetcher: FixtureDocumentFetcher
    let sessionValue: String
    let sessionID: String

    func cleanup() {
        Task { try? await database.close() }
        try? FileManager.default.removeItem(at: root)
    }

    func insertReceipt(sessionID: String, accountDID: String, receiptValue: String,
                       operation: String, now: Date) async throws {
        let digest = Data(SHA256.hash(data: Data(receiptValue.utf8)))
        _ = try await database.connection.query(
            """
            INSERT INTO did_web_step_up_receipts
            (receipt_digest, session_id, account_did, operation, mfa_strength, verified_at, expires_at, consumed_at)
            VALUES (?, ?, ?, ?, 'phishingResistant', ?, ?, NULL)
            """,
            [.blob(ByteBuffer(data: digest)), .text(sessionID), .text(accountDID),
             .text(operation), .integer(Int(now.timeIntervalSince1970 * 1_000_000)),
             .integer(Int((now.timeIntervalSince1970 + 300) * 1_000_000))]
        )
    }
}

private actor FixtureDocumentFetcher: SwanDidWebDocumentFetching {
    private var documents: [String: Data] = [:]

    func set(_ data: Data, forDID did: String) {
        documents[did] = data
    }

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanError.unavailable("fixture document missing")
        }
        return data
    }
}

private struct FixtureSigningKeyProvider: SwanSigningKeyProviding {
    func configuredSigningKey() async throws -> SwanReservedSigningKey {
        try SwanReservedSigningKey(
            keyID: "#atproto", keyType: "Multikey", publicKey: Data(repeating: 0x11, count: 32)
        )
    }
}

private enum DidWebDocumentFixture {
    static func json(did: String, handle: String, pds: String,
                     key: SwanReservedSigningKey, claimEndpoint: String) throws -> Data {
        let object: [String: Any] = [
            "id": did,
            "alsoKnownAs": ["at://\(handle)"],
            "verificationMethod": [[
                "id": "\(did)\(key.keyID)", "type": key.keyType,
                "controller": did,
                "publicKeyMultibase": try SwanATMultikey.encode(publicKey: key.publicKey),
            ]],
            "assertionMethod": ["\(did)\(key.keyID)"],
            "service": [
                ["id": "\(did)#pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": pds],
                ["id": "\(did)#swan-claim", "type": "SwanDidWebClaim", "serviceEndpoint": claimEndpoint],
            ],
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }
}

private extension XCTestCase {
    func XCTAssertThrowsAsyncError(_ expression: @escaping () async throws -> Void) async {
        do {
            try await expression()
            XCTFail("expected error")
        } catch {}
    }

    /// Asserts the expression throws exactly the given typed identity error.
    func XCTAssertThrowsIdentityError(
        _ expected: SwanDidWebIdentityHTTPError,
        _ expression: @escaping () async throws -> Void
    ) async {
        do {
            try await expression()
            XCTFail("expected \(expected)")
        } catch let error as SwanDidWebIdentityHTTPError {
            XCTAssertEqual(error, expected)
        } catch {
            XCTFail("expected \(expected), got \(error)")
        }
    }
}
