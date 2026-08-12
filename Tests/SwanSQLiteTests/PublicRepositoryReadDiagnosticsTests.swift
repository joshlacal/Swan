import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicRepository
@testable import SwanSQLite
import SwanStorage
import XCTest

/// Regression cover for the 2026-08-12 outage's diagnosability, not for its
/// cause. Every public repository read for one account returned an identical
/// opaque `503 {"error":"temporarily_unavailable"}` for roughly three hours
/// while `journalctl -u swan.service` recorded nothing at all, because a single
/// `PublicRepositoryReadError.unavailable` erased which of eight admission
/// guards had fired. These tests pin that each guard is now separately
/// nameable, and specifically that a stale generation pin cannot be confused
/// with a genuine identity failure — the distinction the re-admission fix
/// depends on.
final class PublicRepositoryReadDiagnosticsTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.example.com"

    func testAdmissionFailureNamesTheGuardThatFired() async throws {
        // An account whose journal stage is not .submitted must fail with a
        // reason identifying THAT guard, not a bare .unavailable.
        let outcome = try await captureAdmissionFailure(stage: .submissionPending)
        XCTAssertEqual(outcome, .identityStageNotSubmitted)
    }

    func testDataVersionDriftIsDistinguishableFromIdentityFailure() async throws {
        // The two must not collapse to the same reason — telling them apart
        // is the entire point of this task.
        let drift = try await captureAdmissionFailure(afterForeignCommit: true)
        XCTAssertEqual(drift, .generationPinStale)

        let identity = try await captureAdmissionFailure(stage: .submissionPending)
        XCTAssertNotEqual(
            identity,
            drift,
            "a stale data_version pin and a failed identity guard must not "
                + "report the same reason"
        )
    }

    /// The journal token is what an operator greps for during an incident, and
    /// what any saved query or alert rule is written against. Renaming a case
    /// silently retires every one of those. This is a golden list: adding a
    /// reason means adding a line here on purpose, and renaming one fails.
    func testJournalTokensMatchTheGoldenList() {
        let expected: Set<String> = [
            "identityRowCount",
            "identityStageNotSubmitted",
            "genesisCIDMismatch",
            "missingKeyMaterial",
            "keyReferenceMismatch",
            "historyVerifierUnavailable",
            "terminalIdentityMismatch",
            "repositoryAuthenticatorUnavailable",
            "commitAuthenticationFailed",
            "identityFactsMalformed",
            "recordIndexMalformed",
            "projectionMismatch",
            "intentVerificationFailed",
            "generationPinStale",
            "fileIdentityMismatch",
            "repositoryStateMismatch",
            "repositoryStateMissing",
            "generationIdentityMismatch",
            "directoryClosed",
            "accountNotPreopened",
            "accountNotActive",
            "controlRowChanged",
            "controlStoreFailure",
            "publicIdentityVerifierUnconfigured",
            "blockMaterializationFailed",
            "admissionBudgetExhausted",
            "projectionBoundExceeded",
            "malformedProjectionValue",
            "spoolStreamFailure",
            "storageFailure",
            "postMutationRefreshFailed",
        ]
        let actual = Set(PublicReadUnavailableReason.allCases.map(\.rawValue))
        XCTAssertEqual(
            actual.subtracting(expected),
            [],
            "new reason(s) added without recording their journal token"
        )
        XCTAssertEqual(
            expected.subtracting(actual),
            [],
            "journal token(s) renamed or removed — this breaks operator greps"
        )
    }

    /// The journal must not go quiet just because a refusal arrived without a
    /// reason attached.
    ///
    /// `resourceLimitExceeded` is raised inside admission by the projection
    /// preflight, and it is the one refusal that repeats forever — it names an
    /// account whose own data is over a static bound. Classified as `nil` it
    /// wrote no journal line at all, which is exactly the silent-503 state the
    /// rest of this file exists to prevent. The request-shape errors stay `nil`
    /// on purpose: they are decided from the request, no admission raises one,
    /// and naming one would let it be recorded against the account.
    func testReasonlessReadErrorsAreClassifiedForTheJournal() {
        XCTAssertEqual(
            PublicRepositoryReadError.resourceLimitExceeded
                .admissionFailureReason,
            .projectionBoundExceeded
        )
        XCTAssertNotEqual(
            PublicRepositoryReadError.resourceLimitExceeded
                .admissionFailureReason,
            .admissionBudgetExhausted,
            "a per-account static bound and a shared load-dependent lease "
                + "must not share a journal token"
        )
        for shapeError in [
            PublicRepositoryReadError.invalidSelector,
            .invalidLimit,
            .invalidCursor,
        ] {
            XCTAssertNil(
                shapeError.admissionFailureReason,
                "\(shapeError) is decided from the request, not the account"
            )
        }
        // Availability failures keep answering with the guard that fired.
        for reason in PublicReadUnavailableReason.allCases {
            XCTAssertEqual(
                PublicRepositoryReadError.unavailable(reason: reason)
                    .admissionFailureReason,
                reason
            )
        }
    }

    // MARK: Fixture

    /// Admits a generation and returns the reason the read path refused.
    ///
    /// With `stage` below `.submitted` the failure happens during admission.
    /// With `afterForeignCommit`, admission succeeds and a **second connection**
    /// to the same account database then commits something that touches no
    /// repository state at all — exactly what `PRAGMA data_version` observes,
    /// and exactly the shape of the live trigger.
    private func captureAdmissionFailure(
        stage: PLCAccountPreparationStage = .submitted,
        afterForeignCommit: Bool = false
    ) async throws -> PublicReadUnavailableReason? {
        let fixture = try await makeFixture(stage: stage)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let verifier = DiagnosticsPLCVerifier(
            operationCID: fixture.genesisOperationCID
        )

        var captured: PublicReadUnavailableReason?
        do {
            let generation = try await fixture.database
                .admitPublicRepositoryGeneration(
                    account: fixture.account,
                    identityVerifier: verifier
                )
            guard afterForeignCommit else {
                XCTFail("expected admission to fail for stage \(stage)")
                try await fixture.tearDown()
                return nil
            }
            let foreign = try await SQLiteAccountDatabase(
                dataDirectory: fixture.root, did: did
            )
            _ = try await foreign.connection.query(
                "CREATE TABLE IF NOT EXISTS swan_diagnostics_scratch(x INTEGER)"
            )
            _ = try await foreign.connection.query(
                "INSERT INTO swan_diagnostics_scratch(x) VALUES (1)"
            )
            try await foreign.close()

            do {
                _ = try await fixture.database.readPublicRepositoryDescription(
                    generation: generation
                )
                XCTFail("expected the foreign commit to invalidate the pin")
            } catch let error as PublicRepositoryReadError {
                captured = error.unavailableReason
            }
        } catch let error as PublicRepositoryReadError {
            captured = error.unavailableReason
        }

        try await fixture.tearDown()
        return captured
    }

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let database: SQLiteAccountDatabase
        let account: AccountControlAccount
        let genesisOperationCID: String

        func tearDown() async throws {
            try await database.close()
            try await control.close()
        }
    }

    private func makeFixture(
        stage: PLCAccountPreparationStage
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicReadDiagnostics-\(UUID().uuidString)")
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
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let preparationRequestID = "public-read-diagnostics"
        let journal = try PLCAccountPreparationJournal(
            requestID: preparationRequestID,
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            repositoryRevision: "3jzfcijpj2z2a",
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: DiagnosticsPLCVerifier.signingDIDKey,
                rotationDIDKey: DiagnosticsPLCVerifier.rotationDIDKey,
                signature: DiagnosticsPLCVerifier.signature
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
        if stage != .repositoryInstalled {
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: preparationRequestID,
                expectedStage: .repositoryInstalled,
                to: .submissionPending,
                publicGenesisCommitCID: nil
            )
        }
        if stage == .submitted {
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: preparationRequestID,
                expectedStage: .submissionPending,
                to: .submitted,
                publicGenesisCommitCID: nil
            )
        }

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
        let loaded = try await control.account(did: did)
        let account = try XCTUnwrap(loaded)

        return Fixture(
            root: root,
            control: control,
            database: database,
            account: account,
            genesisOperationCID: genesis.commitCID.string
        )
    }
}

private struct DiagnosticsPLCVerifier:
    PublicPLCGenesisVerifying,
    PublicPLCRepositoryAuthenticating
{
    static let signingDIDKey =
        "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"
    static let rotationDIDKey =
        "did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA"
    static let signature =
        "9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg"

    let operationCID: String

    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID _: String
    ) throws -> String {
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
            verificationIdentity: "diagnostics-structural-verifier"
        )
    }
}
