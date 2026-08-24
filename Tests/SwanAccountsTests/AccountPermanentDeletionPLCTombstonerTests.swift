import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
@testable import SwanAccounts
import SwanCore
import XCTest

final class AccountPermanentDeletionPLCTombstonerTests: XCTestCase {
    func testTombstonerSubmitsExactCurrentOperationAndVerifiesTerminalAudit() async throws {
        let fixture = try PLCDeletionFixture()
        let client = RecordingDeletionPLCClient(initialAudit: [fixture.genesisEntry])
        let keys = RecordingDeletionKeyReader(
            values: [fixture.rotationReference: fixture.rotationKey.rawRepresentation]
        )
        let tombstoner = PLCDirectoryAccountPermanentDeletionTombstoner(
            keyStore: keys,
            plcClient: client
        )

        try await tombstoner.tombstonePLCIdentity(
            did: fixture.did,
            rotationKey: fixture.rotationReference
        )

        let recordedSubmission = await client.submittedOperation()
        let submitted = try XCTUnwrap(recordedSubmission)
        guard case .tombstoneOperation = submitted else {
            return XCTFail("permanent deletion did not submit a PLC tombstone")
        }
        let submitCallCount = await client.submitCallCount()
        let readCallCount = await keys.readCallCount()
        XCTAssertEqual(submitted.prev, fixture.genesisEntry.cid)
        XCTAssertEqual(
            try PLCOperationCodec.verify(
                submitted,
                authorizedRotationKeys:
                    fixture.genesis.regular?.rotationKeys ?? []
            ),
            0
        )
        XCTAssertEqual(submitCallCount, 1)
        XCTAssertEqual(readCallCount, 1)
    }

    func testAlreadyTerminalAuthenticatedTombstoneIsIdempotentWithoutKeyRead() async throws {
        let fixture = try PLCDeletionFixture()
        let tombstone = try PLCOperationCodec.sign(
            .tombstone(
                try PLCUnsignedTombstoneOperation(
                    prev: fixture.genesisEntry.cid
                )
            ),
            using: fixture.rotationKey
        )
        let tombstoneEntry = try fixture.entry(
            operation: tombstone,
            createdAt: "2026-07-30T12:01:00.000Z"
        )
        let client = RecordingDeletionPLCClient(
            initialAudit: [fixture.genesisEntry, tombstoneEntry]
        )
        let keys = RecordingDeletionKeyReader(values: [:])
        let tombstoner = PLCDirectoryAccountPermanentDeletionTombstoner(
            keyStore: keys,
            plcClient: client
        )

        try await tombstoner.tombstonePLCIdentity(
            did: fixture.did,
            rotationKey: fixture.rotationReference
        )

        let submitCallCount = await client.submitCallCount()
        let readCallCount = await keys.readCallCount()
        XCTAssertEqual(submitCallCount, 0)
        XCTAssertEqual(readCallCount, 0)
    }

    func testMismatchedLocalRotationKeyFailsClosedBeforeSubmit() async throws {
        let fixture = try PLCDeletionFixture()
        let unrelated = P256.Signing.PrivateKey()
        let client = RecordingDeletionPLCClient(initialAudit: [fixture.genesisEntry])
        let keys = RecordingDeletionKeyReader(
            values: [fixture.rotationReference: unrelated.rawRepresentation]
        )
        let tombstoner = PLCDirectoryAccountPermanentDeletionTombstoner(
            keyStore: keys,
            plcClient: client
        )

        await XCTAssertThrowsDeletionError(
            try await tombstoner.tombstonePLCIdentity(
                did: fixture.did,
                rotationKey: fixture.rotationReference
            )
        )

        let submitCallCount = await client.submitCallCount()
        XCTAssertEqual(submitCallCount, 0)
    }
}

private struct PLCDeletionFixture {
    let rotationKey = P256.Signing.PrivateKey()
    let genesis: PLCSignedOperation
    let did: String
    let genesisEntry: PLCAuditEntry
    let rotationReference: AccountKeyReference

    init() throws {
        let signingKey = P256.Signing.PrivateKey()
        let unsigned = try PLCATProfile.regularOperation(
            handle: "deletion.example.com",
            signingPublicKey: signingKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        genesis = try PLCOperationCodec.sign(
            .regular(unsigned),
            using: rotationKey
        )
        did = try PLCOperationCodec.genesisDID(for: genesis)
        genesisEntry = try PLCAuditEntry(
            did: did,
            operation: genesis,
            cid: genesis.cid.string,
            nullified: false,
            createdAt: "2026-07-30T12:00:00.000Z"
        )
        rotationReference = try AccountKeyReference(
            accountDID: did,
            purpose: .rotation,
            generation: 1
        )
    }

    func entry(
        operation: PLCSignedOperation,
        createdAt: String
    ) throws -> PLCAuditEntry {
        PLCAuditEntry(
            did: did,
            operation: operation,
            cid: try operation.cid.string,
            nullified: false,
            createdAt: createdAt
        )
    }
}

private actor RecordingDeletionKeyReader: AccountKeyMaterialReader {
    private let values: [AccountKeyReference: Data]
    private var reads = 0

    init(values: [AccountKeyReference: Data]) {
        self.values = values
    }

    func key(for reference: AccountKeyReference) throws -> Data {
        reads += 1
        guard let value = values[reference] else {
            throw SwanError.unavailable("test account key is unavailable")
        }
        return value
    }

    func readCallCount() -> Int { reads }
}

private actor RecordingDeletionPLCClient: PLCClient {
    private var audit: [PLCAuditEntry]
    private var submitted: PLCSignedOperation?
    private var submitCalls = 0

    init(initialAudit: [PLCAuditEntry]) {
        audit = initialAudit
    }

    func submit(
        did: String,
        operation: PLCSignedOperation
    ) throws {
        submitCalls += 1
        submitted = operation
        audit.append(
            PLCAuditEntry(
                did: did,
                operation: operation,
                cid: try operation.cid.string,
                nullified: false,
                createdAt: "2026-07-30T12:02:00.000Z"
            )
        )
    }

    func fetchState(did _: String) throws -> PLCDocumentData {
        throw SwanError.unavailable("tombstoned PLC state is unavailable")
    }

    func fetchAudit(did _: String) -> [PLCAuditEntry] { audit }

    func fetchAuditIfPresent(did _: String) -> [PLCAuditEntry]? { audit }

    func submittedOperation() -> PLCSignedOperation? { submitted }

    func submitCallCount() -> Int { submitCalls }
}

private func XCTAssertThrowsDeletionError<T>(
    _ expression: @autoclosure () async throws -> T
) async {
    do {
        _ = try await expression()
        XCTFail("expected permanent-deletion operation to fail closed")
    } catch {}
}
