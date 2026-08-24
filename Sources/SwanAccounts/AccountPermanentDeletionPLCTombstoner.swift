import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanCore

/// Authenticated, restart-idempotent PLC tombstoning for permanent account
/// deletion. `PLCClient.fetchAudit` is the trust boundary: the concrete
/// directory client has already verified the complete operation chain before
/// this adapter selects its terminal entry.
public struct PLCDirectoryAccountPermanentDeletionTombstoner:
    AccountPermanentDeletionPLCTombstoner
{
    private let keyStore: any AccountKeyMaterialReader
    private let plcClient: any PLCClient

    public init(
        keyStore: any AccountKeyMaterialReader,
        plcClient: any PLCClient
    ) {
        self.keyStore = keyStore
        self.plcClient = plcClient
    }

    public func tombstonePLCIdentity(
        did rawDID: String,
        rotationKey: AccountKeyReference
    ) async throws {
        let did = try AccountIdentifiers.validateDID(rawDID)
        guard rotationKey.accountDID == did,
              rotationKey.purpose == .rotation else {
            throw SwanError.unauthorized(
                "PLC deletion rotation key does not match the account"
            )
        }

        let initialAudit = try await plcClient.fetchAudit(did: did)
        let terminal = try requireTerminalAuditEntry(
            initialAudit,
            did: did
        )
        if case .tombstoneOperation = terminal.operation {
            // A prior attempt may have died after the directory accepted the
            // tombstone but before control.sqlite advanced its stage.
            return
        }
        guard let regular = terminal.operation.regular,
              terminal.cid == (try terminal.operation.cid.string) else {
            throw SwanError.unauthorized(
                "PLC deletion terminal operation is invalid"
            )
        }

        let privateKey = try P256.Signing.PrivateKey(
            rawRepresentation: try await keyStore.key(for: rotationKey)
        )
        let localRotationDIDKey = P256DIDKey(
            publicKey: privateKey.publicKey
        ).value
        guard regular.rotationKeys.contains(localRotationDIDKey) else {
            throw SwanError.unauthorized(
                "PLC deletion rotation key is not currently authorized"
            )
        }

        let operation = try PLCOperationCodec.sign(
            .tombstone(
                try PLCUnsignedTombstoneOperation(prev: terminal.cid)
            ),
            using: privateKey
        )
        // Submission is idempotent only through the authenticated audit. A
        // duplicate status or transport failure is therefore not itself
        // success, but it is safe to continue to the exact terminal proof.
        do {
            try await plcClient.submit(did: did, operation: operation)
        } catch {}

        let finalAudit = try await plcClient.fetchAudit(did: did)
        let finalTerminal = try requireTerminalAuditEntry(
            finalAudit,
            did: did
        )
        guard finalTerminal.operation == operation,
              finalTerminal.cid == (try operation.cid.string) else {
            throw SwanError.unauthorized(
                "PLC deletion tombstone was not the authenticated terminal operation"
            )
        }
    }

    private func requireTerminalAuditEntry(
        _ audit: [PLCAuditEntry],
        did: String
    ) throws -> PLCAuditEntry {
        guard !audit.isEmpty,
              audit.allSatisfy({ $0.did == did }),
              let terminal = audit.last(where: { !$0.nullified }),
              terminal == audit.last,
              terminal.cid == (try terminal.operation.cid.string) else {
            throw SwanError.unauthorized(
                "PLC deletion audit has no authenticated terminal operation"
            )
        }
        return terminal
    }
}
