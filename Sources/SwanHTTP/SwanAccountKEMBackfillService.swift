import Foundation
import Logging
import ServiceLifecycle
import SwanAccounts
import SwanSQLite

/// Runs only with the operator-configured local account key store. A failed
/// account is retried without blocking server startup or other accounts.
public struct SwanAccountKEMBackfillService: Service {
    private let control: SQLiteControlDatabase
    private let keys: any AccountKeyStore
    private let rotation: PLCAccountRotationService
    private let pdsOrigin: URL
    private let logger = Logger(label: "swan.kem-backfill")

    public init(control: SQLiteControlDatabase, keys: any AccountKeyStore,
                rotation: PLCAccountRotationService, pdsOrigin: URL) {
        self.control = control; self.keys = keys; self.rotation = rotation; self.pdsOrigin = pdsOrigin
    }

    @discardableResult
    public func runOnce(now: Date = Date()) async throws -> Bool {
        let timestamp = Int64(now.timeIntervalSince1970)
        guard let claim = try await control.claimAccountKEMBackfill(now: timestamp) else { return false }
        do {
            _ = try await AccountKeyProvisioner(keyStore: keys).provisionKEM(accountDID: claim.did)
            var manual = claim.requiresManualPublication
            if !manual {
                do { _ = try await rotation.backfillKEM(did: claim.did, expectedPDSOrigin: pdsOrigin, now: now) }
                catch PLCAccountRotationError.conflict { manual = true }
            }
            try await control.finishAccountKEMBackfill(claim, manual: manual, now: timestamp)
            logger.info(manual ? "cannot publish kem key, account must update its did doc" : "kem key backfill complete",
                        metadata: ["did": .string(claim.did)])
        } catch {
            try await control.retryAccountKEMBackfill(claim, now: timestamp)
            logger.warning("kem key backfill deferred", metadata: ["did": .string(claim.did)])
            throw error
        }
        return true
    }

    public func run() async throws {
        while !Task.isCancelled {
            do {
                if try await runOnce() { continue }
            } catch is CancellationError { return }
            catch { /* The durable retry retains this account's work. */ }
            do { try await Task.sleep(for: .seconds(10)) }
            catch { return }
        }
    }
}
