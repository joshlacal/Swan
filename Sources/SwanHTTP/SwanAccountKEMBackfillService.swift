import Foundation
import Logging
import ServiceLifecycle
import SwanAccounts
import SwanSQLite

/// Runs only with the operator-configured local account key store. A failed
/// account is retried without blocking server startup or other accounts.
/// Only a pre-submit PLC fact (`PLCAccountRotationError.conflict`) marks an
/// account for manual publication; PLC faults stay retryable.
public struct SwanAccountKEMBackfillService: Service {
    private let control: SQLiteControlDatabase
    private let keys: any AccountKeyStore
    private let rotation: PLCAccountRotationService
    private let pdsOrigin: URL
    private let pacing: Duration
    private let logger = Logger(label: "swan.kem-backfill")

    /// `pacing` is the pause between accounts, so startup does not send
    /// every account's PLC requests back-to-back.
    public init(control: SQLiteControlDatabase, keys: any AccountKeyStore,
                rotation: PLCAccountRotationService, pdsOrigin: URL,
                pacing: Duration = .seconds(1)) {
        self.control = control; self.keys = keys; self.rotation = rotation; self.pdsOrigin = pdsOrigin
        self.pacing = pacing
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
        try await cancelWhenGracefulShutdown { try await self.runLoop() }
    }

    private func runLoop() async throws {
        while !Task.isCancelled {
            var delay: Duration = .seconds(10)
            do {
                if try await runOnce() { delay = pacing }
            } catch is CancellationError { return }
            catch { /* The durable retry retains this account's work. */ }
            do { try await Task.sleep(for: delay) }
            catch { return }
        }
    }
}
