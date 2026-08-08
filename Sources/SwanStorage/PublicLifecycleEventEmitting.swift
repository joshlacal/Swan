import Foundation

/// Emits durable public lifecycle events for confirmed account operations.
/// Implementations are idempotent per operation ID; callers may safely
/// retry after a crash between the operation's completion and emission.
public protocol PublicLifecycleEventEmitting: Sendable {
    /// Activation: enqueue the idempotent [#identity, #account(active)]
    /// batch, then the barriered activation #sync announcing the current
    /// public repository head. `materialTime` is the installed account's
    /// durable creation time; `now` is the current enqueue attempt time.
    func emitActivation(
        did: String, operationID: String, plcOperationCID: String,
        handle: String?, materialTime: Date, now: Date
    ) async throws
    /// Key rotation: enqueue the idempotent [#identity] batch keyed on the
    /// confirmed PLC operation CID. `materialTime` is the persisted PLC
    /// history entry creation time; `now` is the current enqueue attempt time.
    func emitRotationIdentity(
        did: String, plcOperationCID: String, handle: String?,
        materialTime: Date, now: Date
    ) async throws
    /// Reactivation follow-up: #sync announcing the current public head.
    func emitReactivationSync(did: String, operationID: String, now: Date) async throws
    /// Operator-forced #sync announcing the current public head.
    func emitManualSync(did: String, requestUUID: String, now: Date) async throws
}
