import ServiceLifecycle
import SwanSQLite

/// Runs the durable public firehose sequencer as a service-group member.
/// The sequencer has no HTTP routes and no database-opening capability; it
/// only drains already-durable account outboxes and lifecycle batches into
/// `firehose.sqlite`.
public struct SwanPublicFirehoseSequencerService: Service {
    private let sequencer: PublicFirehoseSequencer

    public init(sequencer: PublicFirehoseSequencer) {
        self.sequencer = sequencer
    }

    public func run() async throws {
        await sequencer.runUntilCancelled()
    }
}
