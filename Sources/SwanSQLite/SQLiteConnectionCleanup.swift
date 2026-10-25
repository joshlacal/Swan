import NIOCore
import SQLiteNIO

extension SQLiteConnection {
    /// Cleanup must finish before the connection gate is released, even when
    /// the request task was cancelled. SQLiteNIO's async queries use NIO's
    /// cancellation-aware thread pool. Its future API queues cleanup without
    /// inheriting request cancellation, and awaiting the future still waits
    /// for SQLite to finish the operation.
    func executeCleanupQuery(_ statement: String) async throws {
        let completion: EventLoopFuture<[SQLiteRow]> = self.query(statement)
        _ = try await completion.get()
    }

    /// Closing owns the SQLite handle and must also survive request cancellation.
    func closeForCleanup() async throws {
        let completion: EventLoopFuture<Void> = self.close()
        try await completion.get()
    }
}
