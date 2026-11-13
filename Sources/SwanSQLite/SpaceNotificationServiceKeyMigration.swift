import Foundation
import SQLiteNIO
import SwanCore

extension SQLiteAccountDatabase {
    func notificationTableHasColumn(_ table: String, _ column: String) async throws -> Bool {
        try await connection.query("PRAGMA table_info(\(table))").contains {
            $0.column("name")?.string == column
        }
    }
}
