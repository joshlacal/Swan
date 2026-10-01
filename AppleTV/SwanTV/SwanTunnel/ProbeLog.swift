import Foundation
import os

/// Append-only lifecycle journal in the App Group container. The containing
/// app tails it, so extension liveness can be observed without a debugger
/// attached. Every line: ISO8601 timestamp, pid, event, metrics.
final class ProbeLog: @unchecked Sendable {
    static let groupID = "group.blue.catbird.SwanTV"
    static let shared = ProbeLog()

    private let logger = Logger(subsystem: "blue.catbird.SwanTV", category: "probe")
    private let queue = DispatchQueue(label: "blue.catbird.SwanTV.probelog")
    let fileURL: URL?

    private init() {
        fileURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.groupID)?
            .appendingPathComponent("swantv-heartbeat.log")
    }

    func event(_ name: String, _ detail: String = "") {
        let footprintMB = Double(ProcessMetrics.footprintBytes()) / 1_048_576
        let availableMB = Double(ProcessMetrics.availableBytes()) / 1_048_576
        let line = String(
            format: "%@ pid=%d %@ footprint=%.1fMB available=%.1fMB threads=%d %@\n",
            ISO8601DateFormatter().string(from: Date()), getpid(), name,
            footprintMB, availableMB, ProcessMetrics.threadCount(), detail)
        logger.notice("\(name, privacy: .public) \(detail, privacy: .public) footprint=\(footprintMB, privacy: .public)MB available=\(availableMB, privacy: .public)MB")
        guard let fileURL else { return }
        queue.async {
            if let handle = try? FileHandle(forWritingTo: fileURL) {
                defer { try? handle.close() }
                _ = try? handle.seekToEnd()
                try? handle.write(contentsOf: Data(line.utf8))
                try? handle.synchronize()
            } else {
                try? Data(line.utf8).write(to: fileURL, options: .atomic)
            }
        }
    }

    func tail(lines: Int = 40) -> String {
        guard let fileURL, let data = try? Data(contentsOf: fileURL), let text = String(data: data, encoding: .utf8) else {
            return "(no heartbeat log)"
        }
        return text.split(separator: "\n").suffix(lines).joined(separator: "\n")
    }
}
