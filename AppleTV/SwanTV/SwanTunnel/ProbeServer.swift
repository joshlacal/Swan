import Foundation
import Network

/// Probe T1: the smallest HTTP/1.1 listener that can live inside the tunnel
/// process. Network.framework only; no NIO, no Hummingbird. Enough HTTP to
/// answer curl and a browser, nothing more.
///
/// Routes:
///   GET /health           process metrics as JSON
///   GET /log              tail of the lifecycle journal
///   GET /ballast/<mb>     hold <mb> MiB of touched memory (0 frees); returns metrics.
///                         Used to measure the jetsam ceiling: raise until the
///                         process dies, read the last surviving line in /log.
///   GET /packets          tunnel packet counters
final class ProbeServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "blue.catbird.SwanTV.probe-http")
    private var ballast: [UnsafeMutableRawBufferPointer] = []
    private var requestCount = 0
    var packetCounters: () -> [String: Any] = { [:] }

    init(port: UInt16) throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
    }

    func start() {
        listener.stateUpdateHandler = { state in
            ProbeLog.shared.event("http.listener", "state=\(state)")
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.serve(connection)
        }
        listener.start(queue: queue)
    }

    func stop() {
        listener.cancel()
        freeBallast()
    }

    private func serve(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, error in
            guard let self, let data, error == nil else { connection.cancel(); return }
            let request = String(decoding: data, as: UTF8.self)
            let target = request.split(separator: "\r\n").first?.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
            let (status, contentType, body) = self.respond(to: target)
            let head = "HTTP/1.1 \(status)\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
            connection.send(content: Data(head.utf8) + body, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }

    private func respond(to target: String) -> (String, String, Data) {
        requestCount += 1
        let path = target.split(separator: "?").first.map(String.init) ?? target
        switch path {
        case "/health", "/":
            return ("200 OK", "application/json", ProcessMetrics.snapshotJSON(extra: [
                "requests": requestCount,
                "ballastMB": ballast.count,
                "packets": packetCounters(),
            ]))
        case "/log":
            return ("200 OK", "text/plain; charset=utf-8", Data(ProbeLog.shared.tail(lines: 200).utf8))
        case "/packets":
            let json = (try? JSONSerialization.data(withJSONObject: packetCounters(), options: [.sortedKeys])) ?? Data()
            return ("200 OK", "application/json", json)
        default:
            if path.hasPrefix("/ballast/"), let mb = Int(path.dropFirst("/ballast/".count)), mb >= 0 {
                setBallast(megabytes: mb)
                return ("200 OK", "application/json", ProcessMetrics.snapshotJSON(extra: ["ballastMB": ballast.count]))
            }
            return ("404 Not Found", "text/plain", Data("not found\n".utf8))
        }
    }

    /// One 1 MiB touched allocation per unit so the footprint really grows and
    /// so freeing is exact. Logged before each step: if the step kills the
    /// process, the last log line is the measured ceiling.
    private func setBallast(megabytes: Int) {
        if megabytes < ballast.count {
            for buffer in ballast[megabytes...] { buffer.deallocate() }
            ballast.removeSubrange(megabytes...)
            ProbeLog.shared.event("ballast.freed", "held=\(ballast.count)MB")
            return
        }
        while ballast.count < megabytes {
            ProbeLog.shared.event("ballast.step", "held=\(ballast.count)MB next=\(ballast.count + 1)MB")
            let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 1_048_576, alignment: 16_384)
            // Touch every page; untouched pages are not counted in the footprint.
            var offset = 0
            while offset < buffer.count { buffer[offset] = 0x5A; offset += 16_384 }
            ballast.append(buffer)
        }
        ProbeLog.shared.event("ballast.held", "held=\(ballast.count)MB")
    }

    private func freeBallast() {
        for buffer in ballast { buffer.deallocate() }
        ballast.removeAll()
    }
}
