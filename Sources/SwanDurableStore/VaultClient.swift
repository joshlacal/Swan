import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// HTTP client for `swan-vault` (AppleTV/swan-vault). One instance per vault;
/// holds the lease generation every mutation must carry. Any 409 means this
/// process has been fenced by a newer lease holder and must stop writing.
public actor VaultClient {
    public struct Configuration: Sendable {
        public var baseURL: URL
        public var token: String
        public var holder: String
        public var requestTimeout: TimeInterval

        public init(baseURL: URL, token: String, holder: String, requestTimeout: TimeInterval = 15) {
            self.baseURL = baseURL
            self.token = token
            self.holder = holder
            self.requestTimeout = requestTimeout
        }
    }

    public struct Manifest: Codable, Sendable, Equatable {
        public struct Segment: Codable, Sendable, Equatable {
            public var seq: UInt64
            public var firstFrame: UInt32
            public var frames: UInt32
            public var bytes: UInt64
            public var sha256: String
            public var salt: String
            public var dbPages: UInt32
            public var walReset: Bool
        }

        public var pageSize: UInt32
        public var salt: String?
        public var nextFrame: UInt32
        public var nextSeq: UInt64
        public var snapshotBytes: UInt64
        public var snapshotSha256: String?
        public var segments: [Segment]
    }

    public enum Failure: Error, Equatable, Sendable {
        /// The vault refused our generation: another writer holds the lease.
        case fenced(current: String)
        /// The vault rejected the payload (checksum chain, sequence, digest).
        case rejected(status: Int, message: String)
        /// Transport-level failure or 5xx: retryable.
        case unavailable(String)
        case notLeased
    }

    public let configuration: Configuration
    public private(set) var generation: UInt64 = 0
    private let session: URLSession
    private let decoder: JSONDecoder

    public init(configuration: Configuration) {
        self.configuration = configuration
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.timeoutIntervalForRequest = configuration.requestTimeout
        sessionConfiguration.timeoutIntervalForResource = configuration.requestTimeout * 4
        sessionConfiguration.httpMaximumConnectionsPerHost = 2
        session = URLSession(configuration: sessionConfiguration)
        decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
    }

    // MARK: Lease

    @discardableResult
    public func lease() async throws -> UInt64 {
        let body = try JSONSerialization.data(withJSONObject: ["holder": configuration.holder])
        let (data, _) = try await send("POST", "/v1/lease", body: body, contentType: "application/json")
        struct Lease: Decodable { let generation: UInt64 }
        generation = try decoder.decode(Lease.self, from: data).generation
        return generation
    }

    // MARK: Databases

    /// `nil` when the vault has never seen this database.
    public func manifest(database: String) async throws -> Manifest? {
        do {
            let (data, _) = try await send("GET", "/v1/db/\(database)/manifest")
            return try decoder.decode(Manifest.self, from: data)
        } catch Failure.rejected(status: 404, _) {
            return nil
        }
    }

    public func putSnapshot(database: String, image: Data) async throws -> Manifest {
        let (data, _) = try await send("PUT", "/v1/db/\(database)/snapshot", generation: true, body: image)
        return try decoder.decode(Manifest.self, from: data)
    }

    public struct SegmentDescriptor: Sendable {
        public var seq: UInt64
        public var pageSize: UInt32
        public var firstFrame: UInt32
        public var frameCount: UInt32
        public var salt: Data
        public var bigEndian: Bool
        /// Present only when this segment starts a fresh WAL.
        public var resetHeaderChecksum: (UInt32, UInt32)?
    }

    public func postSegment(database: String, _ descriptor: SegmentDescriptor, frames: Data) async throws -> Manifest.Segment {
        var headers: [String: String] = [
            "X-Wal-Seq": String(descriptor.seq),
            "X-Wal-Page-Size": String(descriptor.pageSize),
            "X-Wal-First-Frame": String(descriptor.firstFrame),
            "X-Wal-Frame-Count": String(descriptor.frameCount),
            "X-Wal-Salt": descriptor.salt.map { String(format: "%02x", $0) }.joined(),
            "X-Wal-Big-Endian": descriptor.bigEndian ? "1" : "0",
        ]
        if let (s0, s1) = descriptor.resetHeaderChecksum {
            headers["X-Wal-Reset"] = "1"
            headers["X-Wal-Header-Checksum"] = "\(s0),\(s1)"
        }
        let (data, _) = try await send("POST", "/v1/db/\(database)/wal", generation: true, body: frames, headers: headers)
        return try decoder.decode(Manifest.Segment.self, from: data)
    }

    public func compact(database: String) async throws -> Manifest {
        let (data, _) = try await send("POST", "/v1/db/\(database)/compact", generation: true)
        return try decoder.decode(Manifest.self, from: data)
    }

    public func snapshot(database: String) async throws -> Data {
        try await send("GET", "/v1/db/\(database)/snapshot").0
    }

    public func segment(database: String, seq: UInt64) async throws -> Data {
        try await send("GET", "/v1/db/\(database)/wal/\(seq)").0
    }

    // MARK: Objects

    /// Content-addressed, idempotent. Returns the digest the vault stored.
    @discardableResult
    public func putObject(_ data: Data) async throws -> String {
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        _ = try await send("PUT", "/v1/objects/\(digest)", generation: true, body: data)
        return digest
    }

    public func object(sha256: String) async throws -> Data? {
        do {
            return try await send("GET", "/v1/objects/\(sha256)").0
        } catch Failure.rejected(status: 404, _) {
            return nil
        }
    }

    // MARK: Transport

    private func send(
        _ method: String,
        _ path: String,
        generation withGeneration: Bool = false,
        body: Data? = nil,
        contentType: String = "application/octet-stream",
        headers: [String: String] = [:]
    ) async throws -> (Data, HTTPURLResponse) {
        var components = URLComponents(url: configuration.baseURL, resolvingAgainstBaseURL: false)!
        components.path = path
        if withGeneration {
            guard generation > 0 else { throw Failure.notLeased }
            components.queryItems = [URLQueryItem(name: "gen", value: String(generation))]
        }
        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        request.setValue("Bearer \(configuration.token)", forHTTPHeaderField: "Authorization")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let body {
            request.httpBody = body
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
            request.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw Failure.unavailable(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw Failure.unavailable("non-HTTP response") }
        switch http.statusCode {
        case 200...299:
            return (data, http)
        case 409 where String(decoding: data, as: UTF8.self).contains("stale generation"):
            throw Failure.fenced(current: String(decoding: data, as: UTF8.self))
        case 500...599:
            throw Failure.unavailable("vault \(http.statusCode): \(String(decoding: data.prefix(200), as: UTF8.self))")
        default:
            throw Failure.rejected(status: http.statusCode, message: String(decoding: data.prefix(200), as: UTF8.self))
        }
    }
}
