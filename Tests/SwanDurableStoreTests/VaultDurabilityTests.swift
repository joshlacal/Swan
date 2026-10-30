import Foundation
import SQLiteNIO
import SwanDurableStore
import SwanSQLite
import SwanStorage
import XCTest

/// End-to-end: Swan's real control database, commit barrier installed, every
/// transaction shipped to a live `swan-vault`, then a cold restore into a
/// fresh directory is opened by Swan and must contain the same account.
///
/// Requires the daemon binary: `cargo build --release` in `AppleTV/swan-vault`
/// (or set `SWAN_VAULT_BINARY`). Skips otherwise so `swift test` stays green
/// on machines without a Rust toolchain.
final class VaultDurabilityTests: XCTestCase {
    private var daemon: Process?
    private var scratch: URL!
    private var baseURL: URL!
    private let token = String(repeating: "k", count: 48)

    override func setUp() async throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let binary = ProcessInfo.processInfo.environment["SWAN_VAULT_BINARY"]
            ?? packageRoot.appendingPathComponent("AppleTV/swan-vault/target/release/swan-vault").path
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: binary), "swan-vault binary not built at \(binary)")

        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("SwanVault-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let tokenFile = scratch.appendingPathComponent("token")
        try Data(token.utf8).write(to: tokenFile)
        let port = UInt16.random(in: 20000 ..< 40000)
        baseURL = URL(string: "http://127.0.0.1:\(port)")!
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["--root", scratch.appendingPathComponent("vault").path, "--listen", "127.0.0.1:\(port)", "--token-file", tokenFile.path]
        process.standardError = FileHandle.nullDevice
        try process.run()
        daemon = process
        for _ in 0 ..< 50 {
            if let (_, response) = try? await URLSession.shared.data(from: baseURL.appendingPathComponent("v1/health")),
               (response as? HTTPURLResponse)?.statusCode == 200 { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTFail("swan-vault did not become healthy")
    }

    override func tearDown() async throws {
        daemon?.terminate()
        daemon?.waitUntilExit()
        if let scratch { try? FileManager.default.removeItem(at: scratch) }
    }

    private func registration(_ did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(purpose: .signing, generation: 1),
            rotationKey: .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func dataDirectory(_ name: String) throws -> URL {
        let url = scratch.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return url
    }

    func testControlDatabaseWritesSurviveColdRestoreFromVault() async throws {
        let client = VaultClient(configuration: .init(baseURL: baseURL, token: token, holder: "xctest"))
        try await client.lease()

        let live = try dataDirectory("live")
        let control = try await SQLiteControlDatabase(dataDirectory: live)
        let controlFile = live.appendingPathComponent("control.sqlite")
        let shipper = WALShipper(client: client, database: "control", fileURL: controlFile)
        try await shipper.bootstrap()
        try await control.installCommitBarrier { try await shipper.ship() }

        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await control.createAccount(registration(did, handle: "vault-restore.example.com"))
        // A second transaction so the vault holds more than one segment.
        _ = try await control.createAccount(registration("did:plc:bcdefghijklmnopqrstuvwxy", handle: "second.example.com"))

        let fetchedManifest = try await client.manifest(database: "control")
        let manifest = try XCTUnwrap(fetchedManifest)
        XCTAssertGreaterThanOrEqual(manifest.segments.count, 2, "each createAccount transaction must ship as a segment before returning")

        // Fold acknowledged frames back into the main file and keep going: a
        // WAL reset must not break the chain.
        try await shipper.checkpointIfShipped()
        _ = try await control.createAccount(registration("did:plc:cdefghijklmnopqrstuvwxyz", handle: "after-checkpoint.example.com"))
        try await control.close()

        // Cold start elsewhere: nothing local, everything from the vault.
        let restored = try dataDirectory("restored")
        try await WALShipper.restore(client: client, database: "control", to: restored.appendingPathComponent("control.sqlite"))
        let reopened = try await SQLiteControlDatabase(dataDirectory: restored)
        defer { Task { try? await reopened.close() } }
        let fetchedAccount = try await reopened.account(did: did)
        let account = try XCTUnwrap(fetchedAccount)
        XCTAssertEqual(account.canonicalHandle, "vault-restore.example.com")
        let afterReset = try await reopened.account(did: "did:plc:cdefghijklmnopqrstuvwxyz")
        XCTAssertNotNil(afterReset, "write after the WAL reset must be present")

        // Compaction on the vault must reproduce the same image.
        _ = try await client.compact(database: "control")
        let compacted = try dataDirectory("compacted")
        try await WALShipper.restore(client: client, database: "control", to: compacted.appendingPathComponent("control.sqlite"))
        let reopenedCompacted = try await SQLiteControlDatabase(dataDirectory: compacted)
        let second = try await reopenedCompacted.account(did: "did:plc:bcdefghijklmnopqrstuvwxy")
        XCTAssertNotNil(second)
        try await reopenedCompacted.close()
    }

    func testFencedWriterFailsTheTransactionNotTheProcess() async throws {
        let client = VaultClient(configuration: .init(baseURL: baseURL, token: token, holder: "first-tv"))
        try await client.lease()
        let live = try dataDirectory("fenced")
        let control = try await SQLiteControlDatabase(dataDirectory: live)
        let shipper = WALShipper(client: client, database: "control", fileURL: live.appendingPathComponent("control.sqlite"))
        try await shipper.bootstrap()
        try await control.installCommitBarrier { try await shipper.ship() }

        // A second Apple TV takes the lease.
        let usurper = VaultClient(configuration: .init(baseURL: baseURL, token: token, holder: "second-tv"))
        try await usurper.lease()

        do {
            _ = try await control.createAccount(registration("did:plc:abcdefghijklmnopqrstuvwx", handle: "fenced.example.com"))
            XCTFail("write must surface the fence")
        } catch let failure as VaultClient.Failure {
            guard case .fenced = failure else { return XCTFail("expected fenced, got \(failure)") }
        }
        // The vault never received the segment.
        let fetchedManifest = try await usurper.manifest(database: "control")
        let manifest = try XCTUnwrap(fetchedManifest)
        XCTAssertTrue(manifest.segments.isEmpty)
        try await control.close()
    }
}
