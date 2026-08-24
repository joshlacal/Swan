import Crypto
import Foundation
import Petrel
import SwanCore
import PetrelRepo
import SwanStorage
import XCTest

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@testable import SwanSQLite

/// This test deliberately seeds and measures in separate child processes. A
/// baseline after seeding can already include the allocator growth caused by
/// `FileHandle.read(upToCount:)`, masking a full-CAR retained-read regression.
final class PublicRepositoryCARSpoolRSSRegressionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let collection = "app.bsky.feed.post"

    func testOptInFreshProcess256MiBPublicCARSpoolDrainHasBoundedRSS()
        async throws
    {
        guard ProcessInfo.processInfo.environment[
            "SWAN_RUN_256MIB_PUBLIC_CAR_SPOOL_RSS"
        ] == "1" else {
            throw XCTSkip(
                "set SWAN_RUN_256MIB_PUBLIC_CAR_SPOOL_RSS=1 for the fresh-process public CAR spool RSS gate"
            )
        }
        if ProcessInfo.processInfo.environment[
            "SWAN_PUBLIC_CAR_SPOOL_RSS_HELPER"
        ] != "1" {
            try runHelperProcess()
            return
        }

        let environment = ProcessInfo.processInfo.environment
        let root = try XCTUnwrap(
            environment["SWAN_PUBLIC_CAR_SPOOL_RSS_ROOT"].map(
                URL.init(fileURLWithPath:)
            )
        )
        switch environment["SWAN_PUBLIC_CAR_SPOOL_RSS_PHASE"] {
        case "seed":
            try await seedFixture(at: root)
        case "measure":
            let reportURL = try XCTUnwrap(
                environment["SWAN_PUBLIC_CAR_SPOOL_RSS_REPORT"].map(
                    URL.init(fileURLWithPath:)
                )
            )
            let report = try await measureFixture(at: root)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            try SwanTestPrivateFilesystem.writeOwnerOnlyNewFile(
                encoder.encode(report),
                to: reportURL
            )
        default:
            throw SwanError.malformed("public CAR spool RSS helper phase is invalid")
        }
    }

    private func runHelperProcess() throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "swan-public-car-spool-rss-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        try SwanTestPrivateFilesystem.createOwnerOnlyDirectory(at: root)
        let reportURL = root.appending(
            path: "rss-report.json"
        )
        defer {
            try? FileManager.default.removeItem(at: reportURL)
            try? FileManager.default.removeItem(at: root)
        }
        try runHelperPhase("seed", root: root, reportURL: nil)
        try runHelperPhase("measure", root: root, reportURL: reportURL)
        XCTAssertEqual(
            try SwanTestPrivateFilesystem.permissions(at: reportURL),
            0o600
        )
        let report = try JSONDecoder().decode(
            PublicCARSpoolRSSReport.self,
            from: Data(contentsOf: reportURL)
        )
        print("public CAR spool RSS report: \(report)")
        XCTAssertGreaterThanOrEqual(
            report.streamedBytes,
            PublicRepositoryLimits.requiredStreamingCARBytes
        )
        XCTAssertLessThanOrEqual(
            report.maximumChunkBytes,
            PublicRepositoryCARSpool.maximumChunkBytes
        )
        XCTAssertTrue(report.rssMeasurementValid)
        XCTAssertLessThan(report.peakRSSIncreaseBytes, 128 * 1_024 * 1_024)
        XCTAssertTrue(report.spoolCleanedUp)
    }

    private func runHelperPhase(
        _ phase: String,
        root: URL,
        reportURL: URL?
    ) throws {
        let process = Process()
        let selector = "PublicRepositoryCARSpoolRSSRegressionTests/"
            + "testOptInFreshProcess256MiBPublicCARSpoolDrainHasBoundedRSS"
        #if canImport(Darwin)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = [
            "xctest", "-XCTest", selector,
            Bundle(for: PublicRepositoryCARSpoolRSSRegressionTests.self)
                .bundleURL.path,
        ]
        #else
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = ["SwanSQLiteTests.\(selector)"]
        #endif
        var testVariables = [
            "SWAN_RUN_256MIB_PUBLIC_CAR_SPOOL_RSS": "1",
            "SWAN_PUBLIC_CAR_SPOOL_RSS_HELPER": "1",
            "SWAN_PUBLIC_CAR_SPOOL_RSS_PHASE": phase,
            "SWAN_PUBLIC_CAR_SPOOL_RSS_ROOT": root.path,
        ]
        if let reportURL {
            testVariables["SWAN_PUBLIC_CAR_SPOOL_RSS_REPORT"] = reportURL.path
        }
        process.environment = SwanTestChildProcessSecurity.environment(
            testVariables: testVariables
        )
        let output = SwanTestBoundedProcessOutput(
            sensitiveValues: [
                root.path,
                reportURL?.path,
            ].compactMap { $0 }
        )
        output.attach(to: process)
        do {
            try process.run()
            output.childDidLaunch()
        } catch {
            output.cancel()
            throw error
        }
        process.waitUntilExit()
        let diagnostic = output.finish()
        guard process.terminationStatus == 0 else {
            XCTFail("\(phase) helper failed:\n\(diagnostic)")
            return
        }
    }

    private func seedFixture(at root: URL) async throws {
        try SwanTestPrivateFilesystem.createOwnerOnlyDirectory(at: root)
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        do {
            let genesis = try PublicRepositoryGenesisCodec.create(
                did: did, revision: "3jzfcijpj2z2a", signingKey: key
            )
            _ = try await database.installPublicRepositoryGenesis(
                genesis, signingPublicKey: key.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
            let initialState = try await database.loadPublicRepositoryState()
            var state = try XCTUnwrap(initialState)
            let payload = Data(repeating: 0x5a, count: 900_000)
            for index in 0..<300 {
                let identifier = "public-car-rss-\(index)"
                let request = try PublicRepositoryMutationRequest(
                    id: identifier,
                    canonicalDigest: Data(SHA256.hash(data: Data(identifier.utf8))),
                    baseCommitCID: state.commitCID
                )
                guard case let .reserved(reservation) =
                    try await database.reservePublicRepositoryRevision(
                        request,
                        wallClockMicroseconds: 1_760_000_000_000_000 + UInt64(index)
                    ) else {
                    throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
                }
                let path = try PublicRepositoryPath(
                    collection: collection,
                    recordKey: String(format: "large-%04d", index)
                )
                let prepared = try await PublicRepositoryEngine.apply(
                    repositoryDID: did,
                    currentState: state,
                    blocks: database,
                    revision: reservation.nextRevision,
                    batch: PublicRepositoryWriteBatch(
                        writes: [.create(path: path, record: [
                            "$type": .string(collection),
                            "index": .integer(index),
                            "payload": .bytes(payload),
                        ])],
                        expectedCommitCID: state.commitCID
                    ),
                    signer: P256PublicRepositoryCommitSigner(privateKey: key)
                )
                state = try await database.applyPublicRepositoryMutation(
                    reservation: reservation, prepared: prepared
                ).state
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func measureFixture(at root: URL) async throws -> PublicCARSpoolRSSReport {
        // Measure before opening SQLite or allocating the response spool. This
        // makes retained per-read allocations observable in the helper's RSS.
        let baseline = try XCTUnwrap(currentResidentBytes())
        let sampler = PublicCARSpoolRSSSampler(initial: baseline)
        let samplingTask = Task {
            while !Task.isCancelled {
                await sampler.sample(currentResidentBytes())
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
        defer { samplingTask.cancel() }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let admission = try PublicRepositorySpoolAdmission()
        let lease = try XCTUnwrap(admission.reserve(
            accountDID: did,
            maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes
        ))
        let car = try await database.preparePublicRepositoryCAR(lease: lease)
        let sink = PublicCARSpoolDiscardSink()
        try await car.spool.stream { chunk in await sink.append(chunk) }
        try await database.close()
        await sampler.sample(currentResidentBytes())
        samplingTask.cancel()
        _ = await samplingTask.result
        let peak = await sampler.peak
        return PublicCARSpoolRSSReport(
            streamedBytes: await sink.byteCount,
            maximumChunkBytes: await sink.maximumChunkBytes,
            baselineRSSBytes: baseline,
            peakRSSBytes: peak,
            peakRSSIncreaseBytes: max(0, peak - baseline),
            rssMeasurementValid: await sampler.measurementValid,
            spoolCleanedUp: car.spool.isCleanedUp
        )
    }
}

private struct PublicCARSpoolRSSReport: Codable, CustomStringConvertible {
    let streamedBytes: Int
    let maximumChunkBytes: Int
    let baselineRSSBytes: Int
    let peakRSSBytes: Int
    let peakRSSIncreaseBytes: Int
    let rssMeasurementValid: Bool
    let spoolCleanedUp: Bool

    var description: String {
        "streamed=\(streamedBytes) baseline=\(baselineRSSBytes) peak=\(peakRSSBytes) delta=\(peakRSSIncreaseBytes)"
    }
}

private actor PublicCARSpoolDiscardSink {
    private(set) var byteCount = 0
    private(set) var maximumChunkBytes = 0

    func append(_ data: Data) {
        byteCount += data.count
        maximumChunkBytes = max(maximumChunkBytes, data.count)
    }
}

private actor PublicCARSpoolRSSSampler {
    private(set) var peak: Int
    private(set) var measurementValid = true

    init(initial: Int) { peak = initial }

    func sample(_ value: Int?) {
        guard let value else { measurementValid = false; return }
        peak = max(peak, value)
    }
}

private func currentResidentBytes() -> Int? {
    #if canImport(Darwin)
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
        }
    }
    return result == KERN_SUCCESS ? Int(info.resident_size) : nil
    #elseif canImport(Glibc)
    guard let fields = try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8).split(separator: " "),
          fields.count > 1, let pages = Int(fields[1]) else { return nil }
    let pageSize = Int(sysconf(Int32(_SC_PAGESIZE)))
    return pageSize > 0 ? pages * pageSize : nil
    #else
    return nil
    #endif
}
