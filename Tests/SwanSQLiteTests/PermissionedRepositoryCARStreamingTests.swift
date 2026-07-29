import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@testable import SwanSQLite

final class PermissionedRepositoryCARStreamingTests: XCTestCase {
    func testHelperEnvironmentExcludesParentSecretSentinels() {
        let secret = "luna-parent-secret-must-not-cross-process-boundary"
        let parent = [
            "PATH": "/safe/toolchain/bin",
            "DEVELOPER_DIR": "/safe/developer",
            "HOME": "/Users/example",
            "AWS_SECRET_ACCESS_KEY": secret,
            "SWAN_OPERATOR_SECRET": secret,
            "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
        ]
        let environment = SwanTestChildProcessSecurity.environment(
            parent: parent,
            testVariables: [
                "SWAN_PERMISSIONED_CAR_RSS_HELPER": "1",
                "SWAN_PERMISSIONED_CAR_RSS_PHASE": "measure",
            ]
        )

        XCTAssertEqual(environment["PATH"], "/safe/toolchain/bin")
        XCTAssertEqual(environment["DEVELOPER_DIR"], "/safe/developer")
        XCTAssertEqual(
            environment["SWAN_PERMISSIONED_CAR_RSS_HELPER"],
            "1"
        )
        XCTAssertNil(environment["HOME"])
        XCTAssertNil(environment["AWS_SECRET_ACCESS_KEY"])
        XCTAssertNil(environment["SWAN_OPERATOR_SECRET"])
        XCTAssertNil(environment["DYLD_INSERT_LIBRARIES"])
        XCTAssertFalse(environment.values.contains(secret))
    }

    func testHelperFailureDiagnosticsAreBoundedAndRedactSecretSentinels() {
        let secret = "luna-output-secret-must-be-redacted"
        let capture = SwanTestBoundedProcessOutput(
            maximumDiagnosticBytes: 1_024,
            sensitiveValues: [secret]
        )
        capture.recordForTesting(
            Data(
                (
                    "AUTHORIZATION=Bearer \(secret)\n"
                        + String(repeating: "x", count: 32 * 1_024)
                ).utf8
            )
        )

        let diagnostic = capture.diagnosticForTesting()
        XCTAssertFalse(diagnostic.contains(secret))
        XCTAssertTrue(diagnostic.contains("<redacted>"))
        XCTAssertTrue(diagnostic.contains("[output truncated]"))
        XCTAssertLessThanOrEqual(diagnostic.utf8.count, 1_024)
    }

    func testPermissionedCARFixtureAndSinkUseOwnerOnlyPermissions()
        async throws
    {
        let fixture = try PermissionedCARFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        do {
            XCTAssertEqual(
                try SwanTestPrivateFilesystem.permissions(at: fixture.root),
                0o700
            )

            let carURL = fixture.root.appending(path: "owner-only.car")
            let sink = try PermissionedCARFileSink(url: carURL)
            XCTAssertEqual(
                try SwanTestPrivateFilesystem.permissions(at: carURL),
                0o600
            )
            try await sink.close()
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testProcessAdmissionBoundsWorstCaseSpoolsAndReleasesIdempotently()
        throws
    {
        let reservationBytes =
            SpaceCARProductionLimits.maximumWorkingSpoolBytes
        let admission = try SpaceCARSpoolAdmission(
            maximumGlobalBytes: reservationBytes * 2,
            maximumPerAccountBytes: reservationBytes
        )
        let alice = try XCTUnwrap(
            admission.reserve(
                accountDID: "did:plc:alice",
                maximumBytes: reservationBytes
            )
        )
        XCTAssertNil(
            admission.reserve(
                accountDID: "did:plc:alice",
                maximumBytes: reservationBytes
            )
        )
        let bob = try XCTUnwrap(
            admission.reserve(
                accountDID: "did:plc:bob",
                maximumBytes: reservationBytes
            )
        )
        XCTAssertNil(
            admission.reserve(
                accountDID: "did:plc:carol",
                maximumBytes: reservationBytes
            )
        )
        XCTAssertEqual(admission.snapshot.activeLeases, 2)
        alice.release()
        alice.release()
        XCTAssertEqual(admission.snapshot.activeLeases, 1)
        bob.release()
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedBytes, 0)
    }

    func testSQLiteProducerEmitsOneBlockForSharedCIDAndStreamingConsumerCountsPaths()
        async throws
    {
        let fixture = try PermissionedCARFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "text", value: "shared value"),
        ]))
        let cid = CID.fromDAGCBOR(value)
        let records = try ["first", "second"].map {
            try fixture.record(rkey: $0, value: value)
        }
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try TID(tidString: "222222222222a"),
            writes: records.map {
                .put(uri: $0.uri, value: $0.value, cid: cid.string)
            }
        )

        let preparedSnapshot = try await database.prepareRepositoryCARSnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let prepared = try XCTUnwrap(preparedSnapshot)
        XCTAssertEqual(
            try SwanTestPrivateFilesystem.permissions(
                at: fixture.root.appending(
                    path: "permissioned-car-spool",
                    directoryHint: .isDirectory
                )
            ),
            0o700
        )
        let key = P256.Signing.PrivateKey()
        let prefix = try fixture.recoveryPrefix(
            prepared: prepared,
            signingKey: key
        )
        XCTAssertTrue(
            try permissionedCARSpoolFiles(in: fixture.root).isEmpty,
            "production permissioned CAR descriptors must be unlinked before handoff"
        )
        var car = prefix
        try await prepared.spool.streamBody { car.append($0) }
        XCTAssertEqual(try testPermissionedCARFrameCount(car), 3)
        XCTAssertEqual(prepared.spool.bodyByteCount, car.count - prefix.count)
        XCTAssertTrue(prepared.spool.isCleanedUp)
        do {
            try await prepared.spool.streamBody { _ in }
            XCTFail("a single-use permissioned CAR spool was drained twice")
        } catch let error as SwanError {
            XCTAssertEqual(
                error,
                .unavailable("permissioned CAR spool is unavailable")
            )
        }

        let index = try await SQLiteSpaceCARRecoveryIndex.create(
            temporaryParentURL: fixture.root
        )
        let summary: VerifiedStreamingSpaceCARRecovery
        do {
            summary = try await SpaceCARCodec.verifyStreamingRecovery(
                from: PermissionedCARDataSource(car),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: key.publicKey
                    )
                },
                index: index,
                limits: try SpaceCARRecoveryLimits(maximumCARBytes: car.count)
            )
        } catch {
            await index.cleanup()
            throw error
        }
        await index.cleanup()
        XCTAssertEqual(summary.recordCount, 2)
        XCTAssertEqual(summary.verifiedExpectedWitnessCount, 0)
        try await database.close()
    }

    func testSQLiteProducerRejectsRecordOverConsumerLimitAndRemovesPartialSpools()
        async throws
    {
        let fixture = try PermissionedCARFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        do {
            let validValue = try DAGCBOR.encodeValue(
                OrderedCBORMap(entries: [
                    (key: "data", value: Data([0x5a])),
                ])
            )
            let record = try fixture.record(
                rkey: "oversized",
                value: validValue
            )
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "222222222222b"),
                writes: [
                    .put(
                        uri: record.uri,
                        value: validValue,
                        cid: CID.fromDAGCBOR(validValue).string
                    ),
                ]
            )
            let value = try DAGCBOR.encodeValue(
                OrderedCBORMap(entries: [
                    (
                        key: "data",
                        value: Data(
                            repeating: 0x5a,
                            count:
                                SpaceCARRecoveryLimits
                                .absoluteMaximumRecordBytes
                        )
                    ),
                ])
            )
            XCTAssertGreaterThan(
                value.count,
                SpaceCARRecoveryLimits.absoluteMaximumRecordBytes
            )
            // Simulate a legacy/corrupt row that predates the storage-boundary
            // validator. The producer must reject it before creating a spool.
            _ = try await database.connection.query(
                """
                UPDATE permissioned_space_records
                SET value = ?, cid = ?
                WHERE space_uri = ? AND author_did = ?
                  AND collection = ? AND rkey = ?
                """,
                [
                    value.sqliteData!,
                    .text(CID.fromDAGCBOR(value).string),
                    .text(fixture.space.rawValue),
                    .text(fixture.author),
                    .text(record.uri.collection),
                    .text(record.uri.rkey),
                ]
            )

            do {
                let unexpected =
                    try await database.prepareRepositoryCARSnapshot(
                        space: fixture.space,
                        author: fixture.author
                    )
                unexpected?.spool.cleanup()
                XCTFail(
                    "a producer CAR containing an over-limit record was prepared"
                )
            } catch {
                XCTAssertEqual(
                    error as? SwanError,
                    SpaceCARProductionLimits.limitExceeded()
                )
            }
            XCTAssertTrue(
                try permissionedCARSpoolFiles(in: fixture.root).isEmpty
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testOptInMaximumCardinalityRecoveryIndexBoundsRSSAndScratchDisk()
        async throws
    {
        guard ProcessInfo.processInfo.environment[
            "SWAN_RUN_100K_PERMISSIONED_CAR_INDEX"
        ] == "1" else {
            throw XCTSkip(
                "set SWAN_RUN_100K_PERMISSIONED_CAR_INDEX=1 for the scratch-index gate"
            )
        }
        let root = FileManager.default.temporaryDirectory.appending(
            path: "swan-permissioned-car-index-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        try SwanTestPrivateFilesystem.createOwnerOnlyDirectory(at: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let baseline = try XCTUnwrap(
            currentPermissionedCARResidentBytes(),
            "the platform RSS probe is unavailable"
        )
        let sampler = PermissionedCARRSSSampler(initial: baseline)
        let samplingTask = Task {
            while !Task.isCancelled {
                await sampler.sample(currentPermissionedCARResidentBytes())
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
        defer { samplingTask.cancel() }

        let index = try await SQLiteSpaceCARRecoveryIndex.create(
            temporaryParentURL: root
        )
        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "text", value: "shared"),
        ]))
        let cid = CID.fromDAGCBOR(value)
        var logicalEntryBytes = 0
        do {
            for number in 0
                ..< SpaceCARRecoveryLimits.absoluteMaximumIndexEntries
            {
                let path = String(
                    format: "app.bsky.feed.post/max-%06d",
                    number
                )
                logicalEntryBytes += path.utf8.count + cid.bytes.count + 1
                try await index.insert(
                    SpaceCARRecoveryIndexEntry(path: path, cid: cid)
                )
            }
            let scratchBytes = try await index
                .testingScratchDatabaseByteCount()
            XCTAssertLessThanOrEqual(
                scratchBytes,
                SpaceCARProductionLimits.maximumLogicalMetadataBytes
            )
            XCTAssertLessThanOrEqual(
                scratchBytes,
                logicalEntryBytes * 6 + 1 * 1_024 * 1_024
            )
            let first = try await index.nextUnconsumedLexicographicEntry()
            XCTAssertEqual(first?.path, "app.bsky.feed.post/max-000000")
            let consumedCount = try await index.consumeEntries(forCID: cid)
            XCTAssertEqual(
                consumedCount,
                SpaceCARRecoveryLimits.absoluteMaximumIndexEntries
            )
            let remaining = try await index
                .nextUnconsumedLexicographicEntry()
            XCTAssertNil(remaining)
            await sampler.sample(currentPermissionedCARResidentBytes())
            samplingTask.cancel()
            _ = await samplingTask.result
            let peak = await sampler.peak
            let measurementValid = await sampler.measurementValid
            print(
                "permissioned CAR max-index report: "
                    + "logical=\(logicalEntryBytes) scratch=\(scratchBytes) "
                    + "baseline=\(baseline) peak=\(peak) "
                    + "delta=\(max(0, peak - baseline))"
            )
            XCTAssertTrue(measurementValid)
            XCTAssertLessThan(peak - baseline, 128 * 1_024 * 1_024)
            await index.cleanup()
        } catch {
            await index.cleanup()
            throw error
        }
        let cleanedUp = await index.isCleanedUp
        XCTAssertTrue(cleanedUp)
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: nil
            ).contains {
                $0.lastPathComponent.hasPrefix("swan-space-recovery-")
            }
        )
    }

    func testOptInProductionSQLiteNear256MiBCARHasBoundedRSSAndRejectsOneMoreRecord()
        async throws
    {
        guard ProcessInfo.processInfo.environment[
            "SWAN_RUN_256MIB_PERMISSIONED_GET_REPO"
        ] == "1" else {
            throw XCTSkip(
                "set SWAN_RUN_256MIB_PERMISSIONED_GET_REPO=1 for the producer CAR gate"
            )
        }
        if ProcessInfo.processInfo.environment[
            "SWAN_PERMISSIONED_CAR_RSS_HELPER"
        ] != "1" {
            try runPermissionedCARHelperProcess()
            return
        }

        let environment = ProcessInfo.processInfo.environment
        let fixtureRoot = try XCTUnwrap(
            environment["SWAN_PERMISSIONED_CAR_FIXTURE_ROOT"].map(
                URL.init(fileURLWithPath:)
            )
        )
        switch environment["SWAN_PERMISSIONED_CAR_RSS_PHASE"] {
        case "seed":
            try await seedPermissionedCARHeavyFixture(at: fixtureRoot)
        case "measure":
            let reportURL = try XCTUnwrap(
                environment["SWAN_PERMISSIONED_CAR_RSS_REPORT"].map(
                    URL.init(fileURLWithPath:)
                )
            )
            let report = try await runPermissionedCARHeavyAcceptance(
                fixtureRoot: fixtureRoot
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            try SwanTestPrivateFilesystem.writeOwnerOnlyNewFile(
                encoder.encode(report),
                to: reportURL
            )
        default:
            throw SwanError.malformed(
                "permissioned CAR RSS helper phase is invalid"
            )
        }
    }

    private func runPermissionedCARHelperProcess() throws {
        let fixtureRoot = FileManager.default.temporaryDirectory.appending(
            path: "swan-permissioned-car-rss-fixture-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        try SwanTestPrivateFilesystem.createOwnerOnlyDirectory(at: fixtureRoot)
        let reportURL = fixtureRoot.appending(
            path: "rss-report.json"
        )
        defer {
            try? FileManager.default.removeItem(at: reportURL)
            try? FileManager.default.removeItem(at: fixtureRoot)
        }
        guard try runPermissionedCARHelperPhase(
            "seed",
            fixtureRoot: fixtureRoot,
            reportURL: nil
        ) else {
            return
        }
        guard try runPermissionedCARHelperPhase(
            "measure",
            fixtureRoot: fixtureRoot,
            reportURL: reportURL
        ) else {
            return
        }
        guard FileManager.default.fileExists(atPath: reportURL.path) else {
            XCTFail("permissioned CAR measurement helper produced no report")
            return
        }
        XCTAssertEqual(
            try SwanTestPrivateFilesystem.permissions(at: reportURL),
            0o600
        )
        let report = try JSONDecoder().decode(
            PermissionedCARRSSReport.self,
            from: Data(contentsOf: reportURL)
        )
        let diagnostic = String(
            decoding: try JSONEncoder().encode(report),
            as: UTF8.self
        )
        print("permissioned CAR RSS report: \(diagnostic)")
        XCTAssertGreaterThanOrEqual(
            report.carBytes,
            SpaceCARRecoveryLimits.absoluteMaximumCARBytes - 2 * 1_024 * 1_024
        )
        XCTAssertLessThanOrEqual(
            report.carBytes,
            SpaceCARRecoveryLimits.absoluteMaximumCARBytes
        )
        XCTAssertLessThanOrEqual(
            report.maximumChunkBytes,
            SpaceCARBodySpool.maximumChunkBytes
        )
        XCTAssertTrue(
            report.rssMeasurementValid,
            "the platform RSS probe failed during the acceptance run"
        )
        XCTAssertLessThan(
            report.peakRSSIncreaseBytes,
            128 * 1_024 * 1_024
        )
        XCTAssertTrue(report.integrityVerified)
        XCTAssertTrue(report.overLimitRejectedWithoutSpool)
    }

    private func runPermissionedCARHelperPhase(
        _ phase: String,
        fixtureRoot: URL,
        reportURL: URL?
    ) throws -> Bool {
        let process = Process()
        let testSelector =
            "PermissionedRepositoryCARStreamingTests/"
                + "testOptInProductionSQLiteNear256MiBCARHasBoundedRSSAndRejectsOneMoreRecord"
        #if canImport(Darwin)
        // On Apple platforms the test product is an MH_BUNDLE loaded by the
        // xctest host; it is not itself a directly executable helper.
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = [
            "xctest",
            "-XCTest",
            testSelector,
            Bundle(for: PermissionedRepositoryCARStreamingTests.self)
                .bundleURL.path,
        ]
        #else
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = [
            "SwanSQLiteTests.\(testSelector)",
        ]
        #endif
        var testVariables = [
            "SWAN_RUN_256MIB_PERMISSIONED_GET_REPO": "1",
            "SWAN_PERMISSIONED_CAR_RSS_HELPER": "1",
            "SWAN_PERMISSIONED_CAR_RSS_PHASE": phase,
            "SWAN_PERMISSIONED_CAR_FIXTURE_ROOT": fixtureRoot.path,
        ]
        if let reportURL {
            testVariables["SWAN_PERMISSIONED_CAR_RSS_REPORT"] = reportURL.path
        }
        process.environment = SwanTestChildProcessSecurity.environment(
            testVariables: testVariables
        )
        let output = SwanTestBoundedProcessOutput(
            sensitiveValues: [
                fixtureRoot.path,
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
        let watchdog = PermissionedCARHelperWatchdog(
            process: process,
            output: output
        )
        let watchdogTask = watchdog.arm()
        let outputText = output.finish()
        guard !watchdog.didTimeOut else {
            watchdogTask.cancel()
            XCTFail(
                "permissioned CAR \(phase) helper exceeded its 20-minute deadline:\n\(outputText)"
            )
            return false
        }
        process.waitUntilExit()
        watchdogTask.cancel()
        guard process.terminationStatus == 0 else {
            XCTFail(
                "permissioned CAR \(phase) helper failed:\n\(outputText)"
            )
            return false
        }
        return true
    }

    private func seedPermissionedCARHeavyFixture(at root: URL) async throws {
        let fixture = try PermissionedCARFixture(root: root)
        let database = try await fixture.open()
        do {
            let recordPayloadBytes =
                SpaceCARRecoveryLimits.absoluteMaximumRecordBytes - 96
            for index in 0..<255 {
                let value = try largePermissionedRecordValue(
                    index: index,
                    payloadBytes: recordPayloadBytes
                )
                XCTAssertLessThanOrEqual(
                    value.count,
                    SpaceCARRecoveryLimits.absoluteMaximumRecordBytes
                )
                let record = try fixture.record(
                    rkey: String(format: "large-%04d", index),
                    value: value
                )
                _ = try await database.apply(
                    space: fixture.space,
                    author: fixture.author,
                    expectedRevision: UInt64(index),
                    requestID: UUID(),
                    wireRevision: try permissionedCARTID(index),
                    writes: [
                        .put(
                            uri: record.uri,
                            value: value,
                            cid: CID.fromDAGCBOR(value).string
                        ),
                    ]
                )
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func runPermissionedCARHeavyAcceptance(
        fixtureRoot: URL
    )
        async throws -> PermissionedCARRSSReport
    {
        let fixture = try PermissionedCARFixture(root: fixtureRoot)
        let recordPayloadBytes =
            SpaceCARRecoveryLimits.absoluteMaximumRecordBytes - 96
        // A separate child seeded and closed this database. Start measuring
        // before this fresh process opens it so allocator and SQLite page-cache
        // reuse cannot hide a whole-repository read.
        let baseline = try XCTUnwrap(
            currentPermissionedCARResidentBytes(),
            "the platform RSS probe is unavailable"
        )
        let sampler = PermissionedCARRSSSampler(initial: baseline)
        let samplingTask = Task {
            while !Task.isCancelled {
                await sampler.sample(currentPermissionedCARResidentBytes())
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
        defer { samplingTask.cancel() }

        let database = try await fixture.open()
        let preparedSnapshot = try await database.prepareRepositoryCARSnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let prepared = try XCTUnwrap(preparedSnapshot)
        await sampler.sample(currentPermissionedCARResidentBytes())
        let preparationPeak = await sampler.peak
        let signingKey = P256.Signing.PrivateKey()
        let prefix = try fixture.recoveryPrefix(
            prepared: prepared,
            signingKey: signingKey
        )
        let carURL = fixture.root.appending(path: "near-256mib.car")
        let sink = try PermissionedCARFileSink(url: carURL)
        try await sink.append(prefix)
        try await prepared.spool.streamBody { chunk in
            try await sink.append(chunk)
        }
        try await sink.close()
        let maximumChunkBytes = await sink.maximumChunkBytes
        let carBytes = try permissionedCARFileSize(carURL)
        XCTAssertEqual(carBytes, prefix.count + prepared.spool.bodyByteCount)
        XCTAssertTrue(prepared.spool.isCleanedUp)
        await sampler.sample(currentPermissionedCARResidentBytes())
        let drainPeak = await sampler.peak

        let source = try PermissionedCARFileSource(url: carURL)
        let recoveryIndex = try await SQLiteSpaceCARRecoveryIndex.create(
            temporaryParentURL: fixture.root
        )
        let firstValue = try largePermissionedRecordValue(
            index: 0,
            payloadBytes: recordPayloadBytes
        )
        let firstCID = CID.fromDAGCBOR(firstValue)
        let summary = try await SpaceCARCodec.verifyStreamingRecovery(
            from: source,
            space: fixture.space,
            author: fixture.author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: signingKey.publicKey
                )
            },
            index: recoveryIndex,
            expectedEntries: [
                SpaceCARRecoveryIndexEntry(
                    path: "app.bsky.feed.post/large-0000",
                    cid: firstCID
                ),
            ]
        )
        try await source.close()
        await recoveryIndex.cleanup()
        let integrityVerified =
            summary.recordCount == 255
                && summary.verifiedExpectedWitnessCount == 1
                && summary.commitment == prepared.state.commitment
        await sampler.sample(currentPermissionedCARResidentBytes())
        let verificationPeak = await sampler.peak

        let overflowValue = try largePermissionedRecordValue(
            index: 255,
            payloadBytes: recordPayloadBytes
        )
        let overflowRecord = try fixture.record(
            rkey: "large-0255",
            value: overflowValue
        )
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 255,
            requestID: UUID(),
            wireRevision: try permissionedCARTID(255),
            writes: [
                .put(
                    uri: overflowRecord.uri,
                    value: overflowValue,
                    cid: CID.fromDAGCBOR(overflowValue).string
                ),
            ]
        )
        var rejected = false
        do {
            let unexpected = try await database.prepareRepositoryCARSnapshot(
                space: fixture.space,
                author: fixture.author
            )
            unexpected?.spool.cleanup()
        } catch let error as SwanError {
            rejected = error == SpaceCARProductionLimits.limitExceeded()
        }
        let remainingSpoolFiles = try permissionedCARSpoolFiles(in: fixture.root)
        let overLimitRejectedWithoutSpool =
            rejected && remainingSpoolFiles.isEmpty
        try await database.close()
        await sampler.sample(currentPermissionedCARResidentBytes())
        let overflowPeak = await sampler.peak

        samplingTask.cancel()
        _ = await samplingTask.result
        let peak = await sampler.peak
        let rssMeasurementValid = await sampler.measurementValid
        return PermissionedCARRSSReport(
            carBytes: carBytes,
            maximumChunkBytes: maximumChunkBytes,
            baselineRSSBytes: baseline,
            peakRSSBytes: peak,
            peakRSSIncreaseBytes: max(0, peak - baseline),
            preparationPeakRSSIncreaseBytes: max(0, preparationPeak - baseline),
            drainPeakRSSIncreaseBytes: max(0, drainPeak - baseline),
            verificationPeakRSSIncreaseBytes: max(
                0,
                verificationPeak - baseline
            ),
            overflowPeakRSSIncreaseBytes: max(0, overflowPeak - baseline),
            rssMeasurementValid: rssMeasurementValid,
            integrityVerified: integrityVerified,
            overLimitRejectedWithoutSpool: overLimitRejectedWithoutSpool
        )
    }
}

private struct PermissionedCARFixture {
    struct Record {
        let uri: SpaceRecordURI
        let value: Data
    }

    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI

    init(root suppliedRoot: URL? = nil) throws {
        root = suppliedRoot
            ?? FileManager.default.temporaryDirectory.appending(
                path:
                    "PermissionedRepositoryCARStreamingTests-\(UUID().uuidString)",
                directoryHint: .isDirectory
            )
        space = try SpaceURI(
            authority: author,
            spaceType: "app.swan.streaming",
            skey: "producer"
        )
    }

    func open() async throws -> SQLiteAccountDatabase {
        try SwanTestPrivateFilesystem.createOwnerOnlyDirectory(at: root)
        return try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author
        )
    }

    func record(rkey: String, value: Data) throws -> Record {
        Record(
            uri: try SpaceRecordURI(
                space: space,
                author: author,
                collection: "app.bsky.feed.post",
                rkey: rkey
            ),
            value: value
        )
    }

    func recoveryPrefix(
        prepared: AuthorizedSpaceRepositoryCARSnapshot,
        signingKey: P256.Signing.PrivateKey
    ) throws -> Data {
        let revision = try XCTUnwrap(prepared.state.wireRevision)
        let envelope = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: revision,
                ikm: Data(repeating: 0x41, count: 32)
            ),
            commitment: prepared.state.commitment,
            key: signingKey
        )
        return try SpaceCARCodec.recoveryPrefix(
            commit: envelope,
            indexCID: prepared.spool.indexCID
        )
    }
}

private actor PermissionedCARDataSource: SpaceCARRecoveryByteSource {
    private let bytes: Data
    private var offset = 0

    init(_ bytes: Data) {
        self.bytes = bytes
    }

    func read(maximumBytes: Int) -> Data? {
        guard offset < bytes.count else { return nil }
        let end = min(bytes.count, offset + maximumBytes)
        defer { offset = end }
        return Data(bytes[offset..<end])
    }
}

private struct PermissionedCARRSSReport: Codable {
    let carBytes: Int
    let maximumChunkBytes: Int
    let baselineRSSBytes: Int
    let peakRSSBytes: Int
    let peakRSSIncreaseBytes: Int
    let preparationPeakRSSIncreaseBytes: Int
    let drainPeakRSSIncreaseBytes: Int
    let verificationPeakRSSIncreaseBytes: Int
    let overflowPeakRSSIncreaseBytes: Int
    let rssMeasurementValid: Bool
    let integrityVerified: Bool
    let overLimitRejectedWithoutSpool: Bool
}

private final class PermissionedCARHelperWatchdog: @unchecked Sendable {
    private let process: Process
    private let output: SwanTestBoundedProcessOutput
    private let lock = NSLock()
    private var timedOut = false

    init(process: Process, output: SwanTestBoundedProcessOutput) {
        self.process = process
        self.output = output
    }

    var didTimeOut: Bool {
        lock.withLock { timedOut }
    }

    func arm() -> Task<Void, Never> {
        Task { [self] in
            do {
                try await Task.sleep(for: .seconds(20 * 60))
                try Task.checkCancellation()
            } catch {
                return
            }
            let shouldTerminate = lock.withLock {
                guard !timedOut else { return false }
                timedOut = true
                return true
            }
            guard shouldTerminate else { return }
            if process.isRunning {
                process.terminate()
            }
            // Unblock the bounded reader even if the child is wedged while
            // retaining the write end.
            output.cancel()
        }
    }
}

private actor PermissionedCARRSSSampler {
    private(set) var peak: Int
    private(set) var measurementValid = true

    init(initial: Int) {
        peak = initial
    }

    func sample(_ bytes: Int?) {
        guard let bytes else {
            measurementValid = false
            return
        }
        peak = max(peak, bytes)
    }
}

private actor PermissionedCARFileSink {
    private var fileDescriptor: Int32
    private(set) var maximumChunkBytes = 0

    init(url: URL) throws {
        #if canImport(Darwin)
        let descriptor = Darwin.open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR)
        )
        #elseif canImport(Glibc)
        let descriptor = Glibc.open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR)
        )
        #else
        let descriptor: Int32 = -1
        #endif
        guard descriptor >= 0,
              fchmod(descriptor, mode_t(0o600)) == 0
        else {
            if descriptor >= 0 {
                #if canImport(Darwin)
                _ = Darwin.close(descriptor)
                #elseif canImport(Glibc)
                _ = Glibc.close(descriptor)
                #endif
            }
            throw SwanError.unavailable(
                "permissioned CAR test sink is unavailable"
            )
        }
        fileDescriptor = descriptor
    }

    func append(_ bytes: Data) throws {
        guard fileDescriptor >= 0 else {
            throw SwanError.unavailable(
                "permissioned CAR test sink is unavailable"
            )
        }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                try Task.checkCancellation()
                guard let baseAddress = buffer.baseAddress else { break }
                #if canImport(Darwin)
                let result = Darwin.write(
                    fileDescriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
                #elseif canImport(Glibc)
                let result = Glibc.write(
                    fileDescriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
                #else
                let result = -1
                #endif
                if result < 0, errno == EINTR { continue }
                guard result > 0 else {
                    throw SwanError.unavailable(
                        "permissioned CAR test sink is unavailable"
                    )
                }
                offset += result
            }
        }
        maximumChunkBytes = max(maximumChunkBytes, bytes.count)
    }

    func close() throws {
        guard fileDescriptor >= 0 else { return }
        let descriptor = fileDescriptor
        fileDescriptor = -1
        #if canImport(Darwin)
        let result = Darwin.close(descriptor)
        #elseif canImport(Glibc)
        let result = Glibc.close(descriptor)
        #else
        let result = -1
        #endif
        guard result == 0 else {
            throw SwanError.unavailable(
                "permissioned CAR test sink is unavailable"
            )
        }
    }
}

private actor PermissionedCARFileSource: SpaceCARRecoveryByteSource {
    private var fileDescriptor: Int32
    private var offset = 0
    private var reusableChunk = Data(
        count: SpaceCARRecoveryLimits.maximumChunkBytes
    )

    init(url: URL) throws {
        #if canImport(Darwin)
        let descriptor = Darwin.open(url.path, O_RDONLY)
        #elseif canImport(Glibc)
        let descriptor = Glibc.open(url.path, O_RDONLY)
        #else
        let descriptor: Int32 = -1
        #endif
        guard descriptor >= 0 else {
            throw SwanError.unavailable(
                "permissioned CAR test source is unavailable"
            )
        }
        fileDescriptor = descriptor
    }

    func read(maximumBytes: Int) throws -> Data? {
        guard fileDescriptor >= 0,
              maximumBytes > 0,
              maximumBytes <= reusableChunk.count
        else {
            throw SwanError.unavailable(
                "permissioned CAR test source is unavailable"
            )
        }
        let byteCount: Int = try reusableChunk.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return 0 }
            while true {
                #if canImport(Darwin)
                let result = Darwin.pread(
                    fileDescriptor,
                    baseAddress,
                    maximumBytes,
                    off_t(offset)
                )
                #elseif canImport(Glibc)
                let result = Glibc.pread(
                    fileDescriptor,
                    baseAddress,
                    maximumBytes,
                    off_t(offset)
                )
                #else
                let result = -1
                #endif
                if result >= 0 { return result }
                guard errno == EINTR else {
                    throw SwanError.unavailable(
                        "permissioned CAR test source is unavailable"
                    )
                }
            }
        }
        guard byteCount > 0 else { return nil }
        offset += byteCount
        if byteCount == reusableChunk.count {
            return reusableChunk
        }
        return Data(reusableChunk.prefix(byteCount))
    }

    func close() throws {
        guard fileDescriptor >= 0 else { return }
        let descriptor = fileDescriptor
        fileDescriptor = -1
        #if canImport(Darwin)
        let result = Darwin.close(descriptor)
        #elseif canImport(Glibc)
        let result = Glibc.close(descriptor)
        #else
        let result = -1
        #endif
        guard result == 0 else {
            throw SwanError.unavailable(
                "permissioned CAR test source is unavailable"
            )
        }
    }
}

private func largePermissionedRecordValue(
    index: Int,
    payloadBytes: Int
) throws -> Data {
    try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
        (key: "index", value: index),
        (key: "payload", value: Data(repeating: 0x6c, count: payloadBytes)),
    ]))
}

private func permissionedCARTID(_ offset: Int) throws -> TID {
    let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
    var value = UInt64(1_800_000_000_000_000_000) + UInt64(offset)
    var encoded: [Character] = []
    repeat {
        encoded.append(alphabet[Int(value & 31)])
        value >>= 5
    } while value != 0
    while encoded.count < 13 {
        encoded.append("2")
    }
    return try TID(tidString: String(encoded.reversed()))
}

private func permissionedCARFileSize(_ url: URL) throws -> Int {
    let values = try url.resourceValues(
        forKeys: [.fileSizeKey, .isRegularFileKey]
    )
    guard values.isRegularFile == true, let size = values.fileSize else {
        throw SwanError.unavailable("permissioned CAR test file is unavailable")
    }
    return size
}

private func currentPermissionedCARResidentBytes() -> Int? {
    #if canImport(Darwin)
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info>.size
            / MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(
            to: integer_t.self,
            capacity: Int(count)
        ) {
            task_info(
                mach_task_self_,
                task_flavor_t(MACH_TASK_BASIC_INFO),
                $0,
                &count
            )
        }
    }
    return result == KERN_SUCCESS ? Int(info.resident_size) : nil
    #elseif canImport(Glibc)
    guard let fields = try? String(
        contentsOfFile: "/proc/self/statm",
        encoding: .utf8
    ).split(separator: " "),
          fields.count > 1,
          let pages = Int(fields[1]),
          pages >= 0
    else {
        return nil
    }
    let pageSize = Int(sysconf(Int32(_SC_PAGESIZE)))
    guard pageSize > 0 else { return nil }
    let (bytes, overflow) = pages.multipliedReportingOverflow(by: pageSize)
    return overflow ? nil : bytes
    #else
    return nil
    #endif
}

private func permissionedCARSpoolFiles(in root: URL) throws -> [URL] {
    let directory = root.appending(
        path: "permissioned-car-spool",
        directoryHint: .isDirectory
    )
    guard FileManager.default.fileExists(atPath: directory.path) else {
        return []
    }
    return try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: [.isRegularFileKey],
        options: [.skipsHiddenFiles]
    )
}

private func testPermissionedCARFrameCount(_ data: Data) throws -> Int {
    var offset = 0
    let headerLength = try testPermissionedCARVarint(data, offset: &offset)
    guard headerLength <= data.count - offset else {
        throw SpaceCARStreamingError.malformedHeader
    }
    offset += headerLength
    var count = 0
    while offset < data.count {
        let frameLength = try testPermissionedCARVarint(data, offset: &offset)
        guard frameLength <= data.count - offset else {
            throw SpaceCARStreamingError.malformedFrame
        }
        offset += frameLength
        count += 1
    }
    return count
}

private func testPermissionedCARVarint(
    _ data: Data,
    offset: inout Int
) throws -> Int {
    var value: UInt64 = 0
    var shift: UInt64 = 0
    while offset < data.count, shift < 64 {
        let byte = data[offset]
        offset += 1
        value |= UInt64(byte & 0x7f) << shift
        if byte & 0x80 == 0 {
            guard value <= UInt64(Int.max) else {
                throw SpaceCARStreamingError.malformedVarint
            }
            return Int(value)
        }
        shift += 7
    }
    throw SpaceCARStreamingError.malformedVarint
}
