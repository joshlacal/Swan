import Foundation
@testable import SwanSpaces
import XCTest
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class SpaceSTARBodySpoolTests: XCTestCase {
    private func spool(_ bytes: Data, declaredCount: Int? = nil) throws -> SpaceSTARBodySpool {
        // tmpfile creates an unnamed temporary file; no repository data is
        // left reachable by pathname, even if a test is interrupted.
        let file = try XCTUnwrap(tmpfile())
        let descriptor = dup(fileno(file))
        fclose(file)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try handle.write(contentsOf: bytes)
        return try SpaceSTARBodySpool(fileHandle: handle, bodyByteCount: declaredCount ?? bytes.count)
    }

    func testChunksAreBoundedAndSpoolIsSingleUse() async throws {
        let bytes = Data(repeating: 0x42, count: 2 * 65_536 + 7)
        let spool = try spool(bytes)
        var output = Data()
        var chunks: [Int] = []
        try await spool.streamBody { chunk in
            chunks.append(chunk.count)
            output.append(chunk)
        }
        XCTAssertEqual(output, bytes)
        XCTAssertEqual(chunks, [65_536, 65_536, 7])
        XCTAssertTrue(spool.isCleanedUp)
        do {
            try await spool.streamBody { _ in XCTFail("a consumed spool must not emit data") }
            XCTFail("spool reused")
        } catch {}
        spool.cleanup()
        XCTAssertTrue(spool.isCleanedUp)
    }

    func testConsumerFailureAlwaysCleansUp() async throws {
        let spool = try spool(Data(repeating: 1, count: 100))
        struct ConsumerError: Error {}
        do {
            try await spool.streamBody { _ in throw ConsumerError() }
            XCTFail("consumer failure must propagate")
        } catch { XCTAssertTrue(error is ConsumerError) }
        XCTAssertTrue(spool.isCleanedUp)
    }

    func testTruncatedAndGrownDescriptorsAreRejected() async throws {
        for declaredCount in [0, 2] {
            let spool = try spool(Data([1]), declaredCount: declaredCount)
            do {
                try await spool.streamBody { _ in }
                XCTFail("descriptor does not match its declared byte count")
            } catch {}
            XCTAssertTrue(spool.isCleanedUp)
        }
    }

    func testEmptySpoolAndInvalidChunkSize() async throws {
        let empty = try spool(Data())
        try await empty.streamBody { _ in XCTFail("empty spool emitted a chunk") }
        XCTAssertTrue(empty.isCleanedUp)
        let invalid = try spool(Data([1]))
        do {
            try await invalid.streamBody(maximumChunkBytes: 65_537) { _ in }
            XCTFail("unbounded chunk size accepted")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .limitExceeded) }
        XCTAssertTrue(invalid.isCleanedUp)
    }
}
