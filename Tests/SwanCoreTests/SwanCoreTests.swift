import Crypto
import Foundation
import XCTest
@testable import SwanCore
@testable import SwanSpacesWire

final class SwanCoreTests: XCTestCase {
    func testPinnedProfileLoadsAndEnforcesLtHashSize() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        let profile = try ProtocolProfile.load(from: file)
        XCTAssertEqual(profile.id, "permissioned-data-0016-2026-07-03")
        XCTAssertEqual(profile.crypto.lthashBytes, 2048)
        XCTAssertFalse(profile.permissionedDataIsEncrypted)
    }

    func testSensitiveValueIsNeverDescribed() {
        XCTAssertEqual(Sensitive("bearer-token").description, "[redacted]")
    }

    func testBootstrapWireRegistryCoversEveryPinnedOperation() {
        let methods = PermissionedData0016.methods
        XCTAssertEqual(methods.count, 27)
        XCTAssertEqual(Set(methods.map(\.nsid)).count, methods.count)
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.getRepo" && $0.outputEncoding == "application/vnd.ipld.car" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.getSpaceCredential" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.simplespace.updateSpace" })
    }

    func testP256WireSignaturesNormalizeAndRejectMalleableHighSValues() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("canonical P-256 wire signature".utf8)
        let canonical = try P256WireSignature.sign(message, using: key)
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(canonical))

        let highS = highSVariant(of: canonical)
        let highSSignature = try P256.Signing.ECDSASignature(rawRepresentation: highS)
        XCTAssertTrue(key.publicKey.isValidSignature(highSSignature, for: message))
        XCTAssertThrowsError(try P256WireSignature.decodeCanonical(highS))
        XCTAssertEqual(try P256WireSignature.canonicalize(highS), canonical)
    }

    // JOSE defines no canonical (r, s) encoding, so the malleability-tolerant
    // decoder must accept the high-S variant that `decodeCanonical` rejects —
    // while still enforcing structural scalar validation.
    func testMalleabilityTolerantDecodeAcceptsHighSButStillValidatesScalars() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("JOSE ES256 has no canonical encoding".utf8)
        let canonical = try P256WireSignature.sign(message, using: key)
        let highS = highSVariant(of: canonical)

        // Both encodings decode, and both verify against the same key.
        for raw in [canonical, highS] {
            let decoded = try P256WireSignature.decodeMalleabilityTolerant(raw)
            XCTAssertTrue(key.publicKey.isValidSignature(decoded, for: message))
        }
        // The strict decoder still rejects high-S, so AT Protocol's own
        // signature suites keep their canonical-encoding guarantee.
        XCTAssertThrowsError(try P256WireSignature.decodeCanonical(highS))

        // Structural validation is not weakened.
        XCTAssertThrowsError(
            try P256WireSignature.decodeMalleabilityTolerant(Data(repeating: 0, count: 63)))
        XCTAssertThrowsError(
            try P256WireSignature.decodeMalleabilityTolerant(Data(repeating: 0, count: 64)))
    }

    func testP256WireSignatureUsesTheExactP256HalfOrderBoundary() {
        let r = Data(repeating: 0, count: 31) + Data([1])
        let halfOrder = Data([
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xd6, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ])
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(r + halfOrder))

        var highS = halfOrder
        highS[highS.index(before: highS.endIndex)] += 1
        XCTAssertFalse(P256WireSignature.isCanonicalLowS(r + highS))
    }
}

private func highSVariant(of canonicalSignature: Data) -> Data {
    precondition(canonicalSignature.count == 64)
    let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]
    let lowS = Array(canonicalSignature.suffix(32))
    var highS = Array(repeating: UInt8.zero, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        var value = Int(order[index]) - Int(lowS[index]) - borrow
        if value < 0 {
            value += 256
            borrow = 1
        } else {
            borrow = 0
        }
        highS[index] = UInt8(value)
    }
    precondition(borrow == 0)
    return Data(canonicalSignature.prefix(32)) + Data(highS)
}
