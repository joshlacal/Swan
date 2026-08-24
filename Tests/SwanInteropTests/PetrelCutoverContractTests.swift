import Foundation
import XCTest
import PetrelRepo
import PetrelFirehose
import PetrelPLC
import PetrelCrypto

final class PetrelCutoverContractTests: XCTestCase {
    func testPublicRepositoryTIDAcceptsAndPreservesRevision() throws {
        let rev = "3jzfcijpj2z2a"
        let tid = try PublicRepositoryTID(rev)
        XCTAssertEqual(tid.value, rev)
        XCTAssertEqual(tid.description, rev)
    }

    func testFirehoseFrameLimitsAcceptsValidSequenceAndRejectsZero() throws {
        XCTAssertNoThrow(try FirehoseFrameLimits.validateSequence(1))
        XCTAssertThrowsError(try FirehoseFrameLimits.validateSequence(0))
    }

    func testAccountIdentifiersValidatesPLCAndCanonicalizesHandle() throws {
        let validDID = "did:plc:z72i7hdynmk6r22z27h6tvur"
        let validated = try AccountIdentifiers.validateDID(validDID)
        XCTAssertEqual(validated, validDID)

        let canonical = try AccountIdentifiers.canonicalHandle("Alice.Example.COM")
        XCTAssertEqual(canonical, "alice.example.com")
    }

    func testHexRoundtripsBytes() {
        let original = Data([0x00, 0xab, 0xff])
        let encoded = Hex.encode(original)
        XCTAssertEqual(encoded.lowercased(), "00abff")
        let decoded = Hex.decode(encoded)
        XCTAssertEqual(decoded, original)
    }
}
