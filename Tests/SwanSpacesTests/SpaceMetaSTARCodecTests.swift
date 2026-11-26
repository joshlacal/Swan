import Foundation
import Petrel
import PetrelCrypto
import SwanCore
@testable import SwanSpaces
import XCTest

/// The `atproto-space-meta` STAR profile: what the reader refuses, so an
/// import can never silently drop access state.
final class SpaceMetaSTARCodecTests: XCTestCase {
    private let owner = "did:plc:alice"
    private var space: SpaceURI { get throws { try SpaceURI("at:space/did:plc:alice/app.bsky.bookmarks/self") } }

    private func archive() throws -> SpaceMetaArchive {
        try SpaceMetaArchive(
            space: space,
            policy: .member(try MemberSpacePolicy(publishMembers: true)),
            members: [
                try SpaceMetaMember(did: "did:plc:bob", read: true, write: false),
                try SpaceMetaMember(did: "did:plc:carol", read: true, write: true),
            ],
            writers: [
                try SpaceMetaWriter(
                    did: "did:plc:bob", repoRev: "3m2aaaaaaaaa2", data: Data(repeating: 1, count: 32),
                    spaceRev: "3m2aaaaaaaab2"
                ),
            ]
        )
    }

    private func metadata(type: String = SpaceMetaSTARCodec.metadataType, ver: Int = 1) throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: type), (key: "ver", value: ver), (key: "space", value: try space.rawValue),
        ]))
    }

    private func policy(_ type: String = "com.atproto.memberspace.policy") throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [(key: "$type", value: type)]))
    }

    private func member(read: Any = true, write: Any = false) throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: SpacePolicy.memberRecordCollection),
            (key: "read", value: read), (key: "write", value: write),
        ]))
    }

    private func writer(revisionKey: String = "repoRev") throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: revisionKey, value: "3m2aaaaaaaaa2"),
            (key: "data", value: Data(repeating: 1, count: 32)),
            (key: "spaceRev", value: "3m2aaaaaaaab2"),
        ]))
    }

    private func raw(_ entries: [(String, Data)], metadata: Data? = nil) throws -> Data {
        var output = SpaceSTARCodec.magic
        SpaceSTARCodec.appendFrame(try metadata ?? self.metadata(), to: &output)
        for (key, value) in entries {
            output.append(0x01)
            SpaceSTARCodec.appendFrame(Data(key.utf8), to: &output)
            SpaceSTARCodec.appendFrame(value, to: &output)
        }
        output.append(0x00)
        return output
    }

    private func assertInvalid(_ bytes: Data, _ message: String, line: UInt = #line) {
        XCTAssertThrowsError(try SpaceMetaSTARCodec.decode(bytes), message, line: line) { error in
            XCTAssertEqual(error as? SpaceMetaArchiveError, .invalidArchive, message, line: line)
        }
    }

    func testRoundTripIsByteStable() throws {
        let original = try archive()
        let bytes = try SpaceMetaSTARCodec.encode(original)
        XCTAssertEqual(bytes.prefix(4), Data([0x2a, 0x6c, 0x01, 0x00]))
        let decoded = try SpaceMetaSTARCodec.decode(bytes)
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(try SpaceMetaSTARCodec.encode(decoded), bytes)
    }

    func testHandBuiltArchiveDecodes() throws {
        let decoded = try SpaceMetaSTARCodec.decode(try raw([
            ("policy", try policy()),
            ("com.atproto.memberspace.member/did:plc:bob", try member()),
            ("writer/did:plc:bob", try writer()),
        ]))
        XCTAssertEqual(decoded.members, [try SpaceMetaMember(did: "did:plc:bob", read: true, write: false)])
        XCTAssertEqual(decoded.writers.map(\.spaceRev), ["3m2aaaaaaaab2"])
    }

    func testRejectsLegacyWriterRevAndInvalidControls() throws {
        assertInvalid(
            try raw([("policy", try policy()), ("writer/did:plc:bob", try writer(revisionKey: "rev"))]),
            "legacy rev"
        )
        var invalidControl = try raw([("policy", try policy())])
        invalidControl[SpaceSTARCodec.magic.count + 1 + (try metadata().count)] = 0x02
        assertInvalid(invalidControl, "invalid control")
        assertInvalid(try raw([("policy", try policy())]) + Data([0xff]), "trailing bytes")
    }

    func testUnknownPolicyTypeIsUnsupportedPolicy() throws {
        XCTAssertThrowsError(try SpaceMetaSTARCodec.decode(try raw([("policy", try policy("com.example.policy"))]))) {
            XCTAssertEqual($0 as? SpacePolicyError, .unsupportedPolicy)
        }
    }

    func testRefusesMissingPolicyUnknownKeysAndBadMetadata() throws {
        assertInvalid(try raw([]), "no policy")
        assertInvalid(try raw([("writer/did:plc:bob", try writer())]), "writers without a policy")
        assertInvalid(try raw([("policy", try policy()), ("com.example.state/x", try member())]), "unknown state key")
        assertInvalid(
            try raw([("policy", try policy()), ("com.atproto.memberspace.member/not-a-did", try member())]),
            "member key that is not a DID"
        )
        assertInvalid(
            try raw([("policy", try policy("com.atproto.personalspace.policy")),
                     ("com.atproto.memberspace.member/did:plc:bob", try member())]),
            "member state under a policy that has none"
        )
        assertInvalid(
            try raw([("policy", try policy()), ("com.atproto.memberspace.member/did:plc:bob", try member(read: 1))]),
            "non-boolean read"
        )
        assertInvalid(try raw([("policy", try policy())], metadata: try metadata(type: "atproto-space-repo")), "wrong $type")
        assertInvalid(try raw([("policy", try policy())], metadata: try metadata(ver: 2)), "unknown version")
        var truncated = try SpaceMetaSTARCodec.encode(try archive())
        truncated.removeLast()
        assertInvalid(truncated, "truncated")
    }

    func testRefusesOutOfOrderSectionsKeysAndDuplicates() throws {
        assertInvalid(
            try raw([("policy", try policy()), ("writer/did:plc:bob", try writer()),
                     ("com.atproto.memberspace.member/did:plc:bob", try member())]),
            "policy state after writers"
        )
        assertInvalid(
            try raw([("com.atproto.memberspace.member/did:plc:bob", try member()), ("policy", try policy())]),
            "policy not first"
        )
        assertInvalid(
            try raw([("policy", try policy()),
                     ("com.atproto.memberspace.member/did:plc:carol", try member()),
                     ("com.atproto.memberspace.member/did:plc:bob", try member())]),
            "member keys out of order"
        )
        assertInvalid(
            try raw([("policy", try policy()),
                     ("com.atproto.memberspace.member/did:plc:bob", try member()),
                     ("com.atproto.memberspace.member/did:plc:bob", try member())]),
            "duplicate member"
        )
        assertInvalid(
            try raw([("policy", try policy()), ("writer/did:plc:bob", try writer()), ("writer/did:plc:bob", try writer())]),
            "duplicate writer"
        )
        assertInvalid(try raw([("policy", try policy()), ("policy", try policy())]), "duplicate policy")
    }

    func testEncoderRefusesDuplicatesAndMembersOutsideMemberspace() throws {
        let bob = try SpaceMetaMember(did: "did:plc:bob", read: true, write: true)
        XCTAssertThrowsError(try SpaceMetaSTARCodec.encode(try SpaceMetaArchive(
            space: space, policy: .member(try MemberSpacePolicy()), members: [bob, bob], writers: []
        )))
        XCTAssertThrowsError(try SpaceMetaWriter(did: "did:plc:bob", repoRev: "3m2aaaaaaaaa2", data: Data(count: 31), spaceRev: "3m2aaaaaaaab2"))
    }
}
