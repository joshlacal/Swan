import Foundation
import Petrel
import PetrelCrypto
import SwanSpaces

/// A bounded witness from a fully authenticated current-protocol STAR file.
public struct VerifiedSwanSTARWitness: Sendable {
    public let verification: VerifiedStreamingSpaceSTARRecovery
    public let verifiedExpectedWitnessCount: Int
}

public struct SwanSTARConsumer: Sendable {
    public let limits: SpaceSTARLimits
    public init(limits: SpaceSTARLimits = .standard) { self.limits = limits }

    public func verifyStreaming(
        fileURL: URL, space: SpaceURI, author: String,
        sharedSecret: Data, mac: Data,
        expectedEntries: [SpaceCARRecoveryIndexEntry] = []
    ) async throws -> VerifiedSwanSTARWitness {
        let source = try PermissionedRemoteReplicaFileSource(fileURL: fileURL)
        let sink = ExpectedSTARRecords(entries: expectedEntries)
        do {
            let result = try await SpaceSTARCodec.verifyStreaming(
                source: source, sink: sink, space: space, author: author, limits: limits,
                commitVerifier: { commit in
                    try SpaceMAC.verify(mac: mac, expected: commit.mac(sharedSecret: sharedSecret))
                    return true
                }
            )
            let matched = await sink.matched
            guard matched == expectedEntries.count else { throw SpaceSTARError.invalidRecord }
            await source.close()
            return VerifiedSwanSTARWitness(verification: result, verifiedExpectedWitnessCount: matched)
        } catch {
            await source.close()
            throw error
        }
    }
}

private actor ExpectedSTARRecords: SpaceSTARRecoverySink {
    let entries: [SpaceCARRecoveryIndexEntry]
    private(set) var matched = 0
    init(entries: [SpaceCARRecoveryIndexEntry]) { self.entries = entries }
    func stage(record: SpaceRecord) async throws {
        let path = "\(record.uri.collection)/\(record.uri.rkey)"
        for entry in entries where entry.path == path {
            guard entry.cid.string == record.cid else { throw SpaceSTARError.invalidRecord }
            matched += 1
        }
    }
    func discard() async { matched = 0 }
}
