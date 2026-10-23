import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanOAuth
import SwanSpaces
@testable import SwanInterop
import XCTest

final class PermissionedSpaceMACHTTPTests: XCTestCase {
    func testRefreshesRotatedKEMAndUsesNewShareForEveryAttempt() async throws {
        let fixture = try MACHTTPFixture()
        let oldKey = P256.KeyAgreement.PrivateKey()
        let resolver = MACKeyResolver(stale: try MACHTTPFixture.didKey(oldKey), current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: fixture.commit)
        let host = try fixture.host(transport: transport, resolver: resolver)
        _ = try await fixture.query(host)
        _ = try await fixture.query(host)
        let refreshes = await resolver.refreshes
        let shares = await transport.shares
        XCTAssertEqual(refreshes, [false, true, false])
        XCTAssertEqual(shares.count, 3)
        XCTAssertEqual(Set(shares).count, 3)
    }

    func testRepeatedMACFailureStopsAfterOneRefresh() async throws {
        let fixture = try MACHTTPFixture()
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: fixture.commit, invalidMAC: true)
        let host = try fixture.host(transport: transport, resolver: resolver)
        do {
            _ = try await fixture.query(host)
            XCTFail("repeated bad MAC accepted")
        } catch { XCTAssertEqual(error as? SpaceMAC.Failure, .mismatch) }
        let refreshes = await resolver.refreshes
        let shares = await transport.shares
        XCTAssertEqual(refreshes, [false, true])
        XCTAssertEqual(Set(shares).count, 2)
    }

    func testValidMACForWrongRepositoryIsRejectedWithoutRefresh() async throws {
        let fixture = try MACHTTPFixture()
        let wrong = ComAtprotoSpaceDefs.Commit(
            ver: 1, repo: try DID(didString: "did:plc:wrongrepository"), space: fixture.commit.space,
            rev: fixture.commit.rev, data: fixture.commit.data
        )
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: wrong)
        let host = try fixture.host(transport: transport, resolver: resolver)
        do {
            _ = try await fixture.query(host)
            XCTFail("foreign repository accepted")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .wrongRepository) }
        let refreshes = await resolver.refreshes
        XCTAssertEqual(refreshes, [false])
    }

    func testRecordRequestsUseFreshSharesAndAuthenticateCanonicalValue() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(fixture: fixture, mode: .valid)
        let host = try fixture.recordHost(transport)
        for _ in 0..<2 {
            let response = try await PermissionedSpaceMACHTTP.record(
                host: host, query: [:], expectedURI: transport.uri, authorization: { .none }
            )
            XCTAssertEqual(response.status, 200)
        }
        let shares = await transport.shares
        XCTAssertEqual(shares.count, 2)
        XCTAssertEqual(Set(shares).count, 2)
    }

    func testRecordRejectsAlteredValueEvenWithValidMACForItsClaimedCID() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(fixture: fixture, mode: .alteredValue)
        do {
            _ = try await PermissionedSpaceMACHTTP.record(
                host: fixture.recordHost(transport), query: [:], expectedURI: transport.uri, authorization: { .none }
            )
            XCTFail("record bytes did not match the authenticated CID")
        } catch {
            XCTAssertEqual(error as? PermissionedRemoteReplicaIncrementalVerificationError, .valueCIDMismatch)
        }
        let shares = await transport.shares
        XCTAssertEqual(shares.count, 1, "content mismatch is not a key-rotation retry")
    }

    func testRecordRejectsValidMACForAnotherURI() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(fixture: fixture, mode: .foreignURI)
        do {
            _ = try await PermissionedSpaceMACHTTP.record(
                host: fixture.recordHost(transport), query: [:], expectedURI: transport.uri, authorization: { .none }
            )
            XCTFail("foreign record URI accepted")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .wrongRepository) }
    }

    func testCommitlessPagesStillSendDistinctKeySharesAndReceiveNoMAC() async throws {
        let fixture = try MACHTTPFixture()
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: nil)
        let host = try fixture.host(transport: transport, resolver: resolver)
        for cursor in ["first", "second"] {
            let result = try await PermissionedSpaceMACHTTP.query(
                host: host, nsid: "com.atproto.space.listRepoOps", query: ["cursor": cursor],
                space: fixture.space, author: fixture.author, authorization: { .none },
                commit: { try JSONDecoder().decode(ComAtprotoSpaceListRepoOps.Output.self, from: $0).commit }
            )
            XCTAssertNil(result.commit)
            XCTAssertNil(result.response.header(SpaceMACHeaders.responseHeader))
        }
        let shares = await transport.shares
        XCTAssertEqual(Set(shares).count, 2)
    }
}

private struct MACHTTPFixture {
    let author = "did:plc:repositoryabcdefghij"
    let space: SpaceURI
    let key: P256.KeyAgreement.PrivateKey
    let didKey: String
    let commit: ComAtprotoSpaceDefs.Commit
    init() throws {
        space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/mac")
        key = P256.KeyAgreement.PrivateKey()
        didKey = try Self.didKey(key)
        commit = .init(ver: 1, repo: try DID(didString: author), space: try SpaceRef(uriString: space.rawValue), rev: try TID(tidString: "222222222222a"), data: Bytes(data: LtHash().commitment))
    }
    static func didKey(_ key: P256.KeyAgreement.PrivateKey) throws -> String {
        try P256DIDKey(publicKey: P256.Signing.PublicKey(compressedRepresentation: key.publicKey.compressedRepresentation)).value
    }
    func host(transport: MACResponseTransport, resolver: MACKeyResolver) throws -> LiveInteropHost {
        let http = try InteropHTTPClient(baseURL: URL(string: "https://source.example")!, executeHandler: { method, url, headers, _, _ in
            try await transport.respond(method: method, url: url, headers: headers)
        })
        return LiveInteropHost(label: "mock-source", client: InteropXRPCClient(http: http), permissionedKEMKeyProvider: { _, forceRefresh in
            await resolver.resolve(forceRefresh: forceRefresh)
        })
    }
    func recordHost(_ transport: MACRecordResponseTransport) throws -> LiveInteropHost {
        let http = try InteropHTTPClient(baseURL: URL(string: "https://source.example")!, executeHandler: { _, url, headers, _, _ in
            try await transport.respond(url: url, headers: headers)
        })
        return LiveInteropHost(label: "mock-record", client: InteropXRPCClient(http: http), permissionedKEMKey: didKey)
    }
    func query(_ host: LiveInteropHost) async throws -> PermissionedSpaceMACResponse {
        try await PermissionedSpaceMACHTTP.query(
            host: host, nsid: "com.atproto.space.getLatestCommit", query: ["repo": author, "space": space.rawValue],
            space: space, author: author, authorization: { .none },
            commit: { try JSONDecoder().decode(ComAtprotoSpaceGetLatestCommit.Output.self, from: $0).commit }
        )
    }
}

private actor MACKeyResolver {
    let stale: String
    let current: String
    private var refreshed = false
    private(set) var refreshes: [Bool] = []
    init(stale: String, current: String) { self.stale = stale; self.current = current }
    func resolve(forceRefresh: Bool) -> String {
        refreshes.append(forceRefresh)
        if forceRefresh { refreshed = true }
        return refreshed ? current : stale
    }
}

private actor MACResponseTransport {
    let key: P256.KeyAgreement.PrivateKey
    let commit: ComAtprotoSpaceDefs.Commit?
    let invalidMAC: Bool
    private(set) var shares: [String] = []
    init(key: P256.KeyAgreement.PrivateKey, commit: ComAtprotoSpaceDefs.Commit?, invalidMAC: Bool = false) {
        self.key = key; self.commit = commit; self.invalidMAC = invalidMAC
    }
    func respond(method: InteropHTTPMethod, url: URL, headers: [String: String]) throws -> InteropHTTPResponse {
        XCTAssertEqual(method, .get)
        let request = try SpaceMACHeaders.parseWantMAC(headers[SpaceMACHeaders.requestHeader], type: .repository)
        shares.append(request.keyShare)
        var responseHeaders = ["content-type": "application/json"]
        let body: Data
        if let commit {
            let secret = try SpaceMAC.decapsulate(privateKey: key, keyShare: request.keyShare)
            let mac = invalidMAC ? Data(repeating: 0, count: 32) : try SpaceMAC.commit(sharedSecret: secret, space: commit.space.uriString(), repo: commit.repo.didString(), rev: commit.rev.toString(), data: commit.data.data)
            responseHeaders[SpaceMACHeaders.responseHeader] = try SpaceMACHeaders.formatMAC(mac, type: .repository)
            body = try JSONEncoder().encode(ComAtprotoSpaceGetLatestCommit.Output(commit: commit))
        } else {
            body = try JSONEncoder().encode(ComAtprotoSpaceListRepoOps.Output(ops: [], commit: nil, cursor: nil))
        }
        return .init(status: 200, headers: responseHeaders, body: body, finalURL: url, redirectCount: 0)
    }
}

private actor MACRecordResponseTransport {
    enum Mode: Sendable, Equatable { case valid, alteredValue, foreignURI }
    let uri: SpaceRecordURI
    let key: P256.KeyAgreement.PrivateKey
    let mode: Mode
    private(set) var shares: [String] = []
    init(fixture: MACHTTPFixture, mode: Mode) throws {
        uri = try SpaceRecordURI(space: fixture.space, author: fixture.author, collection: "app.swan.test", rkey: "record")
        key = fixture.key
        self.mode = mode
    }
    func respond(url: URL, headers: [String: String]) throws -> InteropHTTPResponse {
        let request = try SpaceMACHeaders.parseWantMAC(headers[SpaceMACHeaders.requestHeader], type: .record)
        shares.append(request.keyShare)
        let value = ATProtocolValueContainer.object(["$type": .string(uri.collection), "text": .string("original")])
        let cid = try CID.fromDAGCBOR(DAGCBOR.encodeValue(value.toCBORValue()))
        let returnedURI = mode == .foreignURI
            ? try SpaceRecordURI(space: uri.space, author: uri.author, collection: uri.collection, rkey: "another")
            : uri
        let returnedValue = mode == .alteredValue
            ? ATProtocolValueContainer.object(["$type": .string(uri.collection), "text": .string("tampered")])
            : value
        let secret = try SpaceMAC.decapsulate(privateKey: key, keyShare: request.keyShare)
        let mac = try SpaceMAC.record(sharedSecret: secret, uri: returnedURI.rawValue, cid: cid.bytes)
        let body = try JSONEncoder().encode(ComAtprotoSpaceGetRecord.Output(
            uri: ATProtocolURI(uriString: returnedURI.rawValue), cid: cid, value: returnedValue
        ))
        return .init(status: 200, headers: ["content-type": "application/json", SpaceMACHeaders.responseHeader: try SpaceMACHeaders.formatMAC(mac, type: .record)], body: body, finalURL: url, redirectCount: 0)
    }
}
