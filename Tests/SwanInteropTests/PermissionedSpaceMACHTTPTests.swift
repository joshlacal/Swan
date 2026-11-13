import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanOAuth
import SwanSpaces
@testable import SwanInterop
import XCTest

final class PermissionedSpaceMACHTTPTests: XCTestCase {
    func testRefreshesRotatedKEMAndUsesNewKeyForEveryAttempt() async throws {
        let fixture = try MACHTTPFixture()
        let oldKey = P256.KeyAgreement.PrivateKey()
        let resolver = MACKeyResolver(
            stale: try MACHTTPFixture.didKey(oldKey),
            current: fixture.didKey
        )
        let transport = MACResponseTransport(key: fixture.key, commit: fixture.commit)
        let host = try fixture.host(transport: transport, resolver: resolver)
        _ = try await fixture.query(host)
        _ = try await fixture.query(host)
        let refreshes = await resolver.refreshes
        XCTAssertEqual(refreshes, [false, true, false])
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(keyIDs.count, 3)
        XCTAssertEqual(Set(keyIDs).count, 3)
    }

    func testRepeatedMACFailureStopsAfterOneRefresh() async throws {
        let fixture = try MACHTTPFixture()
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(
            key: fixture.key,
            commit: fixture.commit,
            mode: .wrongSecret
        )
        do {
            _ = try await fixture.query(try fixture.host(
                transport: transport,
                resolver: resolver
            ))
            XCTFail("repeated bad MAC accepted")
        } catch {
            XCTAssertEqual(
                error as? SpaceMACHeaders.HeaderError,
                .invalidSpaceMAC
            )
        }
        let refreshes = await resolver.refreshes
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(refreshes, [false, true])
        XCTAssertEqual(Set(keyIDs).count, 2)
    }

    func testValidMACForWrongRepositoryIsRejectedWithoutRefresh() async throws {
        let fixture = try MACHTTPFixture()
        let wrong = ComAtprotoSpaceDefs.Commit(
            ver: 1,
            repo: try DID(didString: "did:plc:wrongrepository"),
            space: fixture.commit.space,
            rev: fixture.commit.rev,
            data: fixture.commit.data
        )
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: wrong)
        do {
            _ = try await fixture.query(try fixture.host(
                transport: transport,
                resolver: resolver
            ))
            XCTFail("foreign repository accepted")
        } catch {
            XCTAssertEqual(error as? SpaceSTARError, .wrongRepository)
        }
        let refreshes = await resolver.refreshes
        XCTAssertEqual(refreshes, [false])
    }

    func testCommitHeaderBodyMismatchRefreshesThenFails() async throws {
        try await assertCommitFailure(.headerBodyMismatch)
    }

    func testResponseKeyIDMismatchRefreshesThenFails() async throws {
        try await assertCommitFailure(.keyIDMismatch)
    }

    func testRecordRequestsUseFreshKeysAndAuthenticateCanonicalValue() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(fixture: fixture, mode: .valid)
        let host = try fixture.recordHost(transport)
        for _ in 0 ..< 2 {
            let response = try await PermissionedSpaceMACHTTP.record(
                host: host,
                query: [:],
                expectedURI: transport.uri,
                authorization: { .none }
            )
            XCTAssertEqual(response.status, 200)
        }
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(keyIDs.count, 2)
        XCTAssertEqual(Set(keyIDs).count, 2)
    }

    func testRecordRejectsAlteredValueEvenWithValidMACForItsClaimedCID() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(
            fixture: fixture,
            mode: .alteredValue
        )
        do {
            _ = try await PermissionedSpaceMACHTTP.record(
                host: fixture.recordHost(transport),
                query: [:],
                expectedURI: transport.uri,
                authorization: { .none }
            )
            XCTFail("record bytes did not match the authenticated CID")
        } catch {
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaIncrementalVerificationError,
                .valueCIDMismatch
            )
        }
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(
            keyIDs.count,
            1,
            "content mismatch is not a key-rotation retry"
        )
    }

    func testRecordRejectsValidMACForAnotherURI() async throws {
        let fixture = try MACHTTPFixture()
        let transport = try MACRecordResponseTransport(
            fixture: fixture,
            mode: .foreignURI
        )
        do {
            _ = try await PermissionedSpaceMACHTTP.record(
                host: fixture.recordHost(transport),
                query: [:],
                expectedURI: transport.uri,
                authorization: { .none }
            )
            XCTFail("foreign record URI accepted")
        } catch {
            XCTAssertEqual(error as? SpaceSTARError, .wrongRepository)
        }
    }

    func testMissingPageCommitRetriesWithFreshKeysThenFails() async throws {
        let fixture = try MACHTTPFixture()
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(key: fixture.key, commit: nil)
        do {
            _ = try await PermissionedSpaceMACHTTP.query(
                host: try fixture.host(transport: transport, resolver: resolver),
                nsid: "com.atproto.space.listRepoOps",
                query: [:],
                space: fixture.space,
                author: fixture.author,
                authorization: { .none },
                commit: {
                    try JSONDecoder().decode(
                        ComAtprotoSpaceListRepoOps.Output.self,
                        from: $0
                    ).commit
                }
            )
            XCTFail("commitless Nov-12 page accepted")
        } catch {
            XCTAssertEqual(
                error as? SpaceMACHeaders.HeaderError,
                .invalidSpaceMAC
            )
        }
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(Set(keyIDs).count, 2)
    }

    private func assertCommitFailure(
        _ mode: MACResponseTransport.Mode
    ) async throws {
        let fixture = try MACHTTPFixture()
        let resolver = MACKeyResolver(stale: fixture.didKey, current: fixture.didKey)
        let transport = MACResponseTransport(
            key: fixture.key,
            commit: fixture.commit,
            mode: mode
        )
        do {
            _ = try await fixture.query(try fixture.host(
                transport: transport,
                resolver: resolver
            ))
            XCTFail("invalid response accepted")
        } catch {
            XCTAssertEqual(
                error as? SpaceMACHeaders.HeaderError,
                .invalidSpaceMAC
            )
        }
        let refreshes = await resolver.refreshes
        let keyIDs = await transport.keyIDs
        XCTAssertEqual(refreshes, [false, true])
        XCTAssertEqual(Set(keyIDs).count, 2)
    }
}

private struct MACHTTPFixture {
    let author = "did:plc:repositoryabcdefghij"
    let space: SpaceURI
    let key: P256.KeyAgreement.PrivateKey
    let didKey: String
    let commit: ComAtprotoSpaceDefs.Commit

    init() throws {
        space = try SpaceURI(
            "at://did:plc:authorityabcdefghijk/space/app.swan.test/mac"
        )
        key = P256.KeyAgreement.PrivateKey()
        didKey = try Self.didKey(key)
        commit = .init(
            ver: 1,
            repo: try DID(didString: author),
            space: try SpaceRef(uriString: space.rawValue),
            rev: try TID(tidString: "222222222222a"),
            data: Bytes(data: LtHash().commitment)
        )
    }

    static func didKey(_ key: P256.KeyAgreement.PrivateKey) throws -> String {
        P256DIDKey(
            publicKey: try P256.Signing.PublicKey(
                x963Representation: key.publicKey.x963Representation
            )
        ).value
    }

    func host(
        transport: MACResponseTransport,
        resolver: MACKeyResolver
    ) throws -> LiveInteropHost {
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://source.example")!,
            executeHandler: { method, url, headers, _, _ in
                try await transport.respond(
                    method: method,
                    url: url,
                    headers: headers
                )
            }
        )
        return LiveInteropHost(
            label: "mock-source",
            client: InteropXRPCClient(http: http),
            permissionedKEMKeyProvider: { _, forceRefresh in
                await resolver.resolve(forceRefresh: forceRefresh)
            }
        )
    }

    func recordHost(
        _ transport: MACRecordResponseTransport
    ) throws -> LiveInteropHost {
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://source.example")!,
            executeHandler: { _, url, headers, _, _ in
                try await transport.respond(url: url, headers: headers)
            }
        )
        return LiveInteropHost(
            label: "mock-record",
            client: InteropXRPCClient(http: http),
            permissionedKEMKey: didKey
        )
    }

    func query(
        _ host: LiveInteropHost
    ) async throws -> PermissionedSpaceMACResponse {
        try await PermissionedSpaceMACHTTP.query(
            host: host,
            nsid: "com.atproto.space.getLatestCommit",
            query: ["repo": author, "space": space.rawValue],
            space: space,
            author: author,
            authorization: { .none },
            commit: {
                try JSONDecoder().decode(
                    ComAtprotoSpaceGetLatestCommit.Output.self,
                    from: $0
                ).commit
            }
        )
    }
}

private actor MACKeyResolver {
    let stale: String
    let current: String
    private var refreshed = false
    private(set) var refreshes: [Bool] = []

    init(stale: String, current: String) {
        self.stale = stale
        self.current = current
    }

    func resolve(forceRefresh: Bool) -> String {
        refreshes.append(forceRefresh)
        if forceRefresh { refreshed = true }
        return refreshed ? current : stale
    }
}

private actor MACResponseTransport {
    enum Mode: Sendable, Equatable {
        case valid
        case wrongSecret
        case headerBodyMismatch
        case keyIDMismatch
    }

    let key: P256.KeyAgreement.PrivateKey
    let commit: ComAtprotoSpaceDefs.Commit?
    let mode: Mode
    private(set) var keyIDs: [String] = []

    init(
        key: P256.KeyAgreement.PrivateKey,
        commit: ComAtprotoSpaceDefs.Commit?,
        mode: Mode = .valid
    ) {
        self.key = key
        self.commit = commit
        self.mode = mode
    }

    func respond(
        method: InteropHTTPMethod,
        url: URL,
        headers: [String: String]
    ) throws -> InteropHTTPResponse {
        XCTAssertEqual(method, .get)
        let request = try XCTUnwrap(SpaceMACHeaders.parseRequest(
            headers[SpaceMACHeaders.requestHeader],
            profile: .commit
        ))
        keyIDs.append(request.keyID)
        var responseHeaders = ["content-type": "application/json"]
        let body: Data
        if let commit {
            let secret = try SpaceMACKeyAgreement.receive(
                authorPrivateKey: key,
                keyID: request.keyID
            )
            let bodyCommit = try spaceCommit(commit)
            let coveredCommit: SpaceRepositoryCommit
            if mode == .headerBodyMismatch {
                coveredCommit = try SpaceRepositoryCommit(
                    repo: bodyCommit.repo,
                    space: bodyCommit.space,
                    rev: "222222222222b",
                    data: bodyCommit.data
                )
            } else {
                coveredCommit = bodyCommit
            }
            let response = try SpaceMACHeaders.commitResponse(
                coveredCommit,
                request: request,
                sharedSecret: mode == .wrongSecret
                    ? Data(repeating: 0, count: 32)
                    : secret
            )
            responseHeaders.merge(macHeaders(response)) { _, new in new }
            if mode == .keyIDMismatch {
                let other = try MACHTTPFixture.didKey(
                    P256.KeyAgreement.PrivateKey()
                )
                responseHeaders[SpaceMACHeaders.signatureInputHeader] =
                    response.signatureInput.replacingOccurrences(
                        of: request.keyID,
                        with: other
                    )
            }
            body = try JSONEncoder().encode(
                ComAtprotoSpaceGetLatestCommit.Output(commit: commit)
            )
        } else {
            // Deliberately malformed Nov-12 response: every page requires a
            // commit, so construct raw JSON instead of the non-optional model.
            body = Data(#"{"ops":[]}"#.utf8)
        }
        return .init(
            status: 200,
            headers: responseHeaders,
            body: body,
            finalURL: url,
            redirectCount: 0
        )
    }
}

private actor MACRecordResponseTransport {
    enum Mode: Sendable, Equatable {
        case valid
        case alteredValue
        case foreignURI
    }

    let uri: SpaceRecordURI
    let key: P256.KeyAgreement.PrivateKey
    let mode: Mode
    private(set) var keyIDs: [String] = []

    init(fixture: MACHTTPFixture, mode: Mode) throws {
        uri = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.swan.test",
            rkey: "record"
        )
        key = fixture.key
        self.mode = mode
    }

    func respond(
        url: URL,
        headers: [String: String]
    ) throws -> InteropHTTPResponse {
        let request = try XCTUnwrap(SpaceMACHeaders.parseRequest(
            headers[SpaceMACHeaders.requestHeader],
            profile: .record
        ))
        keyIDs.append(request.keyID)
        let value = ATProtocolValueContainer.object([
            "$type": .string(uri.collection),
            "text": .string("original"),
        ])
        let cid = try CID.fromDAGCBOR(DAGCBOR.encodeValue(value.toCBORValue()))
        let returnedURI = mode == .foreignURI
            ? try SpaceRecordURI(
                space: uri.space,
                author: uri.author,
                collection: uri.collection,
                rkey: "another"
            )
            : uri
        let returnedValue = mode == .alteredValue
            ? ATProtocolValueContainer.object([
                "$type": .string(uri.collection),
                "text": .string("tampered"),
            ])
            : value
        let secret = try SpaceMACKeyAgreement.receive(
            authorPrivateKey: key,
            keyID: request.keyID
        )
        let responseMAC = try SpaceMACHeaders.recordResponse(
            uri: returnedURI.rawValue,
            cid: cid.string,
            request: request,
            sharedSecret: secret
        )
        let body = try JSONEncoder().encode(
            ComAtprotoSpaceGetRecord.Output(
                uri: ATProtocolURI(uriString: returnedURI.rawValue),
                cid: cid,
                value: returnedValue
            )
        )
        var responseHeaders = ["content-type": "application/json"]
        responseHeaders.merge(macHeaders(responseMAC)) { _, new in new }
        return .init(
            status: 200,
            headers: responseHeaders,
            body: body,
            finalURL: url,
            redirectCount: 0
        )
    }
}

private func spaceCommit(
    _ commit: ComAtprotoSpaceDefs.Commit
) throws -> SpaceRepositoryCommit {
    try SpaceRepositoryCommit(
        ver: commit.ver,
        repo: commit.repo.didString(),
        space: SpaceURI(commit.space.uriString()),
        rev: commit.rev.toString(),
        data: commit.data.data
    )
}

private func macHeaders(
    _ response: SpaceMACHeaders.ResponseHeaders
) -> [String: String] {
    [
        response.coveredHeaderName: response.coveredHeaderValue,
        SpaceMACHeaders.signatureInputHeader: response.signatureInput,
        SpaceMACHeaders.signatureHeader: response.signature,
    ]
}
