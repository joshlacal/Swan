import Crypto
import Foundation
import XCTest
@testable import SwanSpaces
@testable import SwanStorage
@testable import SwanSQLite
@testable import SwanCore

final class SwanSpacesTests: XCTestCase {
    func testBLAKE3ReferenceVectorAndLtHashInvolution() throws {
        XCTAssertEqual(
            Blake3.xof(Data(), outputLength: 32).map { String(format: "%02x", $0) }.joined(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        )
        var state = LtHash()
        let original = state.serialized
        XCTAssertEqual(
            Hex.encode(state.commitment),
            "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"
        )
        state.add(element: "record-token")
        XCTAssertNotEqual(state.commitment, Data(SHA256.hash(data: original)))
        let afterFirstAdd = state.serialized
        state.add(element: "record-token")
        XCTAssertNotEqual(state.serialized, original, "LtHash is modular addition, not XOR")
        state.remove(element: "record-token")
        XCTAssertEqual(state.serialized, afterFirstAdd)
        state.remove(element: "record-token")
        XCTAssertEqual(state.serialized, original)
    }

    func testStrictSpaceURIGrammar() throws {
        let uri = try SpaceRecordURI("at://did:plc:alice/space/app.bsky.bookmarks/self/did:plc:bob/app.bsky.feed.post/one")
        XCTAssertEqual(uri.space.authority, "did:plc:alice")
        XCTAssertEqual(uri.space.spaceType, "app.bsky.bookmarks")
        XCTAssertEqual(uri.author, "did:plc:bob")
        XCTAssertEqual(uri.rawValue, "at://did:plc:alice/space/app.bsky.bookmarks/self/did:plc:bob/app.bsky.feed.post/one")
        XCTAssertThrowsError(try SpaceURI("at://did:plc:alice/not-space/bookmarks"))
        XCTAssertThrowsError(try SpaceRecordURI("at://did:plc:alice/space/app.bsky.bookmarks/self/app.bsky.feed.post/one"))
    }

    func testRepositoryEnforcesCredentialAndRecoversAfterOplogGap() async throws {
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "self")
        let first = try SpaceRecordURI(space: space, author: "did:plc:alice", collection: "app.bsky.feed.post", rkey: "one")
        let second = try SpaceRecordURI(space: space, author: "did:plc:alice", collection: "app.bsky.feed.post", rkey: "two")
        let grant = SpaceGrant(
            subject: "did:plc:bob", space: space,
            permissions: [.read],
            expiresAt: .distantFuture
        )
        let repository = try SpaceRepository(space: space, author: "did:plc:alice", retention: 1)
        do {
            _ = try await repository.apply(.put(uri: first, value: Data("first".utf8)), authorization: .public)
            XCTFail("a public context must never write a space repository")
        } catch {}
        let author = AuthorizationContext.accountOAuth(subject: "did:plc:alice", scopes: ["atproto"])
        _ = try await repository.apply(.put(uri: first, value: Data("first".utf8)), authorization: author)
        _ = try await repository.apply(.put(uri: second, value: Data("second".utf8)), authorization: author)

        let sync = try await repository.sync(since: 0, authorization: .spaceCredential(grant))
        guard case let .fullSnapshot(revision, records, _) = sync else {
            return XCTFail("retention gap must require a full snapshot")
        }
        XCTAssertEqual(revision, 2)
        XCTAssertEqual(records.count, 2)
    }

    func testPrivateBlobCanNeverUseThePublicReadPath() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let store = try FileBlobStore(root: root)
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "private")
        let privateReference = try await store.put(Data("secret".utf8), namespace: .space(space))
        let privatePublicData = try await store.publicData(cid: privateReference.cid)
        XCTAssertNil(privatePublicData)
        let publicReference = try await store.put(Data("public".utf8), namespace: .public)
        let publicData = try await store.publicData(cid: publicReference.cid)
        XCTAssertEqual(publicData, Data("public".utf8))
    }

    func testContextSignatureAndDeniableBindingAreVerifiedSeparately() throws {
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared")
        let key = P256.Signing.PrivateKey()
        let context = try SpaceCommitContext(space: space, author: "did:plc:alice", rev: "3m2q2l5w2kq", ikm: Data(repeating: 8, count: 32))
        let envelope = try SpaceCommitCodec.sign(context: context, commitment: Data(repeating: 3, count: 32), key: key)
        XCTAssertTrue(try SpaceCommitCodec.verifyContextSignature(envelope, publicKey: key.publicKey))
        XCTAssertTrue(SpaceCommitCodec.verifyContentBinding(envelope))
        let firstReaderEnvelope = try SpaceCommitCodec.createReaderEnvelope(
            space: space, author: "did:plc:alice", rev: "3m2q2l5w2kq", commitment: Data(repeating: 3, count: 32), key: key
        )
        let secondReaderEnvelope = try SpaceCommitCodec.createReaderEnvelope(
            space: space, author: "did:plc:alice", rev: "3m2q2l5w2kq", commitment: Data(repeating: 3, count: 32), key: key
        )
        XCTAssertNotEqual(firstReaderEnvelope.context.ikm, secondReaderEnvelope.context.ikm)
        XCTAssertNotEqual(firstReaderEnvelope.contentBinding, secondReaderEnvelope.contentBinding)
    }

    func testApplyWritesIsAtomicWhenOneWriteIsInvalid() async throws {
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "self")
        let first = try SpaceRecordURI(space: space, author: "did:plc:alice", collection: "app.bsky.feed.post", rkey: "one")
        let missing = try SpaceRecordURI(space: space, author: "did:plc:alice", collection: "app.bsky.feed.post", rkey: "missing")
        let repository = try SpaceRepository(space: space, author: "did:plc:alice")
        let authorization = AuthorizationContext.accountOAuth(subject: "did:plc:alice", scopes: ["atproto"])

        do {
            _ = try await repository.applyAtomically([
                .put(uri: first, value: Data("first".utf8)),
                .delete(uri: missing),
            ], authorization: authorization)
            XCTFail("a missing delete must reject the whole batch")
        } catch {}

        let record = try await repository.record(first, authorization: authorization)
        let state = await repository.currentState()
        XCTAssertNil(record)
        XCTAssertEqual(state.revision, 0)
    }

    func testSimpleSpaceEvaluatesMemberManagingAppAndClientPoliciesIndependently() async throws {
        let authority = SimpleSpaceAuthority(credentialSecret: Data(repeating: 4, count: 32))
        let memberSpace = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "members")
        _ = try await authority.create(
            space: memberSpace,
            owner: "did:plc:alice",
            configuration: try .init(policy: .memberList, appAccess: .allowList(["https://reader.example/client.json"]))
        )
        try await authority.addMember(space: memberSpace, member: "did:plc:bob", by: "did:plc:alice")
        _ = try await authority.issueReadCredential(
            space: memberSpace, user: "did:plc:bob", clientID: "https://reader.example/client.json"
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(space: memberSpace, user: "did:plc:mallory", clientID: "https://reader.example/client.json")
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(space: memberSpace, user: "did:plc:bob", clientID: "https://wrong.example/client.json")
        )

        let managedSpace = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "managed")
        _ = try await authority.create(
            space: managedSpace,
            owner: "did:plc:alice",
            configuration: try .init(policy: .managingApp, appAccess: .open, managingApp: "did:web:app.example#space")
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(space: managedSpace, user: "did:plc:bob", clientID: nil)
        )
        try await authority.setManagingAppAccess(
            space: managedSpace, user: "did:plc:bob", allowed: true, by: "did:web:app.example#space"
        )
        _ = try await authority.issueReadCredential(space: managedSpace, user: "did:plc:bob", clientID: nil)
    }

    func testTwoRootCARAuthenticatesIndexAndRecordBlocks() async throws {
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared")
        let uri = try SpaceRecordURI(space: space, author: "did:plc:alice", collection: "app.bsky.feed.post", rkey: "one")
        let repository = try SpaceRepository(space: space, author: "did:plc:alice")
        let authorization = AuthorizationContext.accountOAuth(subject: "did:plc:alice", scopes: ["atproto"])
        // Canonical DAG-CBOR for {"text": "hello"}.
        let recordCBOR = Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f])
        _ = try await repository.apply(.put(uri: uri, value: recordCBOR), authorization: authorization)
        let state = await repository.currentState()
        let key = P256.Signing.PrivateKey()
        let context = try SpaceCommitContext(space: space, author: "did:plc:alice", rev: "3m2q2l5w2kq", ikm: Data(repeating: 7, count: 32))
        let commit = try SpaceCommitCodec.sign(context: context, commitment: state.commitment, key: key)
        let car = try SpaceCARCodec.encode(commit: commit, records: try await repository.snapshot(authorization: authorization))
        let recovered = try SpaceCARCodec.verify(car.data, space: space, author: "did:plc:alice", publicKey: key.publicKey)
        XCTAssertEqual(recovered["app.bsky.feed.post/one"], recordCBOR)

        var corrupted = car.data
        corrupted[corrupted.index(before: corrupted.endIndex)] ^= 1
        XCTAssertThrowsError(try SpaceCARCodec.verify(corrupted, space: space, author: "did:plc:alice", publicKey: key.publicKey))
    }

    func testSQLiteCommitsOplogAndOutboxTogether() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: "did:plc:alice")
        do {
            let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared")
            let event = try await database.appendOplogAndOutbox(
                space: space,
                revision: 1,
                operation: Data("put".utf8),
                commitment: Data(repeating: 1, count: 32),
                notificationPayload: Data("notify".utf8)
            )
            let initialEvents = try await database.pendingOutbox()
            XCTAssertEqual(initialEvents, [event])
            try await database.markAttempt(event.id)
            let afterAttempt = try await database.pendingOutbox()
            XCTAssertEqual(afterAttempt.first?.attempts, 1)
            try await database.markDelivered(event.id)
            let remainingEvents = try await database.pendingOutbox()
            XCTAssertEqual(remainingEvents, [])
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }
}

private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}
