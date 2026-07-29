import Crypto
import Foundation
import Petrel
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

    func testContentBindingMatchesPermissionedData0016ExpandVector() throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "vector"
        )
        let context = try SpaceCommitContext(
            space: space,
            author: "did:plc:bob",
            rev: "3jzfcj2zq2m2a",
            ikm: Data(0..<32)
        )
        let commitment = Data(1...32)
        let expectedBinding = Data([
            0xd1, 0x9d, 0x21, 0x4e, 0x46, 0xe6, 0x7f, 0x85,
            0x13, 0xb9, 0xbe, 0xfc, 0xe7, 0x2b, 0xaf, 0x7a,
            0xa7, 0x52, 0xa8, 0x0a, 0x3c, 0xb1, 0x2a, 0x32,
            0x20, 0xa8, 0xd0, 0x4a, 0xdd, 0x41, 0x41, 0x5e,
        ])
        let envelope = SpaceCommitEnvelope(
            context: context,
            contextSignature: Data(),
            contentBinding: expectedBinding,
            commitment: commitment
        )
        XCTAssertTrue(SpaceCommitCodec.verifyContentBinding(envelope))
        var corrupted = expectedBinding
        corrupted[0] ^= 0x01
        XCTAssertFalse(SpaceCommitCodec.verifyContentBinding(SpaceCommitEnvelope(
            context: context,
            contextSignature: Data(),
            contentBinding: corrupted,
            commitment: commitment
        )))
    }

    func testContextSignaturesEmitAndRequireCanonicalLowSValues() throws {
        let space = try SpaceURI(authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared")
        let key = P256.Signing.PrivateKey()
        let context = try SpaceCommitContext(
            space: space,
            author: "did:plc:alice",
            rev: "3m2q2l5w2kq",
            ikm: Data(repeating: 8, count: 32)
        )
        let envelope = try SpaceCommitCodec.sign(
            context: context,
            commitment: Data(repeating: 3, count: 32),
            key: key
        )
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(envelope.contextSignature))

        let malleated = SpaceCommitEnvelope(
            context: context,
            contextSignature: highSVariant(of: envelope.contextSignature),
            contentBinding: envelope.contentBinding,
            commitment: envelope.commitment
        )
        XCTAssertThrowsError(try SpaceCommitCodec.verifyContextSignature(malleated, publicKey: key.publicKey))
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

        // Preserve a configured app through a policy-only transition, but
        // never retain its old allow decision when that policy is restored.
        let preservedAppPublic = try SimpleSpaceConfiguration(
            policy: .public,
            appAccess: .open,
            managingApp: "did:web:app.example#space"
        )
        try await authority.update(
            space: managedSpace,
            configuration: preservedAppPublic,
            by: "did:plc:alice"
        )
        let publicState = await authority.space(managedSpace)
        XCTAssertEqual(publicState?.configuration.managingApp, "did:web:app.example#space")
        await XCTAssertThrowsErrorAsync(
            try await authority.setManagingAppAccess(
                space: managedSpace,
                user: "did:plc:bob",
                allowed: true,
                by: "did:web:app.example#space"
            )
        )
        try await authority.update(
            space: managedSpace,
            configuration: try .init(
                policy: .managingApp,
                appAccess: .open,
                managingApp: "did:web:app.example#space"
            ),
            by: "did:plc:alice"
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(
                space: managedSpace,
                user: "did:plc:bob",
                clientID: nil
            )
        )
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
                commitment: Data(repeating: 1, count: 32)
            )
            let initialEvents = try await database.pendingOutbox()
            XCTAssertEqual(initialEvents, [event])
            XCTAssertEqual(event.payload, Data(event.id.uuidString.lowercased().utf8))
            XCTAssertNotEqual(event.payload, Data("notify".utf8))
            let now = Date(timeIntervalSinceNow: 10)
            let maybeFirstLease = try await database.leaseNextOutbox(
                now: now,
                leaseDuration: 30
            )
            let firstLease = try XCTUnwrap(maybeFirstLease)
            let attempts = try await database.failOutboxLease(
                eventID: event.id,
                token: firstLease.token,
                retryAt: now.addingTimeInterval(1)
            )
            XCTAssertEqual(attempts, 1)
            let afterAttempt = try await database.pendingOutbox()
            XCTAssertEqual(afterAttempt.first?.attempts, 1)
            let maybeSecondLease = try await database.leaseNextOutbox(
                now: now.addingTimeInterval(2),
                leaseDuration: 30
            )
            let secondLease = try XCTUnwrap(maybeSecondLease)
            let delivered = try await database.completeOutboxLease(
                eventID: event.id,
                token: secondLease.token
            )
            XCTAssertTrue(delivered)
            let remainingEvents = try await database.pendingOutbox()
            XCTAssertEqual(remainingEvents, [])
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testDurableRepositoryRestartsFromSQLiteWithoutFacadeState() async throws {
        let fixture = try DurableRepositoryFixture()
        let requestID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let database = try await fixture.open()
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        let entry = try await repository.apply(
            .put(uri: fixture.first, value: fixture.firstValue),
            expectedRevision: 0,
            requestID: requestID,
            wireRevision: try fixture.tid(0),
            authorization: fixture.authorized
        )
        XCTAssertEqual(entry.revision, 1)
        let initialState = try await repository.currentState(authorization: fixture.authorized)
        let firstWireRevision = try fixture.tid(0)
        XCTAssertEqual(initialState.revision, 1)
        XCTAssertEqual(initialState.wireRevision, firstWireRevision)
        try await database.close()

        let reopened = try await fixture.open()
        let reloaded = try DurableSpaceRepository(
            database: reopened,
            space: fixture.space,
            author: fixture.author
        )
        let reloadedRecord = try await reloaded.record(
            fixture.first,
            authorization: fixture.authorized
        )
        let reloadedSnapshot = try await reloaded.snapshot(authorization: fixture.authorized)
        let reloadedState = try await reloaded.currentState(authorization: fixture.authorized)
        XCTAssertEqual(reloadedRecord?.value, fixture.firstValue)
        XCTAssertEqual(reloadedSnapshot.map(\.uri), [fixture.first])
        XCTAssertEqual(reloadedState.revision, 1)
        XCTAssertEqual(reloadedState.wireRevision, firstWireRevision)
        try await reopened.close()
    }

    func testDurableRepositoryAuthorizesScopedOAuthAndRejectsCredentialSelfAndServiceWrites() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let durable = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        let grant = SpaceGrant(
            subject: "did:plc:reader",
            space: fixture.space,
            permissions: [.manage],
            expiresAt: .distantFuture
        )
        let service = AuthorizationContext.service(
            subject: "did:web:service.example",
            audience: fixture.space.authority
        )

        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: .public
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: .spaceCredential(grant)
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: .spaceSelfRead(subject: fixture.author, space: fixture.space)
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: service
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: .accountOAuth(subject: "did:plc:other", scopes: ["atproto"])
            )
        )

        let spoofedScope = """
        space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=create&action=create&collection=\(fixture.first.collection)
        """
        await XCTAssertThrowsErrorAsync(
            try await durable.apply(
                .put(uri: fixture.first, value: fixture.firstValue),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                authorization: .accountOAuth(subject: fixture.author, scopes: [spoofedScope])
            )
        )

        let scopedCreate = """
        space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=create&collection=\(fixture.first.collection)
        """
        _ = try await durable.apply(
            .put(uri: fixture.first, value: fixture.firstValue),
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            authorization: .accountOAuth(subject: fixture.author, scopes: [scopedCreate])
        )
        let serviceRead = try await durable.record(fixture.first, authorization: service)
        XCTAssertEqual(serviceRead?.value, fixture.firstValue)

        let inMemory = try SpaceRepository(space: fixture.space, author: fixture.author)
        await XCTAssertThrowsErrorAsync(
            try await inMemory.apply(
                .put(uri: fixture.second, value: fixture.secondValue),
                authorization: service
            )
        )
    }

    func testQualifiedCollectionReadScopesDenyAggregatePermissionedReads() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        let otherCollection = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.bsky.actor.profile",
            rkey: "self"
        )
        _ = try await repository.apply(
            .put(uri: fixture.first, value: fixture.firstValue),
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            authorization: fixture.authorized
        )
        _ = try await repository.apply(
            .put(uri: otherCollection, value: fixture.secondValue),
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            authorization: fixture.authorized
        )

        let collectionLimitedScope = """
        space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=\(fixture.first.collection)
        """
        let collectionLimited = AuthorizationContext.accountOAuth(
            subject: fixture.author,
            scopes: [collectionLimitedScope]
        )
        let allowedRecord = try await repository.record(
            fixture.first,
            authorization: collectionLimited
        )
        XCTAssertEqual(allowedRecord?.value, fixture.firstValue)
        await XCTAssertThrowsErrorAsync(
            try await repository.record(otherCollection, authorization: collectionLimited)
        )
        await XCTAssertThrowsErrorAsync(
            try await repository.snapshot(authorization: collectionLimited)
        )
        await XCTAssertThrowsErrorAsync(
            try await repository.sync(since: 0, authorization: collectionLimited)
        )
        let signingKey = P256.Signing.PrivateKey()
        await XCTAssertThrowsErrorAsync(
            try await repository.exportCAR(
                rev: try fixture.tid(2).toString(),
                signingKey: signingKey,
                authorization: collectionLimited
            )
        )

        let wildcardScope = """
        space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=*
        """
        let wildcard = AuthorizationContext.accountOAuth(
            subject: fixture.author,
            scopes: [wildcardScope]
        )
        let wildcardSnapshot = try await repository.snapshot(authorization: wildcard)
        XCTAssertEqual(wildcardSnapshot.map(\.uri), [otherCollection, fixture.first])

        let unspecifiedScope = """
        space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read
        """
        let unspecified = AuthorizationContext.accountOAuth(
            subject: fixture.author,
            scopes: [unspecifiedScope]
        )
        guard case let .incremental(entries) = try await repository.sync(
            since: 0,
            authorization: unspecified
        ) else {
            return XCTFail("an unspecified read collection must permit an aggregate sync")
        }
        XCTAssertEqual(entries.count, 2)
        let export = try await repository.exportCAR(
            rev: try fixture.tid(2).toString(),
            signingKey: signingKey,
            authorization: unspecified
        )
        XCTAssertFalse(export.data.isEmpty)
    }

    func testDurableRepositoryPropagatesSQLiteCASRaceAndReplay() async throws {
        let fixture = try DurableRepositoryFixture()
        let firstDatabase = try await fixture.open()
        let secondDatabase = try await fixture.open()
        defer {
            Task {
                try? await firstDatabase.close()
                try? await secondDatabase.close()
            }
        }
        let first = try DurableSpaceRepository(
            database: firstDatabase,
            space: fixture.space,
            author: fixture.author
        )
        let second = try DurableSpaceRepository(
            database: secondDatabase,
            space: fixture.space,
            author: fixture.author
        )

        let outcomes = await withTaskGroup(
            of: Result<DurableSpaceOplogEntry, any Error>.self,
            returning: [Result<DurableSpaceOplogEntry, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.apply(
                        .put(uri: fixture.first, value: fixture.firstValue),
                        expectedRevision: 0,
                        requestID: UUID(),
                        wireRevision: try fixture.tid(0),
                        authorization: fixture.authorized
                    ))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.apply(
                        .put(uri: fixture.second, value: fixture.secondValue),
                        expectedRevision: 0,
                        requestID: UUID(),
                        wireRevision: try fixture.tid(0),
                        authorization: fixture.authorized
                    ))
                } catch {
                    return .failure(error)
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(outcomes.compactMap { try? $0.get() }.count, 1)
        let errors = outcomes.compactMap { result -> (any Error)? in
            guard case let .failure(error) = result else { return nil }
            return error
        }
        XCTAssertEqual(errors.count, 1)
        XCTAssertEqual(errors.first as? SwanError, .conflict(expected: 0, actual: 1))

        let replayID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let third = try fixture.record(rkey: "third")
        _ = try await first.apply(
            .put(uri: third, value: fixture.thirdValue),
            expectedRevision: 1,
            requestID: replayID,
            wireRevision: try fixture.tid(1),
            authorization: fixture.authorized
        )
        let fourth = try fixture.record(rkey: "fourth")
        do {
            _ = try await second.apply(
                .put(uri: fourth, value: fixture.thirdValue),
                expectedRevision: 2,
                requestID: replayID,
                wireRevision: try fixture.tid(2),
                authorization: fixture.authorized
            )
            XCTFail("the SQLite replay reservation must propagate through the facade")
        } catch {
            XCTAssertEqual(error as? SQLiteRepositoryError, .duplicateRequest(replayID))
        }
    }

    func testDurableRepositoryRetentionReturnsSnapshotWithoutMutatingState() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open(retention: 1)
        defer { Task { try? await database.close() } }
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        let records = [fixture.first, fixture.second, try fixture.record(rkey: "third")]
        let values = [fixture.firstValue, fixture.secondValue, fixture.thirdValue]
        for (index, record) in records.enumerated() {
            _ = try await repository.apply(
                .put(uri: record, value: values[index]),
                expectedRevision: UInt64(index),
                requestID: UUID(),
                wireRevision: try fixture.tid(index),
                authorization: fixture.authorized
            )
        }

        guard case let .fullSnapshot(revision, recovered, commitment) = try await repository.sync(
            since: 0,
            authorization: fixture.authorized
        ) else {
            return XCTFail("expired retention must return a durable full snapshot")
        }
        XCTAssertEqual(revision, 3)
        XCTAssertEqual(recovered.map(\.uri), records)
        let stateAfterRecovery = try await repository.currentState(authorization: fixture.authorized)
        XCTAssertEqual(stateAfterRecovery.commitment, commitment)
        XCTAssertEqual(stateAfterRecovery.revision, 3)
    }

    func testDurableRepositorySyncRetainsOrderedCursorTIDAndDeleteFacts() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        let created = try await repository.applyAtomically(
            [
                .put(uri: fixture.first, value: fixture.firstValue),
                .put(uri: fixture.second, value: fixture.secondValue),
            ],
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            authorization: fixture.authorized
        )
        XCTAssertEqual(created.map(\.cursor), [
            PersistedOplogCursor(revision: 1, index: 0),
            PersistedOplogCursor(revision: 1, index: 1),
        ])
        XCTAssertEqual(created.map(\.action), [.create, .create])

        let updatedFirstValue = Data([
            0xa1, 0x64, 0x74, 0x65, 0x78, 0x74,
            0x67, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,
        ])
        let changed = try await repository.applyAtomically(
            [
                .put(uri: fixture.first, value: updatedFirstValue),
                .delete(uri: fixture.second),
            ],
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            authorization: fixture.authorized
        )
        XCTAssertEqual(changed.map(\.cursor), [
            PersistedOplogCursor(revision: 2, index: 0),
            PersistedOplogCursor(revision: 2, index: 1),
        ])
        XCTAssertEqual(changed.map(\.action), [.update, .delete])
        XCTAssertEqual(changed[0].previousCID, created[0].cid)
        XCTAssertEqual(changed[1].previousCID, created[1].cid)
        XCTAssertNil(changed[1].cid)

        guard case let .incremental(entries) = try await repository.sync(
            since: 0,
            authorization: fixture.authorized
        ) else {
            return XCTFail("retained oplog must remain incremental")
        }
        XCTAssertEqual(entries.map(\.cursor), [
            PersistedOplogCursor(revision: 1, index: 0),
            PersistedOplogCursor(revision: 1, index: 1),
            PersistedOplogCursor(revision: 2, index: 0),
            PersistedOplogCursor(revision: 2, index: 1),
        ])
        XCTAssertEqual(entries.map(\.wireRevision), [
            try fixture.tid(0), try fixture.tid(0),
            try fixture.tid(1), try fixture.tid(1),
        ])
        XCTAssertEqual(entries.map(\.action), [.create, .create, .update, .delete])
        XCTAssertEqual(entries[2].previousCID, created[0].cid)
        XCTAssertNil(entries[3].cid)
        XCTAssertEqual(entries[3].previousCID, created[1].cid)
    }

    func testDurableRepositoryExportsFreshReaderCARsFromTheSameSQLiteRecords() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        _ = try await repository.apply(
            .put(uri: fixture.first, value: fixture.firstValue),
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            authorization: fixture.authorized
        )
        let beforeExportSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let persistedBeforeExport = try XCTUnwrap(beforeExportSnapshot)
        let signingKey = P256.Signing.PrivateKey()
        let firstCAR = try await repository.exportCAR(
            rev: try fixture.tid(1).toString(),
            signingKey: signingKey,
            authorization: fixture.authorized
        )
        let secondCAR = try await repository.exportCAR(
            rev: try fixture.tid(1).toString(),
            signingKey: signingKey,
            authorization: fixture.authorized
        )
        XCTAssertNotEqual(firstCAR.commitCID, secondCAR.commitCID)
        XCTAssertEqual(firstCAR.indexCID, secondCAR.indexCID)
        XCTAssertEqual(
            try SpaceCARCodec.verify(
                firstCAR.data,
                space: fixture.space,
                author: fixture.author,
                publicKey: signingKey.publicKey
            )["app.bsky.feed.post/first"],
            fixture.firstValue
        )
        XCTAssertEqual(
            try SpaceCARCodec.verify(
                secondCAR.data,
                space: fixture.space,
                author: fixture.author,
                publicKey: signingKey.publicKey
            )["app.bsky.feed.post/first"],
            fixture.firstValue
        )
        let afterExportSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let persistedAfterExport = try XCTUnwrap(afterExportSnapshot)
        XCTAssertEqual(persistedAfterExport.state.commit, persistedBeforeExport.state.commit)
        XCTAssertNil(persistedAfterExport.state.commit.range(of: fixture.firstValue))
    }

    func testDurableRepositoryOutboxAndPublicNamespaceNeverExposeRecordValue() async throws {
        let fixture = try DurableRepositoryFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let repository = try DurableSpaceRepository(
            database: database,
            space: fixture.space,
            author: fixture.author
        )
        // Canonical DAG-CBOR for {"secret": "private-value"}.
        let privateValue = Data([
            0xa1, 0x66, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
            0x6d, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
            0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
        ])
        _ = try await repository.apply(
            .put(uri: fixture.first, value: privateValue),
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            authorization: fixture.authorized
        )
        let privateRecord = try await repository.record(
            fixture.first,
            authorization: fixture.authorized
        )
        let record = try XCTUnwrap(privateRecord)
        let pendingEvents = try await database.pendingOutbox()
        let event = try XCTUnwrap(pendingEvents.only)
        XCTAssertNil(event.payload.range(of: privateValue))
        XCTAssertNil(event.payload.range(of: Data(record.cid.utf8)))
        let publicBlob = try await database.publicData(cid: record.cid)
        XCTAssertNil(publicBlob)
        let publicURI = try PublicRecordURI(
            "at://\(fixture.author)/\(fixture.first.collection)/\(fixture.first.rkey)"
        )
        let publicRecord = try await database.publicRecord(publicURI)
        XCTAssertNil(publicRecord)
    }

    func testDurableSimpleSpaceAuthorityPersistsPolicyAndMakesDuplicateMutationsNoOps() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanDurableAuthorityTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let authorityDID = "did:plc:alice"
        let space = try SpaceURI(
            authority: authorityDID,
            spaceType: "app.bsky.bookmarks",
            skey: "authority"
        )
        let credentialSecret = Data(repeating: 0x5A, count: 32)
        let manage = AuthorizationContext.accountOAuth(
            subject: authorityDID,
            scopes: [
                "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&manage=create",
                "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&manage=update",
            ]
        )
        let initialConfiguration = try SimpleSpaceConfiguration(
            policy: .memberList,
            appAccess: .allowList(["https://reader.example/client.json"])
        )
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: authorityDID
        )
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: credentialSecret
        )
        let created = try await authority.create(
            space: space,
            owner: authorityDID,
            configuration: initialConfiguration,
            authorization: manage
        )
        XCTAssertEqual(created.revision, 1)
        XCTAssertEqual(created.space.members, [authorityDID])

        await XCTAssertThrowsErrorAsync(
            try await authority.addMember(
                space: space,
                member: "did:plc:bob",
                authorization: .accountOAuth(subject: "did:plc:mallory", scopes: ["atproto"])
            )
        )
        let firstMemberMutation = try await authority.addMember(
            space: space,
            member: "did:plc:bob",
            authorization: manage
        )
        XCTAssertEqual(firstMemberMutation.revision, 2)
        let duplicateMemberMutation = try await authority.addMember(
            space: space,
            member: "did:plc:bob",
            authorization: manage
        )
        XCTAssertEqual(duplicateMemberMutation, firstMemberMutation)

        let clientMutation = try await authority.setClientAccess(
            space: space,
            clientID: "https://second-reader.example/client.json",
            allowed: true,
            authorization: manage
        )
        XCTAssertEqual(clientMutation.revision, 3)
        let duplicateClientMutation = try await authority.setClientAccess(
            space: space,
            clientID: "https://second-reader.example/client.json",
            allowed: true,
            authorization: manage
        )
        XCTAssertEqual(duplicateClientMutation, clientMutation)

        // Bob is an authorized member, but Mallory must not be able to mint
        // a credential for Bob by naming him as the requested user.
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(
                space: space,
                user: "did:plc:bob",
                clientID: "https://second-reader.example/client.json",
                authorization: .accountOAuth(
                    subject: "did:plc:mallory",
                    scopes: ["atproto"]
                )
            )
        )

        let credential = try await authority.issueReadCredential(
            space: space,
            user: "did:plc:bob",
            clientID: "https://second-reader.example/client.json",
            authorization: .accountOAuth(
                subject: "did:plc:bob",
                scopes: ["atproto"]
            )
        )
        let verified = try HMACSpaceCredentialAuthority(key: credentialSecret)
            .verify(credential)
        XCTAssertEqual(verified.subject, "did:plc:bob")
        await XCTAssertThrowsErrorAsync(
            try await authority.issueReadCredential(
                space: space,
                user: "did:plc:bob",
                clientID: "https://wrong.example/client.json",
                authorization: .accountOAuth(
                    subject: "did:plc:bob",
                    scopes: ["atproto"]
                )
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.space(
                space,
                authorization: .accountOAuth(
                    subject: "did:plc:bob",
                    scopes: ["atproto"]
                )
            )
        )
        try await database.close()

        let reopenedDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: authorityDID
        )
        let reopened = try DurableSimpleSpaceAuthority(
            database: reopenedDatabase,
            credentialSecret: credentialSecret
        )
        let restoredState = try await reopened.space(
            space,
            authorization: manage
        )
        let restored = try XCTUnwrap(restoredState)
        XCTAssertEqual(restored, clientMutation)
        let restoredCredential = try await reopened.issueReadCredential(
            space: space,
            user: "did:plc:bob",
            clientID: "https://second-reader.example/client.json",
            authorization: .accountOAuth(
                subject: "did:plc:bob",
                scopes: ["atproto"]
            )
        )
        XCTAssertEqual(
            try HMACSpaceCredentialAuthority(key: credentialSecret)
                .verify(restoredCredential).subject,
            "did:plc:bob"
        )
        try await reopenedDatabase.close()
    }

    func testDurableSimpleSpaceManagingAppAndDeletionFailClosedAcrossAuthorityAccounts() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanDurableAuthorityAccountsTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let alice = "did:plc:alice"
        let bob = "did:plc:bob"
        let space = try SpaceURI(
            authority: bob,
            spaceType: "app.bsky.bookmarks",
            skey: "managed"
        )
        let configuration = try SimpleSpaceConfiguration(
            policy: .managingApp,
            appAccess: .open,
            managingApp: "did:web:reader.example#space"
        )
        let aliceDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: alice)
        let aliceAuthority = try DurableSimpleSpaceAuthority(
            database: aliceDatabase,
            credentialSecret: Data(repeating: 1, count: 32)
        )
        await XCTAssertThrowsErrorAsync(
            try await aliceAuthority.create(
                space: space,
                owner: bob,
                configuration: configuration,
                authorization: .accountOAuth(subject: bob, scopes: ["atproto"])
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await aliceAuthority.space(
                space,
                authorization: .accountOAuth(subject: bob, scopes: ["atproto"])
            )
        )

        let bobDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: bob)
        let bobAuthority = try DurableSimpleSpaceAuthority(
            database: bobDatabase,
            credentialSecret: Data(repeating: 2, count: 32)
        )
        let ownerAuthorization = AuthorizationContext.accountOAuth(
            subject: bob,
            scopes: ["atproto"]
        )
        _ = try await bobAuthority.create(
            space: space,
            owner: bob,
            configuration: configuration,
            authorization: ownerAuthorization
        )
        await XCTAssertThrowsErrorAsync(
            try await bobAuthority.setManagingAppAccess(
                space: space,
                user: alice,
                allowed: true,
                authorization: .service(
                    subject: "did:web:wrong.example#space",
                    audience: bob
                )
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await bobAuthority.setManagingAppAccess(
                space: space,
                user: alice,
                allowed: true,
                authorization: .service(
                    subject: "did:web:reader.example#space",
                    audience: alice
                )
            )
        )
        _ = try await bobAuthority.setManagingAppAccess(
            space: space,
            user: alice,
            allowed: true,
            authorization: .service(
                subject: "did:web:reader.example#space",
                audience: bob
            )
        )
        _ = try await bobAuthority.issueReadCredential(
            space: space,
            user: alice,
            clientID: nil,
            authorization: .accountOAuth(subject: alice, scopes: ["atproto"])
        )
        let deleted = try await bobAuthority.delete(
            space: space,
            authorization: ownerAuthorization
        )
        XCTAssertTrue(deleted.space.isDeleted)
        let duplicateDelete = try await bobAuthority.delete(
            space: space,
            authorization: ownerAuthorization
        )
        XCTAssertEqual(duplicateDelete, deleted)
        await XCTAssertThrowsErrorAsync(
            try await bobAuthority.issueReadCredential(
                space: space,
                user: alice,
                clientID: nil,
                authorization: .accountOAuth(subject: alice, scopes: ["atproto"])
            )
        )
        try await aliceDatabase.close()
        try await bobDatabase.close()
    }

    func testPrivateCARSpoolBoundsChunksAndCleansUpOnSuccessAndFailure() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanCARSpoolTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let successURL = root.appending(path: "success.spool")
        FileManager.default.createFile(
            atPath: successURL.path,
            contents: nil,
            attributes: [.posixPermissions: NSNumber(value: 0o600)]
        )
        let expectedBytes = SpaceCARBodySpool.maximumChunkBytes * 3 + 19
        let successHandle = try FileHandle(forWritingTo: successURL)
        let sourceChunk = Data(repeating: 0x5a, count: SpaceCARBodySpool.maximumChunkBytes)
        for _ in 0 ..< 3 { try successHandle.write(contentsOf: sourceChunk) }
        try successHandle.write(contentsOf: Data(repeating: 0xa5, count: 19))
        try successHandle.close()

        let spool = try SpaceCARBodySpool(
            indexCID: CID.fromDAGCBOR(Data([0xa0])),
            bodyURL: successURL
        )
        let collector = CARChunkCollector()
        try await spool.streamBody { chunk in
            await collector.append(chunk.count)
        }
        let streamedTotal = await collector.total
        let maximumChunk = await collector.maximum
        XCTAssertEqual(streamedTotal, expectedBytes)
        XCTAssertEqual(maximumChunk, SpaceCARBodySpool.maximumChunkBytes)
        XCTAssertTrue(spool.isCleanedUp)
        XCTAssertFalse(FileManager.default.fileExists(atPath: successURL.path))

        let failureURL = root.appending(path: "failure.spool")
        try Data(repeating: 0x3c, count: SpaceCARBodySpool.maximumChunkBytes + 1)
            .write(to: failureURL, options: .atomic)
        let failingSpool = try SpaceCARBodySpool(
            indexCID: CID.fromDAGCBOR(Data([0xa0])),
            bodyURL: failureURL
        )
        await XCTAssertThrowsErrorAsync(
            try await failingSpool.streamBody { _ in throw CARSpoolTestError.stop }
        )
        XCTAssertTrue(failingSpool.isCleanedUp)
        XCTAssertFalse(FileManager.default.fileExists(atPath: failureURL.path))

        let truncatedURL = root.appending(path: "truncated.spool")
        try Data([0x01, 0x02, 0x03]).write(
            to: truncatedURL,
            options: .atomic
        )
        let truncatedSpool = try SpaceCARBodySpool(
            indexCID: CID.fromDAGCBOR(Data([0xa0])),
            bodyURL: truncatedURL,
            bodyByteCount: 4
        )
        await XCTAssertThrowsErrorAsync(
            try await truncatedSpool.streamBody { _ in }
        )
        XCTAssertTrue(truncatedSpool.isCleanedUp)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: truncatedURL.path)
        )
    }

    func testPrivateCARSpool256MiBStressWhenExplicitlyEnabled() async throws {
        guard ProcessInfo.processInfo.environment["SWAN_CAR_256M_STRESS"] == "1" else {
            throw XCTSkip("set SWAN_CAR_256M_STRESS=1 to run the 256 MiB CAR streaming stress harness")
        }
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanCARSpoolStress-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let url = root.appending(path: "car.spool")
        FileManager.default.createFile(
            atPath: url.path,
            contents: nil,
            attributes: [.posixPermissions: NSNumber(value: 0o600)]
        )
        let handle = try FileHandle(forWritingTo: url)
        let chunk = Data(repeating: 0x91, count: SpaceCARBodySpool.maximumChunkBytes)
        for _ in 0 ..< (256 * 1_024 * 1_024 / SpaceCARBodySpool.maximumChunkBytes) {
            try handle.write(contentsOf: chunk)
        }
        try handle.close()

        let spool = try SpaceCARBodySpool(
            indexCID: CID.fromDAGCBOR(Data([0xa0])),
            bodyURL: url
        )
        let collector = CARChunkCollector()
        try await spool.streamBody { bodyChunk in
            await collector.append(bodyChunk.count)
        }
        let streamedTotal = await collector.total
        let maximumChunk = await collector.maximum
        XCTAssertEqual(streamedTotal, 256 * 1_024 * 1_024)
        XCTAssertEqual(maximumChunk, SpaceCARBodySpool.maximumChunkBytes)
        XCTAssertTrue(spool.isCleanedUp)
    }
}

private enum CARSpoolTestError: Error { case stop }

private actor CARChunkCollector {
    private(set) var total = 0
    private(set) var maximum = 0

    func append(_ count: Int) {
        total += count
        maximum = max(maximum, count)
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

private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}

private struct DurableRepositoryFixture {
    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI
    let first: SpaceRecordURI
    let second: SpaceRecordURI
    let firstValue = Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, 0x65, 0x66, 0x69, 0x72, 0x73, 0x74])
    let secondValue = Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, 0x66, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64])
    let thirdValue = Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, 0x65, 0x74, 0x68, 0x69, 0x72, 0x64])

    var authorized: AuthorizationContext {
        .accountOAuth(subject: author, scopes: ["atproto"])
    }

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanDurableRepositoryTests-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: author,
            spaceType: "app.bsky.bookmarks",
            skey: "self"
        )
        first = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "first"
        )
        second = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "second"
        )
    }

    func open(retention: Int = 10_000) async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author,
            oplogRetention: retention
        )
    }

    func record(rkey: String) throws -> SpaceRecordURI {
        try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: rkey
        )
    }

    func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }
}

private extension Array {
    var only: Element? { count == 1 ? first : nil }
}
