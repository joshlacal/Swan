import Crypto
import Foundation
import XCTest
@testable import SwanOAuth
@testable import SwanSQLite
@testable import SwanSpaces
import SwanStorage

final class SwanOAuthTests: XCTestCase {
    func testPKCEAndRefreshReuseRevokesFamily() async throws {
        XCTAssertTrue(PKCE.verifyS256(
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ))
        let vault = OAuthTokenVault(secret: Data(repeating: 9, count: 32))
        let pair = await vault.issue(subject: "did:plc:alice", scopes: ["atproto"])
        let rotated = try await vault.redeemRefresh(pair.refreshToken)
        let access = try await vault.validateAccess(rotated.accessToken)
        XCTAssertEqual(access.subject, "did:plc:alice")
        await XCTAssertThrowsErrorAsync(try await vault.redeemRefresh(pair.refreshToken))
        await XCTAssertThrowsErrorAsync(try await vault.validateAccess(rotated.accessToken))
    }

    func testNonceAndReplayProtection() async {
        let nonceService = DPoPNonceService(secret: Data(repeating: 1, count: 32))
        XCTAssertTrue(nonceService.isValid(nonceService.issue()))
        let replay = DPoPReplayStore()
        let firstAccepted = await replay.accept(jti: "one")
        let secondAccepted = await replay.accept(jti: "one")
        XCTAssertTrue(firstAccepted)
        XCTAssertFalse(secondAccepted)
    }

    func testSignedDelegationAndSpaceCredentialsFollowPinnedJWTClaims() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let space = try SpaceURI(
            authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared"
        )
        let delegation = try PermissionedDataJWT.createDelegationToken(
            issuer: "did:plc:bob",
            audience: "did:plc:alice#atproto_space_host",
            space: space,
            key: key,
            now: now
        )
        let delegationClaims = try PermissionedDataJWT.verifyDelegationToken(
            delegation,
            publicKey: key.publicKey,
            audience: "did:plc:alice#atproto_space_host",
            now: now
        )
        XCTAssertEqual(delegationClaims.iss, "did:plc:bob")
        XCTAssertEqual(delegationClaims.sub, space.rawValue)
        XCTAssertThrowsError(try PermissionedDataJWT.verifyDelegationToken(
            delegation, publicKey: key.publicKey, audience: "did:plc:mallory#atproto_space_host", now: now
        ))

        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: "did:plc:alice", space: space, key: key, now: now
        )
        let credentialClaims = try PermissionedDataJWT.verifySpaceCredential(credential, publicKey: key.publicKey, now: now)
        XCTAssertEqual(credentialClaims.sub, space.rawValue)
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(
            credential, publicKey: key.publicKey, now: now.addingTimeInterval(3 * 60 * 60)
        ))
    }

    func testRemoteMetadataPolicyRejectsAllPrivateLiteralRanges() throws {
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.31.1.1/metadata")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://169.254.169.254/latest/meta-data")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://[fe80::1]/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.32.1.1/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "http://127.0.0.1:3000/metadata")!, allowLoopbackDevelopment: true))
    }

    func testDurableTokensSurviveReopenAndNeverPersistRawTokens() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 7, count: 32)
        let dpopJKT = testDPoPJKT("P")
        let binding = oauthBinding(dpopJKT: dpopJKT, clientKeyID: "kid-persist")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(controlStore: database, serverKey: serverKey)
        let now = Date()
        let metadata = try OAuthClientMetadata(
            clientID: URL(string: "https://client.example/metadata")!,
            redirectURIs: [URL(string: "https://client.example/callback")!]
        )
        try await service.cacheClientMetadata(
            metadata,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
        let pair = try await service.issue(subject: "did:plc:alice", binding: binding, now: now)
        let rotated = try await service.redeemRefresh(
            pair.refreshToken,
            presentedDPoPJKT: dpopJKT,
            clientAssertionKeyID: "kid-persist",
            now: now
        )
        let authorizationCode = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            binding: binding,
            codeChallengeS256: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            now: now
        )
        let replayJTI = "durable-replay-jti-that-must-not-persist"
        let replayClaimed = try await service.claimDPoP(
            jti: replayJTI,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
        XCTAssertTrue(replayClaimed)
        let clientAssertionJTI = "durable-client-assertion-jti-that-must-not-persist"
        let clientAssertionClaimed = try await service.claimClientAssertion(
            jti: clientAssertionJTI,
            clientID: binding.clientID,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
        XCTAssertTrue(clientAssertionClaimed)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedService = try DurableOAuthTokenService(controlStore: reopened, serverKey: serverKey)
        let cachedMetadata = try await reopenedService.cachedClientMetadata(
            clientID: metadata.clientID,
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(cachedMetadata, metadata)
        let grant = try await reopenedService.validateAccess(
            rotated.accessToken,
            presentedDPoPJKT: dpopJKT,
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(grant.subject, "did:plc:alice")
        XCTAssertEqual(grant.scopes, ["atproto", "transition:generic"])
        XCTAssertEqual(grant.dpopJKT, dpopJKT)
        let expiredMetadata = try await reopenedService.cachedClientMetadata(
            clientID: metadata.clientID,
            now: now.addingTimeInterval(61)
        )
        XCTAssertNil(expiredMetadata)

        let rawValues = [
            pair.accessToken, pair.refreshToken, rotated.accessToken, rotated.refreshToken,
            authorizationCode, replayJTI, clientAssertionJTI,
        ]
        for file in sqliteFiles(in: root) {
            let bytes = try Data(contentsOf: file)
            for rawValue in rawValues {
                XCTAssertNil(
                    bytes.range(of: Data(rawValue.utf8)),
                    "raw OAuth credential leaked to \(file.lastPathComponent)"
                )
            }
            XCTAssertNil(
                bytes.range(of: serverKey),
                "raw OAuth server key leaked to \(file.lastPathComponent)"
            )
        }
        try await reopened.close()
    }

    func testDurableRefreshRaceAllowsOnePairThenRevokesTheFamily() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 8, count: 32)
        let dpopJKT = testDPoPJKT("R")
        let binding = oauthBinding(dpopJKT: dpopJKT, clientKeyID: "kid-race")
        let firstDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let secondDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let first = try DurableOAuthTokenService(controlStore: firstDatabase, serverKey: serverKey)
        let second = try DurableOAuthTokenService(controlStore: secondDatabase, serverKey: serverKey)
        let original = try await first.issue(subject: "did:plc:alice", binding: binding)

        let outcomes = await withTaskGroup(
            of: Result<OAuthTokenPair, any Error>.self,
            returning: [Result<OAuthTokenPair, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.redeemRefresh(
                        original.refreshToken,
                        presentedDPoPJKT: dpopJKT,
                        clientAssertionKeyID: "kid-race"
                    ))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.redeemRefresh(
                        original.refreshToken,
                        presentedDPoPJKT: dpopJKT,
                        clientAssertionKeyID: "kid-race"
                    ))
                } catch {
                    return .failure(error)
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }

        let issued = outcomes.compactMap { try? $0.get() }
        XCTAssertEqual(issued.count, 1)
        XCTAssertEqual(outcomes.count - issued.count, 1)
        let onlyPair = try XCTUnwrap(issued.first)
        await XCTAssertThrowsErrorAsync(
            try await first.validateAccess(
                onlyPair.accessToken,
                presentedDPoPJKT: dpopJKT
            )
        )
        try await firstDatabase.close()
        try await secondDatabase.close()
    }

    func testDurableAuthorizationCodeRaceAllowsOnePairThenRevokesTheFamily() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 0x51, count: 32)
        let dpopJKT = testDPoPJKT("A")
        let binding = oauthBinding(dpopJKT: dpopJKT, clientKeyID: "kid-code-race")
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let firstDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let secondDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let first = try DurableOAuthTokenService(controlStore: firstDatabase, serverKey: serverKey)
        let second = try DurableOAuthTokenService(controlStore: secondDatabase, serverKey: serverKey)
        let code = try await first.issueAuthorizationCode(
            subject: "did:plc:alice",
            binding: binding,
            codeChallengeS256: challenge
        )

        let outcomes = await withTaskGroup(
            of: Result<OAuthTokenPair, any Error>.self,
            returning: [Result<OAuthTokenPair, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.redeemAuthorizationCode(
                        code,
                        verifier: verifier,
                        binding: binding
                    ))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.redeemAuthorizationCode(
                        code,
                        verifier: verifier,
                        binding: binding
                    ))
                } catch {
                    return .failure(error)
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }

        let issued = outcomes.compactMap { try? $0.get() }
        XCTAssertEqual(issued.count, 1)
        let winningPair = try XCTUnwrap(issued.first)
        await XCTAssertThrowsErrorAsync(
            try await first.validateAccess(
                winningPair.accessToken,
                presentedDPoPJKT: dpopJKT
            )
        )
        try await firstDatabase.close()
        try await secondDatabase.close()
    }

    func testDurablePARAndCodePreserveBindingStateAndSingleUse() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(
            controlStore: database,
            serverKey: Data(repeating: 3, count: 32)
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let dpopJKT = testDPoPJKT("C")
        let binding = oauthBinding(dpopJKT: dpopJKT, clientKeyID: "kid-par")
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        let requestURI = try await service.createPushedAuthorizationRequest(
            binding: binding,
            state: "exact-client-state=alpha",
            codeChallengeS256: challenge,
            now: now
        )
        let pushed = try await service.consumePushedAuthorizationRequest(
            requestURI,
            binding: binding,
            now: now
        )
        XCTAssertEqual(pushed.state, "exact-client-state=alpha")
        XCTAssertEqual(pushed.codeChallengeMethod, .s256)
        XCTAssertEqual(pushed.binding, binding)
        await XCTAssertThrowsErrorAsync(
            try await service.consumePushedAuthorizationRequest(requestURI, binding: binding, now: now)
        )
        await XCTAssertThrowsErrorAsync(
            try await service.createPushedAuthorizationRequest(
                binding: binding,
                state: "exact-client-state=alpha",
                codeChallengeS256: challenge,
                now: now
            )
        )
        let expiredRequest = try await service.createPushedAuthorizationRequest(
            binding: binding,
            state: "expired-state",
            codeChallengeS256: challenge,
            lifetime: 1,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.consumePushedAuthorizationRequest(
                expiredRequest,
                binding: binding,
                now: now.addingTimeInterval(2)
            )
        )

        let code = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            binding: binding,
            codeChallengeS256: challenge,
            now: now
        )
        let tokens = try await service.redeemAuthorizationCode(
            code,
            verifier: verifier,
            binding: binding,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCode(
                code,
                verifier: verifier,
                binding: binding,
                now: now.addingTimeInterval(1)
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(tokens.accessToken, presentedDPoPJKT: dpopJKT, now: now)
        )

        let expiredCode = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            binding: binding,
            codeChallengeS256: challenge,
            codeLifetime: 1,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCode(
                expiredCode,
                verifier: verifier,
                binding: binding,
                now: now.addingTimeInterval(2)
            )
        )
        try await database.close()
    }

    func testDurableDPoPReplayAndClientAssertionSurviveReopen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 4, count: 32)
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let replay = try DurableDPoPReplayStore(controlStore: database, serverKey: key)
        let service = try DurableOAuthTokenService(controlStore: database, serverKey: key)
        let firstDPoPClaim = try await replay.accept(
            jti: "dpop-jti",
            expiresAt: now.addingTimeInterval(30),
            now: now
        )
        XCTAssertTrue(firstDPoPClaim)
        let firstAssertionClaim = try await service.claimClientAssertion(
            jti: "assertion-jti",
            clientID: "https://client.example/metadata",
            expiresAt: now.addingTimeInterval(30),
            now: now
        )
        XCTAssertTrue(firstAssertionClaim)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedReplay = try DurableDPoPReplayStore(controlStore: reopened, serverKey: key)
        let reopenedService = try DurableOAuthTokenService(controlStore: reopened, serverKey: key)
        let secondDPoPClaim = try await reopenedReplay.accept(
            jti: "dpop-jti",
            expiresAt: now.addingTimeInterval(30),
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(secondDPoPClaim)
        let secondAssertionClaim = try await reopenedService.claimClientAssertion(
            jti: "assertion-jti",
            clientID: "https://client.example/metadata",
            expiresAt: now.addingTimeInterval(30),
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(secondAssertionClaim)
        try await reopened.close()
    }

    func testDurableAccessAndRefreshRequireDPoPAndClientKeyBindings() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(
            controlStore: database,
            serverKey: Data(repeating: 6, count: 32)
        )
        await XCTAssertThrowsErrorAsync(
            try await service.issue(subject: "did:plc:alice", binding: oauthBinding())
        )
        let dpopJKT = testDPoPJKT("D")
        let nonATProtoBinding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata",
            redirectURI: "https://client.example/callback",
            scopes: ["transition:generic"],
            dpopJKT: dpopJKT
        )
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        await XCTAssertThrowsErrorAsync(
            try await service.issue(subject: "did:plc:alice", binding: nonATProtoBinding)
        )
        await XCTAssertThrowsErrorAsync(
            try await service.createPushedAuthorizationRequest(
                binding: nonATProtoBinding,
                state: "state",
                codeChallengeS256: challenge
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.issueAuthorizationCode(
                subject: "did:plc:alice",
                binding: nonATProtoBinding,
                codeChallengeS256: challenge
            )
        )
        let binding = oauthBinding(dpopJKT: dpopJKT, clientKeyID: "required-kid")
        let pair = try await service.issue(subject: "did:plc:alice", binding: binding)
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(pair.accessToken, presentedDPoPJKT: testDPoPJKT("W"))
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(pair.accessToken, presentedDPoPJKT: nil)
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(pair.accessToken, presentedDPoPJKT: "not-a-jkt")
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemRefresh(
                pair.refreshToken,
                presentedDPoPJKT: dpopJKT,
                clientAssertionKeyID: "wrong-kid"
            )
        )
        let grant = try await service.validateAccess(
            pair.accessToken,
            presentedDPoPJKT: dpopJKT
        )
        XCTAssertEqual(grant.clientID, binding.clientID)
        let rotated = try await service.redeemRefresh(
            pair.refreshToken,
            presentedDPoPJKT: dpopJKT,
            clientAssertionKeyID: "required-kid"
        )
        XCTAssertFalse(rotated.accessToken.isEmpty)
        try await database.close()
    }
}

private func oauthBinding(dpopJKT: String? = nil, clientKeyID: String? = nil) -> OAuthClientBinding {
    OAuthClientBinding(
        issuer: "https://swan.example",
        clientID: "https://client.example/metadata",
        redirectURI: "https://client.example/callback",
        scopes: ["atproto", "transition:generic"],
        dpopJKT: dpopJKT,
        clientAssertionKeyID: clientKeyID
    )
}

private func testDPoPJKT(_ character: Character) -> String {
    String(repeating: String(character), count: 43)
}

private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appending(path: "SwanOAuthTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func sqliteFiles(in root: URL) -> [URL] {
    let urls = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey]
    )?.allObjects as? [URL] ?? []
    return urls.filter { url in
        (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
    }
}

private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}
