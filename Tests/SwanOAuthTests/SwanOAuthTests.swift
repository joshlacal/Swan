import Crypto
import Foundation
import XCTest
@testable import SwanOAuth
@testable import SwanSQLite
@testable import SwanSpaces
import SwanCore
import SwanStorage

final class SwanOAuthTests: XCTestCase {
    func testBrowserApprovalSessionIsBoundAndExpiresWithoutPersistingCredentials() throws {
        let service = try OAuthBrowserSessionService(serverKey: Data(repeating: 0x43, count: 32))
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let requestURI = "urn:ietf:params:oauth:request_uri:" + String(repeating: "a", count: 43)
        let issued = try service.issue(
            requestURI: requestURI,
            subject: "did:plc:abcdefghijklmnopqrstuvwx",
            now: now
        )
        let verified = try service.verify(issued.value, now: now.addingTimeInterval(1))
        XCTAssertEqual(verified.requestURI, requestURI)
        XCTAssertEqual(verified.subject, "did:plc:abcdefghijklmnopqrstuvwx")
        XCTAssertEqual(verified.csrfToken, issued.session.csrfToken)
        XCTAssertFalse(issued.value.contains("correct horse battery staple"))

        var tampered = issued.value
        let finalIndex = tampered.index(before: tampered.endIndex)
        tampered.replaceSubrange(
            finalIndex ... finalIndex,
            with: tampered[finalIndex] == "A" ? "B" : "A"
        )
        XCTAssertThrowsError(try service.verify(tampered, now: now.addingTimeInterval(1)))
        XCTAssertThrowsError(try service.verify(issued.value, now: now.addingTimeInterval(601)))
        XCTAssertThrowsError(try service.issue(requestURI: "not-a-request-uri", now: now))
    }

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

    func testES256JWTsEmitAndRejectMalleableHighSValues() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let space = try SpaceURI(
            authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared"
        )
        let token = try PermissionedDataJWT.createSpaceCredential(
            issuer: "did:plc:alice", space: space, key: key, now: now
        )
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(parts.count, 3)
        let signature = try XCTUnwrap(Data(base64URLEncoded: parts[2]))
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(signature))

        let highS = highSVariant(of: signature).base64URLEncodedString()
        let malleated = "\(parts[0]).\(parts[1]).\(highS)"
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(
            malleated,
            publicKey: key.publicKey,
            now: now
        ))
        XCTAssertThrowsError(try OAuthCompactJWT.verify(
            malleated,
            publicKey: key.publicKey,
            expectedType: PermissionedDataJWT.credentialType
        ))
    }

    func testRemoteMetadataPolicyRejectsAllPrivateLiteralRanges() throws {
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.31.1.1/metadata")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://169.254.169.254/latest/meta-data")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://[fe80::1]/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.32.1.1/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "http://localhost/")!, allowLoopbackDevelopment: true))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "http://127.0.0.1:3000/metadata")!, allowLoopbackDevelopment: true))
    }

    func testDurableTokensSurviveReopenAndNeverPersistRawTokens() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 7, count: 32)
        let dpopJKT = testDPoPJKT("P")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(controlStore: database, serverKey: serverKey)
        let now = Date()
        let session = try publicOAuthSession(dpopJKT: dpopJKT, now: now)
        let metadata = try OAuthClientMetadata(
            clientID: URL(string: "https://client.example/metadata")!,
            redirectURIs: [URL(string: "https://client.example/callback")!]
        )
        try await service.cacheClientMetadata(
            metadata,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
        let pair = try await service.issue(subject: "did:plc:alice", session: session, now: now)
        let rotated = try await service.redeemRefresh(
            pair.refreshToken,
            dpopProof: session.dpopProof,
            clientAssertion: nil,
            metadataLoader: try testMetadataLoader(database: database),
            now: now
        )
        let authorizationCode = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            session: session,
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
            clientID: session.client.metadata.clientID.absoluteString,
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
            proof: session.dpopProof,
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
        let firstDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let secondDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let first = try DurableOAuthTokenService(controlStore: firstDatabase, serverKey: serverKey)
        let second = try DurableOAuthTokenService(controlStore: secondDatabase, serverKey: serverKey)
        let session = try publicOAuthSession(dpopJKT: dpopJKT)
        let original = try await first.issue(subject: "did:plc:alice", session: session)
        let loader = try testMetadataLoader(database: firstDatabase)

        let outcomes = await withTaskGroup(
            of: Result<OAuthTokenPair, any Error>.self,
            returning: [Result<OAuthTokenPair, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.redeemRefresh(
                        original.refreshToken,
                        dpopProof: session.dpopProof,
                        clientAssertion: nil,
                        metadataLoader: loader
                    ))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.redeemRefresh(
                        original.refreshToken,
                        dpopProof: session.dpopProof,
                        clientAssertion: nil,
                        metadataLoader: loader
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
                proof: session.dpopProof
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
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let firstDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let secondDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let first = try DurableOAuthTokenService(controlStore: firstDatabase, serverKey: serverKey)
        let second = try DurableOAuthTokenService(controlStore: secondDatabase, serverKey: serverKey)
        let session = try publicOAuthSession(dpopJKT: dpopJKT)
        let code = try await first.issueAuthorizationCode(
            subject: "did:plc:alice",
            session: session,
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
                        session: session
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
                        session: session
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
                proof: session.dpopProof
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
        let session = try publicOAuthSession(dpopJKT: dpopJKT, now: now)
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        let requestURI = try await service.createPushedAuthorizationRequest(
            session: session,
            state: "exact-client-state=alpha",
            codeChallengeS256: challenge,
            now: now
        )
        let maybeActive = try await service.activePushedAuthorizationRequest(requestURI, now: now)
        let active = try XCTUnwrap(maybeActive)
        XCTAssertEqual(active.state, "exact-client-state=alpha")
        XCTAssertEqual(active.codeChallengeMethod, .s256)
        XCTAssertEqual(active.binding, session.durableBinding)
        let pushed = try await service.consumePushedAuthorizationRequest(
            requestURI,
            binding: active.binding,
            now: now
        )
        XCTAssertEqual(pushed.state, "exact-client-state=alpha")
        XCTAssertEqual(pushed.codeChallengeMethod, .s256)
        XCTAssertEqual(pushed.binding, session.durableBinding)
        let consumedRequest = try await service.activePushedAuthorizationRequest(requestURI, now: now)
        XCTAssertNil(consumedRequest)
        await XCTAssertThrowsErrorAsync(
            try await service.consumePushedAuthorizationRequest(requestURI, session: session, now: now)
        )
        await XCTAssertThrowsErrorAsync(
            try await service.createPushedAuthorizationRequest(
                session: session,
                state: "exact-client-state=alpha",
                codeChallengeS256: challenge,
                now: now
            )
        )
        let expiredRequest = try await service.createPushedAuthorizationRequest(
            session: session,
            state: "expired-state",
            codeChallengeS256: challenge,
            lifetime: 1,
            now: now
        )
        let expiredActiveRequest = try await service.activePushedAuthorizationRequest(
            expiredRequest,
            now: now.addingTimeInterval(2)
        )
        XCTAssertNil(expiredActiveRequest)
        await XCTAssertThrowsErrorAsync(
            try await service.consumePushedAuthorizationRequest(
                expiredRequest,
                session: session,
                now: now.addingTimeInterval(2)
            )
        )

        let code = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            binding: pushed.binding,
            codeChallengeS256: pushed.codeChallengeS256,
            now: now
        )
        let tokens = try await service.redeemAuthorizationCode(
            code,
            verifier: verifier,
            session: session,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCode(
                code,
                verifier: verifier,
                session: session,
                now: now.addingTimeInterval(1)
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(tokens.accessToken, proof: session.dpopProof, now: now)
        )

        let expiredCode = try await service.issueAuthorizationCode(
            subject: "did:plc:alice",
            session: session,
            codeChallengeS256: challenge,
            codeLifetime: 1,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCode(
                expiredCode,
                verifier: verifier,
                session: session,
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

    func testDurableAccessAndRefreshRequireValidatedProofOutputs() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(
            controlStore: database,
            serverKey: Data(repeating: 6, count: 32)
        )
        let dpopJKT = testDPoPJKT("D")
        let session = try publicOAuthSession(dpopJKT: dpopJKT)
        let pair = try await service.issue(subject: "did:plc:alice", session: session)
        let wrongProof = OAuthValidatedDPoPProof(
            keyThumbprint: testDPoPJKT("W"), jwtID: "wrong-proof", issuedAt: Date()
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(pair.accessToken, proof: wrongProof)
        )
        let grant = try await service.validateAccess(
            pair.accessToken,
            proof: session.dpopProof
        )
        XCTAssertEqual(grant.clientID, session.client.metadata.clientID.absoluteString)
        let rotated = try await service.redeemRefresh(
            pair.refreshToken,
            dpopProof: session.dpopProof,
            clientAssertion: nil,
            metadataLoader: try testMetadataLoader(database: database)
        )
        XCTAssertFalse(rotated.accessToken.isEmpty)
        let metadata = session.client.metadata
        XCTAssertThrowsError(try OAuthValidatedSession(
            issuer: "https://swan.example", client: session.client,
            redirectURI: URL(string: "https://other.example/callback")!,
            scopes: metadata.scopes, dpopProof: session.dpopProof
        ))
        XCTAssertThrowsError(try OAuthValidatedSession(
            issuer: "https://swan.example", client: session.client,
            redirectURI: metadata.redirectURIs[0],
            scopes: ["atproto", "not-registered"], dpopProof: session.dpopProof
        ))
        try await database.close()
    }

    func testConfidentialRefreshRevalidatesCompleteKeyTupleAndRevokesOnRekeyOrRemoval() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = try DurableOAuthTokenService(
            controlStore: database,
            serverKey: Data(repeating: 0x73, count: 32)
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let originalJWK = try testJWK(P256.Signing.PrivateKey(), keyID: "rotating-key")
        let session = try confidentialOAuthSession(
            dpopJKT: testDPoPJKT("K"), key: originalJWK, now: now
        )
        let rekeyedJWK = try testJWK(P256.Signing.PrivateKey(), keyID: "rotating-key")
        XCTAssertNotEqual(originalJWK.thumbprint(), rekeyedJWK.thumbprint())
        let rekeyedLoader = try testMetadataLoader(
            database: database,
            metadata: try confidentialOAuthMetadata(keySet: OAuthJSONWebKeySet(keys: [rekeyedJWK]))
        )
        let rekeyedPair = try await service.issue(
            subject: "did:plc:alice", session: session, now: now
        )
        await XCTAssertThrowsErrorAsync(try await service.redeemRefresh(
            rekeyedPair.refreshToken,
            dpopProof: session.dpopProof,
            clientAssertion: session.clientAssertion,
            metadataLoader: rekeyedLoader,
            now: now
        ))
        await XCTAssertThrowsErrorAsync(try await service.validateAccess(
            rekeyedPair.accessToken, proof: session.dpopProof, now: now
        ))

        let removedJWK = try testJWK(P256.Signing.PrivateKey(), keyID: "replacement-key")
        let removedLoader = try testMetadataLoader(
            database: database,
            metadata: try confidentialOAuthMetadata(keySet: OAuthJSONWebKeySet(keys: [removedJWK]))
        )
        let removedPair = try await service.issue(
            subject: "did:plc:bob", session: session, now: now
        )
        await XCTAssertThrowsErrorAsync(try await service.redeemRefresh(
            removedPair.refreshToken,
            dpopProof: session.dpopProof,
            clientAssertion: session.clientAssertion,
            metadataLoader: removedLoader,
            now: now
        ))
        await XCTAssertThrowsErrorAsync(try await service.validateAccess(
            removedPair.accessToken, proof: session.dpopProof, now: now
        ))
        try await database.close()
    }

    func testStrictMetadataJWKSAndVirtualLocalhostRules() throws {
        let key = P256.Signing.PrivateKey()
        let jwk = try testJWK(key, keyID: "metadata-key")
        XCTAssertThrowsError(try OAuthJSONWebKeySet.decodeValidated(Data("""
        {"keys":[{"kty":"EC","crv":"P-256","x":"abc","y":"abc"}]}
        """.utf8)))
        XCTAssertThrowsError(try OAuthJSONWebKeySet(keys: [jwk, jwk]))

        let duplicateMemberMetadata = Data("""
        {
          "client_id":"https://client.example/metadata",
          "client_id":"https://attacker.example/metadata",
          "redirect_uris":["https://client.example/callback"],
          "grant_types":["authorization_code"],
          "response_types":["code"],
          "scope":"atproto",
          "dpop_bound_access_tokens":true
        }
        """.utf8)
        XCTAssertThrowsError(try OAuthClientMetadata.decodeValidated(
            duplicateMemberMetadata,
            responseURL: URL(string: "https://client.example/metadata")!
        ))
        let duplicateJWTHeader = Data("{\"alg\":\"ES256\",\"alg\":\"none\"}".utf8).base64URLEncodedString()
        XCTAssertThrowsError(try OAuthCompactJWT.unverifiedHeader("\(duplicateJWTHeader).e30.AA"))
        let signature = Data(repeating: 0, count: 64).base64URLEncodedString()
        for unsupportedHeader in [
            "{\"alg\":\"ES256\",\"crit\":[\"exp\"]}",
            "{\"alg\":\"ES256\",\"crit\":[\"b64\"],\"b64\":false}",
            "{\"alg\":\"ES256\",\"b64\":true}",
        ] {
            let encoded = Data(unsupportedHeader.utf8).base64URLEncodedString()
            XCTAssertThrowsError(try OAuthCompactJWT.unverifiedHeader("\(encoded).e30.\(signature)"))
        }
        XCTAssertThrowsError(try OAuthClientMetadata(
            clientID: URL(string: "https://client.example/metadata")!,
            redirectURIs: [URL(string: "https://client.example/callback")!],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: ["atproto"],
            tokenEndpointAuthMethod: .privateKeyJWT,
            tokenEndpointAuthSigningAlgorithm: "ES256",
            dpopBoundAccessTokens: true
        ))
        XCTAssertThrowsError(try OAuthClientMetadata.validateStandardClientID(
            URL(string: "https://client.example:443/metadata")!
        ))

        let localID = URL(string: "http://localhost/?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%3A3333%2Fcallback")!
        let local = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: localID)
        XCTAssertTrue(local.isLocalhostDevelopmentClient)
        XCTAssertEqual(local.applicationType, .native)
        XCTAssertTrue(local.matchesRedirectURI(URL(string: "http://127.0.0.1:9999/callback")!))
        XCTAssertThrowsError(try OAuthClientMetadata.localhostDevelopmentMetadata(
            clientID: URL(string: "http://127.0.0.1/")!
        ))
        XCTAssertThrowsError(try OAuthClientMetadata.localhostDevelopmentMetadata(
            clientID: URL(string: "http://localhost:3000/")!
        ))
        XCTAssertThrowsError(try OAuthClientMetadata.localhostDevelopmentMetadata(
            clientID: URL(string: "https://localhost/metadata")!
        ))
    }

    func testHardenedRemoteFetcherRejectsUnsafeDNSAndBadResponses() async throws {
        let url = URL(string: "https://metadata.example/client.json")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let privateAddress = try XCTUnwrap(OAuthIPAddress(literal: "10.0.0.7"))
        let privateV6 = try XCTUnwrap(OAuthIPAddress(literal: "fc00::7"))
        let body = Data("{}".utf8)
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 2)

        let safeResolver = TestResolver(answers: [[publicAddress], [publicAddress]])
        let safeTransport = TestTransport(responses: [url.absoluteString: .init(
            status: 200,
            headers: ["Content-Type": ["application/json; charset=utf-8"]],
            body: body,
            responseURL: url
        )])
        let fetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: safeResolver, transport: safeTransport)
        let fetched = try await fetcher.fetchJSON(from: url)
        XCTAssertEqual(fetched, body)

        for unsafe in [privateAddress, privateV6] {
            let resolver = TestResolver(answers: [[unsafe]])
            let transport = TestTransport(responses: [:])
            let unsafeFetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: resolver, transport: transport)
            await XCTAssertThrowsErrorAsync(try await unsafeFetcher.fetchJSON(from: url))
        }
        let rebindingResolver = TestResolver(answers: [[publicAddress], [privateAddress]])
        let rebindingTransport = TestTransport(responses: [url.absoluteString: .init(
            status: 200,
            headers: ["content-type": ["application/json"]],
            body: body,
            responseURL: url
        )])
        let rebindingFetcher = OAuthRemoteDocumentFetcher(
            policy: policy, resolver: rebindingResolver, transport: rebindingTransport
        )
        await XCTAssertThrowsErrorAsync(try await rebindingFetcher.fetchJSON(from: url))

        let badResponses: [OAuthRemoteHTTPResponse] = [
            .init(status: 302, headers: ["content-type": ["application/json"]], body: body, responseURL: url),
            .init(status: 200, headers: ["content-type": ["text/html"]], body: body, responseURL: url),
            .init(status: 200, headers: ["content-type": ["application/problem+json"]], body: body, responseURL: url),
            .init(status: 200, headers: ["content-type": ["application/json"]], body: Data(repeating: 0x20, count: 1_025), responseURL: url),
            .init(status: 200, headers: ["content-type": ["application/json"]], body: body, responseURL: URL(string: "https://other.example/")!),
            .init(status: 200, headers: ["content-type": ["application/json"]], body: body, responseURL: url, redirectCount: 1),
            .init(status: 200, headers: ["content-type": ["application/json"]], body: body, responseURL: url, connectedPeerAddress: privateAddress),
        ]
        for response in badResponses {
            let resolver = TestResolver(answers: [[publicAddress], [publicAddress]])
            let transport = TestTransport(responses: [url.absoluteString: response])
            let badFetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: resolver, transport: transport)
            await XCTAssertThrowsErrorAsync(try await badFetcher.fetchJSON(from: url))
        }
    }

    func testMetadataLoaderValidatesJWKSAndUsesDurableCache() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let key = P256.Signing.PrivateKey()
        let jwk = try testJWK(key, keyID: "rotating-key")
        let keySet = try OAuthJSONWebKeySet(keys: [jwk])
        let clientID = URL(string: "https://client.example/metadata")!
        let jwksURI = URL(string: "https://client.example/keys.json")!
        let metadata = try OAuthClientMetadata(
            clientID: clientID,
            redirectURIs: [URL(string: "https://client.example/callback")!],
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: ["atproto"],
            tokenEndpointAuthMethod: .privateKeyJWT,
            tokenEndpointAuthSigningAlgorithm: "ES256",
            dpopBoundAccessTokens: true,
            jwksURI: jwksURI
        )
        let metadataBody = try JSONEncoder().encode(metadata)
        let jwksBody = try JSONEncoder().encode(keySet)
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let resolver = TestResolver(answers: [[publicAddress], [publicAddress], [publicAddress], [publicAddress]])
        let transport = TestTransport(responses: [
            clientID.absoluteString: .init(status: 200, headers: ["content-type": ["application/json"]], body: metadataBody, responseURL: clientID),
            jwksURI.absoluteString: .init(status: 200, headers: ["content-type": ["application/json"]], body: jwksBody, responseURL: jwksURI),
        ])
        let fetcher = OAuthRemoteDocumentFetcher(
            policy: try OAuthRemoteFetchPolicy(), resolver: resolver, transport: transport
        )
        let loader = try OAuthClientMetadataLoader(fetcher: fetcher, controlStore: database, cacheLifetime: 60)
        let now = Date()
        let loaded = try await loader.load(clientID: clientID, now: now)
        XCTAssertEqual(loaded.metadata, metadata)
        XCTAssertEqual(loaded.keySet, keySet)
        let initialRequestCount = await transport.requestCount()
        XCTAssertEqual(initialRequestCount, 2)
        let cached = try await loader.load(clientID: clientID, now: now.addingTimeInterval(1))
        XCTAssertEqual(cached, loaded)
        let cachedRequestCount = await transport.requestCount()
        XCTAssertEqual(cachedRequestCount, 2)
        let refreshed = try await loader.load(clientID: clientID, now: now.addingTimeInterval(61))
        XCTAssertEqual(refreshed, loaded)
        let refreshedRequestCount = await transport.requestCount()
        XCTAssertEqual(refreshedRequestCount, 4)
        try await database.close()
    }

    func testDPoPProofValidationBindsRequestNonceHashAndReplay() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let runtime = try SwanOAuthRuntime(controlStore: database, serverKey: Data(repeating: 0xA1, count: 32))
        let validator = try OAuthDPoPProofValidator(runtime: runtime)
        let signingKey = P256.Signing.PrivateKey()
        let jwk = try testJWK(signingKey, keyID: nil)
        let now = Date()
        let target = URL(string: "https://resource.example/xrpc/com.atproto.repo.getRecord?ignored=query")!
        let nonce = runtime.dpopNonceService.issue(now: now)
        let request = try OAuthDPoPRequest(
            method: "GET", target: target, serverNonce: nonce, accessToken: "access-token", requiresAccessTokenHash: true
        )
        let htu = try OAuthDPoPProofValidator.normalizedTarget(target)
        let valid = try testDPoPToken(
            key: signingKey, jwk: jwk, jti: "dpop-valid", now: now, method: "GET", target: htu,
            nonce: nonce, accessToken: "access-token"
        )
        let result = try await validator.validate(valid, request: request, now: now)
        XCTAssertEqual(result.keyThumbprint, jwk.thumbprint())
        await XCTAssertThrowsErrorAsync(try await validator.validate(valid, request: request, now: now))

        let wrongMethod = try testDPoPToken(key: signingKey, jwk: jwk, jti: "dpop-method", now: now, method: "POST", target: htu, nonce: nonce, accessToken: "access-token")
        let wrongTarget = try testDPoPToken(key: signingKey, jwk: jwk, jti: "dpop-target", now: now, method: "GET", target: "https://resource.example/other", nonce: nonce, accessToken: "access-token")
        let wrongNonce = try testDPoPToken(key: signingKey, jwk: jwk, jti: "dpop-nonce", now: now, method: "GET", target: htu, nonce: "wrong-nonce", accessToken: "access-token")
        let wrongHash = try testDPoPToken(key: signingKey, jwk: jwk, jti: "dpop-ath", now: now, method: "GET", target: htu, nonce: nonce, accessToken: "wrong-token")
        for invalid in [wrongMethod, wrongTarget, wrongNonce, wrongHash] {
            await XCTAssertThrowsErrorAsync(try await validator.validate(invalid, request: request, now: now))
        }
        let expiredNonce = runtime.dpopNonceService.issue(now: now.addingTimeInterval(-301))
        let expiredRequest = try OAuthDPoPRequest(
            method: "GET", target: target, serverNonce: expiredNonce, accessToken: "access-token", requiresAccessTokenHash: true
        )
        let expiredNonceProof = try testDPoPToken(
            key: signingKey, jwk: jwk, jti: "dpop-expired-nonce", now: now, method: "GET", target: htu,
            nonce: expiredNonce, accessToken: "access-token"
        )
        await XCTAssertThrowsErrorAsync(try await validator.validate(expiredNonceProof, request: expiredRequest, now: now))
        try await database.close()
    }

    func testPrivateKeyJWTAssertionValidationBindsKeyAndReplay() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let runtime = try SwanOAuthRuntime(controlStore: database, serverKey: Data(repeating: 0xB2, count: 32))
        let validator = try OAuthClientAssertionValidator(runtime: runtime)
        let signingKey = P256.Signing.PrivateKey()
        let jwk = try testJWK(signingKey, keyID: "assertion-key")
        let keySet = try OAuthJSONWebKeySet(keys: [jwk])
        let clientID = URL(string: "https://client.example/metadata")!
        let metadata = try OAuthClientMetadata(
            clientID: clientID,
            redirectURIs: [URL(string: "https://client.example/callback")!],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: ["atproto"],
            tokenEndpointAuthMethod: .privateKeyJWT,
            tokenEndpointAuthSigningAlgorithm: "ES256",
            dpopBoundAccessTokens: true,
            jwks: keySet
        )
        let client = OAuthResolvedClientMetadata(metadata: metadata, keySet: keySet)
        let now = Date()
        let issuer = "https://auth.example"
        let assertion = try testClientAssertion(
            key: signingKey, keyID: "assertion-key", clientID: clientID.absoluteString,
            audience: issuer, jti: "assertion-valid", now: now
        )
        let result = try await validator.validate(
            assertion,
            assertionType: OAuthClientAssertionValidator.assertionType,
            client: client,
            authorizationServerIssuer: issuer,
            now: now
        )
        XCTAssertEqual(result.selectedKeyID, "assertion-key")
        XCTAssertEqual(result.keyThumbprint, jwk.thumbprint())
        await XCTAssertThrowsErrorAsync(try await validator.validate(
            assertion, assertionType: OAuthClientAssertionValidator.assertionType,
            client: client, authorizationServerIssuer: issuer, now: now
        ))
        let wrongAudience = try testClientAssertion(
            key: signingKey, keyID: "assertion-key", clientID: clientID.absoluteString,
            audience: "https://wrong.example", jti: "assertion-aud", now: now
        )
        let missingKey = try testClientAssertion(
            key: signingKey, keyID: nil, clientID: clientID.absoluteString,
            audience: issuer, jti: "assertion-no-kid", now: now
        )
        for invalid in [wrongAudience, missingKey] {
            await XCTAssertThrowsErrorAsync(try await validator.validate(
                invalid, assertionType: OAuthClientAssertionValidator.assertionType,
                client: client, authorizationServerIssuer: issuer, now: now
            ))
        }
        let otherKey = try testJWK(P256.Signing.PrivateKey(), keyID: "other-key")
        let ambiguous = try OAuthJSONWebKeySet(keys: [jwk, otherKey])
        XCTAssertThrowsError(try ambiguous.select(keyID: nil))
        try await database.close()
    }
}

private func publicOAuthSession(
    dpopJKT: String,
    now: Date = Date()
) throws -> OAuthValidatedSession {
    let metadata = try OAuthClientMetadata(
        clientID: URL(string: "https://client.example/metadata")!,
        redirectURIs: [URL(string: "https://client.example/callback")!],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        scopes: ["atproto", "transition:generic"],
        dpopBoundAccessTokens: true
    )
    return try OAuthValidatedSession(
        issuer: "https://swan.example",
        client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
        redirectURI: URL(string: "https://client.example/callback")!,
        scopes: ["atproto", "transition:generic"],
        dpopProof: OAuthValidatedDPoPProof(
            keyThumbprint: dpopJKT,
            jwtID: "test-dpop-\(UUID().uuidString)",
            issuedAt: now
        ),
        now: now
    )
}

private func confidentialOAuthMetadata(keySet: OAuthJSONWebKeySet) throws -> OAuthClientMetadata {
    try OAuthClientMetadata(
        clientID: URL(string: "https://client.example/metadata")!,
        redirectURIs: [URL(string: "https://client.example/callback")!],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        scopes: ["atproto", "transition:generic"],
        tokenEndpointAuthMethod: .privateKeyJWT,
        tokenEndpointAuthSigningAlgorithm: "ES256",
        dpopBoundAccessTokens: true,
        jwks: keySet
    )
}

private func confidentialOAuthSession(
    dpopJKT: String,
    key: OAuthJSONWebKey,
    now: Date
) throws -> OAuthValidatedSession {
    let keySet = try OAuthJSONWebKeySet(keys: [key])
    let metadata = try confidentialOAuthMetadata(keySet: keySet)
    let assertion = OAuthValidatedClientAssertion(
        clientID: metadata.clientID.absoluteString,
        selectedKeyID: try XCTUnwrap(key.keyID),
        algorithm: "ES256",
        keyThumbprint: key.thumbprint(),
        jwtID: "test-assertion-\(UUID().uuidString)",
        expiresAt: now.addingTimeInterval(120)
    )
    return try OAuthValidatedSession(
        issuer: "https://swan.example",
        client: OAuthResolvedClientMetadata(metadata: metadata, keySet: keySet),
        redirectURI: URL(string: "https://client.example/callback")!,
        scopes: ["atproto", "transition:generic"],
        dpopProof: OAuthValidatedDPoPProof(
            keyThumbprint: dpopJKT,
            jwtID: "test-dpop-\(UUID().uuidString)",
            issuedAt: now
        ),
        clientAssertion: assertion,
        now: now
    )
}

private func testMetadataLoader(
    database: any OAuthControlStore
) throws -> OAuthClientMetadataLoader {
    let address = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
    let fetcher = OAuthRemoteDocumentFetcher(
        policy: try OAuthRemoteFetchPolicy(),
        resolver: TestResolver(answers: [[address]]),
        transport: TestTransport(responses: [:])
    )
    return try OAuthClientMetadataLoader(fetcher: fetcher, controlStore: database, cacheLifetime: 60)
}

private func testMetadataLoader(
    database: any OAuthControlStore,
    metadata: OAuthClientMetadata
) throws -> OAuthClientMetadataLoader {
    let address = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
    let fetcher = OAuthRemoteDocumentFetcher(
        policy: try OAuthRemoteFetchPolicy(),
        resolver: TestResolver(answers: [[address]]),
        transport: TestTransport(responses: [
            metadata.clientID.absoluteString: .init(
                status: 200,
                headers: ["content-type": ["application/json"]],
                body: try JSONEncoder().encode(metadata),
                responseURL: metadata.clientID
            ),
        ])
    )
    return try OAuthClientMetadataLoader(fetcher: fetcher, controlStore: database, cacheLifetime: 60)
}

private func testDPoPJKT(_ character: Character) -> String {
    String(repeating: String(character), count: 43)
}

private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appending(path: "SwanOAuthTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
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

private actor TestResolver: OAuthHostnameResolving {
    private var answers: [[OAuthIPAddress]]
    private var index = 0

    init(answers: [[OAuthIPAddress]]) {
        self.answers = answers
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        guard !answers.isEmpty else { throw SwanError.unavailable("test DNS has no answer") }
        defer { index += 1 }
        return answers[min(index, answers.count - 1)]
    }
}

private actor TestTransport: OAuthRemoteTransport {
    private let responses: [String: OAuthRemoteHTTPResponse]
    private var requests = 0

    init(responses: [String: OAuthRemoteHTTPResponse]) {
        self.responses = responses
    }

    func get(url: URL, timeout _: TimeInterval, maximumBodyBytes _: Int) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        guard let response = responses[url.absoluteString] else {
            throw SwanError.unavailable("test transport has no response")
        }
        return response
    }

    func requestCount() -> Int { requests }
}

private func testJWK(_ key: P256.Signing.PrivateKey, keyID: String?) throws -> OAuthJSONWebKey {
    let representation = key.publicKey.x963Representation
    guard representation.count == 65, representation.first == 0x04 else {
        throw SwanError.malformed("test P-256 key is invalid")
    }
    return try OAuthJSONWebKey(
        x: Data(representation[1 ..< 33]).base64URLEncodedString(),
        y: Data(representation[33 ..< 65]).base64URLEncodedString(),
        keyID: keyID
    )
}

private struct TestDPoPHeader: Encodable {
    let alg = "ES256"
    let typ = OAuthDPoPProofValidator.proofType
    let jwk: OAuthJSONWebKey
}

private struct TestDPoPClaims: Encodable {
    let jti: String
    let iat: Int64
    let htm: String
    let htu: String
    let nonce: String
    let ath: String?
}

private struct TestAssertionHeader: Encodable {
    let alg = "ES256"
    let kid: String?
}

private struct TestAssertionClaims: Encodable {
    let iss: String
    let sub: String
    let aud: String
    let iat: Int64
    let exp: Int64
    let jti: String
}

private func testDPoPToken(
    key: P256.Signing.PrivateKey,
    jwk: OAuthJSONWebKey,
    jti: String,
    now: Date,
    method: String,
    target: String,
    nonce: String,
    accessToken: String
) throws -> String {
    try testCompactJWT(
        header: TestDPoPHeader(jwk: jwk),
        claims: TestDPoPClaims(
            jti: jti,
            iat: Int64(now.timeIntervalSince1970),
            htm: method,
            htu: target,
            nonce: nonce,
            ath: Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncodedString()
        ),
        key: key
    )
}

private func testClientAssertion(
    key: P256.Signing.PrivateKey,
    keyID: String?,
    clientID: String,
    audience: String,
    jti: String,
    now: Date
) throws -> String {
    let issuedAt = Int64(now.timeIntervalSince1970)
    return try testCompactJWT(
        header: TestAssertionHeader(kid: keyID),
        claims: TestAssertionClaims(
            iss: clientID,
            sub: clientID,
            aud: audience,
            iat: issuedAt,
            exp: issuedAt + 120,
            jti: jti
        ),
        key: key
    )
}

private func testCompactJWT<Header: Encodable, Claims: Encodable>(
    header: Header,
    claims: Claims,
    key: P256.Signing.PrivateKey
) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let headerPart = try encoder.encode(header).base64URLEncodedString()
    let claimsPart = try encoder.encode(claims).base64URLEncodedString()
    let signingInput = "\(headerPart).\(claimsPart)"
    let signature = try P256WireSignature.sign(Data(signingInput.utf8), using: key).base64URLEncodedString()
    return "\(signingInput).\(signature)"
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
