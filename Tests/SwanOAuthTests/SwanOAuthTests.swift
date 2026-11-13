import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanStorage
import XCTest
@testable import SwanOAuth
@testable import SwanSQLite
@testable import SwanSpaces

final class SwanOAuthTests: XCTestCase {
    /// Re-aimed for §9-D21. The envelope (`localhostRequestedScopes`) used to
    /// carry a second issuance gate — `value == "atproto" || isIssuableQualified(value)`
    /// — and this test asserted eight shapes bounced off it. D21 **deletes**
    /// that gate rather than re-expressing it: the envelope is now a tokenizer
    /// and a byte budget, nothing semantic. So every one of those shapes is
    /// admitted here.
    ///
    /// **None of them is thereby granted anything.** Each was re-measured against
    /// every layer, and each is still refused — the denial moved, it did not
    /// disappear, which is exactly the claim §6.2 says must be checked rather
    /// than assumed. Split accordingly: five are refused by the PARSER, three
    /// are admitted by design and refused by the FENCES.
    func testLocalhostScopeEnvelopeIsLexicalOnlyAndSemanticsMoveDownstream() throws {
        let subject = "did:plc:abcdefghijklmnopqrstuvwx"
        let valid = "space:app.example.space?authority=\(subject)&skey=whole-space&action=read"
        XCTAssertEqual(try OAuthClientMetadata.localhostRequestedScopes(valid), Set([valid]))

        // ── The envelope admits every one of them (D21 layer 1) ──────────────
        let admittedByTheEnvelope = [
            "space:app.example.space",
            "space:*?authority=*&skey=*&action=read",
            "space:app.example.space?authority=not-a-did&skey=whole-space&action=read",
            "space:not-an-nsid?authority=\(subject)&skey=whole-space&action=read",
            "space:app.example.space?authority=\(subject)&skey=*&action=read",
            "space:app.example.space?authority=\(subject)&skey=whole-space&action=anything",
            "space:app.example.space?authority=\(subject)&skey=whole-space&action=read&unknown=value",
            "space:app.example.space?authority=\(subject)&%61uthority=\(subject)&skey=whole-space&action=read",
        ]
        for scope in admittedByTheEnvelope {
            XCTAssertNoThrow(
                try OAuthClientMetadata.localhostRequestedScopes(scope),
                """
                §9-D21: the envelope is lexical + budget only. If this throws, a \
                semantic gate has grown back at registration — the exact thing \
                D21 deletes rather than relocates.
                """
            )
        }

        // ── Five are refused by the PARSER, each for its own stated reason ───
        // Asserted with the reason, not merely "it throws": a vector that began
        // failing for a different reason would otherwise look identical, and
        // these five cover five different validator branches.
        let refusedByTheParser: [(scope: String, because: String)] = [
            ("space:app.example.space?authority=not-a-did&skey=whole-space&action=read",
             "authority is not a DID"),
            ("space:not-an-nsid?authority=\(subject)&skey=whole-space&action=read",
             "the positional type is not an NSID"),
            ("space:app.example.space?authority=\(subject)&skey=whole-space&action=anything",
             "`anything` is not a SpaceAction"),
            ("space:app.example.space?authority=\(subject)&skey=whole-space&action=read&unknown=value",
             "`unknown` is not a declared parameter"),
            // §7.3 D8 — a percent-decoded key collision. The two keys decode to
            // the same name, so `single(\"authority\")` is `.repeated`. This is a
            // real attack surface and the row §7.3 requires to STAY rejected.
            ("space:app.example.space?authority=\(subject)&%61uthority=\(subject)&skey=whole-space&action=read",
             "authority is single-valued and was supplied twice"),
        ]
        for vector in refusedByTheParser {
            XCTAssertThrowsError(
                try AtprotoScope.parse(vector.scope),
                "must be refused at the parser — \(vector.because)"
            )
        }

        // ── Three PARSE, and are held by the fences instead ──────────────────
        // These are the shapes D21 deliberately admits. The property that
        // replaced the gate is that they amplify into nothing: no delegation
        // exchange, no aggregate listing, no write target.
        for scope in [
            "space:app.example.space",
            "space:*?authority=*&skey=*&action=read",
            "space:app.example.space?authority=\(subject)&skey=*&action=read",
        ] {
            XCTAssertNoThrow(try AtprotoScope.parse(scope), "D21 admits this shape")
            let permissions = SwanScopePermissions(rawScopes: ["atproto", scope], subject: subject)
            XCTAssertTrue(permissions.rejected.isEmpty, scope)

            // No write target, in any collection (M5): an empty `collection`
            // list means NONE, not all.
            for verb in [SpaceScopeTarget.Operation.RecordWrite.create, .update, .delete] {
                XCTAssertFalse(
                    permissions.allowsSpace(
                        SpaceScopeTarget(
                            type: "app.example.space",
                            authority: subject,
                            skey: "whole-space",
                            operation: .write(verb, collection: "app.example.record")
                        )
                    ),
                    "M5: \(scope) must have no write targets"
                )
            }
            // No aggregate listing: the §6.1 fence needs literally-stated
            // `skey=*` and a literal single `action=read`, carried as DURABLE
            // provenance (§9-D23). A value reconstructed from the scope string —
            // which is what this is — must never satisfy it.
            XCTAssertFalse(
                permissions.allowsSpaceListing(type: "app.example.space", authority: nil),
                "§6.1: an aggregate listing needs stated provenance, not a re-parsed string"
            )
            // No delegation exchange, for the same reason (§5.6.3).
            XCTAssertFalse(
                permissions.allowsSpace(
                    SpaceScopeTarget(
                        type: "app.example.space",
                        authority: subject,
                        skey: "whole-space",
                        operation: .delegationExchange
                    )
                ),
                "§5.6.3: the delegation fence needs stated provenance"
            )
        }
    }

    func testBrowserApprovalSessionIsBoundAndExpiresWithoutPersistingCredentials() throws {
        let service = try OAuthBrowserSessionService(serverKey: Data(repeating: 0x43, count: 32))
        let now = Date(timeIntervalSince1970: 1_750_000_000.123_456)
        let subjectRevision = Date(timeIntervalSince1970: 1_749_999_999.654_321)
        let requestURI = "urn:ietf:params:oauth:request_uri:" + String(repeating: "a", count: 43)
        let issued = try service.issue(
            requestURI: requestURI,
            subject: "did:plc:abcdefghijklmnopqrstuvwx",
            subjectUpdatedAt: subjectRevision,
            now: now
        )
        let verified = try service.verify(issued.value, now: now.addingTimeInterval(1))
        XCTAssertEqual(verified.requestURI, requestURI)
        XCTAssertEqual(verified.subject, "did:plc:abcdefghijklmnopqrstuvwx")
        XCTAssertEqual(verified.subjectRevisionMicroseconds, 1_749_999_999_654_321)
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
        XCTAssertThrowsError(try service.issue(
            requestURI: requestURI,
            subject: "did:plc:abcdefghijklmnopqrstuvwx",
            now: now
        ))
        XCTAssertThrowsError(try service.issue(
            requestURI: requestURI,
            subjectUpdatedAt: subjectRevision,
            now: now
        ))

        let preLogin = try service.issue(requestURI: requestURI, now: now)
        let verifiedPreLogin = try service.verify(
            preLogin.value,
            now: now.addingTimeInterval(1)
        )
        XCTAssertNil(verifiedPreLogin.subject)
        XCTAssertNil(verifiedPreLogin.subjectRevisionMicroseconds)
    }

    func testPasswordRecoveryAndBrowserCodeIssuanceAreSafeInBothTransactionOrders() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let second = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let did = "did:plc:abcdefghijklmnopqrstuvwx"
            let initialVerifier =
                "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"
            let replacementVerifier =
                "$argon2id$v=19$m=65536,t=2,p=1$replacesalt$replacement-precomputed-verifier"
            let email = try AccountEmailAddress("person@example.com")
            let now = Date(timeIntervalSince1970: 1_750_000_000.123_456)
            _ = try await first.createAccount(try AccountControlRegistration(
                did: did,
                canonicalHandle: "oauth-recovery-race.example.com",
                passwordVerifier: initialVerifier,
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now
            ))
            try await first.associateEmail(did: did, email: email, now: now)
            let verificationDigest = Data(repeating: 0x81, count: 32)
            try await first.issueEmailToken(
                did: did,
                email: email,
                purpose: .verifyEmail,
                digest: verificationDigest,
                expiresAt: now.addingTimeInterval(600),
                now: now
            )
            let verifiedDID = try await first.consumeEmailToken(
                digest: verificationDigest,
                purpose: .verifyEmail,
                now: now.addingTimeInterval(1)
            )
            XCTAssertEqual(verifiedDID, did)
            let recoveryDigest = Data(repeating: 0x82, count: 32)
            try await first.issueEmailToken(
                did: did,
                email: email,
                purpose: .passwordRecovery,
                digest: recoveryDigest,
                expiresAt: now.addingTimeInterval(600),
                now: now.addingTimeInterval(1)
            )
            let loadedRecoveryConfirmation =
                try await first.passwordRecoveryConfirmation(
                    proofDigest: recoveryDigest,
                    now: now.addingTimeInterval(2)
                )
            let recoveryConfirmation = try XCTUnwrap(
                loadedRecoveryConfirmation
            )
            let recovery = try AccountPasswordRecoveryRequest(
                confirmation: recoveryConfirmation,
                expectedVerifier: initialVerifier,
                replacementVerifier: replacementVerifier
            )
            let loadedOriginalAccount = try await first.account(did: did)
            let originalAccount = try XCTUnwrap(loadedOriginalAccount)
            let originalRevision = try XCTUnwrap(
                OAuthBrowserSessionService.subjectRevisionMicroseconds(
                    for: originalAccount.updatedAt
                )
            )
            let service = try DurableOAuthTokenService(
                controlStore: first,
                serverKey: Data(repeating: 0x84, count: 32)
            )
            let session = try publicOAuthSession(
                dpopJKT: testDPoPJKT("R"),
                now: now
            )
            let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

            // SQLite serializes a real race to one of two orders. Exercise
            // both total orders explicitly so this test is deterministic.
            let codeFirstFamily = UUID()
            let codeFirst = try await service.issueAuthorizationCode(
                subject: did,
                session: session,
                codeChallengeS256: challenge,
                activeSubjectRevisionMicroseconds: originalRevision,
                familyID: codeFirstFamily,
                now: now.addingTimeInterval(3)
            )
            let recoveryResult = try await second.completePasswordRecovery(
                recovery,
                now: now.addingTimeInterval(4)
            )
            XCTAssertEqual(recoveryResult, .completed)
            await XCTAssertThrowsErrorAsync(
                try await service.redeemAuthorizationCode(
                    codeFirst,
                    verifier: verifier,
                    session: session,
                    requireActiveSubject: true,
                    now: now.addingTimeInterval(5)
                )
            )

            let recoveryFirstFamily = UUID()
            await XCTAssertThrowsErrorAsync(
                try await service.issueAuthorizationCode(
                    subject: did,
                    session: session,
                    codeChallengeS256: challenge,
                    activeSubjectRevisionMicroseconds: originalRevision,
                    familyID: recoveryFirstFamily,
                    now: now.addingTimeInterval(5)
                )
            )
            let loadedRecoveredAccount = try await first.account(did: did)
            let recoveredAccount = try XCTUnwrap(loadedRecoveredAccount)
            let recoveredRevision = try XCTUnwrap(
                OAuthBrowserSessionService.subjectRevisionMicroseconds(
                    for: recoveredAccount.updatedAt
                )
            )
            XCTAssertNotEqual(recoveredRevision, originalRevision)

            // Reusing the same family ID with the current revision proves the
            // stale attempt rolled back both the family and code insert.
            _ = try await service.issueAuthorizationCode(
                subject: did,
                session: session,
                codeChallengeS256: challenge,
                activeSubjectRevisionMicroseconds: recoveredRevision,
                familyID: recoveryFirstFamily,
                now: now.addingTimeInterval(6)
            )

            try await second.close()
            try await first.close()
        } catch {
            try? await second.close()
            try? await first.close()
            throw error
        }
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
        // October 22 (atproto ac0c9f15, guide section 3): a delegation's
        // audience is `<authority>#atproto_pds`, previously
        // `#atproto_space_host`.
        let delegation = try PermissionedDataJWT.createDelegationToken(
            issuer: "did:plc:bob",
            audience: "did:plc:alice#atproto_pds",
            space: space,
            key: key,
            now: now
        )
        let delegationClaims = try PermissionedDataJWT.verifyDelegationToken(
            delegation,
            publicKey: key.publicKey,
            audience: "did:plc:alice#atproto_pds",
            now: now
        )
        XCTAssertEqual(delegationClaims.iss, "did:plc:bob")
        XCTAssertEqual(delegationClaims.aud, "did:plc:alice#atproto_pds")
        XCTAssertEqual(delegationClaims.sub, space.rawValue)
        XCTAssertThrowsError(try PermissionedDataJWT.verifyDelegationToken(
            delegation, publicKey: key.publicKey, audience: "did:plc:mallory#atproto_pds", now: now
        ))
        XCTAssertThrowsError(try PermissionedDataJWT.verifyDelegationToken(
            delegation, publicKey: key.publicKey, audience: "did:plc:alice#atproto_space_host", now: now
        ))

        // The retired audience can be neither minted nor accepted. The legacy
        // token is validly signed by the same key, and the identical
        // construction with the current audience verifies, so the rejection
        // is the audience rule rather than the signature or the encoding.
        XCTAssertThrowsError(try PermissionedDataJWT.createDelegationToken(
            issuer: "did:plc:bob",
            audience: "did:plc:alice#atproto_space_host",
            space: space,
            key: key,
            now: now
        ))
        func handSignedDelegation(audience: String) throws -> String {
            try testCompactJWT(
                header: PermissionedDataJWT.Header(
                    alg: "ES256",
                    typ: PermissionedDataJWT.delegationType,
                    kid: PermissionedDataJWT.delegationKeyID
                ),
                claims: PermissionedDataJWT.DelegationClaims(
                    iss: "did:plc:bob",
                    aud: audience,
                    sub: space.rawValue,
                    iat: Int64(now.timeIntervalSince1970),
                    exp: Int64(now.timeIntervalSince1970) + 60,
                    jti: UUID().uuidString
                ),
                key: key
            )
        }
        let currentAudienceDelegation = try handSignedDelegation(
            audience: "did:plc:alice#atproto_pds"
        )
        XCTAssertNoThrow(try PermissionedDataJWT.inspectDelegationToken(currentAudienceDelegation))
        XCTAssertNoThrow(try PermissionedDataJWT.verifyDelegationToken(
            currentAudienceDelegation,
            publicKey: key.publicKey,
            audience: "did:plc:alice#atproto_pds",
            now: now
        ))
        let legacyAudienceDelegation = try handSignedDelegation(
            audience: "did:plc:alice#atproto_space_host"
        )
        XCTAssertThrowsError(try PermissionedDataJWT.inspectDelegationToken(legacyAudienceDelegation))
        XCTAssertThrowsError(try PermissionedDataJWT.verifyDelegationToken(
            legacyAudienceDelegation,
            publicKey: key.publicKey,
            audience: "did:plc:alice#atproto_space_host",
            now: now
        ))

        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: "did:plc:alice", space: space, key: key, confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID, now: now
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
            issuer: "did:plc:alice", space: space, key: key, confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID, now: now
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

    func testSignedJWTVerifiersRejectExtremeTimeClaimsWithoutOverflowing() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let clientID = "https://client.example/metadata"
        let audience = "https://auth.example"
        let assertion = try testCompactJWT(
            header: TestAssertionHeader(kid: "extreme-time-key"),
            claims: TestAssertionClaims(
                iss: clientID,
                sub: clientID,
                aud: audience,
                iat: .min,
                exp: .max,
                jti: "extreme-time-assertion"
            ),
            key: key
        )
        XCTAssertThrowsError(
            try OAuthCompactJWT.verify(
                assertion,
                publicKey: key.publicKey,
                constraints: .init(
                    expectedIssuer: clientID,
                    expectedAudience: audience,
                    now: now,
                    clockSkew: 60,
                    requireIssuedAt: true,
                    requireExpiration: true,
                    maxLifetime: 300
                )
            )
        )

        let serviceToken = try testCompactJWT(
            header: TestSpaceServiceHeader(),
            claims: SpaceServiceJWT.Claims(
                iss: "did:plc:abcdefghijklmnopqrstuvwx",
                aud: "did:plc:zyxwvutsrqponmlkjihgfedc",
                iat: .min,
                exp: .max,
                lxm: "com.atproto.space.notifyOfUpdates",
                jti: "extreme-time-service"
            ),
            key: key
        )
        XCTAssertThrowsError(
            try SpaceServiceJWT.verify(
                serviceToken,
                publicKey: ATProtoJWTVerificationKey.p256(key.publicKey),
                now: now
            )
        )
    }

    /// F04 — the maximum-lifetime control must not be reachable only through
    /// `iat`. `Claims.iat` is optional and the lifetime arithmetic lives inside
    /// `if let issuedAt`, so a correctly signed token that simply omits `iat`
    /// used to be accepted with an arbitrarily distant `exp`. The bound is now
    /// stated on `exp` directly, which holds whether or not `iat` is present.
    ///
    /// This deliberately does not require `iat`: the pinned reference verifier
    /// never inspects it, so the no-`iat` shape must keep verifying when its
    /// expiry is inside the window.
    func testServiceJWTWithoutIssuedAtCannotOutliveTheConfiguredMaximum() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let nowSeconds = Int64(now.timeIntervalSince1970)
        let skew: TimeInterval = 60
        let maximumLifetime: TimeInterval = 300

        func token(exp: Int64, iat: Int64? = nil) throws -> String {
            try testCompactJWT(
                header: TestSpaceServiceHeader(),
                claims: TestOptionalIssuedAtServiceClaims(
                    iss: "did:plc:abcdefghijklmnopqrstuvwx",
                    aud: "did:plc:zyxwvutsrqponmlkjihgfedc",
                    iat: iat,
                    exp: exp,
                    lxm: "com.atproto.space.notifyRepoUpdate",
                    jti: "absent-iat-service"
                ),
                key: key
            )
        }

        func verify(_ compact: String) throws -> SpaceServiceJWT.Claims {
            try SpaceServiceJWT.verify(
                compact,
                publicKey: ATProtoJWTVerificationKey.p256(key.publicKey),
                now: now,
                clockSkew: skew,
                maximumLifetime: maximumLifetime
            )
        }

        // The finding: no `iat`, expiry a year out, correct signature.
        let distant = try token(exp: nowSeconds + 365 * 24 * 60 * 60)
        XCTAssertNil(try SpaceServiceJWT.inspect(distant).claims.iat)
        XCTAssertThrowsError(try verify(distant)) { error in
            XCTAssertEqual(
                error as? PetrelCryptoError,
                .unauthorized("service authentication time claims are invalid")
            )
        }

        // One second past the skew-widened ceiling is still refused.
        let justOver = try token(
            exp: nowSeconds + Int64(skew) + Int64(maximumLifetime) + 1
        )
        XCTAssertThrowsError(try verify(justOver))

        // Interop guard: a no-`iat` token inside the window still verifies.
        let inWindow = try token(exp: nowSeconds + Int64(maximumLifetime))
        XCTAssertEqual(try verify(inWindow).exp, nowSeconds + Int64(maximumLifetime))

        // Regression: a token Swan itself minted is unaffected by the new cap.
        let issued = try SpaceServiceJWT.create(
            issuer: "did:plc:abcdefghijklmnopqrstuvwx",
            audience: "did:plc:zyxwvutsrqponmlkjihgfedc",
            method: "com.atproto.space.notifyRepoUpdate",
            eventID: "swan-issued-service",
            key: key,
            now: now
        )
        XCTAssertEqual(try verify(issued).iat, nowSeconds)

        // And the tighter `iat`-present path is unchanged: a token whose `exp`
        // is inside the cap but whose stated lifetime exceeds it still fails.
        let backdated = try token(
            exp: nowSeconds + Int64(maximumLifetime),
            iat: nowSeconds - Int64(maximumLifetime)
        )
        XCTAssertThrowsError(try verify(backdated))
    }

    func testSpaceServiceAuthenticationVerifierRefusesEmptyJTIAndNonAtprotoMethod() async throws {
        let key = P256.Signing.PrivateKey()
        let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
        let audience = "did:plc:zyxwvutsrqponmlkjihgfedc"
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let verifier = DurableSpaceServiceAuthenticationVerifier(
            publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                try .init(issuer: issuer, generation: 1, publicKey: key.publicKey)
            ])
        )

        // A correctly signed token with empty jti is refused
        let emptyJTIToken = try testCompactJWT(
            header: TestSpaceServiceHeader(),
            claims: SpaceServiceJWT.Claims(
                iss: issuer,
                aud: audience,
                iat: Int64(now.timeIntervalSince1970),
                exp: Int64(now.timeIntervalSince1970) + 60,
                lxm: "com.atproto.space.notifyRepoUpdate",
                jti: ""
            ),
            key: key
        )
        do {
            _ = try await verifier.authenticate(
                emptyJTIToken,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                now: now
            )
            XCTFail("expected empty jti token to be rejected")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // A correctly signed token whose lxm is a syntactically valid non-com.atproto NSID is refused even if expectedMethod matches
        let nonAtprotoMethod = "app.bsky.feed.getPost"
        let nonAtprotoToken = try testCompactJWT(
            header: TestSpaceServiceHeader(),
            claims: SpaceServiceJWT.Claims(
                iss: issuer,
                aud: audience,
                iat: Int64(now.timeIntervalSince1970),
                exp: Int64(now.timeIntervalSince1970) + 60,
                lxm: nonAtprotoMethod,
                jti: "valid-event-id"
            ),
            key: key
        )
        do {
            _ = try await verifier.authenticate(
                nonAtprotoToken,
                expectedAudience: audience,
                expectedMethod: nonAtprotoMethod,
                now: now
            )
            XCTFail("expected non-com.atproto method to be rejected")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }
    }

    func testSpaceServiceAuthenticationVerifierBindsRequestBodyDigestAndRejectsMismatches() async throws {
        let key = P256.Signing.PrivateKey()
        let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
        let audience = "did:plc:zyxwvutsrqponmlkjihgfedc"
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let verifier = DurableSpaceServiceAuthenticationVerifier(
            publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                try .init(issuer: issuer, generation: 1, publicKey: key.publicKey)
            ])
        )

        let space = try SpaceURI(authority: audience, spaceType: "app.bsky.bookmarks", skey: "self")
        let repo = issuer
        let rev = "222222222222z"
        let commitment = Data(repeating: 0x42, count: 32)
        let writeDigest = SpaceServiceRequestDigest.write(
            space: space,
            repository: repo,
            revision: rev,
            commitment: commitment
        )

        let tokenWithDigest = try SpaceServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: "com.atproto.space.notifyRepoUpdate",
            eventID: "event-digest-1",
            requestBodyDigest: writeDigest,
            key: key,
            now: now
        )

        // Matching expected digest succeeds and populates requestBodyDigest
        let verified = try await verifier.authenticate(
            tokenWithDigest,
            expectedAudience: audience,
            expectedMethod: "com.atproto.space.notifyRepoUpdate",
            expectedRequestBodyDigest: writeDigest,
            now: now
        )
        XCTAssertEqual(verified.requestBodyDigest, writeDigest)
        XCTAssertEqual(verified.issuer, issuer)
        XCTAssertEqual(verified.audience, audience)

        // Mismatched expected digest (altered space) throws unauthorized
        let alteredSpace = try SpaceURI(authority: audience, spaceType: "app.bsky.bookmarks", skey: "other")
        let alteredSpaceDigest = SpaceServiceRequestDigest.write(
            space: alteredSpace,
            repository: repo,
            revision: rev,
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                tokenWithDigest,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                expectedRequestBodyDigest: alteredSpaceDigest,
                now: now
            )
            XCTFail("expected altered space digest to fail")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // Mismatched expected digest (altered repository) throws unauthorized
        let alteredRepoDigest = SpaceServiceRequestDigest.write(
            space: space,
            repository: "did:plc:otherrepo1234567890ab",
            revision: rev,
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                tokenWithDigest,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                expectedRequestBodyDigest: alteredRepoDigest,
                now: now
            )
            XCTFail("expected altered repo digest to fail")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // Mismatched expected digest (altered revision) throws unauthorized
        let alteredRevDigest = SpaceServiceRequestDigest.write(
            space: space,
            repository: repo,
            revision: "222222222223a",
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                tokenWithDigest,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                expectedRequestBodyDigest: alteredRevDigest,
                now: now
            )
            XCTFail("expected altered rev digest to fail")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // Mismatched expected digest (altered commitment) throws unauthorized
        let alteredCommitmentDigest = SpaceServiceRequestDigest.write(
            space: space,
            repository: repo,
            revision: rev,
            commitment: Data(repeating: 0x99, count: 32)
        )
        do {
            _ = try await verifier.authenticate(
                tokenWithDigest,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                expectedRequestBodyDigest: alteredCommitmentDigest,
                now: now
            )
            XCTFail("expected altered commitment digest to fail")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // Unbound token (no req claim) is rejected when expected digest is required
        let unboundToken = try SpaceServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: "com.atproto.space.notifyRepoUpdate",
            eventID: "event-unbound-1",
            key: key,
            now: now
        )
        do {
            _ = try await verifier.authenticate(
                unboundToken,
                expectedAudience: audience,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                expectedRequestBodyDigest: writeDigest,
                now: now
            )
            XCTFail("expected unbound token to fail when digest expected")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

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
            requireActiveSubject: false,
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
        let grant = try await reopenedService
            .validateAccessWithoutActiveSubjectCheck(
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
                        metadataLoader: loader,
                        requireActiveSubject: false
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
                        metadataLoader: loader,
                        requireActiveSubject: false
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
            try await first.validateAccessWithoutActiveSubjectCheck(
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
                        session: session,
                        requireActiveSubject: false
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
                        session: session,
                        requireActiveSubject: false
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
            try await first.validateAccessWithoutActiveSubjectCheck(
                winningPair.accessToken,
                proof: session.dpopProof
            )
        )
        try await firstDatabase.close()
        try await secondDatabase.close()
    }

    func testDeactivationPermanentlyRevokesOAuthFamiliesAfterReactivation() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let registration = try AccountControlRegistration(
            did: did,
            canonicalHandle: "alice.swan.test",
            passwordVerifier: "$argon2id$v=19$test-verifier",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: now
        )
        _ = try await database.createAccount(registration)
        let service = try DurableOAuthTokenService(
            controlStore: database, serverKey: Data(repeating: 0xD4, count: 32))
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        let session = try publicOAuthSession(dpopJKT: testDPoPJKT("L"), now: now)
        let unredeemedCode = try await service.issueAuthorizationCode(
            subject: did, session: session, codeChallengeS256: challenge, now: now)
        let redeemedCode = try await service.issueAuthorizationCode(
            subject: did, session: session, codeChallengeS256: challenge, now: now)
        let preDeactivationGrant = try await service.redeemAuthorizationCodeForClient(
            redeemedCode, verifier: verifier,
            redirectURI: URL(string: "https://client.example/callback")!,
            authorizationServerIssuer: "https://swan.example", client: session.client,
            dpopProof: session.dpopProof, clientAssertion: nil, now: now
        )
        let preDeactivationRefresh = try XCTUnwrap(preDeactivationGrant.refreshToken)

        _ = try await database.transitionStatus(
            did: did, to: .deactivated, declaration: .init(), now: now)
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCodeForClient(
                unredeemedCode, verifier: verifier,
                redirectURI: URL(string: "https://client.example/callback")!,
                authorizationServerIssuer: "https://swan.example",
                client: session.client, dpopProof: session.dpopProof, clientAssertion: nil, now: now
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(
                preDeactivationGrant.accessToken,
                proof: session.dpopProof,
                now: now
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemRefreshForClient(
                preDeactivationRefresh, client: session.client,
                authorizationServerIssuer: "https://swan.example", dpopProof: session.dpopProof,
                clientAssertion: nil, metadataLoader: try testMetadataLoader(database: database), now: now
            )
        )

        _ = try await database.transitionStatus(
            did: did, to: .active, declaration: .init(), now: now)
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCodeForClient(
                unredeemedCode, verifier: verifier,
                redirectURI: URL(string: "https://client.example/callback")!,
                authorizationServerIssuer: "https://swan.example",
                client: session.client, dpopProof: session.dpopProof, clientAssertion: nil, now: now
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccess(
                preDeactivationGrant.accessToken,
                proof: session.dpopProof,
                now: now
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemRefreshForClient(
                preDeactivationRefresh, client: session.client,
                authorizationServerIssuer: "https://swan.example", dpopProof: session.dpopProof,
                clientAssertion: nil, metadataLoader: try testMetadataLoader(database: database), now: now
            )
        )

        let freshCode = try await service.issueAuthorizationCode(
            subject: did, session: session, codeChallengeS256: challenge, now: now)
        let freshGrant = try await service.redeemAuthorizationCodeForClient(
            freshCode, verifier: verifier,
            redirectURI: URL(string: "https://client.example/callback")!,
            authorizationServerIssuer: "https://swan.example", client: session.client,
            dpopProof: session.dpopProof, clientAssertion: nil, now: now
        )
        XCTAssertEqual(freshGrant.subject, did)
        XCTAssertNotNil(freshGrant.refreshToken)
        _ = try await service.validateAccess(
            freshGrant.accessToken,
            proof: session.dpopProof,
            now: now
        )
        try await database.close()
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
            requireActiveSubject: false,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await service.redeemAuthorizationCode(
                code,
                verifier: verifier,
                session: session,
                requireActiveSubject: false,
                now: now.addingTimeInterval(1)
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccessWithoutActiveSubjectCheck(
                tokens.accessToken,
                proof: session.dpopProof,
                now: now
            )
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
                requireActiveSubject: false,
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

    func testDurableSpaceDelegationReplayIsSingleUseAndSurvivesReopen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 5, count: 32)
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let space = try SpaceURI(
            authority: "did:plc:abcdefghijklmnopqrstuvwx",
            spaceType: "app.bsky.bookmarks",
            skey: "replay"
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let replay = try DurableSpaceDelegationReplayStore(
            controlStore: database,
            serverKey: serverKey
        )
        let expiry = now.addingTimeInterval(60)
        let firstClaim = try await replay.claim(
            issuer: "did:plc:bcdefghijklmnopqrstuvwxy",
            audience: "did:plc:abcdefghijklmnopqrstuvwx#atproto_space_host",
            space: space,
            jti: "ts-nonce_01",
            expiresAt: expiry,
            now: now
        )
        XCTAssertTrue(firstClaim)
        // A rejected replay makes no issuer call possible: the store returns
        // false atomically before the HTTP capability reaches policy/signing.
        let duplicateClaim = try await replay.claim(
            issuer: "did:plc:bcdefghijklmnopqrstuvwxy",
            audience: "did:plc:abcdefghijklmnopqrstuvwx#atproto_space_host",
            space: space,
            jti: "ts-nonce_01",
            expiresAt: expiry,
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(duplicateClaim)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedReplay = try DurableSpaceDelegationReplayStore(
            controlStore: reopened,
            serverKey: serverKey
        )
        let reopenedDuplicateClaim = try await reopenedReplay.claim(
            issuer: "did:plc:bcdefghijklmnopqrstuvwxy",
            audience: "did:plc:abcdefghijklmnopqrstuvwx#atproto_space_host",
            space: space,
            jti: "ts-nonce_01",
            expiresAt: expiry,
            now: now.addingTimeInterval(2)
        )
        XCTAssertFalse(reopenedDuplicateClaim)
        let reclaimedClaim = try await reopenedReplay.claim(
            issuer: "did:plc:bcdefghijklmnopqrstuvwxy",
            audience: "did:plc:abcdefghijklmnopqrstuvwx#atproto_space_host",
            space: space,
            jti: "ts-nonce_01",
            expiresAt: now.addingTimeInterval(120),
            now: now.addingTimeInterval(61)
        )
        XCTAssertTrue(reclaimedClaim)
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
            try await service.validateAccessWithoutActiveSubjectCheck(
                pair.accessToken,
                proof: wrongProof
            )
        )
        let grant = try await service.validateAccessWithoutActiveSubjectCheck(
            pair.accessToken,
            proof: session.dpopProof
        )
        XCTAssertEqual(grant.clientID, session.client.metadata.clientID.absoluteString)
        let rotated = try await service.redeemRefresh(
            pair.refreshToken,
            dpopProof: session.dpopProof,
            clientAssertion: nil,
            metadataLoader: try testMetadataLoader(database: database),
            requireActiveSubject: false
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
            requireActiveSubject: false,
            now: now
        ))
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccessWithoutActiveSubjectCheck(
            rekeyedPair.accessToken,
            proof: session.dpopProof,
            now: now
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
            requireActiveSubject: false,
            now: now
        ))
        await XCTAssertThrowsErrorAsync(
            try await service.validateAccessWithoutActiveSubjectCheck(
            removedPair.accessToken,
            proof: session.dpopProof,
            now: now
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

    func testStrictJSONRejectsHostileNestingBeforeRecursiveDescent() throws {
        let maximumAcceptedDepth = 64
        let boundaryArray =
            String(repeating: "[", count: maximumAcceptedDepth)
            + "null"
            + String(repeating: "]", count: maximumAcceptedDepth)
        XCTAssertNoThrow(try StrictJSON.validate(Data(boundaryArray.utf8)))

        let hostileDepth = 10_000
        let deeplyNestedObject =
            String(repeating: #"{"nested":"#, count: hostileDepth)
            + "null"
            + String(repeating: "}", count: hostileDepth)
        XCTAssertThrowsError(
            try StrictJSON.validate(Data(deeplyNestedObject.utf8))
        ) { error in
            XCTAssertEqual(
                error as? PetrelCryptoError,
                .malformed("JSON exceeds maximum nesting depth")
            )
        }

        let deeplyNestedArray =
            String(repeating: "[", count: hostileDepth)
            + "null"
            + String(repeating: "]", count: hostileDepth)
        XCTAssertThrowsError(
            try StrictJSON.validate(Data(deeplyNestedArray.utf8))
        ) { error in
            XCTAssertEqual(
                error as? PetrelCryptoError,
                .malformed("JSON exceeds maximum nesting depth")
            )
        }

        let jwtDepth = 512
        let deeplyNestedJWTHeader =
            #"{"alg":"ES256","nested":"#
            + String(repeating: "[", count: jwtDepth)
            + "null"
            + String(repeating: "]", count: jwtDepth)
            + "}"
        let jwtHeaderData = Data(deeplyNestedJWTHeader.utf8)
        XCTAssertLessThan(jwtHeaderData.count, 4_096)
        let encodedHeader = jwtHeaderData.base64URLEncodedString()
        let signature =
            Data(repeating: 0, count: 64).base64URLEncodedString()
        let compactJWT = "\(encodedHeader).e30.\(signature)"
        XCTAssertThrowsError(
            try OAuthCompactJWT.unverifiedHeader(compactJWT)
        ) { error in
            XCTAssertEqual(
                error as? PetrelCryptoError,
                .malformed("JSON exceeds maximum nesting depth")
            )
        }
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
            responseURL: url,
            connectedPeerAddress: publicAddress
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
            responseURL: url,
            connectedPeerAddress: publicAddress
        )])
        let rebindingFetcher = OAuthRemoteDocumentFetcher(
            policy: policy, resolver: rebindingResolver, transport: rebindingTransport
        )
        await XCTAssertThrowsErrorAsync(try await rebindingFetcher.fetchJSON(from: url))

        let badResponses: [OAuthRemoteHTTPResponse] = [
            .init(status: 302, headers: ["content-type": ["application/json"]], body: body, responseURL: url),
            .init(status: 200, headers: ["content-type": ["text/html"]], body: body, responseURL: url),
            // Erratum 03 addendum: `+json` suffix types are JSON and now pass
            // the content-type gate (pinned in
            // testHardenedRemoteFetcherAcceptsStructuredJSONSuffixTypes), so
            // this rejection vector uses a genuinely non-JSON type instead of
            // the former `application/problem+json`.
            .init(status: 200, headers: ["content-type": ["application/xml"]], body: body, responseURL: url),
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
        let nilPeerFetcher = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
            transport: TestTransport(
                responses: [url.absoluteString: .init(
                    status: 200, headers: ["content-type": ["application/json"]],
                    body: body, responseURL: url
                )],
                reportsConnectedPeer: false
            )
        )
        await XCTAssertThrowsErrorAsync(try await nilPeerFetcher.fetchJSON(from: url))
    }

    /// Erratum 03 addendum (defect class instance #9): `fetchJSON` accepts
    /// `application/json` and any RFC 6839 `+json` structured-syntax suffix —
    /// DID documents arrive as `application/did+ld+json` from bulleted.app
    /// and plc.directory alike, and the exact match made every DID-document
    /// resolution unresolvable. Non-JSON types still refuse, as does a bare
    /// suffix with no subtype name.
    func testHardenedRemoteFetcherAcceptsStructuredJSONSuffixTypes() async throws {
        let url = URL(string: "https://metadata.example/.well-known/did.json")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let body = Data(#"{"id":"did:web:metadata.example"}"#.utf8)
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 2)

        for accepted in [
            "application/did+ld+json; charset=utf-8",
            "application/did+json",
            "application/json",
        ] {
            let fetcher = OAuthRemoteDocumentFetcher(
                policy: policy,
                resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
                transport: TestTransport(responses: [url.absoluteString: .init(
                    status: 200,
                    headers: ["Content-Type": [accepted]],
                    body: body,
                    responseURL: url,
                    connectedPeerAddress: publicAddress
                )])
            )
            let fetched = try await fetcher.fetchJSON(from: url)
            XCTAssertEqual(fetched, body, "content-type \(accepted) must be accepted")
        }

        for refused in ["text/html", "application/+json", "text/json", "application/jsonx"] {
            let fetcher = OAuthRemoteDocumentFetcher(
                policy: policy,
                resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
                transport: TestTransport(responses: [url.absoluteString: .init(
                    status: 200,
                    headers: ["Content-Type": [refused]],
                    body: body,
                    responseURL: url,
                    connectedPeerAddress: publicAddress
                )])
            )
            do {
                _ = try await fetcher.fetchJSON(from: url)
                XCTFail("content-type \(refused) must be refused")
            } catch {}
        }
    }

    /// `fetchBytes` must inherit every control `fetchJSON` has except the
    /// JSON-specific ones (content-type-is-JSON, `StrictJSON.validate`),
    /// which do not apply to a binary payload like a CAR. A test that only
    /// asserted "bytes come back" would pass even if `fetchBytes` bypassed
    /// URL policy, the peer proof, redirect policy, or the body cap — so
    /// each control gets its own assertion, mirroring
    /// `testHardenedRemoteFetcherRejectsUnsafeDNSAndBadResponses` above but
    /// through the bytes path.
    func testHardenedRemoteFetcherFetchBytesInheritsControls() async throws {
        let url = URL(string: "https://metadata.example/proof.car")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let privateAddress = try XCTUnwrap(OAuthIPAddress(literal: "10.0.0.7"))
        let privateV6 = try XCTUnwrap(OAuthIPAddress(literal: "fc00::7"))
        let body = Data([0x01, 0x71, 0xA0, 0xE4, 0x02, 0x20])
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 2)

        // Happy path: non-JSON content type succeeds for fetchBytes even
        // though it would fail fetchJSON, proving fetchBytes genuinely skips
        // only the JSON-specific checks rather than accidentally becoming
        // permissive elsewhere.
        let safeResolver = TestResolver(answers: [[publicAddress], [publicAddress]])
        let safeTransport = TestTransport(responses: [url.absoluteString: .init(
            status: 200,
            headers: ["Content-Type": ["application/vnd.ipld.car"]],
            body: body,
            responseURL: url,
            connectedPeerAddress: publicAddress
        )])
        let fetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: safeResolver, transport: safeTransport)
        let fetched = try await fetcher.fetchBytes(from: url)
        XCTAssertEqual(fetched, body)

        // Private-address peer is refused, same as fetchJSON.
        for unsafe in [privateAddress, privateV6] {
            let resolver = TestResolver(answers: [[unsafe]])
            let transport = TestTransport(responses: [:])
            let unsafeFetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: resolver, transport: transport)
            await XCTAssertThrowsErrorAsync(try await unsafeFetcher.fetchBytes(from: url))
        }

        // DNS-rebinding peer mismatch between preflight and postflight answer
        // sets is refused, same as fetchJSON.
        let rebindingResolver = TestResolver(answers: [[publicAddress], [privateAddress]])
        let rebindingTransport = TestTransport(responses: [url.absoluteString: .init(
            status: 200,
            headers: ["content-type": ["application/vnd.ipld.car"]],
            body: body,
            responseURL: url,
            connectedPeerAddress: publicAddress
        )])
        let rebindingFetcher = OAuthRemoteDocumentFetcher(
            policy: policy, resolver: rebindingResolver, transport: rebindingTransport
        )
        await XCTAssertThrowsErrorAsync(try await rebindingFetcher.fetchBytes(from: url))

        // Over-cap body, redirect, wrong response URL, and a nil connected
        // peer are all refused, same as fetchJSON. Content type is
        // deliberately NOT included here since it is JSON-only.
        let badResponses: [OAuthRemoteHTTPResponse] = [
            .init(status: 302, headers: ["content-type": ["application/vnd.ipld.car"]], body: body, responseURL: url),
            .init(status: 200, headers: ["content-type": ["application/vnd.ipld.car"]], body: Data(repeating: 0x20, count: 1_025), responseURL: url),
            .init(status: 200, headers: ["content-type": ["application/vnd.ipld.car"]], body: body, responseURL: URL(string: "https://other.example/")!),
            .init(status: 200, headers: ["content-type": ["application/vnd.ipld.car"]], body: body, responseURL: url, redirectCount: 1),
            .init(status: 200, headers: ["content-type": ["application/vnd.ipld.car"]], body: body, responseURL: url, connectedPeerAddress: privateAddress),
        ]
        for response in badResponses {
            let resolver = TestResolver(answers: [[publicAddress], [publicAddress]])
            let transport = TestTransport(responses: [url.absoluteString: response])
            let badFetcher = OAuthRemoteDocumentFetcher(policy: policy, resolver: resolver, transport: transport)
            await XCTAssertThrowsErrorAsync(try await badFetcher.fetchBytes(from: url))
        }
        let nilPeerFetcher = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
            transport: TestTransport(
                responses: [url.absoluteString: .init(
                    status: 200, headers: ["content-type": ["application/vnd.ipld.car"]],
                    body: body, responseURL: url
                )],
                reportsConnectedPeer: false
            )
        )
        await XCTAssertThrowsErrorAsync(try await nilPeerFetcher.fetchBytes(from: url))

        // Malformed/non-HTTPS URLs are refused before any network work,
        // same as fetchJSON's policy.validateURL gate.
        let insecureURL = URL(string: "http://metadata.example/proof.car")!
        await XCTAssertThrowsErrorAsync(try await fetcher.fetchBytes(from: insecureURL))
    }

    /// Confirms the DNS-preflight/postflight deadline race — the mechanism
    /// most likely to be silently dropped by a naive refactor — applies to
    /// `fetchBytes` exactly as it does to `fetchJSON` in
    /// `testHardenedRemoteFetcherBoundsPreAndPostDNSResolution` below.
    func testHardenedRemoteFetcherFetchBytesBoundsPreAndPostDNSResolution() async throws {
        let url = URL(string: "https://metadata.example/proof.car")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let body = Data([0x01, 0x71, 0xA0, 0xE4])
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 0.05)
        let response = OAuthRemoteHTTPResponse(
            status: 200,
            headers: ["content-type": ["application/vnd.ipld.car"]],
            body: body,
            responseURL: url,
            connectedPeerAddress: publicAddress
        )

        let slowPreflightTransport = TestTransport(responses: [url.absoluteString: response])
        let slowPreflight = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: DelayedTestResolver(
                address: publicAddress, delay: 0.75, delayFirstResolution: true),
            transport: slowPreflightTransport
        )
        let preflightStart = Date()
        await XCTAssertThrowsErrorAsync(try await slowPreflight.fetchBytes(from: url))
        XCTAssertLessThan(Date().timeIntervalSince(preflightStart), 0.4)
        let preflightRequests = await slowPreflightTransport.requestCount()
        XCTAssertEqual(preflightRequests, 0)

        let slowPostflightTransport = TestTransport(responses: [url.absoluteString: response])
        let slowPostflight = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: DelayedTestResolver(
                address: publicAddress, delay: 0.75, delayFirstResolution: false),
            transport: slowPostflightTransport
        )
        let postflightStart = Date()
        await XCTAssertThrowsErrorAsync(try await slowPostflight.fetchBytes(from: url))
        XCTAssertLessThan(Date().timeIntervalSince(postflightStart), 0.4)
        let postflightRequests = await slowPostflightTransport.requestCount()
        XCTAssertEqual(postflightRequests, 1)
    }

    func testHardenedRemoteFetcherBoundsPreAndPostDNSResolution() async throws {
        let url = URL(string: "https://metadata.example/client.json")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let body = Data("{}".utf8)
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 0.05)
        let response = OAuthRemoteHTTPResponse(
            status: 200,
            headers: ["content-type": ["application/json"]],
            body: body,
            responseURL: url,
            connectedPeerAddress: publicAddress
        )

        let slowPreflightTransport = TestTransport(responses: [url.absoluteString: response])
        let slowPreflight = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: DelayedTestResolver(
                address: publicAddress, delay: 0.75, delayFirstResolution: true),
            transport: slowPreflightTransport
        )
        let preflightStart = Date()
        await XCTAssertThrowsErrorAsync(try await slowPreflight.fetchJSON(from: url))
        XCTAssertLessThan(Date().timeIntervalSince(preflightStart), 0.4)
        let preflightRequests = await slowPreflightTransport.requestCount()
        XCTAssertEqual(preflightRequests, 0)

        let slowPostflightTransport = TestTransport(responses: [url.absoluteString: response])
        let slowPostflight = OAuthRemoteDocumentFetcher(
            policy: policy,
            resolver: DelayedTestResolver(
                address: publicAddress, delay: 0.75, delayFirstResolution: false),
            transport: slowPostflightTransport
        )
        let postflightStart = Date()
        await XCTAssertThrowsErrorAsync(try await slowPostflight.fetchJSON(from: url))
        XCTAssertLessThan(Date().timeIntervalSince(postflightStart), 0.4)
        let postflightRequests = await slowPostflightTransport.requestCount()
        XCTAssertEqual(postflightRequests, 1)
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
            clientID.absoluteString: .init(status: 200, headers: ["content-type": ["application/json"]], body: metadataBody, responseURL: clientID, connectedPeerAddress: publicAddress),
            jwksURI.absoluteString: .init(status: 200, headers: ["content-type": ["application/json"]], body: jwksBody, responseURL: jwksURI, connectedPeerAddress: publicAddress),
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

    func testBoundedJSONPosterRejectsPrivateDNSAndRebinding() async throws {
        let url = URL(string: "https://notify.example/xrpc/com.atproto.space.notifyRepoUpdate")!
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let privateAddress = try XCTUnwrap(OAuthIPAddress(literal: "10.0.0.7"))
        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 1_024, timeout: 2)
        let body = Data("{\"space\":\"at://did:plc:alice/app.bsky.bookmarks/self\"}".utf8)

        let safeTransport = TestPostTransport(response: .init(
            status: 204,
            headers: ["content-length": ["0"]],
            body: Data(),
            responseURL: url,
            connectedPeerAddress: publicAddress
        ))
        let safePoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
            transport: safeTransport
        )
        try await safePoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        )
        let safeRequests = await safeTransport.requestCount()
        XCTAssertEqual(safeRequests, 1)

        let privateTransport = TestPostTransport(response: .init(
            status: 204, headers: [:], body: Data(), responseURL: url
        ))
        let privatePoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[privateAddress]]),
            transport: privateTransport
        )
        await XCTAssertThrowsErrorAsync(try await privatePoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        ))
        let privateRequests = await privateTransport.requestCount()
        XCTAssertEqual(privateRequests, 0)

        let rebindingTransport = TestPostTransport(response: .init(
            status: 204,
            headers: [:],
            body: Data(),
            responseURL: url,
            connectedPeerAddress: publicAddress
        ))
        let rebindingPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [privateAddress]]),
            transport: rebindingTransport
        )
        await XCTAssertThrowsErrorAsync(try await rebindingPoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        ))
        let rebindingRequests = await rebindingTransport.requestCount()
        XCTAssertEqual(rebindingRequests, 1)

        // A still-public DNS answer is not sufficient: the actual connected
        // peer must be pinned into the re-resolved approved answer set.
        let alternatePublicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.35"))
        let peerMismatchTransport = TestPostTransport(response: .init(
            status: 204,
            headers: [:],
            body: Data(),
            responseURL: url,
            connectedPeerAddress: publicAddress
        ))
        let peerMismatchPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [alternatePublicAddress]]),
            transport: peerMismatchTransport
        )
        await XCTAssertThrowsErrorAsync(try await peerMismatchPoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        ))
        let peerMismatchRequests = await peerMismatchTransport.requestCount()
        XCTAssertEqual(peerMismatchRequests, 1)

        // The exact-URL guard on the response. It used to compare the request
        // URL against itself and could not fail; the transports now report the
        // URL their emitted request target denotes, so a transport that
        // answers for a different resource is refused here.
        let otherURLTransport = TestPostTransport(response: .init(
            status: 204,
            headers: [:],
            body: Data(),
            responseURL: URL(string: "https://notify.example/other")!,
            connectedPeerAddress: publicAddress
        ))
        let otherURLPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
            transport: otherURLTransport
        )
        await XCTAssertThrowsErrorAsync(try await otherURLPoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        ))
        let otherURLRequests = await otherURLTransport.requestCount()
        XCTAssertEqual(otherURLRequests, 1)

        let nilPeerTransport = TestPostTransport(response: .init(
            status: 204, headers: [:], body: Data(), responseURL: url
        ))
        let nilPeerPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: TestResolver(answers: [[publicAddress], [publicAddress]]),
            transport: nilPeerTransport
        )
        await XCTAssertThrowsErrorAsync(try await nilPeerPoster.postJSON(
            to: url,
            headers: ["content-type": "application/json"],
            body: body
        ))
        let nilPeerRequests = await nilPeerTransport.requestCount()
        XCTAssertEqual(nilPeerRequests, 1)
    }

    func testDurableSpaceServiceAuthenticationVerifierValidatesAndBindsRequestBodyDigest() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let issuer = "did:plc:bcdefghijklmnopqrstuvwxy"
        let audience = "did:plc:abcdefghijklmnopqrstuvwx"
        let method = "com.atproto.space.notifyRepoUpdate"
        let eventID = "evt-test-1234"
        let space = try SpaceURI(authority: audience, spaceType: "app.bsky.bookmarks", skey: "default")
        let repository = issuer
        let wireRevision = "222222222222a"
        let commitment = Data(repeating: 0x42, count: 32)
        let digest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: repository,
            wireRevision: wireRevision,
            commitment: commitment
        )

        let token = try SpaceServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: eventID,
            requestBodyDigest: digest,
            key: privateKey,
            now: Date()
        )

        let resolver = try PinnedSpaceServicePublicKeyResolver(
            pins: [PinnedSpaceServicePublicKey(issuer: issuer, generation: 1, publicKey: publicKey)]
        )
        let verifier = DurableSpaceServiceAuthenticationVerifier(publicKeys: resolver)

        // 1. Exact digest succeeds and returns verified digest in result
        let verified = try await verifier.authenticate(
            token,
            expectedAudience: audience,
            expectedMethod: method,
            expectedRequestBodyDigest: digest,
            now: Date()
        )
        XCTAssertEqual(verified.issuer, issuer)
        XCTAssertEqual(verified.audience, audience)
        XCTAssertEqual(verified.method, method)
        XCTAssertEqual(verified.eventID, eventID)
        XCTAssertEqual(verified.requestBodyDigest, digest)

        // 2. Mismatched space in digest fails
        let otherSpace = try SpaceURI(authority: audience, spaceType: "app.bsky.bookmarks", skey: "other")
        let badSpaceDigest = SpaceNotificationRequestDigest.write(
            space: otherSpace,
            repository: repository,
            wireRevision: wireRevision,
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                token,
                expectedAudience: audience,
                expectedMethod: method,
                expectedRequestBodyDigest: badSpaceDigest,
                now: Date()
            )
            XCTFail("mismatched space digest must fail verification")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // 3. Mismatched repository in digest fails
        let badRepoDigest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: "did:plc:other-repo",
            wireRevision: wireRevision,
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                token,
                expectedAudience: audience,
                expectedMethod: method,
                expectedRequestBodyDigest: badRepoDigest,
                now: Date()
            )
            XCTFail("mismatched repository digest must fail verification")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // 4. Mismatched revision in digest fails
        let badRevDigest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: repository,
            wireRevision: "222222222222b",
            commitment: commitment
        )
        do {
            _ = try await verifier.authenticate(
                token,
                expectedAudience: audience,
                expectedMethod: method,
                expectedRequestBodyDigest: badRevDigest,
                now: Date()
            )
            XCTFail("mismatched revision digest must fail verification")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // 5. Mismatched commitment in digest fails
        let badCommitmentDigest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: repository,
            wireRevision: wireRevision,
            commitment: Data(repeating: 0x99, count: 32)
        )
        do {
            _ = try await verifier.authenticate(
                token,
                expectedAudience: audience,
                expectedMethod: method,
                expectedRequestBodyDigest: badCommitmentDigest,
                now: Date()
            )
            XCTFail("mismatched commitment digest must fail verification")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // 6. Token without req fails when expected digest is provided
        let unboundToken = try SpaceServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: eventID,
            key: privateKey,
            now: Date()
        )
        do {
            _ = try await verifier.authenticate(
                unboundToken,
                expectedAudience: audience,
                expectedMethod: method,
                expectedRequestBodyDigest: digest,
                now: Date()
            )
            XCTFail("token without req claim must fail when expected digest is required")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }
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

/// Deliberately ignores task cancellation while waiting, matching the worst
/// case for a resolver backed by a platform API without cancellation support.
/// The fetcher must still return on its policy deadline rather than awaiting
/// this eventual callback.
private actor DelayedTestResolver: OAuthHostnameResolving {
    private let address: OAuthIPAddress
    private let delay: TimeInterval
    private let delayFirstResolution: Bool
    private var resolutionCount = 0

    init(address: OAuthIPAddress, delay: TimeInterval, delayFirstResolution: Bool) {
        self.address = address
        self.delay = delay
        self.delayFirstResolution = delayFirstResolution
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        resolutionCount += 1
        let shouldDelay = delayFirstResolution ? resolutionCount == 1 : resolutionCount > 1
        guard shouldDelay else { return [address] }
        let address = address
        let delay = delay
        return await withCheckedContinuation { continuation in
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                continuation.resume(returning: [address])
            }
        }
    }
}

private actor TestTransport: OAuthRemoteTransport {
    private let responses: [String: OAuthRemoteHTTPResponse]
    private var requests = 0

    private let reportsConnectedPeer: Bool

    init(
        responses: [String: OAuthRemoteHTTPResponse],
        reportsConnectedPeer: Bool = true
    ) {
        self.responses = responses
        self.reportsConnectedPeer = reportsConnectedPeer
    }

    func get(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        guard let response = responses[url.absoluteString] else {
            throw SwanError.unavailable("test transport has no response")
        }
        guard reportsConnectedPeer, response.connectedPeerAddress == nil,
              let peer = approvedPeers.sorted(by: { $0.description < $1.description }).first else {
            return response
        }
        return .init(
            status: response.status, headers: response.headers, body: response.body,
            responseURL: response.responseURL, redirectCount: response.redirectCount,
            connectedPeerAddress: peer
        )
    }

    func requestCount() -> Int { requests }
}

private actor TestPostTransport: OAuthRemotePostTransport {
    private let response: OAuthRemoteHTTPResponse
    private var requests = 0

    init(response: OAuthRemoteHTTPResponse) {
        self.response = response
    }

    func post(
        url _: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        headers _: [String: String],
        body _: Data,
        timeout _: TimeInterval,
        maximumResponseBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
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

private struct TestSpaceServiceHeader: Encodable {
    let alg = "ES256"
    let typ = "JWT"
}

/// A service-JWT claim set whose `iat` is genuinely absent from the encoded
/// payload rather than encoded as `null`. `SpaceServiceJWT.Claims` cannot
/// express that: its synthesized encoder is what the wire shape must be tested
/// against, not reused to produce it.
private struct TestOptionalIssuedAtServiceClaims: Encodable {
    let iss: String
    let aud: String
    let iat: Int64?
    let exp: Int64
    let lxm: String
    let jti: String

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(iss, forKey: .iss)
        try container.encode(aud, forKey: .aud)
        try container.encodeIfPresent(iat, forKey: .iat)
        try container.encode(exp, forKey: .exp)
        try container.encode(lxm, forKey: .lxm)
        try container.encode(jti, forKey: .jti)
    }

    enum CodingKeys: String, CodingKey {
        case iss, aud, iat, exp, lxm, jti
    }
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
