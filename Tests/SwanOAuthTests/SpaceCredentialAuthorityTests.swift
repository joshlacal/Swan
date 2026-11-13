import Crypto
import Foundation
import PetrelCrypto
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceCredentialAuthorityTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let member = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let outsider = "did:plc:cdefghijklmnopqrstuvwxyz"
    private let now = Date(timeIntervalSince1970: 1_750_000_000)

    func testLocalAuthorityIssuesAndVerifiesPinnedCredentialWithoutSQLiteSecrets() async throws {
        let fixture = try await Fixture(authority: authority)
        defer { fixture.cleanup() }
        do {
            let space = try await fixture.installSpace(
                skey: "public",
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open)
            )
            let issuer = fixture.authorityIssuer()
            let token = try await issuer.issueSpaceCredential(
                space: space,
                user: member,
                authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now
            )
            let inspection = try PermissionedDataJWT.inspectSpaceCredential(token)
            XCTAssertEqual(inspection.header.typ, PermissionedDataJWT.credentialType)
            XCTAssertEqual(inspection.header.kid, "#atproto")
            XCTAssertEqual(inspection.claims.iss, authority)
            XCTAssertEqual(inspection.claims.sub, space.rawValue)
            // Swan issues a five-minute credential, because a credential names
            // no reader and is never re-checked against membership, so its
            // lifetime is the revocation window. The two-hour proposal value is
            // the ceiling this authority still *accepts*, not what it mints —
            // see `SpaceCredentialLifetimeTests`.
            XCTAssertEqual(inspection.claims.exp - inspection.claims.iat, 300)
            XCTAssertNotNil(UUID(uuidString: inspection.claims.jti))

            let verifier = DurableSpaceCredentialVerifier(
                publicKeys: fixture.localPublicKeyResolver
            )
            let authorization = try await verifier.authorization(
                for: token,
                expectedSpace: space,
                now: now.addingTimeInterval(1)
            )
            guard case let .spaceCredential(grant) = authorization else {
                return XCTFail("verified credential must produce a space grant")
            }
            XCTAssertEqual(grant.space, space)
            XCTAssertEqual(grant.permissions, [.read])
            try grant.allows(.read, now: now.addingTimeInterval(1))
            XCTAssertThrowsError(try grant.allows(.create, now: now.addingTimeInterval(1)))

            try await fixture.assertNoCredentialOrPrivateKeyPersistence(
                forbidden: [token, fixture.signingPrivateKey]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testES256KGoldenDelegationAndBoundCredentialFallbackRejectLegacyBearer() async throws {
        // These two compact JWTs were signed by the TypeScript
        // `Secp256k1Keypair` path: sha256, then a deterministic low-S compact
        // secp256k1 signature, rather than Swift keys or a reimplementation
        // used to make a self-consistent test. The credential is the original
        // atproto 3f6c96d golden. The delegation carries the October 22
        // audience `<authority>#atproto_pds`. It was re-signed with secp256k1
        // scalar 1 by that path at atproto ac0c9f15 (@noble/curves 1.8.0,
        // @noble/hashes 1.7.0, the upstream lockfile pins). The same run
        // reproduced the old `#atproto_space_host` golden's signature byte
        // for byte. Only `aud` changed.
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "ts-golden"
        )
        let delegation = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fcGRzIiwic3ViIjoiYXQ6Ly9kaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eC9zcGFjZS9hcHAuYnNreS5ib29rbWFya3MvdHMtZ29sZGVuIiwiaWF0IjoxNzUwMDAwMDAwLCJleHAiOjE3NTAwMDAwNjAsImp0aSI6InRzLW5vbmNlXzAxIn0.xKRrxDuyHIRkXSPIm48yg_gkaTuz0k0XUSOefXojt99GjLl0CRnfmR3Zf_i7a2SkEFXJEvoyYUK3HWU0S6FnuQ"
        let credential = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJ0cy1jcmVkZW50aWFsLW5vbmNlXzAxIn0.kgRbwHruWKzbsHZlMjmSFYmz1dKBjpP0eQBvJLRYlzMAClhsOpYnRYpe2fBMGtuciGngcQgEwWYSjHpa9YmIEQ"
        let delegationPublicKey = try XCTUnwrap(Data(
            base64URLEncoded: "Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY"
        ))
        let credentialPublicKey = try XCTUnwrap(Data(
            base64URLEncoded: "AsYEf5RB7X1tMEVAbpXAfNhcd45LjO88p6usCblccJ7l"
        ))
        let timestamp = Date(timeIntervalSince1970: 1_750_000_010)

        let delegationVerifier = DurableSpaceDelegationVerifier(
            publicKeys: try PinnedSpaceDelegationPublicKeyResolver(pins: [
                try .init(
                    issuer: member,
                    generation: 1,
                    secp256k1PublicKey: delegationPublicKey
                ),
            ])
        )
        // The retained 3f6c96d golden: the same claims and key, validly
        // signed, but with the pre-October 22 `#atproto_space_host` audience.
        let legacyAudienceDelegation = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAwMDYwLCJqdGkiOiJ0cy1ub25jZV8wMSJ9.CiWW_bplyq9ZtybzoUL9f7J_lqlcFKkmAbY2YsVlf5Bly4Ufue7e9QN6_8PioonLWqKnmm6T-RW3Mq2C_JTC6A"
        await XCTAssertThrowsErrorAsync(try await delegationVerifier.verifiedDelegation(
            for: legacyAudienceDelegation,
            expectedSpace: space,
            now: timestamp
        ))
        let verifiedDelegation = try await delegationVerifier.verifiedDelegation(
            for: delegation,
            expectedSpace: space,
            now: timestamp
        )
        XCTAssertEqual(verifiedDelegation.issuer, member)
        XCTAssertEqual(verifiedDelegation.audience, "\(authority)#atproto_pds")
        XCTAssertEqual(verifiedDelegation.jti, "ts-nonce_01")

        let credentialVerifier = DurableSpaceCredentialVerifier(
            publicKeys: try PinnedSpaceCredentialPublicKeyResolver(pins: [
                // The credential advertises ordinary `#atproto`, which the
                // proposal permits when no dedicated space key is published.
                try .init(
                    authority: authority,
                    keyID: PermissionedDataJWT.spaceCredentialFallbackKeyID,
                    generation: 1,
                    secp256k1PublicKey: credentialPublicKey
                ),
            ])
        )
        // The old TypeScript golden is retained to prove that a signature
        // alone no longer authorizes a pre-DPoP bearer credential.
        await XCTAssertThrowsErrorAsync(try await credentialVerifier.authorization(
            for: credential,
            expectedSpace: space,
            now: timestamp
        ))
        let authorization = try await credentialVerifier.authorization(
            for: SpaceCredentialGoldenFixtures.boundSecp256k1,
            expectedSpace: space,
            now: timestamp
        )
        guard case let .spaceCredential(grant) = authorization else {
            return XCTFail("bound ES256K credential must produce a space grant")
        }
        XCTAssertEqual(grant.space, space)
        XCTAssertEqual(grant.permissions, [.read])

        // atproto#5569: a validly signed credential in the old DPoP-bound
        // format (`cnf.jkt`) is refused; its holder must reacquire one.
        await XCTAssertThrowsErrorAsync(try await credentialVerifier.authorization(
            for: SpaceCredentialGoldenFixtures.dpopBoundSecp256k1,
            expectedSpace: space,
            now: timestamp
        ))
        XCTAssertEqual(
            try PermissionedDataJWT.inspectSpaceCredential(
                SpaceCredentialGoldenFixtures.boundSecp256k1
            ).claims.cnf.kid,
            SpaceCredentialGoldenFixtures.holderKeyID
        )

        // The same independent signer's two-hour credential has a valid
        // signature but exceeds the one-hour ceiling (upstream #5567).
        await XCTAssertThrowsErrorAsync(try await credentialVerifier.authorization(
            for: SpaceCredentialGoldenFixtures.boundSecp256k1TwoHour,
            expectedSpace: space,
            now: timestamp
        ))
    }

    func testVerifierRejectsWrongSpaceExpiredTamperedMalformedAndUnknownKeys() async throws {
        let fixture = try await Fixture(authority: authority)
        defer { fixture.cleanup() }
        do {
            let space = try await fixture.installSpace(
                skey: "verify",
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open)
            )
            let token = try await fixture.authorityIssuer().issueSpaceCredential(
                space: space,
                user: member,
                authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now
            )
            let verifier = DurableSpaceCredentialVerifier(publicKeys: fixture.localPublicKeyResolver)
            let otherSpace = try SpaceURI(
                authority: authority,
                spaceType: space.spaceType,
                skey: "other"
            )
            let foreignSpace = try SpaceURI(
                authority: outsider,
                spaceType: space.spaceType,
                skey: space.skey
            )
            await XCTAssertThrowsErrorAsync(
                try await verifier.authorization(
                    for: token,
                    expectedSpace: otherSpace,
                    now: now.addingTimeInterval(1)
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await verifier.authorization(
                    for: token,
                    expectedSpace: foreignSpace,
                    now: now.addingTimeInterval(1)
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await verifier.authorization(
                    for: token,
                    expectedSpace: space,
                    now: now.addingTimeInterval(7_261)
                )
            )
            var tampered = token
            let changed = tampered.index(tampered.startIndex, offsetBy: tampered.count - 12)
            tampered.replaceSubrange(changed ... changed, with: tampered[changed] == "A" ? "B" : "A")
            await XCTAssertThrowsErrorAsync(
                try await verifier.authorization(
                    for: tampered,
                    expectedSpace: space,
                    now: now.addingTimeInterval(1)
                )
            )
            for malformed in ["not-a-jwt", "a..b", String(repeating: "a", count: PermissionedDataJWT.maximumCompactSpaceCredentialBytes + 1)] {
                await XCTAssertThrowsErrorAsync(
                    try await verifier.authorization(
                        for: malformed,
                        expectedSpace: space,
                        now: now.addingTimeInterval(1)
                    )
                )
            }
            let unavailable = DurableSpaceCredentialVerifier(
                publicKeys: UnavailableSpaceCredentialPublicKeyResolver()
            )
            await XCTAssertThrowsErrorAsync(
                try await unavailable.authorization(
                    for: token,
                    expectedSpace: space,
                    now: now.addingTimeInterval(1)
                )
            )
            let key = P256.Signing.PrivateKey()
            XCTAssertThrowsError(try PermissionedDataJWT.createSpaceCredential(
                issuer: authority,
                space: space,
                key: key,
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now,
                lifetime: PermissionedDataJWT.spaceCredentialLifetime + 1
            ))
            XCTAssertNoThrow(try PermissionedDataJWT.createSpaceCredential(
                issuer: authority,
                space: space,
                key: key,
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now,
                kid: "#atproto"
            ))
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testPinnedResolverSelectsLatestKeyGenerationForRotation() async throws {
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "rotation"
        )
        let oldKey = P256.Signing.PrivateKey()
        let newKey = P256.Signing.PrivateKey()
        let token = try PermissionedDataJWT.createSpaceCredential(
            issuer: authority,
            space: space,
            key: newKey,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now
        )
        let resolver = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: authority, generation: 1, publicKey: oldKey.publicKey),
            try .init(authority: authority, generation: 2, publicKey: newKey.publicKey),
        ])
        let verifier = DurableSpaceCredentialVerifier(publicKeys: resolver)
        _ = try await verifier.authorization(
            for: token,
            expectedSpace: space,
            now: now.addingTimeInterval(1)
        )

        let staleToken = try PermissionedDataJWT.createSpaceCredential(
            issuer: authority,
            space: space,
            key: oldKey,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now
        )
        await XCTAssertThrowsErrorAsync(
            try await verifier.authorization(
                for: staleToken,
                expectedSpace: space,
                now: now.addingTimeInterval(1)
            )
        )
    }

    func testCredentialTimeValidationRejectsSignedExtremeValuesWithoutOverflow() throws {
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "time-bounds"
        )
        let key = P256.Signing.PrivateKey()

        let extreme = try signedSpaceCredential(
            issuer: authority,
            space: space,
            iat: .min,
            exp: .max,
            key: key
        )
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(
            extreme,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now
        ))

        let issuedAt = Int64(now.timeIntervalSince1970)
        let exactLifetime = try signedSpaceCredential(
            issuer: authority,
            space: space,
            iat: issuedAt,
            exp: issuedAt + 3_600,
            key: key
        )
        _ = try PermissionedDataJWT.verifySpaceCredential(
            exactLifetime,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now
        )

        let excessiveLifetime = try signedSpaceCredential(
            issuer: authority,
            space: space,
            iat: issuedAt,
            exp: issuedAt + 3_601,
            key: key
        )
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(
            excessiveLifetime,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now
        ))

        let expiryAtSkewBoundary = try signedSpaceCredential(
            issuer: authority,
            space: space,
            iat: issuedAt - 3_600,
            exp: issuedAt - 60,
            key: key
        )
        _ = try PermissionedDataJWT.verifySpaceCredential(
            expiryAtSkewBoundary,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now
        )
    }

    /// Upstream #5567: a credential `iat` may lead the verifier by at most
    /// five seconds, independent of the (wider) expiry clock skew; `exp` must
    /// be strictly after `iat`; and `jti` is required.
    func testCredentialIssuedAtLeadExpiryOrderAndJTIFollowUpstreamRules() throws {
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "iat-lead"
        )
        let key = P256.Signing.PrivateKey()
        let current = Int64(now.timeIntervalSince1970)
        func verify(iat: Int64, exp: Int64, jti: String? = UUID().uuidString) throws {
            _ = try PermissionedDataJWT.verifySpaceCredential(
                try signedSpaceCredential(
                    issuer: authority, space: space, iat: iat, exp: exp,
                    key: key, jti: jti
                ),
                publicKey: key.publicKey,
                expectedSpace: space,
                now: now,
                clockSkew: 60
            )
        }
        XCTAssertNoThrow(try verify(iat: current + 4, exp: current + 600))
        XCTAssertNoThrow(try verify(iat: current + 5, exp: current + 600))
        XCTAssertThrowsError(try verify(iat: current + 6, exp: current + 600))
        XCTAssertThrowsError(try verify(iat: current + 60, exp: current + 600))
        XCTAssertThrowsError(try verify(iat: current, exp: current))
        XCTAssertThrowsError(try verify(iat: current, exp: current + 600, jti: nil))
        XCTAssertThrowsError(try verify(iat: current, exp: current + 600, jti: ""))
    }

    func testVerificationOnlyResolverNeverReadsPrivateSigningMaterial() async throws {
        let fixture = try await Fixture(authority: authority)
        defer { fixture.cleanup() }
        do {
            let space = try SpaceURI(
                authority: authority,
                spaceType: "app.bsky.bookmarks",
                skey: "verification-only"
            )
            let privateKey = P256.Signing.PrivateKey()
            let keyStore = CountingVerificationKeyStore(
                publicKey: privateKey.publicKey.x963Representation
            )
            let resolver = LocalAccountSpaceCredentialPublicKeyResolver(
                accounts: fixture.accountDirectory,
                publicKeyStore: keyStore
            )
            let token = try PermissionedDataJWT.createSpaceCredential(
                issuer: authority,
                space: space,
                key: privateKey,
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now
            )
            let verifier = DurableSpaceCredentialVerifier(publicKeys: resolver)
            _ = try await verifier.authorization(
                for: token,
                expectedSpace: space,
                now: now.addingTimeInterval(1)
            )
            let reads = await keyStore.reads()
            XCTAssertEqual(reads.publicMetadata, 1)
            XCTAssertEqual(reads.privateMaterial, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testDurablePolicyBindsRequesterAndFailsClosedForMembersAppsAndManagingApps() async throws {
        let fixture = try await Fixture(authority: authority)
        defer { fixture.cleanup() }
        do {
            let memberSpace = try await fixture.installSpace(
                skey: "members",
                configuration: try .init(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
                members: [member]
            )
            let issuer = fixture.authorityIssuer()
            _ = try await issuer.issueSpaceCredential(
                space: memberSpace,
                user: member,
                authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now
            )
            await XCTAssertThrowsErrorAsync(
                try await issuer.issueSpaceCredential(
                    space: memberSpace,
                    user: outsider,
                    authorization: .accountOAuthForTesting(subject: outsider, scopes: ["atproto"]),
                    confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                    now: now
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await issuer.issueSpaceCredential(
                    space: memberSpace,
                    user: member,
                    authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"]),
                    confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                    now: now
                )
            )

            let allowListed = try await fixture.installSpace(
                skey: "allow-listed",
                configuration: try .init(
                    readPolicy: .public,
                    writePolicy: .public,
                    appAccess: .allowList(["https://reader.example/client-metadata.json"])
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await issuer.issueSpaceCredential(
                    space: allowListed,
                    user: member,
                    authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                    confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                    now: now
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await issuer.issueSpaceCredential(
                    space: allowListed,
                    user: member,
                    authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                    clientAttestation: "unverified-attestation",
                    confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                    now: now
                )
            )
            let verifiedAppIssuer = fixture.authorityIssuer(
                attestationPolicy: StaticAttestationPolicy(
                    attestation: "test-signed-attestation",
                    clientID: "https://reader.example/client-metadata.json"
                )
            )
            _ = try await verifiedAppIssuer.issueSpaceCredential(
                space: allowListed,
                user: member,
                authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                clientAttestation: "test-signed-attestation",
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                now: now
            )

            let managing = try await fixture.installSpace(
                skey: "managed",
                configuration: try .init(
                    readPolicy: .managingApp,
                    readManagingApp: "did:web:app.example#space",
                    writePolicy: .managingApp,
                    writeManagingApp: "did:web:app.example#space",
                    appAccess: .open
                )
            )
            await XCTAssertThrowsErrorAsync(
                try await issuer.issueSpaceCredential(
                    space: managing,
                    user: member,
                    authorization: .accountOAuthForTesting(subject: member, scopes: ["atproto"]),
                    confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                    now: now
                )
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testConcurrentIssuanceUsesFreshJTIsAndPersistsNoCredentials() async throws {
        let fixture = try await Fixture(authority: authority)
        defer { fixture.cleanup() }
        do {
            let space = try await fixture.installSpace(
                skey: "concurrent",
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open)
            )
            let issuer = fixture.authorityIssuer()
            let tokens = try await withThrowingTaskGroup(
                of: String.self,
                returning: [String].self
            ) { group in
                for _ in 0 ..< 24 {
                    group.addTask {
                        try await issuer.issueSpaceCredential(
                            space: space,
                            user: self.member,
                            authorization: .accountOAuthForTesting(subject: self.member, scopes: ["atproto"]),
                            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
                            now: self.now
                        )
                    }
                }
                var tokens: [String] = []
                for try await token in group { tokens.append(token) }
                return tokens
            }
            XCTAssertEqual(tokens.count, 24)
            let jtIs = try Set(tokens.map { try PermissionedDataJWT.inspectSpaceCredential($0).claims.jti })
            XCTAssertEqual(jtIs.count, tokens.count)
            try await fixture.assertNoCredentialOrPrivateKeyPersistence(
                forbidden: tokens + [fixture.signingPrivateKey]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }
}

private struct StaticAttestationPolicy: SpaceCredentialClientAttestationPolicy {
    let attestation: String
    let clientID: String

    func verifiedClientID(
        for clientAttestation: String?,
        authority _: String,
        now _: Date
    ) async throws -> String? {
        guard clientAttestation == attestation else {
            throw SwanError.unauthorized("test client attestation was not verified")
        }
        return clientID
    }
}

/// The public resolver is deliberately given a store which also records a
/// private-key read attempt. Its `AccountKeyStore` conformance lets the test
/// prove at runtime that verification uses only the narrower metadata API.
private actor CountingVerificationKeyStore: AccountKeyStore, AccountKeyPublicKeyStore {
    private let encodedPublicKey: Data
    private var publicMetadataReads = 0
    private var privateMaterialReads = 0

    init(publicKey: Data) {
        encodedPublicKey = publicKey
    }

    func create(_: Data, for _: AccountKeyReference) throws {
        throw SwanError.unavailable("test verification store cannot create keys")
    }

    func createBatch(_: [AccountKeyMaterial]) throws {
        throw SwanError.unavailable("test verification store cannot create keys")
    }

    func key(for _: AccountKeyReference) throws -> Data {
        privateMaterialReads += 1
        throw SwanError.unavailable("verification attempted to read private key material")
    }

    func publicKey(for _: AccountKeyReference) -> Data? {
        publicMetadataReads += 1
        return encodedPublicKey
    }

    func reads() -> (publicMetadata: Int, privateMaterial: Int) {
        (publicMetadataReads, privateMaterialReads)
    }
}

private func signedSpaceCredential(
    issuer: String,
    space: SpaceURI,
    iat: Int64,
    exp: Int64,
    key: P256.Signing.PrivateKey,
    jti: String? = UUID().uuidString
) throws -> String {
    let header = try JSONSerialization.data(
        withJSONObject: [
            "alg": "ES256",
            "kid": PermissionedDataJWT.spaceCredentialKeyID,
            "typ": PermissionedDataJWT.credentialType,
        ],
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    var claims: [String: Any] = [
        "cnf": ["kid": SpaceCredentialGoldenFixtures.holderKeyID],
        "exp": NSNumber(value: exp),
        "iat": NSNumber(value: iat),
        "iss": issuer,
        "sub": space.rawValue,
    ]
    if let jti { claims["jti"] = jti }
    let payload = try JSONSerialization.data(
        withJSONObject: claims,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    let signingInput = "\(header.base64URLEncodedString()).\(payload.base64URLEncodedString())"
    let signature = try P256WireSignature.sign(
        Data(signingInput.utf8),
        using: key
    ).base64URLEncodedString()
    return "\(signingInput).\(signature)"
}

private struct Fixture: Sendable {
    let root: URL
    let control: SQLiteControlDatabase
    let accountDatabase: SQLiteAccountDatabase
    let keyStore: FileAccountKeyStore
    let accountDirectory: DurableAccountDirectory
    let localSigningKeyResolver: LocalAccountSpaceCredentialSigningKeyResolver
    let localPublicKeyResolver: LocalAccountSpaceCredentialPublicKeyResolver
    let preopenedDirectory: SQLitePreMigratedAccountDirectory
    let authority: String
    let signingReference: AccountKeyReference

    init(authority: String) async throws {
        self.authority = authority
        root = FileManager.default.temporaryDirectory
            .appending(path: "SpaceCredentialAuthorityTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        control = try await SQLiteControlDatabase(dataDirectory: root)
        accountDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
        keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "credential-test-kek",
                activeKey: Data(repeating: 0x51, count: 32)
            )
        )
        let provisioner = AccountKeyProvisioner(keyStore: keyStore)
        let keys = try await provisioner.provisionInitial(accountDID: authority)
        signingReference = keys.signingReference
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: authority,
                canonicalHandle: "credential-authority.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try .init(purpose: .signing, generation: keys.signingReference.generation),
                rotationKey: try .init(purpose: .rotation, generation: keys.rotationReference.generation),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
        accountDirectory = DurableAccountDirectory(
            store: control,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(
                hasher: hasher,
                maximumConcurrentVerifications: 1,
                maximumQueuedVerifications: 1
            )
        )
        localSigningKeyResolver = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: accountDirectory,
            keyStore: keyStore
        )
        localPublicKeyResolver = LocalAccountSpaceCredentialPublicKeyResolver(
            accounts: accountDirectory,
            publicKeyStore: keyStore
        )
        try await accountDatabase.close()
        preopenedDirectory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: nil
        )
    }

    func authorityIssuer(
        attestationPolicy: any SpaceCredentialClientAttestationPolicy = UnavailableSpaceCredentialClientAttestationPolicy()
    ) -> DurableSpaceCredentialAuthority {
        DurableSpaceCredentialAuthority(
            policyDirectory: preopenedDirectory,
            signingKeys: localSigningKeyResolver,
            clientAttestationPolicy: attestationPolicy
        )
    }

    func installSpace(
        skey: String,
        configuration: SimpleSpaceConfiguration,
        members: [String] = []
    ) async throws -> SpaceURI {
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: skey
        )
        let authorization: AuthorizationContext = .accountOAuthForTesting(
            subject: authority,
            scopes: ["atproto"]
        )
        let database = try await activeDatabase()
        do {
            _ = try await database.createSimpleSpace(
                space: space,
                owner: authority,
                configuration: configuration,
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
            _ = try await database.putSimpleSpaceMembers(
                space: space,
                members: members.map { .init(did: $0, read: true, write: true) },
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_001)
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
        return space
    }

    var signingPrivateKey: String {
        // A stable, non-secret sentinel scanned alongside JWTs. The test also
        // scans the actual raw key bytes below before any fixture is removed.
        "raw-space-signing-key-must-not-appear-in-sqlite"
    }

    func assertNoCredentialOrPrivateKeyPersistence(forbidden: [String]) async throws {
        let signing = try await keyStore.key(for: signingReference)
        let enumerator = try XCTUnwrap(
            FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            )
        )
        let sqliteFiles = enumerator.compactMap { $0 as? URL }.filter {
            $0.lastPathComponent.contains(".sqlite")
                && !$0.pathComponents.contains("keys")
        }
        for file in sqliteFiles {
            let bytes = try Data(contentsOf: file)
            for value in forbidden {
                XCTAssertNil(bytes.range(of: Data(value.utf8)), "credential leaked to \(file.lastPathComponent)")
            }
            XCTAssertNil(bytes.range(of: signing), "private key leaked to \(file.lastPathComponent)")
        }
    }

    func close() async throws {
        try await preopenedDirectory.close()
        try await control.close()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    private func activeDatabase() async throws -> SQLiteAccountDatabase {
        // The bootstrap directory owns the account handle after fixture setup.
        // Opening a second handle here would violate its own startup contract,
        // so install spaces through a short-lived isolated setup connection.
        try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}
