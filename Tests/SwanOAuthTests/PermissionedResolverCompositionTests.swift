import Crypto
import Foundation
import PetrelCrypto
import SwanCore
@testable import SwanOAuth
import SwanSpaces
import XCTest

final class PermissionedResolverCompositionTests: XCTestCase {
    private let localDID = "did:plc:cdefghijklmnopqrstuvwxyz"
    private let remoteAuthority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let remoteMember = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let now = Date(timeIntervalSince1970: 1_750_000_010)

    func testLocalES256AndPinnedRemoteES256KVerifyConcurrently() async throws {
        let localKey = P256.Signing.PrivateKey()
        let localSpace = try SpaceURI(
            authority: localDID,
            spaceType: "app.bsky.bookmarks",
            skey: "local"
        )
        let remoteSpace = try SpaceURI(
            authority: remoteAuthority,
            spaceType: "app.bsky.bookmarks",
            skey: "ts-golden"
        )
        let remoteDelegationKey = try XCTUnwrap(Data(
            base64URLEncoded: "Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY"
        ))
        let remoteCredentialKey = try XCTUnwrap(Data(
            base64URLEncoded: "AsYEf5RB7X1tMEVAbpXAfNhcd45LjO88p6usCblccJ7l"
        ))
        let remoteServiceKey = try XCTUnwrap(Data(
            base64URLEncoded: "AoS_dWImK71pQAhXSPO-avpSrjFxVRgezjG2Y1HM_6Sw"
        ))

        let credentialKeys = try await CompositeSpaceCredentialPublicKeyResolver(
            local: StaticCredentialKeys(keys: [
                "\(localDID)|\(PermissionedDataJWT.spaceCredentialIssuedKeyID)": .p256(localKey.publicKey),
            ]),
            pinned: [
                try .init(
                    authority: remoteAuthority,
                    keyID: PermissionedDataJWT.spaceCredentialFallbackKeyID,
                    generation: 1,
                    secp256k1PublicKey: remoteCredentialKey
                ),
            ]
        )
        let delegationKeys = try await CompositeSpaceDelegationPublicKeyResolver(
            local: StaticDelegationKeys(keys: [
                "\(localDID)|\(PermissionedDataJWT.delegationKeyID)": .p256(localKey.publicKey),
            ]),
            pinned: [
                try .init(
                    issuer: remoteMember,
                    generation: 1,
                    secp256k1PublicKey: remoteDelegationKey
                ),
            ]
        )
        let serviceKeys = try await CompositeSpaceServicePublicKeyResolver(
            local: StaticServiceKeys(keys: [localDID: .p256(localKey.publicKey)]),
            pinned: [
                try .init(
                    issuer: remoteMember,
                    generation: 1,
                    secp256k1PublicKey: remoteServiceKey
                ),
            ]
        )

        let localCredential = try PermissionedDataJWT.createSpaceCredential(
            issuer: localDID,
            space: localSpace,
            key: localKey,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now
        )
        _ = try await DurableSpaceCredentialVerifier(publicKeys: credentialKeys)
            .authorization(for: localCredential, expectedSpace: localSpace, now: now)
        _ = try await DurableSpaceCredentialVerifier(publicKeys: credentialKeys)
            .authorization(
                for: SpaceCredentialGoldenFixtures.boundSecp256k1,
                expectedSpace: remoteSpace,
                now: now
            )
        await XCTAssertCompositionThrowsError {
            _ = try await DurableSpaceCredentialVerifier(publicKeys: credentialKeys)
                .authorization(for: Self.remoteCredential, expectedSpace: remoteSpace, now: self.now)
        }

        // October 22 (atproto ac0c9f15, guide section 3): a delegation's
        // audience is the authority's `#atproto_pds`. The retired
        // `#atproto_space_host` audience can no longer be minted.
        XCTAssertThrowsError(try PermissionedDataJWT.createDelegationToken(
            issuer: localDID,
            audience: "\(localDID)#atproto_space_host",
            space: localSpace,
            key: localKey,
            now: now
        ))
        let localDelegation = try PermissionedDataJWT.createDelegationToken(
            issuer: localDID,
            audience: "\(localDID)#atproto_pds",
            space: localSpace,
            key: localKey,
            now: now
        )
        let verifiedLocalDelegation = try await DurableSpaceDelegationVerifier(publicKeys: delegationKeys)
            .verifiedDelegation(for: localDelegation, expectedSpace: localSpace, now: now)
        XCTAssertEqual(verifiedLocalDelegation.audience, "\(localDID)#atproto_pds")
        // The same pinned ES256K key validly signed the retained legacy
        // golden, so this rejection is the audience rule, not the signature.
        await XCTAssertCompositionThrowsError {
            _ = try await DurableSpaceDelegationVerifier(publicKeys: delegationKeys)
                .verifiedDelegation(
                    for: Self.legacyAudienceRemoteDelegation,
                    expectedSpace: remoteSpace,
                    now: self.now
                )
        }
        let verifiedRemoteDelegation = try await DurableSpaceDelegationVerifier(publicKeys: delegationKeys)
            .verifiedDelegation(
                for: Self.remoteDelegation,
                expectedSpace: remoteSpace,
                now: now
            )
        XCTAssertEqual(verifiedRemoteDelegation.issuer, remoteMember)
        XCTAssertEqual(verifiedRemoteDelegation.audience, "\(remoteAuthority)#atproto_pds")

        let localService = try SpaceServiceJWT.create(
            issuer: localDID,
            audience: remoteAuthority,
            method: "com.atproto.space.notifyRepoUpdate",
            eventID: "local-service-event",
            key: localKey,
            now: now
        )
        let serviceVerifier = DurableSpaceServiceAuthenticationVerifier(publicKeys: serviceKeys)
        _ = try await serviceVerifier.authenticate(
            localService,
            expectedAudience: remoteAuthority,
            expectedMethod: "com.atproto.space.notifyRepoUpdate",
            now: now
        )
        // The retained TypeScript token is validly signed by the pinned key,
        // but names the retired notifyWrite method.
        await XCTAssertCompositionThrowsError {
            _ = try await serviceVerifier.authenticate(
                Self.remoteService,
                expectedAudience: self.remoteAuthority,
                expectedMethod: "com.atproto.space.notifyRepoUpdate",
                now: self.now
            )
        }
    }

    func testConflictingPinnedAndLocalIdentitiesFailComposition() async throws {
        let localKey = P256.Signing.PrivateKey()
        let conflictingKey = P256.Signing.PrivateKey()

        await XCTAssertCompositionThrowsError {
            _ = try await CompositeSpaceCredentialPublicKeyResolver(
                local: StaticCredentialKeys(keys: [
                    "\(self.localDID)|\(PermissionedDataJWT.spaceCredentialIssuedKeyID)": .p256(localKey.publicKey),
                ]),
                pinned: [
                    try .init(
                        authority: self.localDID,
                        generation: 1,
                        publicKey: conflictingKey.publicKey
                    ),
                ]
            )
        }
        await XCTAssertCompositionThrowsError {
            _ = try await CompositeSpaceDelegationPublicKeyResolver(
                local: StaticDelegationKeys(keys: [
                    "\(self.localDID)|\(PermissionedDataJWT.delegationKeyID)": .p256(localKey.publicKey),
                ]),
                pinned: [
                    try .init(
                        issuer: self.localDID,
                        generation: 1,
                        publicKey: conflictingKey.publicKey
                    ),
                ]
            )
        }
        await XCTAssertCompositionThrowsError {
            _ = try await CompositeSpaceServicePublicKeyResolver(
                local: StaticServiceKeys(keys: [self.localDID: .p256(localKey.publicKey)]),
                pinned: [
                    try .init(
                        issuer: self.localDID,
                        generation: 1,
                        publicKey: conflictingKey.publicKey
                    ),
                ]
            )
        }
    }

    func testDelegationRemoteResolverIsFallbackAfterLocalAndPins() async throws {
        let localKey = P256.Signing.PrivateKey()
        let remoteKey = P256.Signing.PrivateKey()
        let remote = CountingDelegationKeys(
            keys: [
                "\(remoteMember)|\(PermissionedDataJWT.delegationKeyID)":
                    .p256(remoteKey.publicKey),
            ]
        )
        let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
            local: StaticDelegationKeys(keys: [
                "\(localDID)|\(PermissionedDataJWT.delegationKeyID)":
                    .p256(localKey.publicKey),
            ]),
            remote: remote,
            pinned: []
        )

        let local = try await resolver.publicKey(
            for: localDID,
            keyID: PermissionedDataJWT.delegationKeyID
        )
        XCTAssertEqual(
            local?.deterministicIdentity,
            Data([0x01]) + localKey.publicKey.x963Representation
        )
        let localCallCount = await remote.callCount
        XCTAssertEqual(localCallCount, 0)

        let remoteResolved = try await resolver.publicKey(
            for: remoteMember,
            keyID: PermissionedDataJWT.delegationKeyID
        )
        XCTAssertEqual(
            remoteResolved?.deterministicIdentity,
            Data([0x01]) + remoteKey.publicKey.x963Representation
        )
        let remoteCallCount = await remote.callCount
        XCTAssertEqual(remoteCallCount, 1)
    }

    /// F16, at the composition seam. `LocalAccountSpaceServicePublicKeyResolver`
    /// now reports a revoked managed identity as a terminal negative instead of
    /// an absence; this pins the other half of that contract — the composite
    /// must propagate it rather than reading it as permission to use the pin.
    ///
    /// The delegation and credential composites are asserted alongside it so
    /// the three cannot drift apart again.
    func testTerminalLocalNegativeIsNotAFallThroughToThePin() async throws {
        let pinnedKey = P256.Signing.PrivateKey()
        let failure = SwanError.unavailable("local authority is unavailable")

        // Resolution: the pin is configured for a different issuer, so the
        // composite is constructible; a terminal local negative for the
        // managed DID must still surface rather than resolving as absent.
        let serviceKeys = try await CompositeSpaceServicePublicKeyResolver(
            local: StaticServiceKeys(keys: [:], failing: [localDID: failure]),
            pinned: [
                try .init(issuer: remoteMember, generation: 1, publicKey: pinnedKey.publicKey),
            ]
        )
        await XCTAssertCompositionThrowsError {
            try await serviceKeys.publicKey(for: self.localDID)
        }

        // Composition: a pin that overlaps a locally managed identity in a
        // terminal state now fails the startup preflight instead of silently
        // becoming the authority for it.
        await XCTAssertCompositionThrowsError {
            _ = try await CompositeSpaceServicePublicKeyResolver(
                local: StaticServiceKeys(keys: [:], failing: [self.localDID: failure]),
                pinned: [
                    try .init(
                        issuer: self.localDID,
                        generation: 1,
                        publicKey: pinnedKey.publicKey
                    ),
                ]
            )
        }

        // The two sibling composites already behaved this way. Asserting them
        // here is what stops the three drifting apart again.
        let delegationKeys = try await CompositeSpaceDelegationPublicKeyResolver(
            local: StaticDelegationKeys(keys: [:], failing: [
                "\(localDID)|\(PermissionedDataJWT.delegationKeyID)": failure,
            ]),
            pinned: [
                try .init(issuer: remoteMember, generation: 1, publicKey: pinnedKey.publicKey),
            ]
        )
        await XCTAssertCompositionThrowsError {
            try await delegationKeys.publicKey(
                for: self.localDID,
                keyID: PermissionedDataJWT.delegationKeyID
            )
        }

        let credentialKeys = try await CompositeSpaceCredentialPublicKeyResolver(
            local: StaticCredentialKeys(keys: [:], failing: [
                "\(localDID)|\(PermissionedDataJWT.spaceCredentialKeyID)": failure,
            ]),
            pinned: [
                try .init(
                    authority: remoteAuthority,
                    generation: 1,
                    publicKey: pinnedKey.publicKey
                ),
            ]
        )
        await XCTAssertCompositionThrowsError {
            try await credentialKeys.publicKey(
                for: self.localDID,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
    }

    /// The October 22 ES256K delegation golden, aud `<authority>#atproto_pds`.
    /// It is the legacy golden below, re-signed by upstream's
    /// `Secp256k1Keypair.sign` path with only `aud` changed:
    /// `Scripts/space-token-goldens/`. The same token is used by
    /// `SpaceCredentialAuthorityTests`.
    private static let remoteDelegation =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fcGRzIiwic3ViIjoiYXQ6c3BhY2UvZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAwMDYwLCJqdGkiOiJ0cy1ub25jZV8wMSJ9.TDswjah01N3piyA31xmoEjdMyejdjZzplxCtmKDZ6HgoMIaNS8TEnnjYLgM7XtGGem9aRdyaM6dPCVP3MgCCrw"
    /// The original atproto 3f6c96d golden: the same claims and key, validly
    /// signed, with the pre-October 22 `#atproto_space_host` audience.
    private static let legacyAudienceRemoteDelegation =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsInN1YiI6ImF0OnNwYWNlL2RpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4L2FwcC5ic2t5LmJvb2ttYXJrcy90cy1nb2xkZW4iLCJpYXQiOjE3NTAwMDAwMDAsImV4cCI6MTc1MDAwMDA2MCwianRpIjoidHMtbm9uY2VfMDEifQ.Us8J_z8yfqZwl9XM3nasfLNu8s1DEZoU7__pi9dOY8JqWJsdncXNi2iJTWrHN99og6Eh1_w1vPE40qhGcq9cXA"
    private static let remoteCredential =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0OnNwYWNlL2RpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4L2FwcC5ic2t5LmJvb2ttYXJrcy90cy1nb2xkZW4iLCJpYXQiOjE3NTAwMDAwMDAsImV4cCI6MTc1MDAwNzIwMCwianRpIjoidHMtY3JlZGVudGlhbC1ub25jZV8wMSJ9.zKJNjovfW2K6T1i1eX32l47XUF6s7v4coHe0suFfw2RcWPB7IHmFaNosHSWsSKTZm4Gvba3S_5VmYjGUpVKiZA"
    private static let remoteService =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NTAwMDAwMDAsImlzcyI6ImRpZDpwbGM6YmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5IiwiYXVkIjoiZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3giLCJleHAiOjE3NTAwMDAwNjAsImx4bSI6ImNvbS5hdHByb3RvLnNwYWNlLm5vdGlmeVdyaXRlIiwianRpIjoicGlubmVkLXRzLW5vdGlmeS0wMDEifQ.o782N9f1U23FL8bWXqQiNDBjp7c-5Cxj4IIlvqLdEUZFC4K0C-vUz-AN8PuGZINo1K2Y6_DY-qJmgak6Fk-aPA"
}

private struct StaticCredentialKeys: SpaceCredentialPublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]
    /// Terminal local negatives, keyed identically to `keys`. A resolver that
    /// could only answer "key" or "absent" cannot express the state these
    /// composites must refuse to paper over with a pin.
    var failing: [String: any Error] = [:]

    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        if let failure = failing["\(issuer)|\(keyID)"] { throw failure }
        return keys["\(issuer)|\(keyID)"]
    }
}

private struct StaticDelegationKeys: SpaceDelegationPublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]
    var failing: [String: any Error] = [:]

    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        if let failure = failing["\(issuer)|\(keyID)"] { throw failure }
        return keys["\(issuer)|\(keyID)"]
    }
}

private actor CountingDelegationKeys: SpaceDelegationPublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]
    private(set) var callCount = 0

    init(keys: [String: PermissionedDataJWTVerificationKey]) {
        self.keys = keys
    }

    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        callCount += 1
        return keys["\(issuer)|\(keyID)"]
    }
}

private struct StaticServiceKeys: SpaceServicePublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]
    var failing: [String: any Error] = [:]

    func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        if let failure = failing[issuer] { throw failure }
        return keys[issuer]
    }
}

private func XCTAssertCompositionThrowsError<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected composition to throw", file: file, line: line)
    } catch {}
}
