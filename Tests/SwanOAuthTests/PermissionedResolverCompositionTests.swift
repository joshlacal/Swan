import Crypto
import Foundation
import SwanCore
import SwanSpaces
import XCTest
@testable import SwanOAuth

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
                "\(localDID)|\(PermissionedDataJWT.spaceCredentialKeyID)": .p256(localKey.publicKey),
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
            now: now
        )
        _ = try await DurableSpaceCredentialVerifier(publicKeys: credentialKeys)
            .authorization(for: localCredential, expectedSpace: localSpace, now: now)
        _ = try await DurableSpaceCredentialVerifier(publicKeys: credentialKeys)
            .authorization(
                for: Self.remoteCredential,
                expectedSpace: remoteSpace,
                now: now
            )

        let localDelegation = try PermissionedDataJWT.createDelegationToken(
            issuer: localDID,
            audience: "\(localDID)#atproto_space_host",
            space: localSpace,
            key: localKey,
            now: now
        )
        _ = try await DurableSpaceDelegationVerifier(publicKeys: delegationKeys)
            .verifiedDelegation(for: localDelegation, expectedSpace: localSpace, now: now)
        _ = try await DurableSpaceDelegationVerifier(publicKeys: delegationKeys)
            .verifiedDelegation(
                for: Self.remoteDelegation,
                expectedSpace: remoteSpace,
                now: now
            )

        let localService = try SpaceServiceJWT.create(
            issuer: localDID,
            audience: remoteAuthority,
            method: "com.atproto.space.notifyWrite",
            eventID: "local-service-event",
            key: localKey,
            now: now
        )
        let serviceVerifier = DurableSpaceServiceAuthenticationVerifier(publicKeys: serviceKeys)
        _ = try await serviceVerifier.authenticate(
            localService,
            expectedAudience: remoteAuthority,
            expectedMethod: "com.atproto.space.notifyWrite",
            now: now
        )
        _ = try await serviceVerifier.authenticate(
            Self.remoteService,
            expectedAudience: remoteAuthority,
            expectedMethod: "com.atproto.space.notifyWrite",
            now: now
        )
    }

    func testConflictingPinnedAndLocalIdentitiesFailComposition() async throws {
        let localKey = P256.Signing.PrivateKey()
        let conflictingKey = P256.Signing.PrivateKey()

        await XCTAssertCompositionThrowsError {
            _ = try await CompositeSpaceCredentialPublicKeyResolver(
                local: StaticCredentialKeys(keys: [
                    "\(self.localDID)|\(PermissionedDataJWT.spaceCredentialKeyID)": .p256(localKey.publicKey),
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

    private static let remoteDelegation =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAwMDYwLCJqdGkiOiJ0cy1ub25jZV8wMSJ9.CiWW_bplyq9ZtybzoUL9f7J_lqlcFKkmAbY2YsVlf5Bly4Ufue7e9QN6_8PioonLWqKnmm6T-RW3Mq2C_JTC6A"
    private static let remoteCredential =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJ0cy1jcmVkZW50aWFsLW5vbmNlXzAxIn0.kgRbwHruWKzbsHZlMjmSFYmz1dKBjpP0eQBvJLRYlzMAClhsOpYnRYpe2fBMGtuciGngcQgEwWYSjHpa9YmIEQ"
    private static let remoteService =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NTAwMDAwMDAsImlzcyI6ImRpZDpwbGM6YmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5IiwiYXVkIjoiZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3giLCJleHAiOjE3NTAwMDAwNjAsImx4bSI6ImNvbS5hdHByb3RvLnNwYWNlLm5vdGlmeVdyaXRlIiwianRpIjoicGlubmVkLXRzLW5vdGlmeS0wMDEifQ.o782N9f1U23FL8bWXqQiNDBjp7c-5Cxj4IIlvqLdEUZFC4K0C-vUz-AN8PuGZINo1K2Y6_DY-qJmgak6Fk-aPA"
}

private struct StaticCredentialKeys: SpaceCredentialPublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]

    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        keys["\(issuer)|\(keyID)"]
    }
}

private struct StaticDelegationKeys: SpaceDelegationPublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]

    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        keys["\(issuer)|\(keyID)"]
    }
}

private struct StaticServiceKeys: SpaceServicePublicKeyResolver {
    let keys: [String: PermissionedDataJWTVerificationKey]

    func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        keys[issuer]
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
