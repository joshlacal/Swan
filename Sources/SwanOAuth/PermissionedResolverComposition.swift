import Foundation
import SwanCore

/// Offline-only composition of the local account projection with explicit
/// credential pins. Every configured pin is preflighted during construction,
/// so an issuer/key overlap with different material is a startup error. The
/// request path repeats the same all-source comparison to remain deterministic
/// if the local account projection changes after startup.
public struct CompositeSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    private let local: any SpaceCredentialPublicKeyResolver
    private let pinned: PinnedSpaceCredentialPublicKeyResolver

    public init(
        local: any SpaceCredentialPublicKeyResolver,
        pinned pins: [PinnedSpaceCredentialPublicKey]
    ) async throws {
        let pinned = try PinnedSpaceCredentialPublicKeyResolver(pins: pins)
        for pin in pins {
            _ = try await Self.resolve(
                issuer: pin.authority,
                keyID: pin.keyID,
                local: local,
                pinned: pinned
            )
        }
        self.local = local
        self.pinned = pinned
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try await Self.resolve(
            issuer: issuer,
            keyID: keyID,
            local: local,
            pinned: pinned
        )
    }

    private static func resolve(
        issuer: String,
        keyID: String,
        local: any SpaceCredentialPublicKeyResolver,
        pinned: PinnedSpaceCredentialPublicKeyResolver
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try uniqueVerificationKey(
            local: try await local.publicKey(for: issuer, keyID: keyID),
            pinned: try await pinned.publicKey(for: issuer, keyID: keyID),
            conflict: "conflicting space credential verification keys"
        )
    }
}

/// Delegation-key counterpart to
/// ``CompositeSpaceCredentialPublicKeyResolver``. It performs no DID, PLC,
/// DNS, or HTTP lookup.
public struct CompositeSpaceDelegationPublicKeyResolver:
    SpaceDelegationPublicKeyResolver
{
    private let local: any SpaceDelegationPublicKeyResolver
    private let pinned: PinnedSpaceDelegationPublicKeyResolver

    public init(
        local: any SpaceDelegationPublicKeyResolver,
        pinned pins: [PinnedSpaceDelegationPublicKey]
    ) async throws {
        let pinned = try PinnedSpaceDelegationPublicKeyResolver(pins: pins)
        for pin in pins {
            _ = try await Self.resolve(
                issuer: pin.issuer,
                keyID: pin.keyID,
                local: local,
                pinned: pinned
            )
        }
        self.local = local
        self.pinned = pinned
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try await Self.resolve(
            issuer: issuer,
            keyID: keyID,
            local: local,
            pinned: pinned
        )
    }

    private static func resolve(
        issuer: String,
        keyID: String,
        local: any SpaceDelegationPublicKeyResolver,
        pinned: PinnedSpaceDelegationPublicKeyResolver
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try uniqueVerificationKey(
            local: try await local.publicKey(for: issuer, keyID: keyID),
            pinned: try await pinned.publicKey(for: issuer, keyID: keyID),
            conflict: "conflicting space delegation verification keys"
        )
    }
}

/// Service-authentication counterpart to the credential and delegation
/// composites. Issuer normalization remains owned by the existing resolvers;
/// composition only compares the resulting offline key material.
public struct CompositeSpaceServicePublicKeyResolver:
    SpaceServicePublicKeyResolver
{
    private let local: any SpaceServicePublicKeyResolver
    private let pinned: PinnedSpaceServicePublicKeyResolver

    public init(
        local: any SpaceServicePublicKeyResolver,
        pinned pins: [PinnedSpaceServicePublicKey]
    ) async throws {
        let pinned = try PinnedSpaceServicePublicKeyResolver(pins: pins)
        for pin in pins {
            _ = try await Self.resolve(
                issuer: pin.issuer,
                local: local,
                pinned: pinned
            )
        }
        self.local = local
        self.pinned = pinned
    }

    public func publicKey(
        for issuer: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try await Self.resolve(issuer: issuer, local: local, pinned: pinned)
    }

    private static func resolve(
        issuer: String,
        local: any SpaceServicePublicKeyResolver,
        pinned: PinnedSpaceServicePublicKeyResolver
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try uniqueVerificationKey(
            local: try await local.publicKey(for: issuer),
            pinned: try await pinned.publicKey(for: issuer),
            conflict: "conflicting space service verification keys"
        )
    }
}

private func uniqueVerificationKey(
    local: PermissionedDataJWTVerificationKey?,
    pinned: PermissionedDataJWTVerificationKey?,
    conflict: String
) throws -> PermissionedDataJWTVerificationKey? {
    switch (local, pinned) {
    case (nil, nil):
        return nil
    case let (.some(key), nil), let (nil, .some(key)):
        return key
    case let (.some(local), .some(pinned)):
        guard local.deterministicIdentity == pinned.deterministicIdentity else {
            throw SwanError.malformed(conflict)
        }
        return local
    }
}
