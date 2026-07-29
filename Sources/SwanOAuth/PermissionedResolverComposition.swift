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
    private let remote: (any SpaceCredentialPublicKeyResolver)?
    private let pinned: any SpaceCredentialPublicKeyResolver

    /// Core composition boundary for an already validated offline pin
    /// resolver. It remains module-internal so external callers must use the
    /// public pin-value initializers and their startup conflict preflight.
    init(
        local: any SpaceCredentialPublicKeyResolver,
        remote: (any SpaceCredentialPublicKeyResolver)?,
        prevalidatedPinned pinned: any SpaceCredentialPublicKeyResolver
    ) {
        self.local = local
        self.remote = remote
        self.pinned = pinned
    }

    public init(
        local: any SpaceCredentialPublicKeyResolver,
        pinned pins: [PinnedSpaceCredentialPublicKey]
    ) async throws {
        try await self.init(local: local, remote: nil, pinned: pins)
    }

    /// Compose the managed-account projection with an optional, explicitly
    /// configured PLC resolver and operator pins.  The remote resolver is
    /// consulted only after the local and pinned worlds have no answer; this
    /// keeps local account verification deterministic while allowing a lab to
    /// discover a reference host's rotated `#atproto` key through PLC.
    public init(
        local: any SpaceCredentialPublicKeyResolver,
        remote: (any SpaceCredentialPublicKeyResolver)?,
        pinned pins: [PinnedSpaceCredentialPublicKey]
    ) async throws {
        let pinned = try PinnedSpaceCredentialPublicKeyResolver(pins: pins)
        for pin in pins {
            _ = try await Self.resolve(
                issuer: pin.authority,
                keyID: pin.keyID,
                local: local,
                remote: nil,
                pinned: pinned
            )
        }
        self.init(
            local: local,
            remote: remote,
            prevalidatedPinned: pinned
        )
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        try await Self.resolve(
            issuer: issuer,
            keyID: keyID,
            local: local,
            remote: remote,
            pinned: pinned
        )
    }

    private static func resolve(
        issuer: String,
        keyID: String,
        local: any SpaceCredentialPublicKeyResolver,
        remote: (any SpaceCredentialPublicKeyResolver)?,
        pinned: any SpaceCredentialPublicKeyResolver
    ) async throws -> PermissionedDataJWTVerificationKey? {
        // `nil` is the local resolver's explicit unmanaged-issuer result. Any
        // thrown authoritative-local negative is terminal and therefore
        // prevents both operator-pin and remote PLC fallback.
        let localKey = try await local.publicKey(for: issuer, keyID: keyID)
        let pinnedKey = try await pinned.publicKey(for: issuer, keyID: keyID)
        let known = try uniqueVerificationKey(
            local: localKey,
            pinned: pinnedKey,
            conflict: "conflicting space credential verification keys"
        )
        if let known { return known }
        return try await remote?.publicKey(for: issuer, keyID: keyID)
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
