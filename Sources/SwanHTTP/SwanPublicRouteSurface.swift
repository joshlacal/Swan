import Foundation
import SwanPublicWire

/// Why a public protocol profile could not be turned into a route surface.
///
/// Every case is a refusal to start, never a fallback. Silently registering
/// some other profile's method set would give an operator a server whose
/// advertised contract and served contract disagree, and nothing in the
/// process would ever say so.
public enum SwanPublicRouteSurfaceError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The profile artifact could not be read at all.
    case unreadableProfile
    /// The artifact was read but is not a profile document with an `id`.
    case malformedProfile
    /// The artifact names a profile id this build has no descriptor registry
    /// for. The id is carried because it comes from a local operator-supplied
    /// artifact, not from a request.
    case unregisteredProfile(id: String)

    public var description: String {
        switch self {
        case .unreadableProfile:
            "public protocol profile is unreadable"
        case .malformedProfile:
            "public protocol profile is malformed"
        case let .unregisteredProfile(id):
            "public protocol profile '\(id)' has no registered route surface in this build"
        }
    }
}

/// The finite public XRPC method set a Swan process registers routes for,
/// selected by public protocol profile id.
///
/// Route registration used to iterate `PublicDataTesting20260727.methods`
/// unconditionally, so an operator's profile selection changed nothing about
/// which public methods existed: the control was not the control. This type is
/// the seam that makes the selection real.
///
/// It is deliberately an **allow-list**, and deliberately not constructible
/// from a caller-supplied descriptor array. A surface exists only for a
/// profile id that this build carries a checked-in, separately verified
/// descriptor registry for, so a profile added to `Profiles/` cannot reach
/// route registration carrying a method set nobody reviewed, and an
/// unrecognised id cannot quietly fall back to whichever registry happens to
/// be newest. Conditional registration plus a deny-list is how this codebase
/// has previously shipped surfaces nobody meant to expose.
public struct SwanPublicRouteSurface: Sendable, Equatable {
    /// The 2026-08-06 successor profile maps to `PublicDataTesting20260805`
    /// on purpose rather than for want of a registry of its own.
    ///
    /// It is a retention/liveness successor whose wire contract is identical
    /// to its predecessor's — the same 21 lexicons, the same ordered 19
    /// endpoints, and generated sources copied byte-for-byte, which is why its
    /// `generated-wire.sha256` manifest is byte-identical to 2026-08-05's.
    /// That manifest pins `Sources/SwanPublicWire/SwanPublicWire.swift`, and
    /// the offline verifier additionally rejects any unlisted `.swift` file
    /// under `Sources/SwanPublicWire`, so declaring a duplicate
    /// `PublicDataTesting20260806` there — or adding this registry to that
    /// module — would invalidate the very profile it was meant to serve. The
    /// mapping is not taken on trust: the tests decode each shipped profile
    /// JSON and assert its `endpoints` array equals the registered method
    /// list, so a successor that actually changes its contract fails the
    /// suite instead of silently reusing a stale surface.
    private static let registry: [String: [PublicXRPCMethodDescriptor]] = [
        PublicDataTesting20260727.profileID: PublicDataTesting20260727.methods,
        PublicDataTesting20260730.profileID: PublicDataTesting20260730.methods,
        PublicDataTesting20260805.profileID: PublicDataTesting20260805.methods,
        successorProfileID: PublicDataTesting20260805.methods,
    ]

    /// `public-data-testing-2026-08-06`, spelled here rather than imported
    /// because `SwanPublicWire` deliberately declares no enum for it.
    public static let successorProfileID = "public-data-testing-2026-08-06"

    /// Every profile id this build can register a public route surface for.
    public static var registeredProfileIDs: Set<String> {
        Set(registry.keys)
    }

    public let profileID: String
    public let methods: [PublicXRPCMethodDescriptor]

    private init(profileID: String, methods: [PublicXRPCMethodDescriptor]) {
        self.profileID = profileID
        self.methods = methods
    }

    /// The allow-list lookup. `nil` for any id without a checked-in registry;
    /// callers must refuse to serve rather than substitute another surface.
    public init?(profileID: String) {
        guard let methods = Self.registry[profileID] else { return nil }
        self.init(profileID: profileID, methods: methods)
    }

    /// The surface used when an assembly names no public profile at all.
    ///
    /// This is the profile the process registered before the selection existed,
    /// so an existing deployment's served surface does not change underneath it
    /// on upgrade. It is built from the same two constants the registry entry
    /// is built from, and a test asserts the two agree, so the default cannot
    /// drift into naming a surface the allow-list would refuse.
    public static let `default` = SwanPublicRouteSurface(
        profileID: PublicDataTesting20260727.profileID,
        methods: PublicDataTesting20260727.methods
    )

    /// Reads an operator-supplied public profile artifact and resolves it
    /// through the allow-list.
    ///
    /// Only the `id` field is read. Checksum and pin verification of the
    /// artifact itself is `swan verify`'s job and is deliberately not
    /// duplicated here; this is the route-surface selection, not the artifact
    /// attestation.
    public static func load(profileURL: URL) throws -> SwanPublicRouteSurface {
        let data: Data
        do {
            data = try Data(contentsOf: profileURL, options: [.mappedIfSafe])
        } catch {
            throw SwanPublicRouteSurfaceError.unreadableProfile
        }
        return try resolve(profileData: data)
    }

    /// The pure half of ``load(profileURL:)``, separated so the decode and
    /// allow-list steps are testable without a file on disk.
    public static func resolve(profileData: Data) throws -> SwanPublicRouteSurface {
        struct ProfileIdentity: Decodable {
            let id: String
        }
        let identity: ProfileIdentity
        do {
            identity = try JSONDecoder().decode(ProfileIdentity.self, from: profileData)
        } catch {
            throw SwanPublicRouteSurfaceError.malformedProfile
        }
        guard let surface = SwanPublicRouteSurface(profileID: identity.id) else {
            throw SwanPublicRouteSurfaceError.unregisteredProfile(id: identity.id)
        }
        return surface
    }
}
