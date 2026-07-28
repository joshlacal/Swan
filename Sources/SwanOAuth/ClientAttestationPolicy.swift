import Crypto
import Foundation
import SwanCore
import SwanStorage

/// HMAC-SHA-256 replay namespace for verified client attestations. Every
/// untrusted field is length-delimited beneath a versioned domain tag before
/// crossing the storage boundary.
public actor DurableSpaceClientAttestationReplayStore {
    private let controlStore: any SpaceClientAttestationReplayStore
    private let macKey: SymmetricKey

    public init(
        controlStore: any SpaceClientAttestationReplayStore,
        serverKey: Data
    ) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        self.controlStore = controlStore
        macKey = SymmetricKey(data: serverKey)
    }

    public func claim(
        clientID: String,
        audience: String,
        jti: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        guard !clientID.isEmpty,
              !audience.isEmpty,
              !jti.isEmpty,
              jti.utf8.count <= PermissionedDataJWT.maximumOpaqueJTIBytes,
              jti.utf8.allSatisfy({ $0 >= 0x20 && $0 != 0x7f }) else {
            throw SwanError.malformed("client attestation replay input is invalid")
        }
        // JWT NumericDate and Swan's clock comparison operate at whole-second
        // precision. Retain through the entire final accepted second so expiry
        // cleanup cannot reopen replay at `exp + skew + 0.x`.
        let durableExpiry = max(
            expiresAt.addingTimeInterval(1),
            now.addingTimeInterval(1)
        )
        var input = Data("swan.space.client-attestation-replay-v1\u{0}".utf8)
        for field in [clientID, audience, jti] {
            let bytes = Data(field.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(bytes)
        }
        let digest = Data(
            HMAC<SHA256>.authenticationCode(for: input, using: macKey)
        )
        do {
            return try await controlStore.claimSpaceClientAttestation(
                digest: digest,
                expiresAt: durableExpiry,
                now: now
            )
        } catch {
            throw SwanError.unavailable("client attestation replay store unavailable")
        }
    }
}

/// Cryptographic verification and durable replay policy for proposal-0016
/// client attestations. The implementation is completed alongside its
/// metadata and replay-store tests; the immutable bounds are declared here so
/// callers cannot weaken the profile after construction.
public struct DurableSpaceCredentialClientAttestationPolicy:
    SpaceCredentialClientAttestationPolicy
{
    public struct Configuration: Sendable, Equatable {
        public static let standard = Configuration(
            uncheckedMaximumLifetime: 300,
            uncheckedClockSkew: 60
        )

        public let maximumLifetime: TimeInterval
        public let clockSkew: TimeInterval

        public init(
            maximumLifetime: TimeInterval = 300,
            clockSkew: TimeInterval = 60
        ) throws {
            guard maximumLifetime > 0,
                  maximumLifetime <= 600,
                  maximumLifetime.isFinite,
                  maximumLifetime.rounded(.towardZero) == maximumLifetime,
                  clockSkew >= 0,
                  clockSkew <= 120,
                  clockSkew.isFinite,
                  clockSkew.rounded(.towardZero) == clockSkew else {
                throw SwanError.malformed("client attestation policy bounds are invalid")
            }
            self.maximumLifetime = maximumLifetime
            self.clockSkew = clockSkew
        }

        private init(
            uncheckedMaximumLifetime: TimeInterval,
            uncheckedClockSkew: TimeInterval
        ) {
            maximumLifetime = uncheckedMaximumLifetime
            clockSkew = uncheckedClockSkew
        }
    }

    private enum AttemptFailure: Error {
        case invalid
        case rotationCandidate
    }

    private let metadataLoader: OAuthClientMetadataLoader
    private let replayStore: DurableSpaceClientAttestationReplayStore
    private let configuration: Configuration

    public init(
        metadataLoader: OAuthClientMetadataLoader,
        replayStore: DurableSpaceClientAttestationReplayStore,
        configuration: Configuration = .standard
    ) throws {
        self.metadataLoader = metadataLoader
        self.replayStore = replayStore
        self.configuration = configuration
    }

    /// Verifies only what proposal-0016 carries: fresh key possession for the
    /// exact client metadata identity and authority-service audience. It
    /// cannot bind the proof to the delegation/OAuth session, requested space,
    /// HTTP request, app binary/device, or an app-review identity. Published
    /// metadata/JWKS remain mutable within cache/refresh policy; credentials
    /// already issued cannot be selectively revoked by app or user, and their
    /// claims do not disclose the reader or verified client to a repository.
    public func verifiedClientID(
        for clientAttestation: String?,
        authority: String,
        now: Date
    ) async throws -> String? {
        guard let clientAttestation else {
            return nil
        }
        let inspection: PermissionedDataJWT.UntrustedClientAttestationInspection
        do {
            inspection = try PermissionedDataJWT.inspectUntrustedClientAttestation(
                clientAttestation,
                authority: authority,
                now: now,
                maximumLifetime: configuration.maximumLifetime,
                clockSkew: configuration.clockSkew
            )
        } catch {
            throw SpaceCredentialClientAttestationFailure.invalid
        }

        let resolved: OAuthResolvedClientMetadata
        do {
            resolved = try await metadataLoader.load(
                clientID: inspection.clientID,
                now: now
            )
        } catch {
            throw Self.failure(for: error)
        }

        do {
            try verify(
                clientAttestation,
                inspection: inspection,
                resolved: resolved,
                authority: authority,
                now: now
            )
        } catch AttemptFailure.rotationCandidate {
            let refreshed: OAuthResolvedClientMetadata
            do {
                refreshed = try await metadataLoader.revalidate(
                    clientID: inspection.clientID,
                    now: now
                )
            } catch {
                throw Self.failure(for: error)
            }
            do {
                try verify(
                    clientAttestation,
                    inspection: inspection,
                    resolved: refreshed,
                    authority: authority,
                    now: now
                )
            } catch {
                throw SpaceCredentialClientAttestationFailure.invalid
            }
        } catch {
            throw SpaceCredentialClientAttestationFailure.invalid
        }

        let claimed: Bool
        do {
            claimed = try await replayStore.claim(
                clientID: inspection.claims.iss,
                audience: inspection.claims.aud,
                jti: inspection.claims.jti,
                expiresAt: inspection.replayExpiresAt,
                now: now
            )
        } catch {
            throw SpaceCredentialClientAttestationFailure.unavailable
        }
        guard claimed else {
            throw SpaceCredentialClientAttestationFailure.invalid
        }
        return inspection.claims.iss
    }

    private func verify(
        _ compact: String,
        inspection: PermissionedDataJWT.UntrustedClientAttestationInspection,
        resolved: OAuthResolvedClientMetadata,
        authority: String,
        now: Date
    ) throws {
        guard resolved.metadata.clientID.absoluteString
                == inspection.clientID.absoluteString,
              !resolved.metadata.isLocalhostDevelopmentClient,
              resolved.metadata.tokenEndpointAuthMethod == .privateKeyJWT,
              resolved.metadata.tokenEndpointAuthSigningAlgorithm == "ES256",
              let keySet = resolved.keySet else {
            throw AttemptFailure.invalid
        }
        let matches = keySet.keys.filter { $0.keyID == inspection.keyID }
        guard matches.count == 1, let key = matches.first else {
            throw AttemptFailure.rotationCandidate
        }
        let verified: OAuthVerifiedJWT
        do {
            verified = try OAuthCompactJWT.verify(
                compact,
                publicKey: key.publicKey(),
                expectedType: PermissionedDataJWT.clientAttestationType,
                constraints: OAuthJWTVerificationConstraints(
                    expectedIssuer: inspection.claims.iss,
                    expectedAudience: inspection.claims.aud,
                    now: now,
                    clockSkew: configuration.clockSkew,
                    requireIssuedAt: true,
                    requireExpiration: true,
                    maxLifetime: configuration.maximumLifetime
                )
            )
        } catch {
            throw AttemptFailure.rotationCandidate
        }
        let signedClaims = try OAuthCompactJWT.decodeClaims(
            PermissionedDataJWT.ClientAttestationClaims.self,
            from: verified
        )
        guard verified.header.keyID == inspection.keyID,
              verified.header.jwk == nil,
              signedClaims == inspection.claims else {
            throw AttemptFailure.invalid
        }
        // Re-run exact proposal-specific type, URL, audience, time, and JTI
        // checks on the signed payload before any replay state is changed.
        let reinspection = try PermissionedDataJWT.inspectUntrustedClientAttestation(
            compact,
            authority: authority,
            now: now,
            maximumLifetime: configuration.maximumLifetime,
            clockSkew: configuration.clockSkew
        )
        guard reinspection.claims == inspection.claims,
              reinspection.keyID == inspection.keyID else {
            throw AttemptFailure.invalid
        }
    }

    private static func failure(
        for error: any Error
    ) -> SpaceCredentialClientAttestationFailure {
        if let failure = error as? SpaceCredentialClientAttestationFailure {
            return failure
        }
        if case .unavailable = error as? SwanError {
            return .unavailable
        }
        return .invalid
    }
}
