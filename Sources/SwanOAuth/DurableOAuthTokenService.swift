import Crypto
import Foundation
import SwanCore
import SwanStorage

/// The single typed OAuth dependency accepted by a running Swan HTTP server.
/// Both actors are backed by the same durable control store and the same
/// injected server HMAC key; an HTTP server cannot be assembled with an
/// in-memory token vault by accident.
public struct SwanOAuthRuntime: Sendable {
    public let tokenService: DurableOAuthTokenService
    public let dpopReplayStore: DurableDPoPReplayStore
    public let browserSessionService: OAuthBrowserSessionService
    /// The nonce MAC key is the injected non-persisted OAuth server key. It
    /// never crosses into `OAuthControlStore`; validators receive this service
    /// from the runtime rather than accepting arbitrary caller text as a nonce.
    public let dpopNonceService: DPoPNonceService

    public init(controlStore: any OAuthControlStore, serverKey: Data) throws {
        tokenService = try DurableOAuthTokenService(
            controlStore: controlStore,
            serverKey: serverKey
        )
        dpopReplayStore = try DurableDPoPReplayStore(
            controlStore: controlStore,
            serverKey: serverKey
        )
        browserSessionService = try OAuthBrowserSessionService(serverKey: serverKey)
        dpopNonceService = DPoPNonceService(secret: serverKey)
    }
}

/// An OAuth token/control-plane adapter whose only durable secrets are keyed
/// HMAC digests. The injected server key must be supplied by configuration or
/// a mounted secret; it is never written to `OAuthControlStore`.
public actor DurableOAuthTokenService {
    private enum DigestPurpose: String {
        case accessToken = "access-token"
        case refreshToken = "refresh-token"
        case authorizationCode = "authorization-code"
        case pushedAuthorizationRequest = "pushed-authorization-request"
        case pushedAuthorizationState = "pushed-authorization-state"
        case dpopJTI = "dpop-jti"
        case clientAssertionJTI = "client-assertion-jti"
    }

    private let controlStore: any OAuthControlStore
    private let macKey: SymmetricKey

    /// A resource-facing grant deliberately includes the DPoP binding instead
    /// of looking like a plain bearer-token result. Resource middleware must
    /// call `validateAccess(_:proof:now:)`, which verifies that
    /// binding before this value can be obtained.
    public struct AccessGrant: Sendable, Equatable {
        public let subject: String
        public let scopes: Set<String>
        public let issuer: String
        public let clientID: String
        public let redirectURI: String
        public let dpopJKT: String?

        fileprivate init(family: OAuthTokenFamily) {
            subject = family.subject
            scopes = family.binding.scopes
            issuer = family.binding.issuer
            clientID = family.binding.clientID
            redirectURI = family.binding.redirectURI
            dpopJKT = family.binding.dpopJKT
        }
    }

    public init(controlStore: any OAuthControlStore, serverKey: Data) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        self.controlStore = controlStore
        macKey = SymmetricKey(data: serverKey)
    }

    /// Creates an opaque access/refresh pair in a new durable family.
    public func issue(
        subject: String,
        session: OAuthValidatedSession,
        accessLifetime: TimeInterval = 300,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        let binding = session.durableBinding
        try requireOAuthDPoPBinding(binding)
        let pair = try makeTokenPair(
            familyID: familyID,
            accessLifetime: accessLifetime,
            refreshLifetime: refreshLifetime,
            now: now
        )
        let family = OAuthTokenFamily(
            familyID: familyID,
            subject: subject,
            binding: binding,
            expiresAt: pair.refreshExpiresAt
        )
        do {
            try await controlStore.issueTokenPair(
                family: family,
                tokens: tokenDigests(for: pair),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return pair
    }

    /// Stores a PAR by a digest of its returned opaque request URI. The caller
    /// gets the raw URI exactly once; SQLite gets only its HMAC digest.
    public func createPushedAuthorizationRequest(
        session: OAuthValidatedSession,
        state: String,
        codeChallengeS256: String,
        lifetime: TimeInterval = 90,
        now: Date = Date()
    ) async throws -> String {
        guard lifetime > 0, lifetime.isFinite else {
            throw SwanError.malformed("PAR lifetime must be positive")
        }
        let binding = session.durableBinding
        try requireOAuthDPoPBinding(binding)
        let requestURI = "urn:ietf:params:oauth:request_uri:\(Self.randomOpaqueValue())"
        let request = OAuthPushedAuthorizationRequest(
            requestDigest: digest(requestURI, purpose: .pushedAuthorizationRequest),
            binding: binding,
            state: state,
            stateDigest: digest(
                "\(binding.clientID)\u{0}\(state)",
                purpose: .pushedAuthorizationState
            ),
            codeChallengeS256: codeChallengeS256,
            expiresAt: now.addingTimeInterval(lifetime)
        )
        do {
            try await controlStore.storePushedAuthorizationRequest(request, now: now)
        } catch {
            throw secureControlError(error)
        }
        return requestURI
    }

    /// Claims a PAR exactly once, enforcing the issuer/client/redirect binding
    /// before a future HTTP authorization handler can create a code from it.
    public func consumePushedAuthorizationRequest(
        _ requestURI: String,
        session: OAuthValidatedSession,
        now: Date = Date()
    ) async throws -> OAuthPushedAuthorizationRequest {
        let binding = session.durableBinding
        do {
            return try await controlStore.consumePushedAuthorizationRequest(
                requestDigest: digest(requestURI, purpose: .pushedAuthorizationRequest),
                binding: binding,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    /// Returns the live PAR selected by its opaque request URI without
    /// consuming it. This is the browser-authorization handoff: the handler
    /// can render login and consent from durable, DPoP-bound facts, then the
    /// final consent POST consumes the same binding atomically. Possession of
    /// the high-entropy request URI is the only lookup capability; its raw
    /// value is never persisted.
    public func activePushedAuthorizationRequest(
        _ requestURI: String,
        now: Date = Date()
    ) async throws -> OAuthPushedAuthorizationRequest? {
        try validateRequestURI(requestURI)
        do {
            return try await controlStore.activePushedAuthorizationRequest(
                requestDigest: digest(requestURI, purpose: .pushedAuthorizationRequest),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    /// Consumes a PAR using the exact binding previously returned by
    /// ``activePushedAuthorizationRequest(_:now:)``. A browser never needs to
    /// reconstruct a DPoP proof: DPoP was validated at PAR, and the durable
    /// comparison below proves the approval is still bound to that proof,
    /// redirect URI, scopes, and (if applicable) confidential-client key.
    public func consumePushedAuthorizationRequest(
        _ requestURI: String,
        binding: OAuthClientBinding,
        now: Date = Date()
    ) async throws -> OAuthPushedAuthorizationRequest {
        try validateRequestURI(requestURI)
        do {
            return try await controlStore.consumePushedAuthorizationRequest(
                requestDigest: digest(requestURI, purpose: .pushedAuthorizationRequest),
                binding: binding,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    /// Creates a code whose future token family is already durable. That lets
    /// the store revoke every resulting token if this code is replayed.
    public func issueAuthorizationCode(
        subject: String,
        session: OAuthValidatedSession,
        codeChallengeS256: String,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        try await issueAuthorizationCode(
            subject: subject,
            binding: session.durableBinding,
            codeChallengeS256: codeChallengeS256,
            codeLifetime: codeLifetime,
            refreshLifetime: refreshLifetime,
            familyID: familyID,
            now: now
        )
    }

    /// Issues an authorization code after a browser approval has consumed a
    /// persisted PAR. The caller supplies the PAR's durable binding rather
    /// than strings selected from a form, preserving the DPoP/PKCE/client
    /// tuple that PAR validated.
    public func issueAuthorizationCode(
        subject: String,
        binding: OAuthClientBinding,
        codeChallengeS256: String,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        guard codeLifetime > 0, refreshLifetime > 0,
              codeLifetime.isFinite, refreshLifetime.isFinite else {
            throw SwanError.malformed("authorization code lifetimes must be positive")
        }
        try requireOAuthDPoPBinding(binding)
        let code = Self.randomOpaqueValue()
        let record = OAuthAuthorizationCode(
            codeDigest: digest(code, purpose: .authorizationCode),
            familyID: familyID,
            subject: subject,
            binding: binding,
            codeChallengeS256: codeChallengeS256,
            expiresAt: now.addingTimeInterval(codeLifetime),
            familyExpiresAt: now.addingTimeInterval(refreshLifetime)
        )
        do {
            try await controlStore.storeAuthorizationCode(record, now: now)
        } catch {
            throw secureControlError(error)
        }
        return code
    }

    /// Verifies PKCE before atomically consuming the code and inserting both
    /// token digests. A second verified use revokes the family in that same
    /// durable transaction.
    public func redeemAuthorizationCode(
        _ code: String,
        verifier: String,
        session: OAuthValidatedSession,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        let binding = session.durableBinding
        let codeDigest = digest(code, purpose: .authorizationCode)
        let record: OAuthAuthorizationCode
        do {
            guard let loaded = try await controlStore.authorizationCode(
                codeDigest: codeDigest,
                now: now
            ) else {
                throw OAuthControlStoreError.notFound
            }
            record = loaded
        } catch {
            throw secureControlError(error)
        }
        guard record.binding == binding,
              PKCE.verifyS256(verifier: verifier, challenge: record.codeChallengeS256) else {
            throw SwanError.unauthorized("authorization code rejected")
        }
        let refreshLifetime = record.familyExpiresAt.timeIntervalSince(now)
        let pair = try makeTokenPair(
            familyID: record.familyID,
            accessLifetime: min(accessLifetime, refreshLifetime),
            refreshLifetime: refreshLifetime,
            now: now
        )
        do {
            try await controlStore.redeemAuthorizationCode(
                codeDigest: codeDigest,
                binding: binding,
                issuedTokens: tokenDigests(for: pair),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return pair
    }

    public func validateAccess(
        _ token: String,
        proof: OAuthValidatedDPoPProof,
        now: Date = Date()
    ) async throws -> AccessGrant {
        do {
            let family = try await controlStore.validatedAccessToken(
                accessTokenDigest: digest(token, purpose: .accessToken),
                now: now
            )
            try requirePresentedBindings(
                family: family,
                dpopProof: proof,
                clientAssertion: nil,
                requireClientAssertionKey: false
            )
            return AccessGrant(family: family)
        } catch {
            throw secureControlError(error)
        }
    }

    /// Rotates a refresh token inside one durable transaction. Concurrent
    /// redemptions cannot both issue a pair: the loser observes `used_at` and
    /// atomically revokes the complete token family.
    public func redeemRefresh(
        _ refreshToken: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        let refreshDigest = digest(refreshToken, purpose: .refreshToken)
        let family: OAuthTokenFamily
        do {
            family = try await controlStore.refreshTokenFamily(
                refreshTokenDigest: refreshDigest,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        do {
            try await requireFreshConfidentialClientBinding(
                family: family,
                clientAssertion: clientAssertion,
                metadataLoader: metadataLoader,
                now: now
            )
            try requirePresentedBindings(
                family: family,
                dpopProof: dpopProof,
                clientAssertion: clientAssertion,
                requireClientAssertionKey: true
            )
        } catch {
            throw secureControlError(error)
        }
        let remainingLifetime = family.expiresAt.timeIntervalSince(now)
        let pair = try makeTokenPair(
            familyID: family.familyID,
            accessLifetime: min(accessLifetime, remainingLifetime),
            refreshLifetime: remainingLifetime,
            now: now
        )
        do {
            try await controlStore.redeemRefreshToken(
                refreshTokenDigest: refreshDigest,
                replacement: tokenDigests(for: pair),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return pair
    }

    /// Rotates a token family belonging to the AT Protocol localhost
    /// development-client exception. This deliberately accepts only a public
    /// client identifier already validated by
    /// `OAuthClientMetadata.localhostDevelopmentMetadata`; it never bypasses
    /// remote metadata/JWKS revalidation for a confidential family.
    public func redeemLocalhostPublicRefresh(
        _ refreshToken: String,
        clientID: URL,
        dpopProof: OAuthValidatedDPoPProof,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        let refreshDigest = digest(refreshToken, purpose: .refreshToken)
        let family: OAuthTokenFamily
        do {
            family = try await controlStore.refreshTokenFamily(
                refreshTokenDigest: refreshDigest,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        do {
            guard family.binding.clientID == metadata.clientID.absoluteString,
                  family.binding.confidentialClientKey == nil else {
                throw OAuthControlStoreError.bindingMismatch
            }
            try requirePresentedBindings(
                family: family,
                dpopProof: dpopProof,
                clientAssertion: nil,
                requireClientAssertionKey: true
            )
        } catch {
            throw secureControlError(error)
        }
        let remainingLifetime = family.expiresAt.timeIntervalSince(now)
        let pair = try makeTokenPair(
            familyID: family.familyID,
            accessLifetime: min(accessLifetime, remainingLifetime),
            refreshLifetime: remainingLifetime,
            now: now
        )
        do {
            try await controlStore.redeemRefreshToken(
                refreshTokenDigest: refreshDigest,
                replacement: tokenDigests(for: pair),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return pair
    }

    /// Revokes the complete family for one locally-valid public-client token.
    /// An unknown, expired, revoked, or differently-bound token returns false
    /// so the RFC 7009 HTTP adapter can remain an oracle-free 200 response.
    /// The DPoP proof must already have been validated for the revocation
    /// endpoint; this method rechecks its JKT against the selected family.
    public func revokeLocalhostPublicToken(
        _ token: String,
        kind: OAuthOpaqueTokenKind,
        clientID: URL,
        dpopProof: OAuthValidatedDPoPProof,
        now: Date = Date()
    ) async throws -> Bool {
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        let family: OAuthTokenFamily?
        do {
            family = try await controlStore.tokenFamily(
                tokenDigest: digest(token, purpose: kind == .accessToken ? .accessToken : .refreshToken),
                kind: kind,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        guard let family,
              family.binding.clientID == metadata.clientID.absoluteString,
              family.binding.confidentialClientKey == nil else {
            return false
        }
        do {
            try requirePresentedBindings(
                family: family,
                dpopProof: dpopProof,
                clientAssertion: nil,
                requireClientAssertionKey: true
            )
            try await controlStore.revokeTokenFamily(familyID: family.familyID, now: now)
            return true
        } catch {
            // A wrong proof or caller ID must not reveal that the family was
            // present, and must never revoke a token it did not bind.
            if error is OAuthControlStoreError { return false }
            throw secureControlError(error)
        }
    }

    public func revokeFamily(for refreshToken: String, now: Date = Date()) async throws -> Bool {
        do {
            return try await controlStore.revokeTokenFamily(
                refreshTokenDigest: digest(refreshToken, purpose: .refreshToken),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    /// Atomically claims a DPoP proof ID without persisting the proof body or
    /// raw `jti`. Callers must pass the proof's validated `exp` boundary.
    public func claimDPoP(
        jti: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        guard validJTI(jti) else { throw SwanError.unauthorized("DPoP proof rejected") }
        do {
            return try await controlStore.claimDPoPReplay(
                digest: digest(jti, purpose: .dpopJTI),
                expiresAt: expiresAt,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    /// Reserves a private-key client assertion ID for its entire validity
    /// interval, independently from DPoP's replay namespace.
    public func claimClientAssertion(
        jti: String,
        clientID: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        guard validJTI(jti), !clientID.isEmpty else {
            throw SwanError.unauthorized("client assertion rejected")
        }
        do {
            return try await controlStore.claimClientAssertion(
                digest: digest(jti, purpose: .clientAssertionJTI),
                clientID: clientID,
                expiresAt: expiresAt,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    public func cacheClientMetadata(
        _ metadata: OAuthClientMetadata,
        expiresAt: Date,
        now: Date = Date()
    ) async throws {
        do {
            let document = try JSONEncoder().encode(metadata)
            try await controlStore.cacheClientMetadata(
                OAuthCachedClientMetadata(
                    clientID: metadata.clientID.absoluteString,
                    document: document,
                    expiresAt: expiresAt
                ),
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
    }

    public func cachedClientMetadata(
        clientID: URL,
        now: Date = Date()
    ) async throws -> OAuthClientMetadata? {
        do {
            guard let cached = try await controlStore.cachedClientMetadata(
                clientID: clientID.absoluteString,
                now: now
            ) else { return nil }
            let metadata = try JSONDecoder().decode(OAuthClientMetadata.self, from: cached.document)
            guard metadata.clientID == clientID else {
                throw OAuthControlStoreError.malformedRecord
            }
            return metadata
        } catch {
            throw secureControlError(error)
        }
    }

    private func tokenDigests(for pair: OAuthTokenPair) -> OAuthIssuedTokenDigests {
        OAuthIssuedTokenDigests(
            familyID: pair.familyID,
            accessTokenDigest: digest(pair.accessToken, purpose: .accessToken),
            refreshTokenDigest: digest(pair.refreshToken, purpose: .refreshToken),
            accessExpiresAt: pair.accessExpiresAt,
            refreshExpiresAt: pair.refreshExpiresAt
        )
    }

    private func makeTokenPair(
        familyID: UUID,
        accessLifetime: TimeInterval,
        refreshLifetime: TimeInterval,
        now: Date
    ) throws -> OAuthTokenPair {
        guard accessLifetime > 0, refreshLifetime > 0,
              accessLifetime.isFinite, refreshLifetime.isFinite else {
            throw SwanError.malformed("OAuth token lifetimes must be positive")
        }
        return OAuthTokenPair(
            accessToken: Self.randomOpaqueValue(),
            refreshToken: Self.randomOpaqueValue(),
            accessExpiresAt: now.addingTimeInterval(accessLifetime),
            refreshExpiresAt: now.addingTimeInterval(refreshLifetime),
            familyID: familyID
        )
    }

    private func digest(_ rawValue: String, purpose: DigestPurpose) -> Data {
        var input = Data("swan.oauth.\(purpose.rawValue)\u{0}".utf8)
        input.append(contentsOf: rawValue.utf8)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: macKey))
    }

    private func validateRequestURI(_ requestURI: String) throws {
        let prefix = "urn:ietf:params:oauth:request_uri:"
        guard requestURI.hasPrefix(prefix),
              requestURI.utf8.count == prefix.utf8.count + 43,
              requestURI.utf8.dropFirst(prefix.utf8.count).allSatisfy({ byte in
                  (65 ... 90).contains(byte) || (97 ... 122).contains(byte)
                      || (48 ... 57).contains(byte) || byte == 45 || byte == 95
              }) else {
            throw SwanError.unauthorized("authorization request rejected")
        }
    }

    private func secureControlError(_ error: any Error) -> any Error {
        guard let controlError = error as? OAuthControlStoreError else {
            // SQLite/serialization details can reveal deployment shape and
            // must not become an OAuth response or loggable credential path.
            return SwanError.unavailable("OAuth control state unavailable")
        }
        switch controlError {
        case .expired:
            return SwanError.expired
        case .notFound, .bindingMismatch, .alreadyConsumed, .replayDetected,
                .invalidInput, .malformedRecord:
            return SwanError.unauthorized("OAuth credential rejected")
        }
    }

    private func requirePresentedBindings(
        family: OAuthTokenFamily,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        requireClientAssertionKey: Bool
    ) throws {
        guard let requiredJKT = family.binding.dpopJKT,
              Self.validDPoPJKT(requiredJKT),
              Self.validDPoPJKT(dpopProof.keyThumbprint),
              constantTimeTextEqual(requiredJKT, dpopProof.keyThumbprint) else {
            throw OAuthControlStoreError.bindingMismatch
        }
        if requireClientAssertionKey, let requiredKey = family.binding.confidentialClientKey {
            guard let clientAssertion,
                  clientAssertion.clientID == family.binding.clientID,
                  clientAssertion.algorithm == requiredKey.algorithm,
                  constantTimeTextEqual(requiredKey.keyID, clientAssertion.selectedKeyID),
                  constantTimeTextEqual(requiredKey.keyThumbprint, clientAssertion.keyThumbprint) else {
                throw OAuthControlStoreError.bindingMismatch
            }
        } else if requireClientAssertionKey, clientAssertion != nil {
            throw OAuthControlStoreError.bindingMismatch
        }
    }

    /// Confidential families are revalidated on every rotation. A matching
    /// `kid` alone is explicitly insufficient: the refreshed JWKS must contain
    /// the stored `(kid, ES256, JKT)` tuple, otherwise one transaction revokes
    /// the entire family before the request is rejected.
    private func requireFreshConfidentialClientBinding(
        family: OAuthTokenFamily,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        now: Date
    ) async throws {
        guard let persisted = family.binding.confidentialClientKey else {
            guard clientAssertion == nil else { throw OAuthControlStoreError.bindingMismatch }
            return
        }
        guard let clientID = URL(string: family.binding.clientID) else {
            try await revokeFamilyAfterConfidentialKeyChange(family.familyID, now: now)
            throw OAuthControlStoreError.bindingMismatch
        }

        let refreshed: OAuthResolvedClientMetadata
        do {
            refreshed = try await metadataLoader.revalidate(clientID: clientID, now: now)
        } catch let error as SwanError {
            // A transient loader failure denies this rotation but does not
            // destroy a family solely because the network is unavailable.
            throw error
        } catch {
            throw SwanError.unavailable("OAuth client metadata revalidation failed")
        }
        guard refreshed.metadata.clientID.absoluteString == family.binding.clientID,
              refreshed.metadata.tokenEndpointAuthMethod == .privateKeyJWT,
              let keySet = refreshed.keySet else {
            try await revokeFamilyAfterConfidentialKeyChange(family.familyID, now: now)
            throw OAuthControlStoreError.bindingMismatch
        }
        let refreshedKey: OAuthJSONWebKey
        do {
            refreshedKey = try keySet.select(keyID: persisted.keyID)
        } catch {
            try await revokeFamilyAfterConfidentialKeyChange(family.familyID, now: now)
            throw OAuthControlStoreError.bindingMismatch
        }
        guard persisted.algorithm == "ES256",
              refreshedKey.algorithm == nil || refreshedKey.algorithm == persisted.algorithm,
              constantTimeTextEqual(refreshedKey.thumbprint(), persisted.keyThumbprint) else {
            try await revokeFamilyAfterConfidentialKeyChange(family.familyID, now: now)
            throw OAuthControlStoreError.bindingMismatch
        }
        guard let clientAssertion, clientAssertion.expiresAt > now else {
            throw OAuthControlStoreError.bindingMismatch
        }
    }

    private func revokeFamilyAfterConfidentialKeyChange(_ familyID: UUID, now: Date) async throws {
        do {
            try await controlStore.revokeTokenFamily(familyID: familyID, now: now)
        } catch {
            throw secureControlError(error)
        }
    }

    /// AT Protocol OAuth is sender-constrained: a durable OAuth family must
    /// always have a syntactically valid DPoP JKT. The nullable model type is
    /// useful while parsing untrusted input, but it cannot cross this boundary.
    private func requireOAuthDPoPBinding(_ binding: OAuthClientBinding) throws {
        guard binding.scopes.contains("atproto") else {
            throw SwanError.unauthorized("atproto scope is required for OAuth")
        }
        guard let jkt = binding.dpopJKT, Self.validDPoPJKT(jkt) else {
            throw SwanError.unauthorized("DPoP binding is required for OAuth")
        }
    }

    private static func validDPoPJKT(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

    private func constantTimeTextEqual(_ lhs: String, _ rhs: String) -> Bool {
        let lhsData = Data(lhs.utf8)
        let rhsData = Data(rhs.utf8)
        guard lhsData.count == rhsData.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhsData, rhsData) { difference |= left ^ right }
        return difference == 0
    }

    private func validJTI(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && !value.utf8.contains(0)
    }

    private static func randomOpaqueValue() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0..<32).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        })
        return bytes.base64URLEncodedString()
    }
}

/// A narrow durable replacement for the in-memory `DPoPReplayStore`. It is
/// useful to a proof verifier that should not also expose token issuance APIs.
public actor DurableDPoPReplayStore {
    private let controlStore: any OAuthControlStore
    private let macKey: SymmetricKey

    public init(controlStore: any OAuthControlStore, serverKey: Data) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        self.controlStore = controlStore
        macKey = SymmetricKey(data: serverKey)
    }

    public func accept(jti: String, expiresAt: Date, now: Date = Date()) async throws -> Bool {
        guard !jti.isEmpty, jti.utf8.count <= 4_096, !jti.utf8.contains(0) else {
            throw SwanError.unauthorized("DPoP proof rejected")
        }
        var input = Data("swan.oauth.dpop-jti\u{0}".utf8)
        input.append(contentsOf: jti.utf8)
        let digest = Data(HMAC<SHA256>.authenticationCode(for: input, using: macKey))
        do {
            return try await controlStore.claimDPoPReplay(
                digest: digest,
                expiresAt: expiresAt,
                now: now
            )
        } catch let error as OAuthControlStoreError {
            if error == .expired { throw SwanError.expired }
            throw SwanError.unauthorized("DPoP proof rejected")
        }
    }
}
