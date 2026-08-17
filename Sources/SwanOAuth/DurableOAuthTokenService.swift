import Crypto
import Foundation
import SwanCore
import SwanStorage

/// Raw values live only long enough to build one remote token response.  In
/// particular, refresh material is optional so an authorization-code client
/// which did not request/declare refresh capability never receives—or leaves
/// behind—a refresh bearer credential.
private struct OAuthTokenGrantMaterial: Sendable {
    let accessToken: String
    let refreshToken: String?
    let accessExpiresAt: Date
    let refreshExpiresAt: Date?
    let familyID: UUID
}
import SwanSpaces

/// The single typed OAuth dependency accepted by a running Swan HTTP server.
/// Both actors are backed by the same durable control store and the same
/// injected server HMAC key; an HTTP server cannot be assembled with an
/// in-memory token vault by accident.
public struct SwanOAuthRuntime: Sendable {
    public let tokenService: DurableOAuthTokenService
    public let dpopReplayStore: DurableDPoPReplayStore
    /// A dedicated, durable single-use reservation for permissioned-data
    /// delegations. It shares the injected non-persisted HMAC key with the
    /// OAuth runtime but has a distinct storage and digest namespace.
    public let spaceDelegationReplayStore: DurableSpaceDelegationReplayStore
    public let browserSessionService: OAuthBrowserSessionService
    /// The nonce MAC key is the injected non-persisted OAuth server key. It
    /// never crosses into `OAuthControlStore`; validators receive this service
    /// from the runtime rather than accepting arbitrary caller text as a nonce.
    public let dpopNonceService: DPoPNonceService
    /// §5.7.4's resolver, or `nil` when this deployment has no lexicon authority
    /// configured.
    ///
    /// It is carried on the runtime rather than reached for at a call site
    /// because BOTH §5.7.5 call sites need the same instance: PAR/consent lives
    /// in SwanHTTP and token mint lives in ``DurableOAuthTokenService``, and two
    /// resolvers would mean two caches — so a document proved at PAR would be
    /// re-proved, over the network, at mint.
    ///
    /// The concrete `SwanLexiconResolver` is in **SwanInterop**, which depends on
    /// SwanOAuth and not the reverse; only the protocol (SwanCore) is nameable
    /// here. The composition root (`swan`) depends on both and injects one into
    /// the other. No source target's `Package.swift` dependencies change.
    ///
    /// `nil` is Phase-1 behaviour, deliberately and with a recorded cost: an
    /// `include:` grants nothing and a bare `space:<type>` materialises no write
    /// targets. See ``OAuthLexiconScopeResolution``.
    public let lexiconResolver: (any SwanLexiconResolving)?

    public init(
        controlStore: any OAuthControlStore & SpaceDelegationReplayStore,
        serverKey: Data,
        lexiconResolver: (any SwanLexiconResolving)? = nil
    ) throws {
        tokenService = try DurableOAuthTokenService(
            controlStore: controlStore,
            serverKey: serverKey,
            lexiconResolver: lexiconResolver
        )
        self.lexiconResolver = lexiconResolver
        dpopReplayStore = try DurableDPoPReplayStore(
            controlStore: controlStore,
            serverKey: serverKey
        )
        spaceDelegationReplayStore = try DurableSpaceDelegationReplayStore(
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
    /// §5.7.5 call site 2. `nil` leaves this service in Phase-1 behaviour — see
    /// ``SwanOAuthRuntime/lexiconResolver``.
    private let lexiconResolver: (any SwanLexiconResolving)?

    /// A resource-facing grant deliberately includes the DPoP binding instead
    /// of looking like a plain bearer-token result. Resource middleware must
    /// call `validateAccess(_:proof:now:)`, which verifies that
    /// binding before this value can be obtained.
    public struct AccessGrant: Sendable, Equatable {
        public let subject: String
        /// The **effective** grant — post-`self`-resolution (§9-D8). This, and
        /// never `scopesRequested`, is what the matcher enforces against.
        public let scopes: Set<String>
        public let issuer: String
        public let clientID: String
        public let redirectURI: String
        public let dpopJKT: String?
        /// The pre-resolution set — the bytes the client asked for (§6.7). Equal
        /// to `scopes` for a grant Swan did not rewrite; never `nil`, because
        /// the durable NULL means "requested == stored", not "unknown".
        public let scopesRequested: Set<String>
        /// The durable §9-D23 provenance bits: for each effective scope string,
        /// which parameter keys the client physically wrote.
        ///
        /// These ride on the grant because `SwanScopePermissions` cannot recover
        /// them any other way. A persisted scope string is lossy in **both**
        /// directions: mint writes a literal `authority=did:plc:…` where the
        /// client wrote nothing, so a re-parse reports `authority` as *stated*
        /// and the delegation fence flips open; and canonical serialisation
        /// deletes a value equal to its default, so a literally-written
        /// `skey=*` disappears and the listing fence can never fire again.
        /// Provenance is therefore carried from the parse that produced it,
        /// through mint and persistence, to here — never reconstructed.
        public let scopeProvenance: OAuthScopeProvenance

        fileprivate init(family: OAuthTokenFamily) {
            subject = family.subject
            scopes = family.binding.scopes
            issuer = family.binding.issuer
            clientID = family.binding.clientID
            redirectURI = family.binding.redirectURI
            dpopJKT = family.binding.dpopJKT
            scopesRequested = family.binding.requestedScopes
            // Absent bits mean "nothing was stated", which is the fail-closed
            // direction for both fences: a missing record denies, never grants.
            scopeProvenance = family.binding.scopeProvenance ?? OAuthScopeProvenance()
        }

        /// The durable stated-key bits in exactly the shape
        /// `SwanScopePermissions.init(rawScopes:subject:statedKeys:)` takes.
        ///
        /// A plain dictionary rather than `OAuthScopeProvenance` because
        /// `SwanScopePermissions` lives in SwanCore, which sits *beneath*
        /// SwanStorage and so cannot name that type.
        public var statedScopeKeys: [String: Set<String>] {
            scopeProvenance.statedParameterKeys
        }
    }

    public init(
        controlStore: any OAuthControlStore,
        serverKey: Data,
        lexiconResolver: (any SwanLexiconResolving)? = nil
    ) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        self.controlStore = controlStore
        self.lexiconResolver = lexiconResolver
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
        // §5.7.5 call site 2, as at `_issueAuthorizationCode`: this is a mint, so
        // the family row must hold the RESOLVED grant or it would grant nothing.
        // (a) `include:` → concrete, (b) `expandSpaceCollections`, (c) stage F's
        // `self` → subject, in that order.
        let binding = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            session.durableBinding,
            subject: subject,
            resolver: lexiconResolver
        )
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
    /// Issues a browser authorization code only against a durable active
    /// subject revision. Production callers must provide the revision that
    /// was checked with the login/consent session; the account-free variant
    /// is kept internal for token-mechanics tests only.
    public func issueAuthorizationCode(
        subject: String,
        session: OAuthValidatedSession,
        codeChallengeS256: String,
        activeSubjectRevisionMicroseconds: Int64,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        try await _issueAuthorizationCode(
            subject: subject,
            binding: session.durableBinding,
            codeChallengeS256: codeChallengeS256,
            activeSubjectRevisionMicroseconds: activeSubjectRevisionMicroseconds,
            codeLifetime: codeLifetime,
            refreshLifetime: refreshLifetime,
            familyID: familyID,
            now: now
        )
    }

    func issueAuthorizationCode(
        subject: String,
        session: OAuthValidatedSession,
        codeChallengeS256: String,
        activeSubjectRevisionMicroseconds: Int64? = nil,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        try await _issueAuthorizationCode(
            subject: subject,
            binding: session.durableBinding,
            codeChallengeS256: codeChallengeS256,
            activeSubjectRevisionMicroseconds: activeSubjectRevisionMicroseconds,
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
        activeSubjectRevisionMicroseconds: Int64,
        authorizationGrantDigest: Data? = nil,
        authorizationContext: AccountAuthorizationContext? = nil,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        try await _issueAuthorizationCode(
            subject: subject,
            binding: binding,
            codeChallengeS256: codeChallengeS256,
            activeSubjectRevisionMicroseconds: activeSubjectRevisionMicroseconds,
            codeLifetime: codeLifetime,
            refreshLifetime: refreshLifetime,
            familyID: familyID,
            now: now,
            authorizationGrantDigest: authorizationGrantDigest,
            authorizationContext: authorizationContext
        )
    }

    func issueAuthorizationCode(
        subject: String,
        binding: OAuthClientBinding,
        codeChallengeS256: String,
        activeSubjectRevisionMicroseconds: Int64? = nil,
        codeLifetime: TimeInterval = 60,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> String {
        try await _issueAuthorizationCode(
            subject: subject,
            binding: binding,
            codeChallengeS256: codeChallengeS256,
            activeSubjectRevisionMicroseconds: activeSubjectRevisionMicroseconds,
            codeLifetime: codeLifetime,
            refreshLifetime: refreshLifetime,
            familyID: familyID,
            now: now
        )
    }

    private func _issueAuthorizationCode(
        subject: String,
        binding: OAuthClientBinding,
        codeChallengeS256: String,
        activeSubjectRevisionMicroseconds: Int64?,
        codeLifetime: TimeInterval,
        refreshLifetime: TimeInterval,
        familyID: UUID,
        now: Date,
        authorizationGrantDigest: Data? = nil,
        authorizationContext: AccountAuthorizationContext? = nil
    ) async throws -> String {
        guard codeLifetime > 0, refreshLifetime > 0,
              codeLifetime.isFinite, refreshLifetime.isFinite else {
            throw SwanError.malformed("authorization code lifetimes must be positive")
        }
        // Stage F (§6.4). This is the first point at which the subject DID meets
        // the client binding — `createPushedAuthorizationRequest` has no subject,
        // so a PAR row genuinely cannot hold a resolved scope.
        //
        // Resolution is mandatory rather than cosmetic: an unresolved `self`
        // matches NOTHING (`SpacePermission.matches` returns false on
        // `.unresolvedSelf`), so a family storing `authority=self` would grant
        // nothing at all on every request. The requested bytes are preserved
        // separately on the binding, and provenance is carried rather than
        // re-derived — resolving `self` changes the value, never the statedness.
        //
        // Stage F is (c) of §5.7.5's three transformations, and it does not run
        // alone: (a) `include:` → concrete and (b) `expandSpaceCollections` run
        // first, in that order, inside `resolvingLexiconGrants`. All three land
        // here rather than earlier because §6.3 stage C compares *raw requested*
        // against *registered* and both sides must still be in `include:` form
        // for that comparison to mean anything.
        let resolved = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            binding,
            subject: subject,
            resolver: lexiconResolver
        )
        try requireOAuthDPoPBinding(resolved)
        let code = Self.randomOpaqueValue()
        let record = OAuthAuthorizationCode(
            codeDigest: digest(code, purpose: .authorizationCode),
            familyID: familyID,
            subject: subject,
            binding: resolved,
            codeChallengeS256: codeChallengeS256,
            expiresAt: now.addingTimeInterval(codeLifetime),
            familyExpiresAt: now.addingTimeInterval(refreshLifetime)
        )
        do {
            if let authorizationGrantDigest {
                guard let authorizationContext,
                      authorizationGrantDigest.count == 32,
                      let grantStore = controlStore as? any OAuthAuthorizationGrantStore,
                      let activeSubjectRevisionMicroseconds else {
                    throw OAuthControlStoreError.bindingMismatch
                }
                try await grantStore.storeAuthorizationCode(
                    record,
                    requiringActiveSubjectRevisionMicroseconds: activeSubjectRevisionMicroseconds,
                    authorizationGrantDigest: authorizationGrantDigest,
                    authorizationContext: authorizationContext,
                    now: now)
            } else {
                if let activeSubjectRevisionMicroseconds {
                    try await controlStore.storeAuthorizationCode(
                        record,
                        requiringActiveSubjectRevisionMicroseconds:
                            activeSubjectRevisionMicroseconds,
                        now: now
                    )
                } else {
                    try await controlStore.storeAuthorizationCode(record, now: now)
                }
            }
        } catch {
            throw secureControlError(error)
        }
        return code
    }

    /// Verifies PKCE before atomically consuming the code and inserting both
    /// token digests. A second verified use revokes the family in that same
    /// durable transaction.
    /// Redeems an authorization code only for an active account subject.
    /// Token-mechanics tests use the internal overload below when they need a
    /// synthetic subject with no account row.
    public func redeemAuthorizationCode(
        _ code: String,
        verifier: String,
        session: OAuthValidatedSession,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        try await redeemAuthorizationCode(
            code,
            verifier: verifier,
            session: session,
            accessLifetime: accessLifetime,
            requireActiveSubject: true,
            now: now
        )
    }

    func redeemAuthorizationCode(
        _ code: String,
        verifier: String,
        session: OAuthValidatedSession,
        accessLifetime: TimeInterval = 300,
        requireActiveSubject: Bool,
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
                requireActiveSubject: requireActiveSubject,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return pair
    }

    /// Redeems a code after the token endpoint freshly validates the client
    /// document. Requested scopes come only from the durable code record, and
    /// the form redirect URI must exactly equal that record.
    public func redeemAuthorizationCodeForClient(
        _ code: String,
        verifier: String,
        redirectURI: URL,
        authorizationServerIssuer: String,
        client: OAuthResolvedClientMetadata,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenGrantResult {
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

        do {
            try validateCurrentClient(
                client,
                assertion: clientAssertion,
                against: record.binding,
                authorizationServerIssuer: authorizationServerIssuer,
                now: now
            )
            guard redirectURI.absoluteString == record.binding.redirectURI else {
                throw OAuthControlStoreError.bindingMismatch
            }
            guard client.metadata.grantTypes.contains("authorization_code") else {
                throw OAuthControlStoreError.bindingMismatch
            }
            let family = OAuthTokenFamily(
                familyID: record.familyID,
                subject: record.subject,
                binding: record.binding,
                expiresAt: record.familyExpiresAt
            )
            try requirePresentedBindings(
                family: family,
                dpopProof: dpopProof,
                clientAssertion: clientAssertion,
                requireClientAssertionKey: true
            )
            guard PKCE.verifyS256(verifier: verifier, challenge: record.codeChallengeS256) else {
                throw OAuthControlStoreError.bindingMismatch
            }
        } catch {
            throw secureControlError(error)
        }

        let refreshLifetime = record.familyExpiresAt.timeIntervalSince(now)
        let issueRefresh = record.binding.refreshTokenAllowed
            && client.metadata.grantTypes.contains("refresh_token")
        let grant: OAuthTokenGrantMaterial
        do {
            grant = try makeTokenGrant(
                familyID: record.familyID,
                accessLifetime: min(accessLifetime, refreshLifetime),
                refreshLifetime: issueRefresh ? refreshLifetime : nil,
                now: now
            )
            try await controlStore.redeemAuthorizationCode(
                codeDigest: codeDigest,
                binding: record.binding,
                issuedTokens: tokenDigests(for: grant),
                requireActiveSubject: true,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return OAuthTokenGrantResult(
            accessToken: grant.accessToken,
            accessExpiresAt: grant.accessExpiresAt,
            scopes: record.binding.scopes,
            subject: record.subject,
            refreshToken: grant.refreshToken,
            // The pre-resolution bytes, so a caller can tell preservation from
            // mutation (§6.7). Stage F rewrote `binding.scopes` in place.
            scopesRequested: record.binding.requestedScopes
        )
    }

    public func validateAccess(
        _ token: String,
        proof: OAuthValidatedDPoPProof,
        now: Date = Date()
    ) async throws -> AccessGrant {
        try await validateAccess(
            token,
            proof: proof,
            requireActiveSubject: true,
            now: now
        )
    }

    /// Test-only seam for durable token mechanics that intentionally construct
    /// token families without provisioning an account row. Runtime call sites
    /// cannot opt out of the active-subject check.
    func validateAccessWithoutActiveSubjectCheck(
        _ token: String,
        proof: OAuthValidatedDPoPProof,
        now: Date = Date()
    ) async throws -> AccessGrant {
        try await validateAccess(
            token,
            proof: proof,
            requireActiveSubject: false,
            now: now
        )
    }

    private func validateAccess(
        _ token: String,
        proof: OAuthValidatedDPoPProof,
        requireActiveSubject: Bool,
        now: Date
    ) async throws -> AccessGrant {
        do {
            let family = try await controlStore.validatedAccessToken(
                accessTokenDigest: digest(token, purpose: .accessToken),
                requireActiveSubject: requireActiveSubject,
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
    /// Rotates a refresh token only for an active account subject. The
    /// bool-bearing overload is intentionally internal and exists solely for
    /// account-free durable token tests.
    public func redeemRefresh(
        _ refreshToken: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        try await redeemRefresh(
            refreshToken,
            dpopProof: dpopProof,
            clientAssertion: clientAssertion,
            metadataLoader: metadataLoader,
            accessLifetime: accessLifetime,
            requireActiveSubject: true,
            now: now
        )
    }

    @discardableResult
    func redeemRefresh(
        _ refreshToken: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        accessLifetime: TimeInterval = 300,
        requireActiveSubject: Bool,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        try await rotateRefresh(
            refreshToken,
            dpopProof: dpopProof,
            clientAssertion: clientAssertion,
            metadataLoader: metadataLoader,
            accessLifetime: accessLifetime,
            requireActiveSubject: requireActiveSubject,
            now: now
        ).pair
    }

    private func rotateRefresh(
        _ refreshToken: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        accessLifetime: TimeInterval,
        requireActiveSubject: Bool,
        now: Date
    ) async throws -> (pair: OAuthTokenPair, scopes: Set<String>) {
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
        // BEFORE the rotation, deliberately: re-derivation performs network I/O
        // and can fail, and a failure must leave the presented refresh token
        // still usable rather than burning it on a rotation that then refuses.
        let rederived = try await rederivedGrant(for: family)
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
                rewrittenGrant: rederived,
                requireActiveSubject: requireActiveSubject,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        return (pair, rederived?.scopes ?? family.binding.scopes)
    }

    /// §5.7.5's second call site, the half F2 found missing: **refresh
    /// re-derives the token scope**, exactly as `rotateToken` does upstream
    /// (`token-manager.ts:260-263` → `buildTokenScope(parameters.scope!, did)`).
    ///
    /// The input is the **requested** baseline (`scopes_requested ?? scopes`,
    /// §9-D20), never `binding.scopes`: the latter holds the post-`self`
    /// resolution grant (§9-D8), so re-deriving from it would re-resolve an
    /// already-resolved value and drift a little further on every rotation.
    /// Upstream's operand is the same one — `parameters.scope` is the
    /// authorization request's own bytes.
    ///
    /// **Why this matters more than "we hadn't wired refresh yet."** §5.7.4
    /// introduced Swan's 24-hour hard cache expiry with a rationale that argues
    /// *from* re-derivation: without it, a permission set that was **narrowed**
    /// upstream would keep minting the wider grant. With the scope frozen at
    /// mint, that safeguard was inert — a 14-day refresh family kept its
    /// mint-time grant for its whole life whether or not the resolver was
    /// reachable, and whatever the authority now declares.
    ///
    /// **Failure policy: a re-derivation failure fails the refresh.** It is not
    /// a fall-back-to-stored, and the two are genuinely different layers:
    /// serving a stale document on a fetch failure is the *cache's* job
    /// (§5.7.5's matrix, first row), so by the time a failure reaches here the
    /// cache has already declined to answer — either it has nothing or its 24 h
    /// hard expiry has passed. Continuing at that point would mint the wider
    /// grant precisely when Swan can no longer show it is still granted, which
    /// is the outcome the hard expiry exists to prevent. Upstream makes the same
    /// call in the same place and says so (`token-manager.ts:257-259`: "it's
    /// fine to propagate a 500 here"). Swan's code is `invalid_request` rather
    /// than `server_error`, carried by the stage on
    /// ``OAuthScopeResolutionError`` (§5.7.5's asymmetry).
    ///
    /// Returns `nil` — leave the stored grant exactly as it is — in two cases:
    /// the re-derivation reproduced what is already stored, which is the common
    /// case and must not churn the row; or the family predates
    /// `scope_provenance_requested` and has no baseline to derive from, which is
    /// bounded by the 14-day family lifetime and preserves today's behaviour for
    /// those rows rather than narrowing a live grant on a guess.
    /// `internal` rather than `private` so the two decisions that produce `nil` —
    /// no change, and no baseline — can be asserted directly. Neither is
    /// observable from the rotation's outputs: both look exactly like a refresh
    /// that re-derived and happened to agree.
    func rederivedGrant(for family: OAuthTokenFamily) async throws -> OAuthRefreshedGrant? {
        guard let baseline = family.binding.requestedBaseline() else { return nil }
        let resolved = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            baseline,
            subject: family.subject,
            resolver: lexiconResolver
        )
        let provenance = resolved.scopeProvenance ?? OAuthScopeProvenance()
        guard resolved.scopes != family.binding.scopes
            || provenance != (family.binding.scopeProvenance ?? OAuthScopeProvenance())
        else { return nil }
        return OAuthRefreshedGrant(scopes: resolved.scopes, scopeProvenance: provenance)
    }

    /// Authorization-server refresh adapter. It reuses the existing durable
    /// rotation/reuse-revocation transaction while returning the persisted
    /// scope set for the token response.
    public func redeemRefreshForClient(
        _ refreshToken: String,
        client: OAuthResolvedClientMetadata,
        authorizationServerIssuer: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenGrantResult {
        let refreshDigest = digest(refreshToken, purpose: .refreshToken)
        let family: OAuthTokenFamily
        do {
            family = try await controlStore.refreshTokenFamily(
                refreshTokenDigest: refreshDigest,
                now: now
            )
            try validateCurrentClient(
                client,
                assertion: clientAssertion,
                against: family.binding,
                authorizationServerIssuer: authorizationServerIssuer,
                now: now
            )
            guard family.binding.refreshTokenAllowed,
                  client.metadata.grantTypes.contains("refresh_token") else {
                throw OAuthControlStoreError.bindingMismatch
            }
        } catch {
            throw secureControlError(error)
        }
        let rotated = try await rotateRefresh(
            refreshToken,
            dpopProof: dpopProof,
            clientAssertion: clientAssertion,
            metadataLoader: metadataLoader,
            accessLifetime: accessLifetime,
            requireActiveSubject: true,
            now: now
        )
        return OAuthTokenGrantResult(
            accessToken: rotated.pair.accessToken,
            accessExpiresAt: rotated.pair.accessExpiresAt,
            // The RE-DERIVED grant, not the one the family held on the way in:
            // a rotation that narrowed the stored scope and then reported the
            // old one would tell the client it still holds capabilities the
            // access token no longer carries. Upstream reports the same value it
            // just persisted (`token-manager.ts:266-295`).
            scopes: rotated.scopes,
            subject: family.subject,
            // Unchanged by rotation, and that is the point: it is the baseline
            // the NEXT refresh re-derives from (§9-D20).
            refreshToken: rotated.pair.refreshToken,
            scopesRequested: family.binding.requestedScopes
        )
    }

    /// Rotates a token family belonging to the AT Protocol localhost
    /// development-client exception. This deliberately accepts only a public
    /// client identifier already validated by
    /// `OAuthClientMetadata.localhostDevelopmentMetadata`; it never bypasses
    /// remote metadata/JWKS revalidation for a confidential family.
    /// Rotates a localhost public-client refresh token only for an active
    /// account subject. The bool-bearing overload is internal test support.
    public func redeemLocalhostPublicRefresh(
        _ refreshToken: String,
        clientID: URL,
        dpopProof: OAuthValidatedDPoPProof,
        requestedScopes: Set<String>? = nil,
        accessLifetime: TimeInterval = 300,
        now: Date = Date()
    ) async throws -> OAuthTokenPair {
        try await redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: clientID,
            dpopProof: dpopProof,
            requestedScopes: requestedScopes,
            accessLifetime: accessLifetime,
            requireActiveSubject: true,
            now: now
        )
    }

    func redeemLocalhostPublicRefresh(
        _ refreshToken: String,
        clientID: URL,
        dpopProof: OAuthValidatedDPoPProof,
        requestedScopes: Set<String>? = nil,
        accessLifetime: TimeInterval = 300,
        requireActiveSubject: Bool,
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
            // The baseline is the REQUESTED set, never `binding.scopes` (§9-D20).
            // `binding.scopes` holds the post-`self`-resolution grant (§9-D8),
            // which the client has never seen; `authority=self` is the grammar's
            // default, so comparing against it would fail refresh for
            // essentially every grant Swan issues. The comparison itself stays
            // raw-string equality — only the operand changes, and there is no
            // canonical fallback in this rollout.
            //
            // `requestedScopes` on the binding is `scopesRequested ?? scopes`,
            // total by §6.7's NULL rule: a pre-migration family compares against
            // its own unchanged `scopes`, exactly as it does today.
            guard family.binding.clientID == metadata.clientID.absoluteString,
                  family.binding.confidentialClientKey == nil,
                  requestedScopes.map({ $0 == family.binding.requestedScopes }) ?? true else {
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
        // The localhost bridge rotates through the same durable transaction and
        // therefore re-derives on the same terms. Exempting it would leave one
        // refresh path minting a frozen grant, which is the defect, not a
        // simplification.
        let rederived = try await rederivedGrant(for: family)
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
                rewrittenGrant: rederived,
                requireActiveSubject: requireActiveSubject,
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

    /// Revokes an opaque token only after its durable client, DPoP, and (for
    /// confidential clients) freshly revalidated key binding have all been
    /// checked. An absent or differently-bound token returns `false` so the
    /// HTTP adapter can remain an oracle-free RFC 7009 response.
    public func revokeTokenForClient(
        _ token: String,
        kind: OAuthOpaqueTokenKind,
        client: OAuthResolvedClientMetadata,
        authorizationServerIssuer: String,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion?,
        metadataLoader: OAuthClientMetadataLoader,
        now: Date = Date()
    ) async throws -> Bool {
        let purpose: DigestPurpose = kind == .accessToken ? .accessToken : .refreshToken
        let family: OAuthTokenFamily?
        do {
            family = try await controlStore.tokenFamily(
                tokenDigest: digest(token, purpose: purpose),
                kind: kind,
                now: now
            )
        } catch {
            throw secureControlError(error)
        }
        guard let family else { return false }
        do {
            try validateCurrentClient(
                client,
                assertion: clientAssertion,
                against: family.binding,
                authorizationServerIssuer: authorizationServerIssuer,
                now: now
            )
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
            try await controlStore.revokeTokenFamily(familyID: family.familyID, now: now)
            return true
        } catch let error as OAuthControlStoreError {
            // A wrong sender constraint must neither reveal a family nor
            // revoke a token it did not bind.
            switch error {
            case .bindingMismatch, .notFound, .expired, .alreadyConsumed, .replayDetected:
                return false
            case .invalidInput, .malformedRecord:
                throw secureControlError(error)
            }
        } catch {
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

    private func tokenDigests(for grant: OAuthTokenGrantMaterial) -> OAuthIssuedTokenDigests {
        OAuthIssuedTokenDigests(
            familyID: grant.familyID,
            accessTokenDigest: digest(grant.accessToken, purpose: .accessToken),
            refreshTokenDigest: grant.refreshToken.map { digest($0, purpose: .refreshToken) },
            accessExpiresAt: grant.accessExpiresAt,
            refreshExpiresAt: grant.refreshExpiresAt
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

    private func makeTokenGrant(
        familyID: UUID,
        accessLifetime: TimeInterval,
        refreshLifetime: TimeInterval?,
        now: Date
    ) throws -> OAuthTokenGrantMaterial {
        guard accessLifetime > 0, accessLifetime.isFinite else {
            throw SwanError.malformed("OAuth access-token lifetime must be positive")
        }
        if let refreshLifetime {
            guard refreshLifetime > 0, refreshLifetime.isFinite else {
                throw SwanError.malformed("OAuth refresh-token lifetime must be positive")
            }
        }
        return OAuthTokenGrantMaterial(
            accessToken: Self.randomOpaqueValue(),
            refreshToken: refreshLifetime == nil ? nil : Self.randomOpaqueValue(),
            accessExpiresAt: now.addingTimeInterval(accessLifetime),
            refreshExpiresAt: refreshLifetime.map { now.addingTimeInterval($0) },
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

    /// Validates the complete durable tuple before an authorization-server
    /// token operation. Redirects, granted scopes, DPoP, and confidential key
    /// material are durable authorization facts and cannot be replaced by a
    /// current browser or form value.
    private func validateCurrentClient(
        _ client: OAuthResolvedClientMetadata,
        assertion: OAuthValidatedClientAssertion?,
        against binding: OAuthClientBinding,
        authorizationServerIssuer: String,
        now: Date
    ) throws {
        guard binding.issuer == authorizationServerIssuer,
              binding.clientID == client.metadata.clientID.absoluteString,
              let redirectURI = URL(string: binding.redirectURI),
              redirectURI.absoluteString == binding.redirectURI,
              client.metadata.matchesRedirectURI(redirectURI),
              !binding.scopes.isEmpty,
              // Stage C compares REQUESTED against REGISTERED — both supplied by
              // the client in the same generation (§9-D7). It must not compare
              // `binding.scopes`, which under §9-D8 holds the post-`self`
              // resolution grant: the resolved DID was never in the client's
              // registered set, so this guard would reject every `self`-bearing
              // family at the token endpoint. That is the same operand defect
              // §9-D20 fixes at `:770`, at a second site the stage table lists
              // under stage C.
              //
              // Both sides are canonicalised so a client that spells the same
              // grant differently in its metadata and its request is not
              // rejected by the canonical form itself.
              OAuthScopeAdmissionPolicy.isCanonicalSubset(
                  binding.requestedScopes,
                  of: client.metadata.scopes
              ) else {
            throw OAuthControlStoreError.bindingMismatch
        }
        switch client.metadata.tokenEndpointAuthMethod {
        case .none:
            guard binding.confidentialClientKey == nil, assertion == nil else {
                throw OAuthControlStoreError.bindingMismatch
            }
        case .privateKeyJWT:
            guard let assertion,
                  assertion.clientID == binding.clientID,
                  assertion.algorithm == "ES256",
                  assertion.expiresAt > now,
                  let persisted = binding.confidentialClientKey,
                  persisted.keyID == assertion.selectedKeyID,
                  persisted.algorithm == assertion.algorithm,
                  constantTimeTextEqual(persisted.keyThumbprint, assertion.keyThumbprint),
                  let keys = client.keySet else {
                throw OAuthControlStoreError.bindingMismatch
            }
            let selected = try keys.select(keyID: assertion.selectedKeyID)
            guard selected.algorithm == nil || selected.algorithm == "ES256",
                  constantTimeTextEqual(selected.thumbprint(), assertion.keyThumbprint) else {
                throw OAuthControlStoreError.bindingMismatch
            }
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
        guard Self.hasATProtocolResourceScope(binding.scopes) else {
            throw SwanError.unauthorized("an AT Protocol resource scope is required for OAuth")
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

    /// One of the three copies of this predicate that must not drift apart
    /// again (§6.1); all three now route through the same facade.
    ///
    /// `subject: nil` is correct here (§6.5.2): this layer may run before `self`
    /// is resolvable, and a `self` grant must not be counted as satisfying the
    /// floor before it is. No provenance is passed because this site reads only
    /// `hasResourceScope` and never reaches a fence.
    private static func hasATProtocolResourceScope(_ scopes: Set<String>) -> Bool {
        SwanScopePermissions(rawScopes: scopes, subject: nil).hasResourceScope
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

/// Reserves a verified proposal-0016 delegation exactly once through its
/// expiry. The SQLite store receives only an authority-scoped HMAC digest, not
/// the bearer JWT, its `jti`, or its identity claims. This must be invoked
/// after signature validation but before any authority policy or credential
/// signing work.
public actor DurableSpaceDelegationReplayStore {
    private let controlStore: any SpaceDelegationReplayStore
    private let macKey: SymmetricKey

    public init(
        controlStore: any SpaceDelegationReplayStore,
        serverKey: Data
    ) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        self.controlStore = controlStore
        macKey = SymmetricKey(data: serverKey)
    }

    /// Returns `true` only for the first valid use of this exact delegation.
    /// Every input field is length-delimited before HMAC so separate issuer,
    /// audience, space, and opaque-JTI values cannot collide by concatenation.
    public func claim(
        issuer: String,
        audience: String,
        space: SpaceURI,
        jti: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        guard Self.validOpaqueJTI(jti),
              expiresAt > now else {
            throw SwanError.expired
        }
        var input = Data("swan.space.delegation-replay-v1\u{0}".utf8)
        for field in [issuer, audience, space.rawValue, jti] {
            let bytes = Data(field.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(bytes)
        }
        let digest = Data(HMAC<SHA256>.authenticationCode(for: input, using: macKey))
        do {
            return try await controlStore.claimSpaceDelegation(
                digest: digest,
                expiresAt: expiresAt,
                now: now
            )
        } catch let error as OAuthControlStoreError {
            if error == .expired { throw SwanError.expired }
            throw SwanError.unauthorized("delegation token rejected")
        } catch {
            throw SwanError.unavailable("delegation replay store unavailable")
        }
    }

    private static func validOpaqueJTI(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty
            && bytes.count <= PermissionedDataJWT.maximumOpaqueJTIBytes
            && bytes.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
    }
}
