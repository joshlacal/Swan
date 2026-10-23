import Foundation
import Hummingbird
import HTTPTypes
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The only failures a future resource HTTP adapter needs to render. They do
/// not carry a token, DPoP proof, JTI, account identifier, or storage detail.
///
/// Missing, malformed, or expired nonces receive a fresh nonce challenge.
/// Other proof, token-binding, and account-lifecycle failures remain opaque
/// denials. Challenging a stale nonce does not authorize the request: the
/// retry must still pass every proof, token, and account check.
public enum SwanResourceAuthorizationFailure: Error, Sendable, Equatable {
    case nonceChallengeRequired
    case denied
    case unavailable
}

/// Validates sender-constrained OAuth access for a *preselected* resource
/// route. This is deliberately not Hummingbird middleware: callers must pass
/// the route's fixed method and path, which prevents a hostile `Host` header
/// or request target from becoming the DPoP `htu` binding.
///
/// The authorizer knows only the durable control plane. In particular it has
/// no account-repository store and never opens an account database.
public struct SwanOAuthResourceAuthorizer: Sendable {
    /// The maximum accepted opaque access-token representation. The service
    /// does not parse the token, but it bounds it before hashing and querying
    /// durable control state.
    public static let maximumAccessTokenBytes = 8 * 1024
    /// Matches the compact-JWT bound enforced by `OAuthCompactJWT` while
    /// rejecting an oversized header before any proof parsing or persistence.
    public static let maximumDPoPProofBytes = 32 * 1024

    private let publicURL: URL
    private let runtime: SwanOAuthRuntime
    private let accountControlStore: any AccountControlStore
    /// Legacy (app-password) sessions, when the deployment enables them.
    ///
    /// `nil` leaves this authorizer DPoP-only, which is what every deployment
    /// without `--enable-legacy-sessions` gets: a `Bearer` credential then falls
    /// through to the DPoP parser and is refused exactly as it is today.
    private let legacySessions: DurableLegacySessionService?
    /// `--enable-spaces-open-interop` (decision B(d)); consulted only by
    /// ``authorizeSpaceRoute(request:method:fixedPath:legacyAdmission:now:)``.
    private let spacesOpenInterop: Bool

    /// `publicURL` is the process's configured canonical public identity, not
    /// a request-derived origin. It must be a scheme/host root URL so each
    /// caller-provided fixed path has one unambiguous DPoP target.
    public init(
        publicURL: URL,
        runtime: SwanOAuthRuntime,
        accountControlStore: any AccountControlStore,
        legacySessions: DurableLegacySessionService? = nil,
        spacesOpenInterop: Bool = false
    ) throws {
        guard Self.validPublicURL(publicURL) else {
            throw SwanError.malformed("resource authorization public URL is invalid")
        }
        self.publicURL = publicURL
        self.runtime = runtime
        self.accountControlStore = accountControlStore
        self.legacySessions = legacySessions
        self.spacesOpenInterop = spacesOpenInterop
    }

    /// Issues a challenge nonce from the exact OAuth runtime used by
    /// ``authorize(request:method:fixedPath:now:)``. Keeping issuance behind
    /// this boundary means an HTTP resource adapter cannot accidentally send
    /// a nonce that its DPoP validator will reject.
    public func issueNonce(now: Date = Date()) -> String {
        runtime.dpopNonceService.issue(now: now)
    }

    /// Reads the `atproto-space` presentation fields as complete field-line
    /// lists. The request URI, Host, and method are deliberately not inputs:
    /// a space signature binds only the credential and its audience.
    static func spaceCredentialPresentation(
        from headers: HTTPFields
    ) -> SpaceCredentialHTTPPresentation {
        SpaceCredentialHTTPPresentation(
            authorization: headers[values: .authorization],
            audience: headers[values: spaceAudienceField],
            signatureInput: headers[values: signatureInputField],
            signature: headers[values: signatureField]
        )
    }

    static let spaceAudienceField = HTTPField.Name(SpaceHTTPSignature.audienceFieldName)!
    static let signatureInputField = HTTPField.Name(SpaceHTTPSignature.signatureInputFieldName)!
    static let signatureField = HTTPField.Name(SpaceHTTPSignature.signatureFieldName)!

    /// Verifies the delegation exchange's `atproto-space` signature, which
    /// covers exactly `("authorization")` and must name the client's fresh
    /// P-256 `did:key` as `keyid`. Returns that key ID for `cnf.kid`.
    func verifySpaceDelegationSignature(request: Request) throws -> String {
        do {
            return try SpaceHTTPSignature.verify(
                authorization: request.headers[values: .authorization],
                audience: nil,
                signatureInput: request.headers[values: Self.signatureInputField],
                signature: request.headers[values: Self.signatureField],
                credentialKeyID: nil
            )
        } catch {
            throw SpaceCredentialPresentationFailure.badSignature
        }
    }

    /// Verifies an `Atproto-Space` credential presentation for one operation.
    /// `expectedAudience` is derived by the route from the operation, never
    /// from the request's Host or this server's identity: the repo owner's
    /// DID for repo reads, the space authority's bare DID for space-host
    /// operations. A credential whose `(space, jti)` the authority revoked is
    /// refused while the revocation is retained; an unreadable revocation
    /// list fails closed as unavailable. Throws
    /// ``SpaceCredentialPresentationFailure`` for the protocol's named errors
    /// and the verifier's opaque errors otherwise.
    func authorizeSpaceCredential(
        _ token: String,
        verifier: any SpaceCredentialAuthorizationVerifier,
        request: Request,
        expectedSpace: SpaceURI,
        expectedAudience: String,
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        let presentation = try await verifier.verifiedPresentation(
            token,
            expectedSpace: expectedSpace,
            presentation: Self.spaceCredentialPresentation(from: request.headers),
            now: now
        )
        // The reference checks revocation before the handler's audience
        // check; keep that order so a revoked credential always reports
        // CredentialRevoked.
        guard try await !runtime.spaceCredentialRevocations.isRevoked(
            space: presentation.space,
            credentialID: presentation.credentialID,
            now: now
        ) else {
            throw SpaceCredentialPresentationFailure.revoked
        }
        guard presentation.audience == expectedAudience else {
            throw SpaceCredentialPresentationFailure.badAudience
        }
        return presentation.authorization
    }

    /// Records an authority's `notifyCredentialRevoked` for this repo host.
    func recordSpaceCredentialRevocations(
        space: SpaceURI,
        credentialIDs: [String],
        now: Date = Date()
    ) async throws {
        try await runtime.spaceCredentialRevocations.record(
            space: space,
            credentialIDs: credentialIDs,
            now: now
        )
    }

    /// Whether `did` names an account this host stores, in any lifecycle
    /// state (the reference includes deactivated and taken-down accounts):
    /// the audience test for `notifyCredentialRevoked`. Store failures are
    /// `SwanError.unavailable`.
    func hostsAccount(did: String) async throws -> Bool {
        do {
            return try await accountControlStore.account(did: did) != nil
        } catch {
            throw SwanError.unavailable("account directory unavailable")
        }
    }

    /// Which legacy sessions a space route admits under open interop.
    enum SpaceRouteLegacyAdmission: Sendable {
        /// Upstream `ACCESS_STANDARD`: account-password and app-password
        /// sessions (own-repo space reads/writes, listSpaces).
        case standard
        /// Upstream `ACCESS_FULL`: account-password sessions only
        /// (getDelegationToken).
        case fullAccessOnly
    }

    /// ``authorize(request:method:fixedPath:now:)`` for an atproto-spaces
    /// route. Without `--enable-spaces-open-interop` it is exactly that.
    ///
    /// With the flag (decision B(d)), an OAuth grant is evaluated under
    /// upstream space-scope defaults, and a legacy session is admitted as
    /// upstream admits it: it becomes an account grant for
    /// `space:*?authority=*&collection=*` with default actions, so the domain
    /// policy still confines it to the subject's own repository and grants no
    /// `manage` operation. App-password sessions are refused where
    /// `legacyAdmission` is ``SpaceRouteLegacyAdmission/fullAccessOnly``.
    func authorizeSpaceRoute(
        request: Request,
        method: String,
        fixedPath: String,
        legacyAdmission: SpaceRouteLegacyAdmission = .standard,
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        let context = try await authorize(
            request: request,
            method: method,
            fixedPath: fixedPath,
            now: now
        )
        guard spacesOpenInterop else { return context }
        switch context {
        case let .accountOAuth(subject, permissions):
            return .accountOAuth(
                subject: subject,
                permissions: permissions.withUpstreamSpaceDefaults()
            )
        case let .accountLegacySession(subject, _):
            guard let legacySessions,
                  let bearer = Self.bearerToken(from: request.headers) else {
                throw SwanResourceAuthorizationFailure.denied
            }
            if legacyAdmission == .fullAccessOnly {
                do {
                    let fullAccessSubject = try await legacySessions.authorizeFullAccess(
                        accessJWT: bearer,
                        now: now
                    )
                    guard fullAccessSubject == subject else {
                        throw SwanResourceAuthorizationFailure.denied
                    }
                } catch {
                    throw SwanResourceAuthorizationFailure.denied
                }
            }
            return .accountOAuth(
                subject: subject,
                permissions: Self.upstreamLegacySpacePermissions(subject: subject)
            )
        default:
            return context
        }
    }

    /// The space grant an upstream legacy session carries under open interop.
    static func upstreamLegacySpacePermissions(subject: String) -> SwanScopePermissions {
        SwanScopePermissions(
            rawScopes: ["atproto", "space:*?authority=*&collection=*"],
            subject: subject
        ).withUpstreamSpaceDefaults()
    }

    /// Returns only a domain authorization context. A raw opaque token, a
    /// parsed subject, or a DPoP JKT is never treated as authorization on its
    /// own: all three durable/token/lifecycle checks must complete first.
    ///
    /// - Parameters:
    ///   - request: Used solely for `Authorization` and `DPoP` headers. Its
    ///     URI and Host/authority are intentionally ignored.
    ///   - method: The exact method registered by the eventual route.
    ///   - fixedPath: The exact route path registered by the eventual route.
    public func authorize(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        // Credential-aware read routes have already selected their separate
        // verifier. A space credential presented to an account-only route is
        // never an OAuth token and cannot acquire write access by satisfying
        // that route's nonce challenge.
        do {
            guard try spaceCredentialSchemeToken(from: request.headers) == nil else {
                throw SwanResourceAuthorizationFailure.denied
            }
        } catch {
            throw SwanResourceAuthorizationFailure.denied
        }
        // A legacy session presents `Bearer`, an OAuth token presents `DPoP`.
        // The two prefixes are disjoint, so this dispatch cannot mistake one for
        // the other, and it is the ONLY place a bearer credential enters the
        // resource plane — every route already funnels through here.
        //
        // The legacy path deliberately performs no DPoP work: these tokens are
        // not sender-constrained, which is the price of the feature. What it
        // does NOT do is relax anything on the OAuth path below.
        if let legacySessions, let bearer = Self.bearerToken(from: request.headers) {
            do {
                return try await legacySessions.authorize(accessJWT: bearer, now: now)
            } catch {
                throw SwanResourceAuthorizationFailure.denied
            }
        }
        let accessToken: String
        do {
            accessToken = try Self.accessToken(from: request.headers)
        } catch {
            throw SwanResourceAuthorizationFailure.denied
        }

        // Do all no-side-effect header and nonce-shape work before invoking
        // the validator. The validator's replay reservation is therefore
        // never reached for a missing/malformed header or nonce candidate.
        guard let proof = Self.dpopProof(from: request.headers),
              let presentedNonce = Self.untrustedNonce(from: proof) else {
            throw SwanResourceAuthorizationFailure.nonceChallengeRequired
        }

        let target: URL
        do {
            target = try Self.target(publicURL: publicURL, fixedPath: fixedPath)
            try Self.validateFixedMethod(method)
        } catch {
            // An invalid fixed route is a deployment/programming mistake, but
            // it still must not turn a request into a proof predicate oracle.
            throw SwanResourceAuthorizationFailure.denied
        }

        let proofBinding: OAuthValidatedDPoPProof
        do {
            let validator = try OAuthDPoPProofValidator(runtime: runtime)
            proofBinding = try await validator.validate(
                proof,
                request: OAuthDPoPRequest(
                    method: method,
                    target: target,
                    serverNonce: presentedNonce,
                    accessToken: accessToken,
                    requiresAccessTokenHash: true
                ),
                now: now
            )
        } catch {
            // Cached nonces outlive their five-minute validity, including
            // across fresh logins. A bare denial leaves the client stuck.
            if !runtime.dpopNonceService.isValid(presentedNonce, now: now) {
                throw SwanResourceAuthorizationFailure.nonceChallengeRequired
            }
            throw Self.proofFailure(for: error)
        }

        let grant: DurableOAuthTokenService.AccessGrant
        do {
            // Validate only after the DPoP proof has verified its method,
            // configured htu, nonce, ath, and replay reservation. This keeps
            // the opaque token permanently sender constrained.
            grant = try await runtime.tokenService.validateAccess(
                accessToken,
                proof: proofBinding,
                now: now
            )
        } catch {
            throw Self.durableOrDeniedFailure(for: error)
        }

        // Token families are durable input at this boundary. Accept the
        // broad `atproto` resource grant or a bounded permissioned-space
        // scope, then let SwanSpaces make the exact authority/skey/action/
        // collection decision for the selected operation. Do not let a
        // malformed or legacy stored binding reach that domain policy merely
        // because its DPoP proof and opaque token digest were otherwise valid.
        //
        // Parse ONCE, here, and hand a frozen value to the domain layer
        // (§6.5.1, §6.5.2). `hasResourceScope` is `atproto`-or-`space:` only —
        // deliberately NOT "any recognised family" (§6.1). Several routes
        // perform no further scope check at all, so widening this floor would
        // hand an `identity:`- or `blob:`-only token an unguarded route.
        //
        // `statedKeys` is DURABLE provenance (§9-D23), read from the token
        // family's stored record via `AccessGrant.scopeProvenance`. It must
        // NEVER be derived here: re-parsing `grant.scopes` would INVENT
        // provenance for a mint-resolved `self` (flipping the delegation fence
        // open) and DESTROY it for a canonical `skey=*` (silently disabling the
        // listing fence). The two failures run in opposite directions, which is
        // why no parser change can substitute for the stored bits.
        //
        // `statedScopeKeys` is non-optional and keyed by the effective scope
        // string, i.e. the members of `grant.scopes`. A family with no
        // persisted record yields `[:]`, which is the fail-closed case: absent
        // bits deny, they never grant.
        let permissions = SwanScopePermissions(
            rawScopes: grant.scopes,
            subject: grant.subject,
            statedKeys: grant.statedScopeKeys
        )
        guard permissions.hasResourceScope else {
            throw SwanResourceAuthorizationFailure.denied
        }

        do {
            guard let account = try await accountControlStore.account(did: grant.subject),
                  account.status.authorizesAccount else {
                throw SwanResourceAuthorizationFailure.denied
            }
        } catch let failure as SwanResourceAuthorizationFailure {
            throw failure
        } catch {
            throw Self.accountFailure(for: error)
        }

        return .accountOAuth(subject: grant.subject, permissions: permissions)
    }

    /// A `Bearer` credential, or `nil` when the header is absent, malformed, or
    /// carries a different scheme.
    ///
    /// Returning `nil` rather than throwing keeps a `DPoP` header falling
    /// through to the OAuth path unchanged.
    private static func bearerToken(from headers: HTTPFields) -> String? {
        let values = headers[values: .authorization]
        guard values.count == 1 else { return nil }
        let prefix = "Bearer "
        guard values[0].hasPrefix(prefix) else { return nil }
        let token = String(values[0].dropFirst(prefix.count))
        guard !token.isEmpty, token.utf8.count <= maximumAccessTokenBytes else { return nil }
        return token
    }

    private static func accessToken(from headers: HTTPFields) throws -> String {
        let values = headers[values: .authorization]
        guard values.count == 1 else { throw HeaderError.malformed }
        let value = values[0]
        let prefix = "DPoP "
        guard value.hasPrefix(prefix) else { throw HeaderError.malformed }
        let token = String(value.dropFirst(prefix.count))
        guard token.utf8.count > 0,
              token.utf8.count <= maximumAccessTokenBytes,
              validToken68(token) else {
            throw HeaderError.malformed
        }
        return token
    }

    /// RFC 9110 token68 is the one Authorization credential grammar that can
    /// represent Swan's opaque tokens without admitting whitespace, parameter
    /// delimiters, or quoted-string syntax into a supposedly single token.
    /// `=` is padding only, and therefore may appear only after all payload
    /// characters. Swan currently issues URL-safe values, while this accepts
    /// the full token68 alphabet for future compatible opaque issuers.
    private static func validToken68(_ token: String) -> Bool {
        var sawPadding = false
        var sawPayload = false
        for byte in token.utf8 {
            switch byte {
            case UInt8(ascii: "A") ... UInt8(ascii: "Z"),
                 UInt8(ascii: "a") ... UInt8(ascii: "z"),
                 UInt8(ascii: "0") ... UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
                 UInt8(ascii: "~"), UInt8(ascii: "+"), UInt8(ascii: "/"):
                guard !sawPadding else { return false }
                sawPayload = true
            case UInt8(ascii: "="):
                guard sawPayload else { return false }
                sawPadding = true
            default:
                return false
            }
        }
        return true
    }

    private static func dpopProof(from headers: HTTPFields) -> String? {
        let name = HTTPField.Name("DPoP")!
        let values = headers[values: name]
        guard values.count == 1,
              !values[0].isEmpty,
              values[0].utf8.count <= maximumDPoPProofBytes,
              values[0].utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return nil
        }
        return values[0]
    }

    /// Reads a nonce only as an untrusted candidate. The proof validator
    /// later verifies the compact JWT, duplicate-member-free claims, nonce
    /// MAC/lifetime, and exact signed nonce equality. This mirrors the PAR
    /// bridge's deliberately narrow pre-validation parse.
    private static func untrustedNonce(from proof: String) -> String? {
        struct UntrustedNonce: Decodable {
            let nonce: String
        }

        let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let payload = try? OAuthBase64URL.decode(String(parts[1]), maxBytes: 16_384),
              let claims = try? JSONDecoder().decode(UntrustedNonce.self, from: payload),
              !claims.nonce.isEmpty,
              claims.nonce.utf8.count <= 4_096,
              !claims.nonce.utf8.contains(0) else {
            return nil
        }
        return claims.nonce
    }

    private static func validPublicURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/" else {
            return false
        }
        // An OAuth resource endpoint can carry an opaque access token and
        // DPoP proof. Permit cleartext only for an explicit, non-routable
        // local development origin; all remotely reachable identities must
        // use TLS.
        return scheme == "https" || (scheme == "http" && isLiteralLoopback(host))
    }

    private static func isLiteralLoopback(_ host: String) -> Bool {
        switch host {
        case "localhost", "127.0.0.1", "::1": true
        default: false
        }
    }

    private static func target(publicURL: URL, fixedPath: String) throws -> URL {
        guard fixedPath.utf8.count > 0,
              fixedPath.utf8.count <= 4_096,
              fixedPath.hasPrefix("/"),
              !fixedPath.contains("?"), !fixedPath.contains("#"),
              fixedPath.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("resource authorization fixed path is invalid")
        }
        guard var components = URLComponents(url: publicURL, resolvingAgainstBaseURL: false) else {
            throw SwanError.malformed("resource authorization public URL is invalid")
        }
        components.percentEncodedPath = fixedPath
        components.query = nil
        components.fragment = nil
        guard let target = components.url else {
            throw SwanError.malformed("resource authorization target is invalid")
        }
        return target
    }

    private static func validateFixedMethod(_ method: String) throws {
        guard !method.isEmpty, method.utf8.count <= 32,
              method == method.uppercased(),
              method.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("resource authorization fixed method is invalid")
        }
    }

    private static func proofFailure(for error: any Error) -> SwanResourceAuthorizationFailure {
        if let swanError = error as? SwanError, case .unavailable = swanError {
            return .unavailable
        }
        // `OAuthDPoPProofValidator` maps its durable replay write failures to
        // SwanError.unavailable. Everything else is an intentionally opaque
        // proof denial, including expiry and replay.
        return .denied
    }

    private static func durableOrDeniedFailure(for error: any Error) -> SwanResourceAuthorizationFailure {
        if let swanError = error as? SwanError, case .unavailable = swanError {
            return .unavailable
        }
        return .denied
    }

    private static func accountFailure(for error: any Error) -> SwanResourceAuthorizationFailure {
        guard let controlError = error as? AccountControlStoreError else {
            // This call is exclusively durable control-plane I/O. Never leak
            // a backend/serialization error through a resource response.
            return .unavailable
        }
        switch controlError {
        case .unavailable, .malformedRecord:
            return .unavailable
        case .notFound, .duplicateDID, .duplicateHandle, .invalidInput,
                .invalidStatus, .invalidTransition:
            return .denied
        }
    }

    private enum HeaderError: Error {
        case malformed
    }
}

extension SpaceCredentialPresentationFailure {
    /// The lexicon error name each route renders with HTTP 401, matching the
    /// reference PDS (`AuthRequiredError(..., 'BadSpaceSignature' |
    /// 'BadSpaceAudience' | 'CredentialRevoked')`).
    var httpStatus: HTTPResponse.Status { self == .unsupportedAuthorization ? .badRequest : .unauthorized }

    var xrpcErrorCode: String {
        switch self {
        case .unsupportedAuthorization: "InvalidToken"
        case .badSignature: "BadSpaceSignature"
        case .badAudience: "BadSpaceAudience"
        case .revoked: "CredentialRevoked"
        }
    }
}
