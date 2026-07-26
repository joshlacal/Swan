import Crypto
import Foundation
import SwanCore

public struct OAuthDPoPRequest: Sendable {
    public let method: String
    public let target: URL
    public let serverNonce: String
    public let accessToken: String?
    public let requiresAccessTokenHash: Bool

    public init(
        method: String,
        target: URL,
        serverNonce: String,
        accessToken: String? = nil,
        requiresAccessTokenHash: Bool = false
    ) throws {
        guard !method.isEmpty, method.utf8.count <= 32,
              method.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }),
              !serverNonce.isEmpty, serverNonce.utf8.count <= 4_096,
              !serverNonce.utf8.contains(0),
              !requiresAccessTokenHash || accessToken != nil else {
            throw SwanError.malformed("DPoP request binding is invalid")
        }
        self.method = method
        self.target = target
        self.serverNonce = serverNonce
        self.accessToken = accessToken
        self.requiresAccessTokenHash = requiresAccessTokenHash
    }
}

public struct OAuthValidatedDPoPProof: Sendable, Equatable {
    public let keyThumbprint: String
    public let jwtID: String
    public let issuedAt: Date
}

/// Verifies a DPoP proof and reserves its `jti` through Swan's durable OAuth
/// control service. Receiving a parsed JWT or a caller-supplied thumbprint is
/// deliberately insufficient: this type only emits a JKT after ES256
/// signature, embedded-JWK, target, nonce, access-token hash, and replay checks
/// all pass.
public struct OAuthDPoPProofValidator: Sendable {
    public static let proofType = "dpop+jwt"

    private let tokenService: DurableOAuthTokenService
    private let nonceService: DPoPNonceService
    private let proofLifetime: TimeInterval
    private let clockSkew: TimeInterval

    public init(
        runtime: SwanOAuthRuntime,
        proofLifetime: TimeInterval = 300,
        clockSkew: TimeInterval = 60
    ) throws {
        guard proofLifetime > 0, proofLifetime <= 600, proofLifetime.isFinite,
              clockSkew >= 0, clockSkew <= 120, clockSkew.isFinite else {
            throw SwanError.malformed("DPoP validation lifetime is invalid")
        }
        tokenService = runtime.tokenService
        nonceService = runtime.dpopNonceService
        self.proofLifetime = proofLifetime
        self.clockSkew = clockSkew
    }

    public func validate(
        _ proof: String,
        request: OAuthDPoPRequest,
        now: Date = Date()
    ) async throws -> OAuthValidatedDPoPProof {
        let header = try OAuthCompactJWT.unverifiedHeader(proof)
        guard let jwk = header.jwk else { throw SwanError.malformed("DPoP proof lacks public JWK") }
        let publicKey = try jwk.publicKey()
        let verified = try OAuthCompactJWT.verify(
            proof,
            publicKey: publicKey,
            expectedType: Self.proofType,
            constraints: .init(
                now: now,
                clockSkew: clockSkew,
                requireIssuedAt: true,
                maximumAge: proofLifetime
            )
        )
        let claims = try OAuthCompactJWT.decodeClaims(DPoPClaims.self, from: verified)
        guard validJTI(claims.jwtID),
              nonceService.isValid(request.serverNonce, now: now),
              claims.method == request.method.uppercased(),
              claims.method == claims.method.uppercased(),
              constantTimeTextEqual(claims.target, try Self.normalizedTarget(request.target)),
              constantTimeTextEqual(claims.nonce, request.serverNonce) else {
            throw SwanError.unauthorized("DPoP proof binding is invalid")
        }
        if request.requiresAccessTokenHash {
            guard let accessToken = request.accessToken, let accessTokenHash = claims.accessTokenHash,
                  constantTimeTextEqual(
                      accessTokenHash,
                      Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncodedString()
                  ) else {
                throw SwanError.unauthorized("DPoP proof access token hash is invalid")
            }
        } else if let accessTokenHash = claims.accessTokenHash, let accessToken = request.accessToken {
            guard constantTimeTextEqual(
                accessTokenHash,
                Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncodedString()
            ) else {
                throw SwanError.unauthorized("DPoP proof access token hash is invalid")
            }
        }
        guard let issuedAt = verified.registeredClaims.issuedAt else {
            throw SwanError.malformed("DPoP proof lacks iat")
        }
        let replayExpiresAt = Date(timeIntervalSince1970: TimeInterval(issuedAt) + proofLifetime)
        guard replayExpiresAt > now,
              try await tokenService.claimDPoP(jti: claims.jwtID, expiresAt: replayExpiresAt, now: now) else {
            throw SwanError.unauthorized("DPoP proof was replayed")
        }
        return OAuthValidatedDPoPProof(
            keyThumbprint: jwk.thumbprint(),
            jwtID: claims.jwtID,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(issuedAt))
        )
    }

    /// RFC 9449's `htu`: URI scheme/host/path, with query and fragment omitted,
    /// lowercased scheme/host, and an omitted default port. The JWT's string is
    /// compared exactly to this canonical target rather than normalized after
    /// parsing, so alternate spellings cannot bind the same request.
    public static func normalizedTarget(_ url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let host = components.host?.lowercased(),
              components.user == nil, components.password == nil else {
            throw SwanError.malformed("DPoP request target is invalid")
        }
        let hostText = host.contains(":") ? "[\(host)]" : host
        let defaultPort = (scheme == "https" ? 443 : 80)
        let port = components.port.flatMap { $0 == defaultPort ? nil : $0 }.map { ":\($0)" } ?? ""
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        return "\(scheme)://\(hostText)\(port)\(path)"
    }

    private struct DPoPClaims: Decodable, Sendable {
        let jwtID: String
        let issuedAt: Int64
        let method: String
        let target: String
        let nonce: String
        let accessTokenHash: String?

        private enum CodingKeys: String, CodingKey {
            case jwtID = "jti"
            case issuedAt = "iat"
            case method = "htm"
            case target = "htu"
            case nonce
            case accessTokenHash = "ath"
        }
    }

    private func validJTI(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && !value.utf8.contains(0)
    }
}

public struct OAuthValidatedClientAssertion: Sendable, Equatable {
    public let clientID: String
    public let selectedKeyID: String
    public let algorithm: String
    public let keyThumbprint: String
    public let jwtID: String
    public let expiresAt: Date
}

/// Verifies AT Protocol confidential-client `private_key_jwt` authentication
/// against the JWKS already bound to validated client metadata. It returns the
/// selected key identity and JKT for the existing durable token-family binding.
public struct OAuthClientAssertionValidator: Sendable {
    public static let assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    private let tokenService: DurableOAuthTokenService
    private let maximumLifetime: TimeInterval
    private let clockSkew: TimeInterval

    public init(
        runtime: SwanOAuthRuntime,
        maximumLifetime: TimeInterval = 300,
        clockSkew: TimeInterval = 60
    ) throws {
        guard maximumLifetime > 0, maximumLifetime <= 600, maximumLifetime.isFinite,
              clockSkew >= 0, clockSkew <= 120, clockSkew.isFinite else {
            throw SwanError.malformed("client assertion validation lifetime is invalid")
        }
        tokenService = runtime.tokenService
        self.maximumLifetime = maximumLifetime
        self.clockSkew = clockSkew
    }

    public func validate(
        _ assertion: String,
        assertionType: String,
        client: OAuthResolvedClientMetadata,
        authorizationServerIssuer: String,
        now: Date = Date()
    ) async throws -> OAuthValidatedClientAssertion {
        guard assertionType == Self.assertionType,
              client.metadata.tokenEndpointAuthMethod == .privateKeyJWT,
              let keySet = client.keySet else {
            throw SwanError.unauthorized("client assertion authentication is invalid")
        }
        let header = try OAuthCompactJWT.unverifiedHeader(assertion)
        guard header.jwk == nil, let keyID = header.keyID else {
            throw SwanError.unauthorized("client assertion must identify one metadata key")
        }
        let key = try keySet.select(keyID: keyID)
        let clientID = client.metadata.clientID.absoluteString
        let verified = try OAuthCompactJWT.verify(
            assertion,
            publicKey: try key.publicKey(),
            constraints: .init(
                expectedIssuer: clientID,
                expectedAudience: authorizationServerIssuer,
                now: now,
                clockSkew: clockSkew,
                requireIssuedAt: true,
                requireExpiration: true,
                maxLifetime: maximumLifetime,
                maximumAge: maximumLifetime
            )
        )
        guard verified.registeredClaims.subject == clientID,
              let jwtID = verified.registeredClaims.jwtID, validJTI(jwtID),
              let expiry = verified.registeredClaims.expiresAt else {
            throw SwanError.unauthorized("client assertion claims are invalid")
        }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(expiry))
        guard try await tokenService.claimClientAssertion(
            jti: jwtID,
            clientID: clientID,
            expiresAt: expiresAt,
            now: now
        ) else {
            throw SwanError.unauthorized("client assertion was replayed")
        }
        return OAuthValidatedClientAssertion(
            clientID: clientID,
            selectedKeyID: keyID,
            algorithm: header.algorithm,
            keyThumbprint: key.thumbprint(),
            jwtID: jwtID,
            expiresAt: expiresAt
        )
    }

    private func validJTI(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && !value.utf8.contains(0)
    }
}

private func constantTimeTextEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Data(lhs.utf8)
    let right = Data(rhs.utf8)
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (leftByte, rightByte) in zip(left, right) { difference |= leftByte ^ rightByte }
    return difference == 0
}
