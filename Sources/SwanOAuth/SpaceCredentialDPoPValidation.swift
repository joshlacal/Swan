import Crypto
import Foundation
import SwanCore

/// Proposal 0016 uses DPoP without server-provided nonces. This separate
/// validator preserves the nonce requirement on ordinary OAuth endpoints.
public struct SpaceCredentialDPoPValidator: Sendable {
    private let tokenService: DurableOAuthTokenService
    private let proofLifetime: TimeInterval
    private let clockSkew: TimeInterval

    public init(
        runtime: SwanOAuthRuntime,
        proofLifetime: TimeInterval = 300,
        clockSkew: TimeInterval = 60
    ) throws {
        guard proofLifetime.isFinite, proofLifetime > 0, proofLifetime <= 600,
              clockSkew.isFinite, clockSkew >= 0, clockSkew <= 120 else {
            throw SwanError.malformed("space credential DPoP lifetime is invalid")
        }
        tokenService = runtime.tokenService
        self.proofLifetime = proofLifetime
        self.clockSkew = clockSkew
    }

    /// An absent credential denotes the initial delegation exchange: `ath`
    /// must be absent because a delegation is an authorization grant. Reading
    /// with a credential requires both its hash and its confirmation key.
    public func validate(
        _ proof: String,
        method: String,
        target: URL,
        credential: String? = nil,
        expectedKeyThumbprint: String? = nil,
        now: Date = Date()
    ) async throws -> OAuthValidatedDPoPProof {
        guard !method.isEmpty, method.utf8.count <= 32,
              method.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              (credential == nil) == (expectedKeyThumbprint == nil) else {
            throw SwanError.malformed("space credential DPoP request is invalid")
        }
        let header = try OAuthCompactJWT.unverifiedHeader(proof)
        guard let jwk = header.jwk else {
            throw SwanError.unauthorized("space credential DPoP key is invalid")
        }
        let verified = try OAuthCompactJWT.verify(
            proof,
            publicKey: try jwk.publicKey(),
            expectedType: OAuthDPoPProofValidator.proofType,
            signatureEncoding: .joseInteroperable,
            constraints: .init(
                now: now,
                clockSkew: clockSkew,
                requireIssuedAt: true,
                maximumAge: proofLifetime
            )
        )
        let claims = try OAuthCompactJWT.decodeClaims(Claims.self, from: verified)
        guard !claims.jwtID.isEmpty, claims.jwtID.utf8.count <= 4_096,
              !claims.jwtID.utf8.contains(0),
              claims.method == method.uppercased(),
              spaceCredentialConstantTimeTextEqual(claims.target, try OAuthDPoPProofValidator.normalizedTarget(target)),
              let issuedAt = verified.registeredClaims.issuedAt else {
            throw SwanError.unauthorized("space credential DPoP binding is invalid")
        }
        let thumbprint = jwk.thumbprint()
        if let credential, let expectedKeyThumbprint {
            guard Self.isValidKeyThumbprint(expectedKeyThumbprint),
                  spaceCredentialConstantTimeTextEqual(thumbprint, expectedKeyThumbprint),
                  let tokenHash = claims.accessTokenHash,
                  spaceCredentialConstantTimeTextEqual(
                      tokenHash,
                      Data(SHA256.hash(data: Data(credential.utf8))).base64URLEncodedString()
                  ) else {
                throw SwanError.unauthorized("space credential DPoP credential binding is invalid")
            }
        } else if claims.hasAccessTokenHash {
            throw SwanError.unauthorized("space credential exchange DPoP must omit token hash")
        }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(issuedAt) + proofLifetime + clockSkew)
        // Namespace by key so one key cannot reserve another application's
        // client-generated JTI. Retain the claim for the full accepted skew.
        let replayID = Data(SHA256.hash(data: Data("space-dpop\u{0}\(thumbprint)\u{0}\(claims.jwtID)".utf8)))
            .base64URLEncodedString()
        guard expiresAt > now,
              try await tokenService.claimDPoP(jti: replayID, expiresAt: expiresAt, now: now) else {
            throw SwanError.unauthorized("space credential DPoP proof was replayed")
        }
        return OAuthValidatedDPoPProof(
            keyThumbprint: thumbprint,
            jwtID: claims.jwtID,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(issuedAt))
        )
    }

    public static func isValidKeyThumbprint(_ value: String) -> Bool {
        guard value.utf8.count == 43,
              let bytes = Data(base64URLEncoded: value), bytes.count == 32 else { return false }
        return bytes.base64URLEncodedString() == value
    }

    private struct Claims: Decodable {
        let jwtID: String
        let method: String
        let target: String
        let accessTokenHash: String?
        let hasAccessTokenHash: Bool

        enum CodingKeys: String, CodingKey {
            case jwtID = "jti", method = "htm", target = "htu", accessTokenHash = "ath"
        }

        init(from decoder: any Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            jwtID = try values.decode(String.self, forKey: .jwtID)
            method = try values.decode(String.self, forKey: .method)
            target = try values.decode(String.self, forKey: .target)
            accessTokenHash = try values.decodeIfPresent(String.self, forKey: .accessTokenHash)
            hasAccessTokenHash = values.contains(.accessTokenHash)
        }
    }
}

func spaceCredentialConstantTimeTextEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Data(lhs.utf8)
    let right = Data(rhs.utf8)
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (leftByte, rightByte) in zip(left, right) { difference |= leftByte ^ rightByte }
    return difference == 0
}
