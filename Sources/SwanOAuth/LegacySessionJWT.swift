import Crypto
import Foundation
import SwanCore

/// The `scope` claim of a legacy session token.
///
/// Upstream uses this claim as a CREDENTIAL-TYPE discriminator, not as a
/// permission set (`packages/pds/src/auth-scope.ts:2-9`). Swan keeps that
/// meaning rather than the app-password design's D1 reading — which was written
/// against tranquil, where the claim carries permission scopes — because the
/// permission scope is not in the token at all here. It is re-derived from the
/// app-password row on every use, so a revoked or narrowed credential takes
/// effect at once instead of at the end of a 120-minute access-token life.
public enum LegacyAuthScope: String, Sendable, Equatable, CaseIterable {
    case access = "com.atproto.access"
    case refresh = "com.atproto.refresh"
    case appPassword = "com.atproto.appPass"
    case appPasswordPrivileged = "com.atproto.appPassPrivileged"
}

/// Mints and verifies the `at+jwt` / `refresh+jwt` pair the official Bluesky
/// client expects from `createSession`.
///
/// ## Why a JWT at all, when Swan's OAuth tokens are opaque
///
/// The signature is not what authorizes the request — the durable row is, and
/// every call still resolves one. The JWT exists for the CLIENT: `@atproto/api`
/// decodes the access token to read `exp` and schedule its refresh, so an opaque
/// string would leave the official app unable to tell a live session from a dead
/// one until a request failed.
///
/// HS256 with a symmetric key, matching upstream
/// (`account-manager/helpers/auth.ts:48-58`, "only symmetric keys supported").
/// Nothing outside Swan verifies these, so there is no asymmetric-key
/// requirement to satisfy — and a symmetric key keeps the whole surface inside
/// the one owner-only mounted file.
public enum LegacySessionJWT {
    /// Upstream's `120mins` / `90days` (`auth.ts:46`, `:73`).
    public static let accessLifetime: TimeInterval = 120 * 60
    public static let refreshLifetime: TimeInterval = 90 * 24 * 60 * 60

    public enum Kind: String, Sendable, Equatable {
        case access = "at+jwt"
        case refresh = "refresh+jwt"
    }

    public struct Claims: Sendable, Equatable {
        public let subject: String
        public let audience: String
        public let tokenID: String
        public let scope: LegacyAuthScope
        public let issuedAt: Date
        public let expiresAt: Date
    }

    private struct Header: Encodable {
        let alg = "HS256"
        let typ: String
    }

    private struct Body: Encodable {
        let sub: String
        let aud: String
        let jti: String
        let scope: String
        let iat: Int64
        let exp: Int64
    }

    private struct DecodedBody: Decodable {
        let sub: String
        let aud: String
        let jti: String
        let scope: String
        let iat: Int64
        let exp: Int64
    }

    private struct DecodedHeader: Decodable {
        let alg: String
        let typ: String
    }

    public static func create(
        kind: Kind,
        subject: String,
        audience: String,
        tokenID: String,
        scope: LegacyAuthScope,
        key: SymmetricKey,
        now: Date,
        lifetime: TimeInterval
    ) throws -> String {
        guard isPrintable(subject, maximumBytes: 2_048),
              isPrintable(audience, maximumBytes: 2_048),
              isPrintable(tokenID, maximumBytes: 256),
              lifetime > 0,
              now.timeIntervalSince1970.isFinite else {
            throw SwanError.malformed("legacy session claims are invalid")
        }
        let iat = Int64(now.timeIntervalSince1970.rounded(.towardZero))
        let (exp, overflow) = iat.addingReportingOverflow(Int64(lifetime))
        guard !overflow else {
            throw SwanError.malformed("legacy session expiry is invalid")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let header = try encoder.encode(Header(typ: kind.rawValue))
        let body = try encoder.encode(
            Body(
                sub: subject,
                aud: audience,
                jti: tokenID,
                scope: scope.rawValue,
                iat: iat,
                exp: exp
            )
        )
        let signingInput = "\(base64URL(header)).\(base64URL(body))"
        let signature = HMAC<SHA256>.authenticationCode(
            for: Data(signingInput.utf8),
            using: key
        )
        return "\(signingInput).\(base64URL(Data(signature)))"
    }

    /// Verifies signature, type, algorithm and expiry, and returns the claims.
    ///
    /// **This is a syntactic check, not an authorization.** It proves the token
    /// was minted by this host and has not expired. Whether the session behind
    /// it still exists — and what it may do — comes from the durable row, which
    /// the caller must resolve separately.
    public static func verify(
        _ token: String,
        kind: Kind,
        key: SymmetricKey,
        now: Date
    ) throws -> Claims {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw SwanError.unauthorized("legacy session token is malformed")
        }
        let signingInput = "\(parts[0]).\(parts[1])"
        guard let provided = Data(base64URLEncoded: String(parts[2])) else {
            throw SwanError.unauthorized("legacy session token is malformed")
        }
        // Constant time, and computed over the exact bytes presented rather
        // than over a re-encoding of the decoded claims — a re-encode would
        // accept a token whose JSON differs from what was signed.
        guard HMAC<SHA256>.isValidAuthenticationCode(
            provided,
            authenticating: Data(signingInput.utf8),
            using: key
        ) else {
            throw SwanError.unauthorized("legacy session token signature is invalid")
        }
        guard let headerData = Data(base64URLEncoded: String(parts[0])),
              let bodyData = Data(base64URLEncoded: String(parts[1])),
              let header = try? JSONDecoder().decode(DecodedHeader.self, from: headerData),
              let body = try? JSONDecoder().decode(DecodedBody.self, from: bodyData) else {
            throw SwanError.unauthorized("legacy session token is malformed")
        }
        // `typ` is the access/refresh discriminator. Accepting a refresh token
        // where an access token is required would hand a 90-day credential the
        // authority of a 120-minute one.
        guard header.alg == "HS256", header.typ == kind.rawValue else {
            throw SwanError.unauthorized("legacy session token type is invalid")
        }
        guard let scope = LegacyAuthScope(rawValue: body.scope) else {
            throw SwanError.unauthorized("legacy session token scope is invalid")
        }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(body.exp))
        guard expiresAt > now else {
            throw SwanError.unauthorized("legacy session token has expired")
        }
        return Claims(
            subject: body.sub,
            audience: body.aud,
            tokenID: body.jti,
            scope: scope,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(body.iat)),
            expiresAt: expiresAt
        )
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func isPrintable(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximumBytes
            && value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }
}
