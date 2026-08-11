import Crypto
import Foundation
import SwanCore

/// Inter-service auth for proxied XRPC, mirroring
/// `com.atproto.server.getServiceAuth`.
///
/// Deliberately separate from `SpaceServiceJWT`, whose method validator is
/// restricted to `com.atproto.*` to guard Swan's own space-service path.
/// Widening that validator would loosen a control on traffic Swan *verifies*;
/// this type only *mints* tokens that a remote service verifies, so a general
/// NSID space here weakens nothing on this host.
public enum ProxyServiceJWT {
    public static let maximumLifetime: TimeInterval = 60

    private struct Header: Encodable {
        let alg = "ES256"
        let typ = "JWT"
    }

    private struct Claims: Encodable {
        let iss: String
        let aud: String
        let lxm: String
        let jti: String
        let iat: Int64
        let exp: Int64
    }

    public static func create(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = maximumLifetime
    ) throws -> String {
        guard isValidDID(issuer),
              isPrintable(audience, maximumBytes: 4096),
              isValidNSID(method),
              isPrintable(eventID, maximumBytes: 256),
              lifetime > 0, lifetime <= maximumLifetime,
              lifetime.rounded(.towardZero) == lifetime,
              now.timeIntervalSince1970.isFinite
        else {
            throw SwanError.malformed("proxy service authentication claims are invalid")
        }
        let iat = Int64(now.timeIntervalSince1970.rounded(.towardZero))
        let (exp, overflow) = iat.addingReportingOverflow(Int64(lifetime))
        guard !overflow else {
            throw SwanError.malformed("proxy service authentication expiry is invalid")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let header = try encoder.encode(Header())
        let claims = try encoder.encode(
            Claims(iss: issuer, aud: audience, lxm: method, jti: eventID, iat: iat, exp: exp)
        )
        let signingInput = "\(base64URL(header)).\(base64URL(claims))"
        let signature = try key.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(base64URL(signature.rawRepresentation))"
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func isPrintable(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes
            && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E }
    }

    private static func isValidDID(_ value: String) -> Bool {
        value.hasPrefix("did:") && isPrintable(value, maximumBytes: 2048)
            && !value.contains("#")
    }

    /// Dotted segments of alphanumerics/hyphen, at least three segments.
    private static func isValidNSID(_ value: String) -> Bool {
        guard value.utf8.count <= 317 else { return false }
        let segments = value.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else { return false }
        return segments.allSatisfy { segment in
            !segment.isEmpty
                && segment.utf8.allSatisfy {
                    ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                        || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                        || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                        || $0 == UInt8(ascii: "-")
                }
        }
    }
}
