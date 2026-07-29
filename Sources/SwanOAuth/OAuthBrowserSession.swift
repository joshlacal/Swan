import Crypto
import Foundation
import SwanCore

/// Signed, short-lived state carried only in Swan's secure authorization
/// cookie. It deliberately contains an opaque PAR URI and an account DID, not
/// a password, token, DPoP proof, client assertion, or persistent session ID.
public struct OAuthBrowserApprovalSession: Sendable, Equatable {
    public let requestURI: String
    public let subject: String?
    /// Exact `accounts.updated_at` revision, expressed as microseconds since
    /// the Unix epoch. It is present exactly when `subject` is present.
    public let subjectRevisionMicroseconds: Int64?
    public let csrfToken: String
    public let issuedAt: Date
    public let expiresAt: Date
}

/// Stateless browser transaction signer for the OAuth authorization surface.
/// Durable PAR state remains in `control.sqlite`; this cookie merely binds a
/// browser's login and consent forms to the opaque PAR capability and, after
/// successful password verification, to the selected active account.
public struct OAuthBrowserSessionService: Sendable {
    private static let signingDomain = Data("swan.oauth.browser-session.v2\0".utf8)
    private static let maximumLifetime: TimeInterval = 10 * 60
    private static let requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

    private struct Payload: Codable {
        let format: String
        let requestURI: String
        let subject: String?
        let subjectRevisionMicroseconds: Int64?
        let csrfToken: String
        let issuedAt: Int64
        let expiresAt: Int64
    }

    private let key: SymmetricKey

    public init(serverKey: Data) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("OAuth server key must be exactly 32 bytes")
        }
        key = SymmetricKey(data: serverKey)
    }

    /// Returns a compact `payload.signature` value appropriate for a
    /// `Secure; HttpOnly; SameSite=Lax` cookie.
    public func issue(
        requestURI: String,
        subject: String? = nil,
        subjectUpdatedAt: Date? = nil,
        lifetime: TimeInterval = 10 * 60,
        now: Date = Date()
    ) throws -> (value: String, session: OAuthBrowserApprovalSession) {
        let subjectRevision = Self.subjectRevisionMicroseconds(for: subjectUpdatedAt)
        guard lifetime > 0, lifetime <= Self.maximumLifetime, lifetime.isFinite,
              validRequestURI(requestURI), validSubject(subject),
              (subject == nil) == (subjectUpdatedAt == nil),
              (subject == nil) == (subjectRevision == nil) else {
            throw SwanError.malformed("OAuth browser session is invalid")
        }
        let expiresAt = now.addingTimeInterval(lifetime)
        let csrfToken = Self.randomOpaqueValue()
        let payload = Payload(
            format: "swan-oauth-browser-session-v2",
            requestURI: requestURI,
            subject: subject,
            subjectRevisionMicroseconds: subjectRevision,
            csrfToken: csrfToken,
            issuedAt: Int64(now.timeIntervalSince1970),
            expiresAt: Int64(expiresAt.timeIntervalSince1970)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(payload)
        let encodedText = encoded.base64URLEncodedString()
        let signature = sign(encoded)
        return (
            "\(encodedText).\(signature.base64URLEncodedString())",
            OAuthBrowserApprovalSession(
                requestURI: requestURI,
                subject: subject,
                subjectRevisionMicroseconds: subjectRevision,
                csrfToken: csrfToken,
                issuedAt: now,
                expiresAt: expiresAt
            )
        )
    }

    public func verify(
        _ value: String,
        now: Date = Date()
    ) throws -> OAuthBrowserApprovalSession {
        guard value.utf8.count <= 8 * 1024,
              value.split(separator: ".", omittingEmptySubsequences: false).count == 2 else {
            throw SwanError.unauthorized("OAuth browser session rejected")
        }
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        let payloadText = String(components[0])
        let signatureText = String(components[1])
        guard let payloadData = Data(base64URLEncoded: payloadText),
              payloadData.count <= 4 * 1024,
              let presentedSignature = Data(base64URLEncoded: signatureText),
              presentedSignature.count == 32,
              payloadData.base64URLEncodedString() == payloadText,
              presentedSignature.base64URLEncodedString() == signatureText,
              Self.constantTimeEqual(presentedSignature, sign(payloadData)) else {
            throw SwanError.unauthorized("OAuth browser session rejected")
        }
        let payload: Payload
        do {
            payload = try StrictJSON.decode(Payload.self, from: payloadData)
        } catch {
            throw SwanError.unauthorized("OAuth browser session rejected")
        }
        let issuedAt = Date(timeIntervalSince1970: TimeInterval(payload.issuedAt))
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(payload.expiresAt))
        guard payload.format == "swan-oauth-browser-session-v2",
              validRequestURI(payload.requestURI),
              validSubject(payload.subject),
              (payload.subject == nil) == (payload.subjectRevisionMicroseconds == nil),
              payload.subjectRevisionMicroseconds.map({ $0 >= 0 }) ?? true,
              validOpaqueValue(payload.csrfToken),
              expiresAt > now,
              issuedAt <= now.addingTimeInterval(60),
              expiresAt.timeIntervalSince(issuedAt) > 0,
              expiresAt.timeIntervalSince(issuedAt) <= Self.maximumLifetime else {
            throw SwanError.unauthorized("OAuth browser session rejected")
        }
        return OAuthBrowserApprovalSession(
            requestURI: payload.requestURI,
            subject: payload.subject,
            subjectRevisionMicroseconds: payload.subjectRevisionMicroseconds,
            csrfToken: payload.csrfToken,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    private func sign(_ payload: Data) -> Data {
        var input = Self.signingDomain
        input.append(payload)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
    }

    private func validRequestURI(_ value: String) -> Bool {
        value.hasPrefix(Self.requestURIPrefix)
            && value.utf8.count == Self.requestURIPrefix.utf8.count + 43
            && validOpaqueValue(String(value.dropFirst(Self.requestURIPrefix.count)))
    }

    private func validSubject(_ value: String?) -> Bool {
        guard let value else { return true }
        return value.hasPrefix("did:")
            && value.utf8.count <= 4_096
            && !value.utf8.contains(0)
    }

    /// Converts an account timestamp read from SQLite back to its exact
    /// microsecond revision. SQLite decoding may introduce a sub-microsecond
    /// floating-point remainder, so nearest-microsecond rounding is required.
    public static func subjectRevisionMicroseconds(for updatedAt: Date?) -> Int64? {
        guard let updatedAt else { return nil }
        let value = updatedAt.timeIntervalSince1970 * 1_000_000
        guard value.isFinite, value >= 0, value <= Double(Int64.max) else {
            return nil
        }
        return Int64(value.rounded())
    }

    private func validOpaqueValue(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte)
                || (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

    private static func randomOpaqueValue() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0 ..< 32).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        })
        return bytes.base64URLEncodedString()
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        let count = max(lhs.count, rhs.count)
        var difference = UInt64(lhs.count) ^ UInt64(rhs.count)
        for index in 0 ..< count {
            let left = index < lhs.count ? lhs[lhs.startIndex + index] : 0
            let right = index < rhs.count ? rhs[rhs.startIndex + index] : 0
            difference |= UInt64(left ^ right)
        }
        return difference == 0
    }
}
