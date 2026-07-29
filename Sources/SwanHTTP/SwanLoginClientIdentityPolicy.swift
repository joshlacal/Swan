import Foundation
import HTTPTypes
import SwanOAuth

/// A failure at the login client-identity boundary. Configuration errors are
/// reported before the listener is built. Request errors deliberately collapse
/// to one unavailable result so a trusted-proxy mismatch cannot reach password
/// verification or rate-limit storage.
public enum SwanLoginClientIdentityError: Error, Sendable, Equatable {
    case invalidTrustedProxyPeer
    case unavailable
}

/// Selects the IP address used by password-login admission.
///
/// Forwarding headers are never consulted for a directly connected client or
/// an untrusted intermediary. When an accepted socket peer is explicitly
/// trusted, it must replace the internal header with exactly one strict IP
/// literal; any ambiguity fails closed.
public struct SwanLoginClientIdentityPolicy: Sendable, Equatable {
    public static let clientIPHeader = HTTPField.Name("X-Swan-Client-IP")!
    public static let direct = SwanLoginClientIdentityPolicy(
        trustedProxyPeers: []
    )

    private let trustedProxyPeers: Set<OAuthIPAddress>

    public init(trustedProxyPeerLiterals: [String] = []) throws {
        var parsed: Set<OAuthIPAddress> = []
        parsed.reserveCapacity(trustedProxyPeerLiterals.count)
        for literal in trustedProxyPeerLiterals {
            guard let address = Self.strictIPAddress(literal) else {
                throw SwanLoginClientIdentityError.invalidTrustedProxyPeer
            }
            parsed.insert(address)
        }
        self.init(trustedProxyPeers: parsed)
    }

    private init(trustedProxyPeers: Set<OAuthIPAddress>) {
        self.trustedProxyPeers = trustedProxyPeers
    }

    public func clientIPAddress(
        directPeer: String?,
        headers: HTTPFields
    ) throws -> String {
        guard let directPeer,
              let directAddress = Self.strictIPAddress(directPeer) else {
            throw SwanLoginClientIdentityError.unavailable
        }
        guard trustedProxyPeers.contains(directAddress) else {
            return directAddress.description
        }

        let values = headers[values: Self.clientIPHeader]
        guard values.count == 1,
              let forwardedAddress = Self.strictIPAddress(values[0]) else {
            throw SwanLoginClientIdentityError.unavailable
        }
        return forwardedAddress.description
    }

    private static func strictIPAddress(_ literal: String) -> OAuthIPAddress? {
        let bytes = literal.utf8
        guard (2 ... 45).contains(bytes.count),
              bytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              !literal.contains(","),
              !literal.contains("["),
              !literal.contains("]"),
              !literal.contains("%") else {
            return nil
        }
        return OAuthIPAddress(literal: literal)
    }
}
