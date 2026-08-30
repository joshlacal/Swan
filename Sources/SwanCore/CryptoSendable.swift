import Crypto

// swift-crypto's key wrappers are immutable value types for the operations
// Swan performs, but the Linux 3.15.1 overlay does not currently carry
// Sendable annotations. Swan passes these values across actor/protocol
// boundaries, so make the immutability assumption explicit in one narrow
// compatibility shim instead of weakening every caller.
extension SymmetricKey: @unchecked Sendable {}
extension P256.Signing.PrivateKey: @unchecked Sendable {}
extension P256.Signing.PublicKey: @unchecked Sendable {}

import Foundation

public extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded value: String) {
        var text = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = text.count % 4
        if remainder > 0 {
            text += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: text)
    }
}
