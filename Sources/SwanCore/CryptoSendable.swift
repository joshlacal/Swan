import Crypto

// swift-crypto's key wrappers are immutable value types for the operations
// Swan performs, but the Linux 3.15.1 overlay does not currently carry
// Sendable annotations. Swan passes these values across actor/protocol
// boundaries, so make the immutability assumption explicit in one narrow
// compatibility shim instead of weakening every caller.
extension SymmetricKey: @unchecked Sendable {}
extension P256.Signing.PrivateKey: @unchecked Sendable {}
extension P256.Signing.PublicKey: @unchecked Sendable {}
extension P256.KeyAgreement.PrivateKey: @unchecked Sendable {}

