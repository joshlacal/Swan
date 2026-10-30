import Crypto
import Foundation

/// Independent Node.js crypto ES256K fixtures, using secp256k1 scalar 2,
/// SHA-256, IEEE P1363 encoding, and low-S normalization. The retained
/// pre-DPoP TypeScript fixture and the pre-#5569 DPoP-bound (`cnf.jkt`)
/// fixtures remain rejection cases: holders of either must reacquire.
enum SpaceCredentialGoldenFixtures {
    /// The holder key every credential below is bound to: P-256 scalar
    /// `0x3c` repeated, whose canonical `did:key` the fixtures carry as
    /// `cnf.kid` (derived independently in Node.js and Python).
    static var holderKey: P256.Signing.PrivateKey {
        get throws { try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x3C, count: 32)) }
    }

    static let holderKeyID = "did:key:zDnaenWLqH8nddvKvYSgjaUsCJkuoxXhbXSqdmf8eM946nBQe"

    /// One-hour (`exp - iat == 3600`) credential bound to ``holderKeyID``:
    /// exactly the upstream #5567 ceiling, so it verifies.
    static let boundSecp256k1 =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAzNjAwLCJqdGkiOiJub2RlLWtpZC1jcmVkZW50aWFsLTAyIiwiY25mIjp7ImtpZCI6ImRpZDprZXk6ekRuYWVuV0xxSDhuZGR2S3ZZU2dqYVVzQ0prdW94WGhiWFNxZG1mOGVNOTQ2bkJRZSJ9fQ.52KmmJ0mR_1LZhnxZV3FrHvdzpwKO_WOPy-6HMlKlhBfoTRCH5ri3blmY9-YFCiCfY1xe1AJo3MGpAopMh-9pQ"
    /// The same binding with a two-hour lifetime. Its signature is valid, but
    /// `exp - iat == 7200` exceeds the one-hour ceiling, so it must be
    /// rejected by verification.
    static let boundSecp256k1TwoHour =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJub2RlLWtpZC1jcmVkZW50aWFsLTAxIiwiY25mIjp7ImtpZCI6ImRpZDprZXk6ekRuYWVuV0xxSDhuZGR2S3ZZU2dqYVVzQ0prdW94WGhiWFNxZG1mOGVNOTQ2bkJRZSJ9fQ.7vLrVKZnbM-0jHL3GYFXOEo2R4HvFNW6vV270nJA2Cse08ieriOA2qu43AkcLyNFneRd-bFOjn1H7APh13eFFA"
    /// A validly signed one-hour credential in the pre-#5569 format, bound to
    /// a Spaces DPoP thumbprint (`cnf.jkt`). It must no longer verify.
    static let dpopBoundSecp256k1 =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAzNjAwLCJqdGkiOiJub2RlLWJvdW5kLWNyZWRlbnRpYWwtMDIiLCJjbmYiOnsiamt0IjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9fQ.1o0gjIeKrLy0I4rU5jIgO26FvoVyjX_5qNSWgR9HpB1B5uHUupq8jkqlScbLixMuhAIwpAZ5Sx-2algzeKV7Rw"
}
