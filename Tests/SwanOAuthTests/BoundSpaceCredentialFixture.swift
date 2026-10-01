/// Independent Node.js crypto ES256K fixtures, using secp256k1 scalar 2,
/// SHA-256, IEEE P1363 encoding, and low-S normalization. The retained
/// pre-DPoP TypeScript fixture remains a rejection case.
enum SpaceCredentialGoldenFixtures {
    /// One-hour (`exp - iat == 3600`) DPoP-bound credential: exactly the
    /// upstream #5567 ceiling, so it verifies.
    static let boundSecp256k1 =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAzNjAwLCJqdGkiOiJub2RlLWJvdW5kLWNyZWRlbnRpYWwtMDIiLCJjbmYiOnsiamt0IjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9fQ.1o0gjIeKrLy0I4rU5jIgO26FvoVyjX_5qNSWgR9HpB1B5uHUupq8jkqlScbLixMuhAIwpAZ5Sx-2algzeKV7Rw"
    /// The original two-hour bound fixture. Its signature is valid, but
    /// `exp - iat == 7200` exceeds the one-hour ceiling, so it must be
    /// rejected by verification.
    static let boundSecp256k1TwoHour =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJub2RlLWJvdW5kLWNyZWRlbnRpYWwtMDEiLCJjbmYiOnsiamt0IjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9fQ.UezNylbYXYppJZ3-m0oxdDLjRYDxRlMfk3FFKBmD_GxsCo05DICKvTZIXXbCdmahQqBFUo45_Z3y4lJYszvrHw"
}
