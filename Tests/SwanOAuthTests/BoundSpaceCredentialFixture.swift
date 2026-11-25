import Crypto
import Foundation

/// Independent Node.js crypto ES256K fixtures, using secp256k1 scalar 2,
/// SHA-256, IEEE P1363 encoding, and low-S normalization. The retained
/// pre-DPoP TypeScript fixture and the pre-#5569 DPoP-bound (`cnf.jkt`)
/// fixtures remain rejection cases: holders of either must reacquire.
/// November 24 Spaces alpha: each was re-signed with the same scalar and only
/// `sub` moved to the `at:space/` form in the raw payload bytes, with a
/// deterministic (RFC 6979) low-S signature; see
/// `Scripts/space-token-goldens/README.md`.
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
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0OnNwYWNlL2RpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4L2FwcC5ic2t5LmJvb2ttYXJrcy90cy1nb2xkZW4iLCJpYXQiOjE3NTAwMDAwMDAsImV4cCI6MTc1MDAwMzYwMCwianRpIjoibm9kZS1raWQtY3JlZGVudGlhbC0wMiIsImNuZiI6eyJraWQiOiJkaWQ6a2V5OnpEbmFlbldMcUg4bmRkdkt2WVNnamFVc0NKa3VveFhoYlhTcWRtZjhlTTk0Nm5CUWUifX0.dmlZtw53CmthTinE7ybQpdXZAhhlZ8faRKQNIItBs1VYErTosPsgbm5ASX8LG0rrHDQlrjmbsBBBPNIRCA__AQ"
    /// The same binding with a two-hour lifetime. Its signature is valid, but
    /// `exp - iat == 7200` exceeds the one-hour ceiling, so it must be
    /// rejected by verification.
    static let boundSecp256k1TwoHour =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0OnNwYWNlL2RpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4L2FwcC5ic2t5LmJvb2ttYXJrcy90cy1nb2xkZW4iLCJpYXQiOjE3NTAwMDAwMDAsImV4cCI6MTc1MDAwNzIwMCwianRpIjoibm9kZS1raWQtY3JlZGVudGlhbC0wMSIsImNuZiI6eyJraWQiOiJkaWQ6a2V5OnpEbmFlbldMcUg4bmRkdkt2WVNnamFVc0NKa3VveFhoYlhTcWRtZjhlTTk0Nm5CUWUifX0.N73DguZJ9oGduBMTp4Yxq94aeJVkX2gnfeVL0LU5YE0XoZvchd2qu57TbV6MoI9-erfX3heAX3G1dZ8R2fnu1Q"
    /// A validly signed one-hour credential in the pre-#5569 format, bound to
    /// a Spaces DPoP thumbprint (`cnf.jkt`). It must no longer verify.
    static let dpopBoundSecp256k1 =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0OnNwYWNlL2RpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4L2FwcC5ic2t5LmJvb2ttYXJrcy90cy1nb2xkZW4iLCJpYXQiOjE3NTAwMDAwMDAsImV4cCI6MTc1MDAwMzYwMCwianRpIjoibm9kZS1ib3VuZC1jcmVkZW50aWFsLTAyIiwiY25mIjp7ImprdCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifX0.blsOZuR6uW2WQZ8juVy4RXMa_t0yyVVROKArdnaQwgkUccW4QfZEVGicLCkXQ4zQD4HD1oEkwbUoNonaSSPmLQ"
}
