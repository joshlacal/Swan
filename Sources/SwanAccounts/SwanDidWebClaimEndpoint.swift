import Foundation

/// Temporary, URL-bound claim service. Only an unexpired reservation's
/// canonical claim bytes are exposed; a released or committed tuple is not
/// accepted by the endpoint unless composition explicitly keeps it live.
public actor SwanDidWebClaimEndpoint {
    private let lookup: @Sendable (String) async throws -> SwanDidWebClaimReservation?

    public init(lookup: @escaping @Sendable (String) async throws -> SwanDidWebClaimReservation?) {
        self.lookup = lookup
    }

    public func response(nonce: String, now: Date = Date()) async throws -> (status: Int, contentType: String, body: Data) {
        guard nonce.utf8.count <= 128, !nonce.isEmpty,
              let reservation = try await lookup(nonce), now < reservation.expiresAt,
              reservation.claimServiceEndpoint.hasSuffix("/" + nonce),
              reservation.claimReceiptDigest == SwanDidWebClaimCanonicalizer.receiptDigest(for: reservation.claimBytes) else {
            return (404, "application/json", Data(#"{"error":"not_found"}"#.utf8))
        }
        return (200, "application/octet-stream", reservation.claimBytes)
    }
}
