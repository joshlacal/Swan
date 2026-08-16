import SwanAccounts

/// The existing resolver is the only production document-fetch path. This
/// conformance makes the peer-pinned transport consumable by the identity
/// claim/revalidation service without introducing a second HTTP client.
extension SwanPeerPinnedDIDDocumentFetcher: SwanDidWebDocumentFetching {}
