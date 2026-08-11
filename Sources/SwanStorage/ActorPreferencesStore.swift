import Foundation

/// Durable storage for `app.bsky.actor.getPreferences` /
/// `app.bsky.actor.putPreferences`. Preferences are never proxied to an
/// AppView: the AppView does not store them, and forwarding a write would
/// silently discard the account's saved feeds, content-label settings, and
/// muted words. This store is the sole source of truth.
///
/// Preferences are kept as an opaque JSON blob (the exact bytes the caller
/// wrote), matching the reference PDS. Storage never parses, re-serializes,
/// or encrypts the document; the HTTP layer is responsible for validating
/// the wire shape before it ever reaches this boundary.
public protocol ActorPreferencesStore: Sendable {
    /// Returns the durable preferences document for `did`, or `nil` if the
    /// account has never written one. A `nil` result is not an error: an
    /// account that has never called `putPreferences` is still fully
    /// functional and must resolve to an empty preferences array, never a
    /// 404.
    func actorPreferences(did: String) async throws -> Data?

    /// Overwrites the durable preferences document for `did` with `json`.
    /// Callers must pass only the authenticated subject's DID; this store
    /// has no way to distinguish an authenticated write from a spoofed one
    /// and trusts its caller completely on that point.
    func setActorPreferences(did: String, json: Data) async throws
}
