import Foundation
import SwanCore
import SwanStorage

public struct OAuthResolvedClientMetadata: Sendable, Equatable {
    public let metadata: OAuthClientMetadata
    /// Present only for confidential clients, after inline or remote JWKS
    /// material has been parsed and validated.
    public let keySet: OAuthJSONWebKeySet?

    public init(metadata: OAuthClientMetadata, keySet: OAuthJSONWebKeySet?) {
        self.metadata = metadata
        self.keySet = keySet
    }
}

/// Loads client metadata and its optional JWKS with a small explicit cache.
/// Entries are retained only after the metadata identity, all profile fields,
/// and any referenced JWKS have validated. `revalidate(clientID:)` is an
/// intentional rotation hook for a later session manager; this task does not
/// claim to revalidate already-active sessions automatically.
public actor OAuthClientMetadataLoader {
    private struct CachedDocument: Codable, Sendable {
        let metadata: OAuthClientMetadata
        let keySet: OAuthJSONWebKeySet?
    }

    private let fetcher: OAuthRemoteDocumentFetcher
    private let controlStore: any OAuthControlStore
    private let cacheLifetime: TimeInterval

    public init(
        fetcher: OAuthRemoteDocumentFetcher,
        controlStore: any OAuthControlStore,
        cacheLifetime: TimeInterval = 300
    ) throws {
        guard cacheLifetime >= 5, cacheLifetime <= 900, cacheLifetime.isFinite else {
            throw SwanError.malformed("OAuth metadata cache lifetime is out of bounds")
        }
        self.fetcher = fetcher
        self.controlStore = controlStore
        self.cacheLifetime = cacheLifetime
    }

    public func load(clientID: URL, now: Date = Date()) async throws -> OAuthResolvedClientMetadata {
        try await load(clientID: clientID, now: now, bypassCache: false)
    }

    private func load(clientID: URL, now: Date, bypassCache: Bool) async throws -> OAuthResolvedClientMetadata {
        let key = clientID.absoluteString
        if OAuthClientMetadata.isExactLocalhostDevelopmentClientID(clientID) {
            guard fetcher.policy.allowLocalhostDevelopment else {
                throw SwanError.unauthorized("localhost OAuth development client is disabled")
            }
            // The profile defines a virtual document; do not make an SSRF-prone
            // loopback fetch for it and do not treat it as a cached response.
            return OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID),
                keySet: nil
            )
        }
        try OAuthClientMetadata.validateStandardClientID(clientID)
        if !bypassCache {
            do {
                if let cached = try await controlStore.cachedClientMetadata(clientID: key, now: now) {
                    guard cached.expiresAt <= now.addingTimeInterval(cacheLifetime),
                          cached.clientID == key else {
                        throw SwanError.unavailable("OAuth metadata cache record exceeded policy")
                    }
                    let cachedDocument = try StrictJSON.decode(CachedDocument.self, from: cached.document)
                    guard cachedDocument.metadata.clientID.absoluteString == key,
                          !cachedDocument.metadata.isLocalhostDevelopmentClient else {
                        throw SwanError.unavailable("OAuth metadata cache record is malformed")
                    }
                    return OAuthResolvedClientMetadata(
                        metadata: cachedDocument.metadata,
                        keySet: cachedDocument.keySet
                    )
                }
            } catch let error as SwanError {
                throw error
            } catch {
                throw SwanError.unavailable("OAuth metadata cache unavailable")
            }
        }
        let metadataData = try await fetcher.fetchJSON(from: clientID)
        let metadata = try OAuthClientMetadata.decodeValidated(metadataData, responseURL: clientID)
        let keySet: OAuthJSONWebKeySet?
        if let inline = metadata.jwks {
            keySet = inline
        } else if let jwksURI = metadata.jwksURI {
            keySet = try OAuthJSONWebKeySet.decodeValidated(try await fetcher.fetchJSON(from: jwksURI))
        } else {
            keySet = nil
        }
        let resolved = OAuthResolvedClientMetadata(metadata: metadata, keySet: keySet)
        do {
            let document = try JSONEncoder().encode(CachedDocument(metadata: metadata, keySet: keySet))
            try await controlStore.cacheClientMetadata(
                OAuthCachedClientMetadata(
                    clientID: key,
                    document: document,
                    expiresAt: now.addingTimeInterval(cacheLifetime)
                ),
                now: now
            )
        } catch {
            throw SwanError.unavailable("OAuth metadata cache unavailable")
        }
        return resolved
    }

    /// Forces a fresh validation pass for confidential-key rotation callers.
    /// Callers decide how a missing previously-bound key affects their session.
    public func revalidate(clientID: URL, now: Date = Date()) async throws -> OAuthResolvedClientMetadata {
        return try await load(clientID: clientID, now: now, bypassCache: true)
    }
}
