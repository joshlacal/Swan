import Foundation
import PetrelCrypto
import PetrelPLC
import SwanCore
import SwanStorage

/// Open-federation key and endpoint resolution for atproto spaces, composed
/// only under `swan serve --enable-spaces-open-interop` (Josh, 2026-10-01,
/// decision B(c)). It overrides the closed-federation rule in `AGENTS.md`
/// ("unknown issuers never trigger DID/PLC/DNS/HTTP lookups") for exactly
/// these lookups while the flag is on:
///
/// - delegation, space-credential, and service-JWT issuer keys for any
///   `did:plc` or `did:web` issuer, read from the issuer's DID document;
/// - the `notifyRepoUpdate` destination of a space authority, read from its
///   `#atproto_pds` (type `AtprotoSpaceHost`) entry, else `#atproto_pds`.
///
/// Every fetch goes through the caller-supplied ``SwanDIDDocumentFetching``,
/// which in `serve` is ``SwanPeerPinnedDIDDocumentFetcher`` (peer-pinned, no
/// redirects, SSRF policy). Documents are cached for at most 60 seconds
/// (the same bound as the PLC credential-key cache), the cache is bounded,
/// failures are negatively cached, and new-issuer lookups are rate-limited
/// process-wide so a stream of forged issuers cannot amplify into fetches.
public actor SwanDIDDocumentSpaceResolver:
    SpaceCredentialPublicKeyResolver,
    SpaceDelegationPublicKeyResolver,
    SpaceServicePublicKeyResolver
{
    public struct Limits: Sendable, Equatable {
        public static let standard = Limits(
            documentLifetime: 60,
            negativeLifetime: 30,
            maximumCachedDocuments: 4_096,
            maximumNewLookupsPerMinute: 120
        )

        public let documentLifetime: TimeInterval
        public let negativeLifetime: TimeInterval
        public let maximumCachedDocuments: Int
        public let maximumNewLookupsPerMinute: Int

        public init(
            documentLifetime: TimeInterval,
            negativeLifetime: TimeInterval,
            maximumCachedDocuments: Int,
            maximumNewLookupsPerMinute: Int
        ) {
            self.documentLifetime = min(max(documentLifetime, 1), 60)
            self.negativeLifetime = min(max(negativeLifetime, 1), 300)
            self.maximumCachedDocuments = max(maximumCachedDocuments, 1)
            self.maximumNewLookupsPerMinute = max(maximumNewLookupsPerMinute, 1)
        }
    }

    /// A resolved `notifyRepoUpdate` destination: the endpoint origin and the
    /// service-JWT audience that endpoint verifies.
    public struct NotifyDestination: Sendable, Equatable {
        public let endpoint: URL
        public let audience: String
    }

    struct Document: Decodable, Sendable {
        struct VerificationMethod: Decodable, Sendable {
            let id: String
            let type: String?
            let publicKeyMultibase: String?
        }

        struct Service: Decodable, Sendable {
            let id: String
            let type: String?
            let serviceEndpoint: String?
        }

        let id: String?
        let verificationMethod: [VerificationMethod]?
        let service: [Service]?
    }

    private struct CacheEntry {
        let document: Document?
        let expiresAt: Date
    }

    private let documents: any SwanDIDDocumentFetching
    private let limits: Limits
    private let clock: @Sendable () -> Date
    private var cache: [String: CacheEntry] = [:]
    private var lookupWindowStart: Date?
    private var lookupsInWindow = 0

    public init(
        documents: any SwanDIDDocumentFetching,
        limits: Limits = .standard,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.documents = documents
        self.limits = limits
        self.clock = clock
    }

    // MARK: Keys

    /// October 22 space credentials resolve only the account `#atproto`
    /// signing method. KEM material has a separate purpose and resolver.
    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        guard keyID == "#atproto" else { return nil }
        let fragments = ["atproto"]
        guard let document = try await document(for: issuer) else { return nil }
        for fragment in fragments {
            if let key = try Self.verificationKey(in: document, did: issuer, fragment: fragment) {
                return key
            }
        }
        return nil
    }

    /// Service JWTs are signed with the issuer's `#atproto` key; an issuer of
    /// the form `did#service` is resolved by its DID.
    public func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        let did = serviceIssuerDID(issuer) ?? issuer
        guard let document = try await document(for: did) else { return nil }
        return try Self.verificationKey(in: document, did: did, fragment: "atproto")
    }

    // MARK: notifyRepoUpdate routing

    /// `#atproto_pds` (which must be typed `AtprotoSpaceHost`) when
    /// present, else `#atproto_pds`. A present-but-malformed space-host entry
    /// is an error rather than a fallback. The audience is always
    /// `<authority>#atproto_pds`, also when the endpoint falls back to
    /// `#atproto_pds`: the reference sender (atproto#5574) addresses the
    /// space-host role, not the endpoint it happened to resolve.
    public func notifyDestination(forAuthority authority: String) async throws -> NotifyDestination? {
        guard let document = try await document(for: authority) else { return nil }
        let services = document.service ?? []
        let pds = services.filter {
            Self.matches(did: authority, fragment: "atproto_pds", candidate: $0.id)
        }
        guard !pds.isEmpty else { return nil }
        guard pds.count == 1,
              let entry = pds.first,
              let endpoint = entry.serviceEndpoint.flatMap(Self.httpsOrigin) else {
            throw SwanError.malformed("space authority #atproto_pds entry is malformed")
        }
        return NotifyDestination(
            endpoint: endpoint,
            audience: "\(authority)#atproto_pds"
        )
    }

    // MARK: Documents

    private func document(for did: String) async throws -> Document? {
        guard did.hasPrefix("did:plc:") || did.hasPrefix("did:web:"),
              (try? AccountIdentifiers.validateDID(did)) != nil else {
            return nil
        }
        let now = clock()
        if let entry = cache[did], entry.expiresAt > now {
            guard let document = entry.document else {
                throw SwanError.unavailable("DID document is temporarily unavailable")
            }
            return document
        }
        cache.removeValue(forKey: did)
        try admitLookup(now: now)
        let fetched: Document?
        do {
            let data = try await documents.documentJSON(forDID: did)
            let decoded = try JSONDecoder().decode(Document.self, from: data)
            fetched = decoded.id == did ? decoded : nil
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            fetched = nil
        }
        store(did: did, document: fetched, now: clock())
        guard let fetched else {
            throw SwanError.unavailable("DID document is temporarily unavailable")
        }
        return fetched
    }

    private func admitLookup(now: Date) throws {
        if let start = lookupWindowStart, now.timeIntervalSince(start) < 60 {
            guard lookupsInWindow < limits.maximumNewLookupsPerMinute else {
                throw SwanError.unavailable("DID document resolution is rate limited")
            }
            lookupsInWindow += 1
        } else {
            lookupWindowStart = now
            lookupsInWindow = 1
        }
    }

    private func store(did: String, document: Document?, now: Date) {
        if cache.count >= limits.maximumCachedDocuments {
            cache = cache.filter { $0.value.expiresAt > now }
            if cache.count >= limits.maximumCachedDocuments,
               let victim = cache.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                cache.removeValue(forKey: victim)
            }
        }
        let lifetime = document == nil ? limits.negativeLifetime : limits.documentLifetime
        cache[did] = CacheEntry(document: document, expiresAt: now.addingTimeInterval(lifetime))
    }

    /// Upstream `ATPROTO_VERIFICATION_METHOD_TYPES`.
    private static let verificationMethodTypes: Set<String> = [
        "Multikey",
        "EcdsaSecp256r1VerificationKey2019",
        "EcdsaSecp256k1VerificationKey2019",
    ]

    /// `nil` when no method has this fragment; throws when one is present but
    /// duplicated, of an unsupported type, or carries an unparseable key.
    static func verificationKey(
        in document: Document,
        did: String,
        fragment: String
    ) throws -> PermissionedDataJWTVerificationKey? {
        let matches = (document.verificationMethod ?? []).filter {
            Self.matches(did: did, fragment: fragment, candidate: $0.id)
        }
        guard !matches.isEmpty else { return nil }
        guard matches.count == 1,
              let method = matches.first,
              let type = method.type,
              verificationMethodTypes.contains(type),
              let multibase = method.publicKeyMultibase else {
            throw SwanError.malformed("DID document verification method is malformed")
        }
        do {
            let decoded: PLCDIDVerificationKey
            switch type {
            case "Multikey":
                decoded = try PLCDIDKeyCodec.decode("did:key:" + multibase)
            case "EcdsaSecp256r1VerificationKey2019":
                decoded = try PLCDIDKeyCodec.decodeLegacyMultibase(multibase, curve: .p256)
            default:
                decoded = try PLCDIDKeyCodec.decodeLegacyMultibase(multibase, curve: .secp256k1)
            }
            switch decoded {
            case let .p256(publicKey):
                return .p256(publicKey)
            case let .secp256k1(publicKey):
                return try .init(secp256k1PublicKey: publicKey)
            }
        } catch {
            throw SwanError.malformed("DID document verification method is malformed")
        }
    }

    private static func matches(did: String, fragment: String, candidate: String) -> Bool {
        candidate == "#\(fragment)" || candidate == "\(did)#\(fragment)"
    }

    private static func httpsOrigin(_ raw: String) -> URL? {
        guard let url = URL(string: raw),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else {
            return nil
        }
        return url
    }
}

/// Consults `primary`, then `fallback` only when `primary` has no answer.
/// A thrown error from `primary` is terminal (it never falls through).
public struct FallbackSpaceCredentialPublicKeyResolver: SpaceCredentialPublicKeyResolver {
    private let primary: (any SpaceCredentialPublicKeyResolver)?
    private let fallback: any SpaceCredentialPublicKeyResolver

    public init(primary: (any SpaceCredentialPublicKeyResolver)?, fallback: any SpaceCredentialPublicKeyResolver) {
        self.primary = primary
        self.fallback = fallback
    }

    public func publicKey(for issuer: String, keyID: String) async throws -> PermissionedDataJWTVerificationKey? {
        if let key = try await primary?.publicKey(for: issuer, keyID: keyID) { return key }
        return try await fallback.publicKey(for: issuer, keyID: keyID)
    }
}

/// Delegation counterpart of ``FallbackSpaceCredentialPublicKeyResolver``.
public struct FallbackSpaceDelegationPublicKeyResolver: SpaceDelegationPublicKeyResolver {
    private let primary: (any SpaceDelegationPublicKeyResolver)?
    private let fallback: any SpaceDelegationPublicKeyResolver

    public init(primary: (any SpaceDelegationPublicKeyResolver)?, fallback: any SpaceDelegationPublicKeyResolver) {
        self.primary = primary
        self.fallback = fallback
    }

    public func publicKey(for issuer: String, keyID: String) async throws -> PermissionedDataJWTVerificationKey? {
        if let key = try await primary?.publicKey(for: issuer, keyID: keyID) { return key }
        return try await fallback.publicKey(for: issuer, keyID: keyID)
    }
}

/// Service-JWT counterpart of ``FallbackSpaceCredentialPublicKeyResolver``.
public struct FallbackSpaceServicePublicKeyResolver: SpaceServicePublicKeyResolver {
    private let primary: any SpaceServicePublicKeyResolver
    private let fallback: any SpaceServicePublicKeyResolver

    public init(primary: any SpaceServicePublicKeyResolver, fallback: any SpaceServicePublicKeyResolver) {
        self.primary = primary
        self.fallback = fallback
    }

    public func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        if let key = try await primary.publicKey(for: issuer) { return key }
        return try await fallback.publicKey(for: issuer)
    }
}
