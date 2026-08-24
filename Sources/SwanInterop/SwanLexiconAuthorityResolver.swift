import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanOAuth

/// The two DID methods atproto blesses for identity
/// (`AtprotoIdentityDidMethods` = `plc | web`, upstream
/// `packages/internal/did-resolver/src/create-did-resolver.ts:21-35`).
///
/// This is a closed set on purpose: a method Swan does not know how to resolve
/// is refused at the parse step rather than reaching a resolver branch that
/// would have to guess.
public enum DIDMethod: String, Sendable, Hashable, CaseIterable, Codable {
    case plc
    case web
}

/// Steps 5-6 of the §5.7.4 lexicon-resolution sequence, as a value.
///
/// Both halves come from **one** DID document read. That is not an
/// optimisation: resolving the key and the PDS endpoint from two separate
/// fetches admits a document that changes between them, so the CAR would be
/// fetched from one document's PDS and verified against another document's
/// key. The pair is only meaningful when it is a pair.
public struct SwanLexiconAuthority: Sendable, Equatable {
    public let pdsEndpoint: URL
    public let commitVerifier: PermissionedDataPublicRepositoryCommitVerifier

    public init(
        pdsEndpoint: URL,
        commitVerifier: PermissionedDataPublicRepositoryCommitVerifier
    ) {
        self.pdsEndpoint = pdsEndpoint
        self.commitVerifier = commitVerifier
    }

    /// `PermissionedDataPublicRepositoryCommitVerifier` holds its key material
    /// privately and is not itself `Equatable`, so equality is taken over the
    /// algorithm plus the verifier's published SHA-256 key fingerprint. Two
    /// verifiers compare equal exactly when they would verify with the same
    /// key under the same algorithm, and no key bytes are compared here.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.pdsEndpoint == rhs.pdsEndpoint
            && lhs.commitVerifier.signingAlgorithm == rhs.commitVerifier.signingAlgorithm
            && lhs.commitVerifier.verificationIdentity == rhs.commitVerifier.verificationIdentity
    }
}

public enum SwanLexiconAuthorityResolutionError: Error, Sendable, Equatable {
    /// Not a syntactically valid DID, or a method Swan cannot resolve at all.
    case invalidAuthorityDID
    /// A method this build understands, refused by operator policy (§9-D22).
    /// Kept distinct from `invalidAuthorityDID` because the remedy is an
    /// operator configuration change, not a different authority.
    case didMethodNotAllowed(DIDMethod)
    case documentUnavailable
    case documentSubjectMismatch
    case missingSigningKey
    case unsupportedSigningKey
    case missingPDSEndpoint
}

/// Resolves a lexicon authority's DID to the two things step 7 needs: where to
/// send `com.atproto.sync.getRecord`, and the key the returned commit must
/// verify under.
///
/// `P2-C` produces this; the resolver orchestrator (`P2-E`) consumes it.
public protocol SwanLexiconAuthorityResolving: Sendable {
    /// Steps 5-6. Accepts `did:plc:` AND `did:web:`, gated by operator policy
    /// `allowedLexiconAuthorityDIDMethods` (default `[.plc, .web]`, §9-D22).
    /// Throws if no PDS endpoint or no `atproto` verification method.
    func resolveAuthority(did: String) async throws -> SwanLexiconAuthority
}

/// The production `SwanLexiconAuthorityResolving`.
///
/// **Why this is a separate type from `PLCPublicRepositoryCommitKeyResolver`.**
/// That resolver serves repository *import*, where a `did:plc:`-only rule is a
/// deliberate operator constraint on what may be imported, and
/// `PublicRepositoryDIDResolverTests` pins `did:web:example.com` →
/// `.invalidRepositoryDID` for it. §5.7.4 lifts the method restriction **for
/// lexicon-authority resolution only**; widening the import resolver in place
/// would have silently changed an unrelated trust decision. Neither
/// `PublicRepositoryDIDResolver.swift` nor its callers are touched.
///
/// **Why the PDS host is not tied to the DID host.** It deliberately is not.
/// Upstream's `extractPdsUrl` is `new URL(service.serviceEndpoint)`
/// (`packages/did/src/atproto.ts:145-160`) and
/// `isAtprotoPersonalDataServerService` (`:174-186`) constrains only the
/// service *id* to `<did>#atproto_pds` and the endpoint to being parseable —
/// nothing binds its host to the DID's. A `did:web:identity.example.com` whose
/// `#atproto_pds` is `https://pds.some-other-host.net` is legitimate, and that
/// independence is precisely what the step 8-13 proof chain exists for: the
/// PDS can return arbitrary CAR bytes and still cannot produce a valid commit
/// under the document's key. An earlier spec revision claimed same-origin and
/// used it to justify a `did:plc:`-only restriction; that claim is false as
/// stated and the restriction is **withdrawn** (§5.7.4, "Note on failure
/// domains").
///
/// **This type performs steps 5-6 only.** It resolves an authority; it proves
/// nothing about a record. A caller that takes the `pdsEndpoint`, fetches a
/// CAR, and reads the record without steps 8-13 has not implemented a partial
/// version of §5.7.4 — it has implemented a different, unsafe protocol wearing
/// this one's name. The `commitVerifier` returned here is the *only* reason
/// the endpoint above may be talked to at all.
public struct SwanLexiconAuthorityResolver: SwanLexiconAuthorityResolving {
    /// §9-D22. Operator policy, not protocol. The default matches upstream,
    /// which types its resolver over `plc | web`; a deployment that wants the
    /// stronger failure-domain separation may set `[.plc]`. A unilateral
    /// method restriction would be an interop divergence, so it is a knob with
    /// an upstream-matching default rather than a silent narrowing.
    public let allowedLexiconAuthorityDIDMethods: Set<DIDMethod>

    private let plc: any PLCClient
    private let documents: any SwanDIDDocumentFetching

    /// - Parameters:
    ///   - plc: resolves `did:plc:` state. `PLCDirectoryClient` authenticates
    ///     the returned state against the complete PLC audit chain, which is
    ///     strictly stronger than reading the directory's rendered document,
    ///     so the `plc` branch does not go through `documents`.
    ///   - documents: fetches a `did:web:` document. The production conformer
    ///     `SwanPeerPinnedDIDDocumentFetcher` routes through
    ///     `OAuthRemoteDocumentFetcher`, so a hostile `did:web` host cannot
    ///     reach a private or loopback address and a DNS rebind between
    ///     resolution and connection is rejected.
    ///   - allowedLexiconAuthorityDIDMethods: §9-D22.
    public init(
        plc: any PLCClient,
        documents: any SwanDIDDocumentFetching,
        allowedLexiconAuthorityDIDMethods: Set<DIDMethod> = [.plc, .web]
    ) throws {
        // An empty set disables every lexicon authority, which looks exactly
        // like "resolution is broken" at every call site. Refuse it at
        // construction so the misconfiguration is loud and one-time rather
        // than quiet and per-request.
        guard !allowedLexiconAuthorityDIDMethods.isEmpty else {
            throw SwanError.malformed(
                "allowedLexiconAuthorityDIDMethods must permit at least one DID method"
            )
        }
        self.plc = plc
        self.documents = documents
        self.allowedLexiconAuthorityDIDMethods = allowedLexiconAuthorityDIDMethods
    }

    public func resolveAuthority(did: String) async throws -> SwanLexiconAuthority {
        let method = try Self.method(of: did)
        guard allowedLexiconAuthorityDIDMethods.contains(method) else {
            throw SwanLexiconAuthorityResolutionError.didMethodNotAllowed(method)
        }
        switch method {
        case .plc:
            return try await resolvePLCAuthority(did: did)
        case .web:
            return try await resolveWebAuthority(did: did)
        }
    }

    // MARK: - Method parsing

    static func method(of did: String) throws -> DIDMethod {
        guard (try? AccountIdentifiers.validateDID(did)) != nil else {
            throw SwanLexiconAuthorityResolutionError.invalidAuthorityDID
        }
        if did.hasPrefix("did:plc:") { return .plc }
        if did.hasPrefix("did:web:") { return .web }
        throw SwanLexiconAuthorityResolutionError.invalidAuthorityDID
    }

    // MARK: - did:plc:

    private func resolvePLCAuthority(did: String) async throws -> SwanLexiconAuthority {
        let state: PLCDocumentData
        do {
            state = try await plc.fetchState(did: did)
        } catch {
            throw SwanLexiconAuthorityResolutionError.documentUnavailable
        }
        // The directory's answer is bound to the DID that was asked for, for
        // the same reason the `did:web` branch below binds `id`: without it a
        // redirected or substituted lookup silently selects another subject's
        // key and endpoint.
        guard state.did == did else {
            throw SwanLexiconAuthorityResolutionError.documentSubjectMismatch
        }
        guard let signingDIDKey = state.verificationMethods["atproto"] else {
            throw SwanLexiconAuthorityResolutionError.missingSigningKey
        }
        let resolved: PLCDIDVerificationKey
        do {
            resolved = try PLCDIDKeyCodec.decode(signingDIDKey)
        } catch {
            throw SwanLexiconAuthorityResolutionError.unsupportedSigningKey
        }
        guard let service = state.services["atproto_pds"],
              service.type == "AtprotoPersonalDataServer" else {
            throw SwanLexiconAuthorityResolutionError.missingPDSEndpoint
        }
        return SwanLexiconAuthority(
            pdsEndpoint: try Self.pdsEndpoint(service.endpoint),
            commitVerifier: try Self.verifier(for: resolved)
        )
    }

    // MARK: - did:web:

    private func resolveWebAuthority(did: String) async throws -> SwanLexiconAuthority {
        let data: Data
        do {
            data = try await documents.documentJSON(forDID: did)
        } catch {
            throw SwanLexiconAuthorityResolutionError.documentUnavailable
        }
        guard let document = try? JSONDecoder().decode(DIDDocument.self, from: data) else {
            throw SwanLexiconAuthorityResolutionError.documentUnavailable
        }
        // Byte-exact, with no normalisation, matching
        // `SwanServiceEndpointResolver`. Any normalisation here would be a
        // second and weaker grammar than the one
        // `SwanPeerPinnedDIDDocumentFetcher` already used to derive the fetch
        // URL, which is exactly how a mismatch gets accepted. A document with
        // no `id` cannot be bound to a subject and is refused.
        guard document.id == did else {
            throw SwanLexiconAuthorityResolutionError.documentSubjectMismatch
        }
        return SwanLexiconAuthority(
            pdsEndpoint: try Self.pdsEndpoint(in: document, did: did),
            commitVerifier: try Self.verifier(for: Self.atprotoVerificationMethod(
                in: document, did: did
            ))
        )
    }

    private struct DIDDocument: Decodable {
        struct VerificationMethod: Decodable {
            let id: String
            let type: String
            /// Optional so a method entry that omits it still decodes and is
            /// then filtered out below, rather than failing the whole
            /// document's decode because some *other* entry is malformed.
            let publicKeyMultibase: String?
        }

        struct Service: Decodable {
            let id: String
            let type: String
            let serviceEndpoint: String
        }

        /// Optional only so a document omitting it decodes and is rejected
        /// below with a subject mismatch, rather than taking a different path
        /// to the same answer.
        let id: String?
        let verificationMethod: [VerificationMethod]?
        let service: [Service]?
    }

    /// Upstream's `ATPROTO_VERIFICATION_METHOD_TYPES`
    /// (`packages/did/src/atproto.ts:189-193`).
    private static let atprotoVerificationMethodTypes: Set<String> = [
        "EcdsaSecp256r1VerificationKey2019",
        "EcdsaSecp256k1VerificationKey2019",
        "Multikey",
    ]

    /// Upstream's `matchesIdentifier` (`packages/did/src/utils.ts:4-17`): a
    /// reference may be written `#frag` or `<did>#frag`, and nothing else.
    private static func matchesIdentifier(
        did: String, fragment: String, candidate: String
    ) -> Bool {
        candidate == "#\(fragment)" || candidate == "\(did)#\(fragment)"
    }

    private static func atprotoVerificationMethod(
        in document: DIDDocument, did: String
    ) throws -> PLCDIDVerificationKey {
        let matches = (document.verificationMethod ?? []).filter {
            matchesIdentifier(did: did, fragment: "atproto", candidate: $0.id)
                && atprotoVerificationMethodTypes.contains($0.type)
                && $0.publicKeyMultibase != nil
        }
        // Upstream takes the first match (`Array.prototype.find`). Swan takes
        // exactly one, matching `SwanServiceEndpointResolver`'s rule for
        // services: a document declaring `#atproto` twice is malformed, and
        // picking the first would let a later duplicate be appended to shadow
        // or be shadowed depending only on ordering. This is fail-closed —
        // it refuses documents upstream would accept, never the reverse.
        guard matches.count == 1, let method = matches.first,
              let multibase = method.publicKeyMultibase else {
            throw SwanLexiconAuthorityResolutionError.missingSigningKey
        }
        return try verificationKey(type: method.type, publicKeyMultibase: multibase)
    }

    /// `publicKeyMultibase` → key, via the **single** `did:key` grammar Swan
    /// already owns.
    ///
    /// A `Multikey`'s multibase is `z` + base58btc(multicodec prefix ‖
    /// compressed point) — byte-identical to a `did:key:` minus its prefix
    /// (upstream `parseMultikey`, `packages/crypto/src/did.ts:11-24`). So it
    /// is reconstituted into a `did:key:` and handed to `PLCDIDKeyCodec`,
    /// which already proves curve, multicodec, canonical base58, and canonical
    /// point encoding.
    ///
    /// **The two legacy types are accepted too**, matching upstream's
    /// `ATPROTO_VERIFICATION_METHOD_TYPES` (`packages/did/src/atproto.ts:189-192`).
    /// Their multibase carries a *raw* point with no multicodec prefix and
    /// takes its curve from the `type` field, so they cannot go through the
    /// `did:key` grammar above; they route to
    /// `PLCDIDKeyCodec.decodeLegacyMultibase(_:curve:)` instead, which owns the
    /// base58 + canonical-form + point-validity proof in the same file as every
    /// other key rule. This deliberately does **not** widen `Base58BTC` — see
    /// that function's doc comment for why the proof lives there rather than
    /// here.
    ///
    /// An earlier revision refused both legacy types. That was fail-closed but
    /// wrong on cost: a `did:web` authority publishing the older W3C spelling
    /// could never have its lexicons resolved by Swan, surfacing as an opaque
    /// `invalid_scope` that the *operator* cannot fix because the document
    /// belongs to the authority. Accepting them adds no attack surface — the
    /// key must still verify a real commit signature, so a wrong curve or wrong
    /// bytes either fail to construct here or fail to verify there.
    private static func verificationKey(
        type: String, publicKeyMultibase: String
    ) throws -> PLCDIDVerificationKey {
        do {
            switch type {
            case "Multikey":
                return try PLCDIDKeyCodec.decode("did:key:" + publicKeyMultibase)
            case "EcdsaSecp256r1VerificationKey2019":
                return try PLCDIDKeyCodec.decodeLegacyMultibase(publicKeyMultibase, curve: .p256)
            case "EcdsaSecp256k1VerificationKey2019":
                return try PLCDIDKeyCodec.decodeLegacyMultibase(publicKeyMultibase, curve: .secp256k1)
            default:
                throw SwanLexiconAuthorityResolutionError.unsupportedSigningKey
            }
        } catch {
            throw SwanLexiconAuthorityResolutionError.unsupportedSigningKey
        }
    }

    private static func pdsEndpoint(in document: DIDDocument, did: String) throws -> URL {
        let matches = (document.service ?? []).filter {
            matchesIdentifier(did: did, fragment: "atproto_pds", candidate: $0.id)
                && $0.type == "AtprotoPersonalDataServer"
        }
        // Exactly one, for the same reason as `#atproto` above.
        guard matches.count == 1, let service = matches.first else {
            throw SwanLexiconAuthorityResolutionError.missingPDSEndpoint
        }
        return try pdsEndpoint(service.serviceEndpoint)
    }

    /// Upstream requires only `URL.canParse`. Swan additionally requires
    /// https, a non-empty host, and no embedded credentials — the same rule
    /// `SwanServiceEndpointResolver` (`:94-98`) already applies to every
    /// service endpoint it hands out. The host is deliberately unconstrained
    /// relative to the DID's host; see the type doc comment.
    private static func pdsEndpoint(_ endpoint: String) throws -> URL {
        guard let url = URL(string: endpoint),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil else {
            throw SwanLexiconAuthorityResolutionError.missingPDSEndpoint
        }
        return url
    }

    private static func verifier(
        for key: PLCDIDVerificationKey
    ) throws -> PermissionedDataPublicRepositoryCommitVerifier {
        switch key {
        case let .p256(publicKey):
            return PermissionedDataPublicRepositoryCommitVerifier(key: .p256(publicKey))
        case let .secp256k1(publicKey):
            do {
                return PermissionedDataPublicRepositoryCommitVerifier(
                    key: try .init(secp256k1PublicKey: publicKey)
                )
            } catch {
                throw SwanLexiconAuthorityResolutionError.unsupportedSigningKey
            }
        }
    }
}
