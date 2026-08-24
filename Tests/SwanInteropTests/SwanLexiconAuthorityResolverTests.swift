import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanInterop
import SwanOAuth
import PetrelRepo
import XCTest

/// P2-C — §5.7.4 steps 5-6. The lane's premise is that a lexicon authority may
/// legitimately be `did:web:`, so most of these are `did:web` vectors; the
/// `did:plc:` ones exist to prove the new path did not become a second, weaker
/// grammar for the method Swan already resolved.
final class SwanLexiconAuthorityResolverTests: XCTestCase {
    private let plcDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let webDID = "did:web:identity.example.com"
    /// The same reference secp256k1 `did:key:` `PublicRepositoryDIDResolverTests`
    /// pins for the PLC import path.
    private let referenceSecp256k1Key =
        "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc"
    private var referenceSecp256k1Multibase: String {
        String(referenceSecp256k1Key.dropFirst("did:key:".count))
    }

    // MARK: - did:web resolves, and its PDS need not share the DID's host

    /// The vector §5.7.4's "Note on failure domains" turns on: an earlier
    /// revision claimed `did:web` implies same-origin and used that to restrict
    /// authorities to `did:plc:`. The claim is false and the restriction is
    /// withdrawn, so a `did:web:identity.example.com` whose `#atproto_pds`
    /// lives on an unrelated host must resolve.
    func testWebAuthorityResolvesWithPDSOnADifferentHost() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.some-other-host.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)

        XCTAssertEqual(authority.pdsEndpoint, URL(string: "https://pds.some-other-host.net"))
        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .secp256k1)
        XCTAssertTrue(
            authority.commitVerifier.verificationIdentity.hasPrefix("secp256k1-sha256:")
        )
    }

    /// A reference may be written `#frag` or `<did>#frag` and nothing else
    /// (upstream `matchesIdentifier`). Both spellings must select the same
    /// authority, or a legitimate document resolves or fails on formatting.
    func testWebAuthorityAcceptsFullyQualifiedReferenceIDs() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "\(webDID)#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "\(webDID)#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)

        XCTAssertEqual(authority.pdsEndpoint, URL(string: "https://pds.example.net"))
    }

    func testWebAuthorityResolvesP256Multikey() async throws {
        let key = P256.Signing.PrivateKey().publicKey
        let multibase = String(P256DIDKey(publicKey: key).value.dropFirst("did:key:".count))
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)

        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .p256)
    }

    // MARK: - did:web rejects (step 6: reject if no key or no PDS)

    func testWebAuthorityWithoutAtprotoVerificationMethodIsRejected() async throws {
        // `#atproto_signing` is a real-looking fragment that is not `#atproto`.
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto_signing",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .missingSigningKey)
    }

    func testWebAuthorityWithoutPDSServiceIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_labeler",
            serviceEndpoint: "https://labeler.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .missingPDSEndpoint)
    }

    /// A service carrying the right id but the wrong `type` is not the PDS.
    func testWebAuthorityWithWrongPDSServiceTypeIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceType: "AtprotoLabeler",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .missingPDSEndpoint)
    }

    func testWebAuthorityWithNonHTTPSPDSEndpointIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "http://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .missingPDSEndpoint)
    }

    /// The document must name the subject that was asked for. Without this the
    /// fetch path's answer is trusted on its own, and a host serving another
    /// subject's document silently substitutes that subject's key and PDS.
    func testWebDocumentNamingAnotherSubjectIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: "did:web:attacker.example.com",
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .documentSubjectMismatch)
    }

    func testWebDocumentWithoutIDIsRejected() async throws {
        let json = """
        {"verificationMethod":[{"id":"#atproto","type":"Multikey",\
        "publicKeyMultibase":"\(referenceSecp256k1Multibase)"}],\
        "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer",\
        "serviceEndpoint":"https://pds.example.net"}]}
        """
        let resolver = try makeResolver(document: Data(json.utf8))

        await assertResolutionFails(resolver, webDID, .documentSubjectMismatch)
    }

    /// Two `#atproto` methods is ambiguity, not a choice. Picking the first
    /// would let a later duplicate shadow or be shadowed on ordering alone.
    func testWebDocumentWithDuplicateAtprotoMethodsIsRejected() async throws {
        let json = """
        {"id":"\(webDID)","verificationMethod":[\
        {"id":"#atproto","type":"Multikey",\
        "publicKeyMultibase":"\(referenceSecp256k1Multibase)"},\
        {"id":"\(webDID)#atproto","type":"Multikey",\
        "publicKeyMultibase":"\(referenceSecp256k1Multibase)"}],\
        "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer",\
        "serviceEndpoint":"https://pds.example.net"}]}
        """
        let resolver = try makeResolver(document: Data(json.utf8))

        await assertResolutionFails(resolver, webDID, .missingSigningKey)
    }

    func testWebDocumentWithDuplicatePDSServicesIsRejected() async throws {
        let json = """
        {"id":"\(webDID)","verificationMethod":[{"id":"#atproto","type":"Multikey",\
        "publicKeyMultibase":"\(referenceSecp256k1Multibase)"}],\
        "service":[\
        {"id":"#atproto_pds","type":"AtprotoPersonalDataServer",\
        "serviceEndpoint":"https://pds.example.net"},\
        {"id":"\(webDID)#atproto_pds","type":"AtprotoPersonalDataServer",\
        "serviceEndpoint":"https://other.example.net"}]}
        """
        let resolver = try makeResolver(document: Data(json.utf8))

        await assertResolutionFails(resolver, webDID, .missingPDSEndpoint)
    }

    /// An unparseable multibase must not reach the verifier. The `did:key`
    /// grammar `PLCDIDKeyCodec` owns is the only one applied.
    func testWebAuthorityWithUndecodableMultikeyIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: "zNotAValidBase58Key0OIl",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .unsupportedSigningKey)
    }

    /// The documented fail-closed divergence: upstream also accepts the two
    /// legacy verification-method types, whose multibase carries raw key bytes
    /// under a second grammar. Swan rejects them rather than adding one. This
    /// test exists so the divergence is deliberate and visible, not discovered.
    // MARK: - the two legacy W3C verification method types

    /// Raw points with the multicodec prefix stripped — which is what a legacy
    /// method's `publicKeyMultibase` carries. The secp256k1 pair is the same
    /// key as `referenceSecp256k1Key` above, minus its `0xe701` prefix; the
    /// P-256 one is `did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF`
    /// minus `0x8024`. Deriving them from the Multikey fixtures is deliberate:
    /// it makes the legacy and Multikey vectors provably the same keys, so a
    /// difference in outcome is about the ENCODING and not about the key
    /// (`getDidKeyFromMultibase`, `lex-resolver.ts:558-577`: legacy types go
    /// through `multibaseToBytes`, taking their curve from `type`, while
    /// `Multikey` goes through `parseMultikey`)
    /// (`getDidKeyFromMultibase`, `lex-resolver.ts:558-577`: legacy types go
    /// through `multibaseToBytes`, taking their curve from `type`, while
    /// `Multikey` goes through `parseMultikey`).
    private let legacySecp256k1Compressed = "z25z9DTpsiYYJKGsWmSPJK2NFN8PcJtZig12K59UgW7q5t"
    private let legacyP256Compressed = "zviRreKX5SuoitdRY6TAbADXtHs6vjveQGre8SADVnra9"
    private let legacySecp256k1Uncompressed =
        "zQq4zWVMz5uyw6daveR17rgCG3h6dYcMWJ9Dwc5CkkWz7SJpnfUb4tWorFcoFQWPadUi3cieZUVv1Xbe1Zmej8Pux"

    func testLegacySecp256k1VerificationMethodResolves() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: legacySecp256k1Compressed,
            verificationMethodType: "EcdsaSecp256k1VerificationKey2019",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)
        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .secp256k1)
    }

    func testLegacyP256VerificationMethodResolves() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: legacyP256Compressed,
            verificationMethodType: "EcdsaSecp256r1VerificationKey2019",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)
        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .p256)
    }

    /// Upstream normalises rather than requiring compressed input:
    /// `formatMultikey` (`crypto/src/did.ts:26-41`) calls `compressPubkey`,
    /// which is `ProjectivePoint.fromHex` (`crypto/src/p256/encoding.ts:3-6`)
    /// and accepts 33- and 65-byte points alike. Refusing uncompressed here
    /// would reject documents upstream resolves.
    func testLegacyVerificationMethodAcceptsAnUncompressedPoint() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: legacySecp256k1Uncompressed,
            verificationMethodType: "EcdsaSecp256k1VerificationKey2019",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        let authority = try await resolver.resolveAuthority(did: webDID)
        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .secp256k1)
    }

    /// A legacy `type` whose bytes are actually MULTIKEY-prefixed is refused.
    ///
    /// This is the test the legacy support had to not break, and it is a real
    /// property rather than a leftover: a legacy type declares "raw point", so
    /// 35 bytes beginning `0xe701` is a document disagreeing with itself. The
    /// earlier version of this test asserted that legacy types were rejected
    /// *categorically*; it used `referenceSecp256k1Multibase`, which is a
    /// Multikey, so it would have kept passing after legacy support landed
    /// while claiming something no longer true.
    func testLegacyTypeCarryingMultikeyPrefixedBytesIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            verificationMethodType: "EcdsaSecp256k1VerificationKey2019",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .unsupportedSigningKey)
    }

    /// The converse: a `Multikey` carrying a bare raw point is refused too, so
    /// the two encodings cannot be swapped in either direction.
    func testMultikeyCarryingABareRawPointIsRejected() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: legacySecp256k1Compressed,
            verificationMethodType: "Multikey",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .unsupportedSigningKey)
    }

    /// The recorded residual divergence: upstream's `multibaseToBytes`
    /// (`crypto/src/multibase.ts:4-20`) handles several multibase prefixes;
    /// Swan accepts only `z` (base58btc). Pinned so the narrowing is visible
    /// rather than discovered.
    func testLegacyVerificationMethodRejectsANonBase58Multibase() async throws {
        let resolver = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: "f02a1b2c3d",
            verificationMethodType: "EcdsaSecp256k1VerificationKey2019",
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))

        await assertResolutionFails(resolver, webDID, .unsupportedSigningKey)
    }

    func testUnfetchableWebDocumentIsRejected() async throws {
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: nil)
        )

        await assertResolutionFails(resolver, webDID, .documentUnavailable)
    }

    func testMalformedWebDocumentJSONIsRejected() async throws {
        let resolver = try makeResolver(document: Data("not json".utf8))

        await assertResolutionFails(resolver, webDID, .documentUnavailable)
    }

    // MARK: - did:plc still resolves, through the audit-chain-backed client

    func testPLCAuthorityResolvesKeyAndPDSFromDirectoryState() async throws {
        let resolver = try makeResolver(plcState: PLCDocumentData(
            did: plcDID,
            rotationKeys: [referenceSecp256k1Key],
            verificationMethods: ["atproto": referenceSecp256k1Key],
            alsoKnownAs: [],
            services: [
                "atproto_pds": PLCService(
                    type: "AtprotoPersonalDataServer",
                    endpoint: "https://pds.example.net"
                ),
            ]
        ))

        let authority = try await resolver.resolveAuthority(did: plcDID)

        XCTAssertEqual(authority.pdsEndpoint, URL(string: "https://pds.example.net"))
        XCTAssertEqual(authority.commitVerifier.signingAlgorithm, .secp256k1)
    }

    /// `PLCPublicRepositoryCommitKeyResolver` needed no PDS endpoint, so a
    /// state with no `atproto_pds` service was fine for it. Step 6 requires
    /// both halves, so the same state must now fail here — and fail as a
    /// missing endpoint, not as a missing key.
    func testPLCAuthorityWithoutPDSServiceIsRejected() async throws {
        let resolver = try makeResolver(plcState: PLCDocumentData(
            did: plcDID,
            rotationKeys: [referenceSecp256k1Key],
            verificationMethods: ["atproto": referenceSecp256k1Key],
            alsoKnownAs: [],
            services: [:]
        ))

        await assertResolutionFails(resolver, plcDID, .missingPDSEndpoint)
    }

    func testPLCAuthorityWithoutAtprotoKeyIsRejected() async throws {
        let resolver = try makeResolver(plcState: PLCDocumentData(
            did: plcDID,
            rotationKeys: [referenceSecp256k1Key],
            verificationMethods: [:],
            alsoKnownAs: [],
            services: [
                "atproto_pds": PLCService(
                    type: "AtprotoPersonalDataServer",
                    endpoint: "https://pds.example.net"
                ),
            ]
        ))

        await assertResolutionFails(resolver, plcDID, .missingSigningKey)
    }

    func testPLCStateNamingAnotherSubjectIsRejected() async throws {
        // The fixture answers any DID with this state, which is what a
        // substituted or redirected directory lookup looks like.
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(
                state: PLCDocumentData(
                    did: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz",
                    rotationKeys: [referenceSecp256k1Key],
                    verificationMethods: ["atproto": referenceSecp256k1Key],
                    alsoKnownAs: [],
                    services: [
                        "atproto_pds": PLCService(
                            type: "AtprotoPersonalDataServer",
                            endpoint: "https://pds.example.net"
                        ),
                    ]
                ),
                answersAnyDID: true
            ),
            documents: FixtureDIDDocumentFetcher(document: nil)
        )

        await assertResolutionFails(resolver, plcDID, .documentSubjectMismatch)
    }

    // MARK: - §9-D22 operator policy

    func testPLCOnlyPolicyRefusesWebAuthorities() async throws {
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: webDocument(
                id: webDID,
                verificationMethodID: "#atproto",
                multibase: referenceSecp256k1Multibase,
                serviceID: "#atproto_pds",
                serviceEndpoint: "https://pds.example.net"
            )),
            allowedLexiconAuthorityDIDMethods: [.plc]
        )

        await assertResolutionFails(resolver, webDID, .didMethodNotAllowed(.web))
    }

    func testWebOnlyPolicyRefusesPLCAuthorities() async throws {
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: nil),
            allowedLexiconAuthorityDIDMethods: [.web]
        )

        await assertResolutionFails(resolver, plcDID, .didMethodNotAllowed(.plc))
    }

    /// The default is upstream's: a build that ships without an explicit
    /// policy must accept both methods, because a unilateral narrowing would
    /// be a silent interop divergence rather than an operator decision.
    func testDefaultPolicyIsBothAtprotoBlessedMethods() throws {
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: nil)
        )

        XCTAssertEqual(resolver.allowedLexiconAuthorityDIDMethods, [.plc, .web])
    }

    func testEmptyPolicyIsRefusedAtConstruction() {
        XCTAssertThrowsError(
            try SwanLexiconAuthorityResolver(
                plc: LexiconAuthorityFixturePLCClient(state: nil),
                documents: FixtureDIDDocumentFetcher(document: nil),
                allowedLexiconAuthorityDIDMethods: []
            )
        )
    }

    func testUnsupportedDIDMethodIsRejectedBeforeAnyFetch() async throws {
        let resolver = try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: nil)
        )

        await assertResolutionFails(resolver, "did:key:zQ3shqwJ", .invalidAuthorityDID)
        await assertResolutionFails(resolver, "not-a-did", .invalidAuthorityDID)
    }

    // MARK: - Non-regression on the import path

    /// §5.7.4 lifts the method restriction **for lexicon-authority
    /// resolution**. The repository-import resolver keeps its `did:plc:`-only
    /// rule, which is an unrelated trust decision.
    /// `PublicRepositoryDIDResolverTests` already pins its rejection; this
    /// pins the *contrast* — the same `did:web` DID resolving on one path and
    /// refused on the other — so a later "unification" cannot quietly widen
    /// import.
    func testImportResolverStillRefusesWebDIDsThatLexiconResolutionAccepts() async throws {
        let lexicon = try makeResolver(document: webDocument(
            id: webDID,
            verificationMethodID: "#atproto",
            multibase: referenceSecp256k1Multibase,
            serviceID: "#atproto_pds",
            serviceEndpoint: "https://pds.example.net"
        ))
        _ = try await lexicon.resolveAuthority(did: webDID)

        let importResolver = PLCPublicRepositoryCommitKeyResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil)
        )
        do {
            _ = try await importResolver.resolveCommitVerifier(for: webDID)
            XCTFail("repository import must stay did:plc:-only")
        } catch let error as PublicRepositoryDIDResolutionError {
            XCTAssertEqual(error, .invalidRepositoryDID)
        }
    }

    // MARK: - Helpers

    private func makeResolver(document: Data) throws -> SwanLexiconAuthorityResolver {
        try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: nil),
            documents: FixtureDIDDocumentFetcher(document: document)
        )
    }

    private func makeResolver(plcState: PLCDocumentData) throws -> SwanLexiconAuthorityResolver {
        try SwanLexiconAuthorityResolver(
            plc: LexiconAuthorityFixturePLCClient(state: plcState),
            documents: FixtureDIDDocumentFetcher(document: nil)
        )
    }

    private func webDocument(
        id: String,
        verificationMethodID: String,
        multibase: String,
        verificationMethodType: String = "Multikey",
        serviceID: String,
        serviceType: String = "AtprotoPersonalDataServer",
        serviceEndpoint: String
    ) -> Data {
        let json = """
        {"@context":["https://www.w3.org/ns/did/v1"],"id":"\(id)",\
        "verificationMethod":[{"id":"\(verificationMethodID)",\
        "type":"\(verificationMethodType)","controller":"\(id)",\
        "publicKeyMultibase":"\(multibase)"}],\
        "service":[{"id":"\(serviceID)","type":"\(serviceType)",\
        "serviceEndpoint":"\(serviceEndpoint)"}]}
        """
        return Data(json.utf8)
    }

    private func assertResolutionFails(
        _ resolver: SwanLexiconAuthorityResolver,
        _ did: String,
        _ expected: SwanLexiconAuthorityResolutionError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await resolver.resolveAuthority(did: did)
            XCTFail("resolution must fail closed", file: file, line: line)
        } catch let error as SwanLexiconAuthorityResolutionError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected error: \(error)", file: file, line: line)
        }
    }
}

private struct LexiconAuthorityFixturePLCClient: PLCClient {
    let state: PLCDocumentData?
    /// Models a directory that answers every lookup with the same state — what
    /// a substituted or redirected lookup looks like from the caller's side.
    var answersAnyDID = false

    func submit(did: String, operation: PLCSignedOperation) async throws {
        throw SwanError.unavailable("fixture PLC does not accept writes")
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        guard let state, answersAnyDID || did == state.did else {
            throw SwanError.unavailable("fixture PLC has no such DID")
        }
        return state
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        throw SwanError.unavailable("fixture PLC audit is not needed by this resolver")
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        nil
    }
}

private struct FixtureDIDDocumentFetcher: SwanDIDDocumentFetching {
    let document: Data?

    func documentJSON(forDID did: String) async throws -> Data {
        guard let document else {
            throw SwanError.unavailable("fixture has no document for \(did)")
        }
        return document
    }
}
