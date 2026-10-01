import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import XCTest
@testable import SwanOAuth

/// `--enable-spaces-open-interop` decision B(c): DID-document key resolution
/// for any did:plc / did:web issuer and `#atproto_space_host` / `#atproto_pds`
/// notifyWrite routing, with present-but-malformed entries as errors.
final class SpacesOpenFederationTests: XCTestCase {
    private let authority = "did:web:authority.example"
    private let key = P256.Signing.PrivateKey()

    private var multikey: String {
        String(PLCDIDVerificationKey.p256(key.publicKey).didKey.dropFirst("did:key:".count))
    }

    private func resolver(
        _ documents: [String: String],
        limits: SwanDIDDocumentSpaceResolver.Limits = .standard
    ) -> (SwanDIDDocumentSpaceResolver, CountingDIDDocumentFetcher) {
        let fetcher = CountingDIDDocumentFetcher(
            documents: documents.mapValues { Data($0.utf8) }
        )
        return (SwanDIDDocumentSpaceResolver(documents: fetcher, limits: limits), fetcher)
    }

    private func document(methods: String = "", services: String = "") -> String {
        """
        {"id":"\(authority)","verificationMethod":[\(methods)],"service":[\(services)]}
        """
    }

    private var atprotoMethod: String {
        ##"{"id":"#atproto","type":"Multikey","controller":"\##(authority)","publicKeyMultibase":"\##(multikey)"}"##
    }

    func testResolvesAtprotoKeyForCredentialsDelegationsAndServiceJWTs() async throws {
        let (resolver, fetcher) = resolver([authority: document(methods: atprotoMethod)])
        let expected = PermissionedDataJWTVerificationKey.p256(key.publicKey).deterministicIdentity
        let credential: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto")
        XCTAssertEqual(credential?.deterministicIdentity, expected)
        // `#atproto_space` falls back to `#atproto` only because it is absent.
        let dedicated: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto_space")
        XCTAssertEqual(dedicated?.deterministicIdentity, expected)
        let service: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: "\(authority)#atproto_pds")
        XCTAssertEqual(service?.deterministicIdentity, expected)
        let unknownKid: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#other")
        XCTAssertNil(unknownKid)
        // One fetch served every lookup (60 s cache).
        let fetches = await fetcher.count()
        XCTAssertEqual(fetches, 1)
    }

    func testMalformedDedicatedSpaceKeyIsAnErrorNotAFallback() async throws {
        let malformed = ##"{"id":"#atproto_space","type":"Multikey","publicKeyMultibase":"zNotAKey"}"##
        let (resolver, _) = resolver([authority: document(methods: "\(malformed),\(atprotoMethod)")])
        do {
            let _: PermissionedDataJWTVerificationKey? =
                try await resolver.publicKey(for: authority, keyID: "#atproto_space")
            XCTFail("a present-but-malformed #atproto_space must not fall back")
        } catch {}
        // Positive control: the same document's #atproto still resolves.
        let ordinary: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto")
        XCTAssertNotNil(ordinary)
    }

    func testUnsupportedMethodsAndForeignDocumentsResolveNothing() async throws {
        let (resolver, fetcher) = resolver([
            "did:web:mismatch.example": document(methods: atprotoMethod),
        ])
        let other: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: "did:key:z6Mk", keyID: "#atproto")
        XCTAssertNil(other)
        let fetchesAfterUnsupported = await fetcher.count()
        XCTAssertEqual(fetchesAfterUnsupported, 0)
        // A document whose id is not the requested DID is refused.
        do {
            let _: PermissionedDataJWTVerificationKey? =
                try await resolver.publicKey(for: "did:web:mismatch.example", keyID: "#atproto")
            XCTFail("a document for another DID must not resolve")
        } catch {}
    }

    func testNotifyDestinationPrefersTypedSpaceHostThenPDS() async throws {
        let spaceHost = ##"{"id":"#atproto_space_host","type":"AtprotoSpaceHost","serviceEndpoint":"https://space.example"}"##
        let pds = ##"{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example"}"##
        let (both, _) = resolver([authority: document(services: "\(pds),\(spaceHost)")])
        let hosted = try await both.notifyDestination(forAuthority: authority)
        XCTAssertEqual(hosted?.endpoint.absoluteString, "https://space.example")
        XCTAssertEqual(hosted?.audience, "\(authority)#atproto_space_host")

        let (pdsOnly, _) = resolver([authority: document(services: pds)])
        let fallback = try await pdsOnly.notifyDestination(forAuthority: authority)
        XCTAssertEqual(fallback?.endpoint.absoluteString, "https://pds.example")
        XCTAssertEqual(fallback?.audience, authority)

        let (none, _) = resolver([authority: document()])
        let missing = try await none.notifyDestination(forAuthority: authority)
        XCTAssertNil(missing)
    }

    func testMalformedSpaceHostEntryIsAnErrorNotAFallback() async throws {
        let pds = ##"{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example"}"##
        for badHost in [
            ##"{"id":"#atproto_space_host","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://space.example"}"##,
            ##"{"id":"#atproto_space_host","type":"AtprotoSpaceHost","serviceEndpoint":"http://space.example"}"##,
            ##"{"id":"#atproto_space_host","type":"AtprotoSpaceHost"}"##,
        ] {
            let (resolver, _) = resolver([authority: document(services: "\(pds),\(badHost)")])
            do {
                _ = try await resolver.notifyDestination(forAuthority: authority)
                XCTFail("malformed #atproto_space_host must not fall back: \(badHost)")
            } catch {}
        }
    }

    func testNewIssuerLookupsAreRateLimited() async throws {
        let limits = SwanDIDDocumentSpaceResolver.Limits(
            documentLifetime: 60,
            negativeLifetime: 30,
            maximumCachedDocuments: 16,
            maximumNewLookupsPerMinute: 2
        )
        let (resolver, fetcher) = resolver([:], limits: limits)
        for index in 0 ..< 4 {
            do {
                let _: PermissionedDataJWTVerificationKey? = try await resolver.publicKey(
                    for: "did:web:issuer\(index).example",
                    keyID: "#atproto"
                )
            } catch {}
        }
        let fetches = await fetcher.count()
        XCTAssertEqual(fetches, 2)
    }
}

private actor CountingDIDDocumentFetcher: SwanDIDDocumentFetching {
    private let documents: [String: Data]
    private var fetches = 0

    init(documents: [String: Data]) {
        self.documents = documents
    }

    func documentJSON(forDID did: String) async throws -> Data {
        fetches += 1
        guard let data = documents[did] else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return data
    }

    func count() -> Int { fetches }
}
