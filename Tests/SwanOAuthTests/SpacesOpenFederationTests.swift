import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import XCTest
@testable import SwanOAuth

/// Current DID-document credential-key and PDS service resolution for
/// did:plc / did:web issuers, with malformed entries rejected.
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
        // The retired dedicated signing-key identifier is never an alias.
        let dedicated: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto_space")
        XCTAssertNil(dedicated)
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

    func testCredentialKeyNeverFallsBackToDedicatedSpaceKey() async throws {
        let dedicated = ##"{"id":"#atproto_space","type":"Multikey","controller":"\##(authority)","publicKeyMultibase":"\##(multikey)"}"##
        let (resolver, _) = resolver([authority: document(methods: dedicated)])
        let ordinary: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto")
        XCTAssertNil(ordinary)
        let retired: PermissionedDataJWTVerificationKey? =
            try await resolver.publicKey(for: authority, keyID: "#atproto_space")
        XCTAssertNil(retired)
    }

    func testMalformedAtprotoKeyFailsWithoutDedicatedFallback() async throws {
        let malformed = ##"{"id":"#atproto","type":"Multikey","controller":"\##(authority)","publicKeyMultibase":"zNotAKey"}"##
        let dedicated = ##"{"id":"#atproto_space","type":"Multikey","controller":"\##(authority)","publicKeyMultibase":"\##(multikey)"}"##
        let (resolver, _) = resolver([authority: document(methods: "\(malformed),\(dedicated)")])
        do {
            let _: PermissionedDataJWTVerificationKey? = try await resolver.publicKey(for: authority, keyID: "#atproto")
            XCTFail("malformed #atproto must not resolve through another key")
        } catch {}
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

    func testNotifyDestinationUsesPDSOnly() async throws {
        let retired = ##"{"id":"#atproto_space_host","type":"AtprotoSpaceHost","serviceEndpoint":"https://retired.example"}"##
        let pds = ##"{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example"}"##
        let (both, _) = resolver([authority: document(services: "\(pds),\(retired)")])
        let destination = try await both.notifyDestination(forAuthority: authority)
        XCTAssertEqual(destination?.endpoint.absoluteString, "https://pds.example")
        XCTAssertEqual(destination?.audience, "\(authority)#atproto_pds")
        let (retiredOnly, _) = resolver([authority: document(services: retired)])
        let missing = try await retiredOnly.notifyDestination(forAuthority: authority)
        XCTAssertNil(missing)
    }

    func testMalformedPDSIsAnErrorWithoutRetiredServiceFallback() async throws {
        let retired = ##"{"id":"#atproto_space_host","type":"AtprotoSpaceHost","serviceEndpoint":"https://retired.example"}"##
        for badPDS in [
            ##"{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"http://pds.example"}"##,
            ##"{"id":"#atproto_pds","type":"AtprotoPersonalDataServer"}"##,
            ##"{"id":"#atproto_pds","serviceEndpoint":"https://first.example"},{"id":"#atproto_pds","serviceEndpoint":"https://second.example"}"##,
        ] {
            let (resolver, _) = resolver([authority: document(services: "\(retired),\(badPDS)")])
            do {
                _ = try await resolver.notifyDestination(forAuthority: authority)
                XCTFail("malformed or duplicate #atproto_pds must be rejected")
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
