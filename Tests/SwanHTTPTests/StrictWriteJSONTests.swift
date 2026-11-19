import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
import PetrelRepo
import SQLiteNIO
import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// `StrictPermissionedWriteJSON.validate` is the depth, duplicate-key and
/// trailing-garbage gate in front of `JSONDecoder` on five unrelated write
/// surfaces — the public repository mutation routes, the permissioned record
/// routes, the simple-space routes, space credentials and space
/// notifications. It shipped with no test coverage at all, which is also why
/// an automated scan of the public write path missed it entirely: it is
/// defined mid-file in the permissioned module and named after the
/// permissioned path.
///
/// The depth accounting is the load-bearing part. `PublicRepositoryRecordCodec`
/// has its own encode-time depth ceiling, but the conversion phase it feeds
/// relies on this gate having already bounded the document.
final class StrictWriteJSONTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let collection = "app.bsky.feed.post"
    private static let mutationPath = "/xrpc/com.atproto.repo.createRecord"

    // MARK: - Depth

    /// Objects and arrays must both advance the counter, and the boundary must
    /// be exactly 64 accepted / 65 refused. Object-only documents are the case
    /// with no coverage anywhere: the codec's own conversion phase does not
    /// advance depth through objects, so this gate is the only thing bounding
    /// object recursion before the decoder runs.
    func testObjectOnlyNestingAcceptsSixtyFourLevelsAndRefusesSixtyFive() throws {
        XCTAssertNoThrow(
            try StrictPermissionedWriteJSON.validate(Self.nestedObjects(levels: 64)),
            "64 object levels are inside the documented bound"
        )
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Self.nestedObjects(levels: 65)),
            "65 object levels must be refused"
        )
    }

    func testArrayOnlyNestingAcceptsSixtyFourLevelsAndRefusesSixtyFive() throws {
        XCTAssertNoThrow(
            try StrictPermissionedWriteJSON.validate(Self.nestedArrays(levels: 64))
        )
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Self.nestedArrays(levels: 65))
        )
    }

    /// Mixing containers must not reset or double-count the counter: 32 object
    /// levels alternating with 32 array levels is 64 levels, not 32.
    func testAlternatingContainersShareOneDepthBudget() throws {
        XCTAssertNoThrow(
            try StrictPermissionedWriteJSON.validate(Self.alternating(levels: 64))
        )
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Self.alternating(levels: 65))
        )
    }

    // MARK: - The gate's other two jobs

    func testDuplicateKeysAreRefusedAtEveryObjectLevel() throws {
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Data(#"{"a":1,"a":2}"#.utf8))
        )
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(
                Data(#"{"outer":{"inner":{"a":1,"a":2}}}"#.utf8)
            ),
            "a duplicate key nested three levels down must be refused too"
        )
        XCTAssertNoThrow(
            try StrictPermissionedWriteJSON.validate(
                Data(#"{"a":{"a":1},"b":{"a":2}}"#.utf8)
            ),
            "the same key at sibling levels is not a duplicate"
        )
    }

    func testTrailingGarbageAndEmptyBodiesAreRefused() throws {
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data()))
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Data(#"{"a":1} {"b":2}"#.utf8))
        )
        XCTAssertThrowsError(
            try StrictPermissionedWriteJSON.validate(Data(#"{"a":1}%"#.utf8))
        )
        XCTAssertNoThrow(
            try StrictPermissionedWriteJSON.validate(Data("{\"a\":1}\n \t".utf8)),
            "trailing whitespace is not garbage"
        )
    }
    func testStringLiteralsValidationParity() throws {
        // Unescaped ASCII and multi-byte UTF-8
        XCTAssertNoThrow(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"hello world"}"#.utf8)))
        XCTAssertNoThrow(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"こんにちは 🌍"}"#.utf8)))
        
        // Valid escapes
        XCTAssertNoThrow(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"line1\nline2\t\"quoted\"\\slash\/back\bform\f"}"#.utf8)))
        XCTAssertNoThrow(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\u0041\u0042\u0043"}"#.utf8)))
        XCTAssertNoThrow(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\uD83D\uDE00"}"#.utf8)))
        
        // Control characters in string must be refused
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0x0a, 0x22, 0x7d])))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0x00, 0x22, 0x7d])))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0x1f, 0x22, 0x7d])))
        
        // Invalid escapes must be refused
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\x00"}"#.utf8)))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\u12"}"#.utf8)))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\u123"}"#.utf8)))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"\uD800"}"#.utf8)))
        
        // Invalid UTF-8 must be refused
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])))
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d])))
        
        // Unterminated string must be refused
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"text":"unterminated"# .utf8)))
        
        // Escaped vs unescaped duplicate key detection
        XCTAssertThrowsError(try StrictPermissionedWriteJSON.validate(Data(#"{"\u0061":1,"a":2}"#.utf8)))
    }


    // MARK: - Route

    /// The gate is only worth anything if it actually runs in front of the
    /// live public write surface and refuses before anything durable happens.
    func testOverDeepMutationBodyIsRefusedWithoutADurableWrite() async throws {
        let fixture = try await makeFixture()
        defer { fixture.cleanUp() }

        let loaded = try await fixture.database.loadPublicRepositoryState()
        let initialState = try XCTUnwrap(loaded)
        let app = fixture.server.buildApplication(
            logger: Logger(label: "StrictWriteJSONTests.route")
        )

        try await app.test(.router) { client in
            // The envelope itself is one object level, so 64 more inside
            // `record` makes 65 for the document.
            let overDeep = Self.mutationBody(
                rkey: "over-deep",
                record: Self.nestedObjectsFragment(levels: 64)
            )
            let refused = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "strict-json-over-deep",
                    method: "POST",
                    path: Self.mutationPath
                ),
                body: ByteBuffer(string: overDeep)
            )
            XCTAssertEqual(refused.status, .badRequest)
            XCTAssertEqual(
                try Self.errorCode(refused.body),
                "InvalidRequest"
            )
            let stateAfterRefusal =
                try await fixture.database.loadPublicRepositoryState()
            XCTAssertEqual(
                stateAfterRefusal,
                initialState,
                "a body refused by the JSON gate must not advance the repository"
            )

            // Same shape, same credentials, shallow record: proves the 400
            // above is the gate and not the plumbing.
            let accepted = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "strict-json-shallow",
                    method: "POST",
                    path: Self.mutationPath
                ),
                body: ByteBuffer(string: Self.mutationBody(
                    rkey: "shallow",
                    record: #"{"text":"fine"}"#
                ))
            )
            XCTAssertEqual(
                accepted.status,
                .ok,
                String(decoding: accepted.body.readableBytesView, as: UTF8.self)
            )
            let stateAfterAccepted =
                try await fixture.database.loadPublicRepositoryState()
            XCTAssertNotEqual(stateAfterAccepted, initialState)
        }
    }

    // MARK: - Bodies

    private static func nestedObjects(levels: Int) -> Data {
        Data(nestedObjectsFragment(levels: levels).utf8)
    }

    private static func nestedObjectsFragment(levels: Int) -> String {
        String(repeating: #"{"a":"#, count: levels - 1) + "{}"
            + String(repeating: "}", count: levels - 1)
    }

    private static func nestedArrays(levels: Int) -> Data {
        Data((String(repeating: "[", count: levels)
                + String(repeating: "]", count: levels)).utf8)
    }

    private static func alternating(levels: Int) -> Data {
        var open = ""
        var close = ""
        for level in 0 ..< (levels - 1) {
            if level.isMultiple(of: 2) {
                open += #"{"a":"#
                close = "}" + close
            } else {
                open += "["
                close = "]" + close
            }
        }
        let innermost = (levels - 1).isMultiple(of: 2) ? "{}" : "[]"
        return Data((open + innermost + close).utf8)
    }

    private static func mutationBody(rkey: String, record: String) -> String {
        #"{"repo":"\#(did)","collection":"\#(collection)","rkey":"\#(rkey)","record":\#(record)}"#
    }

    private static func errorCode(_ body: ByteBuffer) throws -> String? {
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any]
        )
        return object["error"] as? String
    }

    // MARK: - Fixture

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let database: SQLiteAccountDatabase
        let server: SwanHTTPServer
        let token: String
        let key: P256.Signing.PrivateKey
        let jwk: OAuthJSONWebKey
        let runtime: SwanOAuthRuntime

        func cleanUp() {
            Task {
                try? await database.close()
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
            }
        }

        func headers(
            jti: String,
            method: String,
            path: String
        ) throws -> HTTPFields {
            struct Header: Encodable {
                let alg = "ES256"
                let typ = OAuthDPoPProofValidator.proofType
                let jwk: OAuthJSONWebKey
            }
            struct Claims: Encodable {
                let jti: String
                let iat: Int64
                let htm: String
                let htu: String
                let nonce: String
                let ath: String
            }
            let nonce = runtime.dpopNonceService.issue()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
            let claims = try encoder.encode(Claims(
                jti: jti,
                iat: Int64(Date().timeIntervalSince1970),
                htm: method,
                htu: StrictWriteJSONTests.publicURL.absoluteString + path,
                nonce: nonce,
                ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
            )).base64URLEncodedString()
            let input = header + "." + claims
            let signature = try P256WireSignature.sign(
                Data(input.utf8), using: key
            ).base64URLEncodedString()
            var fields = HTTPFields()
            fields[.authorization] = "DPoP " + token
            fields[HTTPField.Name("DPoP")!] = input + "." + signature
            fields[.contentType] = "application/json"
            return fields
        }
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanStrictWriteJSONTests-" + UUID().uuidString
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let signingKey = P256.Signing.PrivateKey()
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: Self.did,
            revision: "3jzfcijpj2z2a",
            signingKey: signingKey
        )
        do {
            _ = try await control.createAccount(try AccountControlRegistration(
                did: Self.did,
                canonicalHandle: "alice.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                publicGenesisCommitCID: genesis.commitCID.string,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let database = try await SQLiteAccountDatabase(
                dataDirectory: root, did: Self.did
            )
            _ = try await database.installPublicRepositoryGenesis(
                genesis,
                signingPublicKey: signingKey.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x41, count: 32)
            )
            let token = try await issueToken(runtime: runtime)
            let directory = StrictWriteJSONTestDirectory(
                did: Self.did, database: database
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(publicURL: Self.publicURL),
                oauthRuntime: runtime,
                authenticatedGetSpaceDirectory: StrictWriteJSONNoopSpaceDirectory(),
                accountControlStore: control,
                publicRepositoryReadDirectory: directory,
                publicRepositoryMutationDirectory: directory,
                publicRepositoryMutationSignerProvider:
                    StrictWriteJSONSignerProvider(
                        signer: P256PublicRepositoryCommitSigner(
                            privateKey: signingKey
                        )
                    ),
                publicBlobSpoolAdmission: try PublicRepositorySpoolAdmission()
            )
            return Fixture(
                root: root,
                control: control,
                database: database,
                server: server,
                token: token.token,
                key: token.key,
                jwk: token.jwk,
                runtime: runtime
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private struct TokenMaterial: Sendable {
        let token: String
        let key: P256.Signing.PrivateKey
        let jwk: OAuthJSONWebKey
    }

    private func issueToken(runtime: SwanOAuthRuntime) async throws -> TokenMaterial {
        let key = P256.Signing.PrivateKey()
        let representation = key.publicKey.x963Representation
        let jwk = try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
        let now = Date()
        let session = try OAuthValidatedSession(
            issuer: Self.publicURL.absoluteString,
            client: OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata(
                    clientID: URL(string: "https://client.example/metadata")!,
                    redirectURIs: [URL(string: "https://client.example/callback")!],
                    grantTypes: ["authorization_code", "refresh_token"],
                    responseTypes: ["code"],
                    // `atproto` alone grants nothing on the repo surface since
                    // the `assertRepo` port (§6.5.10). This suite is about JSON
                    // body strictness, not scopes, so it holds what every real
                    // client holds and lets the body policy be the only variable.
                    scopes: ["atproto", "transition:generic"],
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: ["atproto", "transition:generic"],
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: "issue-" + UUID().uuidString,
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(
            subject: Self.did, session: session, now: now
        )
        return TokenMaterial(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private actor StrictWriteJSONTestDirectory:
    PublicRepositoryMutationDirectory, PublicRepositoryReadDirectory
{
    private let did: String
    private let database: SQLiteAccountDatabase

    init(did: String, database: SQLiteAccountDatabase) {
        self.did = did
        self.database = database
    }

    func publicRepositoryMutationTarget(
        selector: String
    ) async throws -> PublicRepositoryMutationTarget? {
        guard selector == did else { return nil }
        return try PublicRepositoryMutationTarget(
            did: did, status: .active, store: database
        )
    }

    func publicRepositoryBlobOutcome(
        did selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget> {
        guard selector == did else { return .notFound }
        return .active(
            try PublicRepositoryReadBlobTarget(
                did: did, status: .active, store: database
            )
        )
    }

    func publicRepositoryRecordProofOutcome(
        did _: String,
        path _: PublicRepositoryPath
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordProof> {
        .notFound
    }

    func publicRepositoryStatus(
        selector _: String
    ) async throws -> PublicRepositoryReadStatus? { nil }

    func describePublicRepository(
        selector _: String
    ) async throws -> PublicRepositoryReadDescription? { nil }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? { nil }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage {
        try .init(records: [], cursor: nil)
    }

    func publicRepositoryCAR(
        selector _: String
    ) async throws -> PublicRepositoryReadCAR? { nil }

    func publicRepositoryDescriptionOutcome(
        selector _: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    { .notFound }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    { .notFound }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    { .notFound }

    func publicRepositoryCAROutcome(
        selector _: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
    { .notFound }
}

private actor StrictWriteJSONNoopSpaceDirectory: AuthorizedSimpleSpaceDirectory {
    func space(
        _: SpaceURI,
        authorization _: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? { nil }

    func close() async throws {}
}

private struct StrictWriteJSONSignerProvider: PublicRepositoryMutationSignerProvider {
    let signer: any PublicRepositoryCommitSigner

    func signer(for _: String) async throws -> PublicRepositoryMutationSigner {
        .init(generation: 1, signer: signer)
    }
}
