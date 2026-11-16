import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import Petrel
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest

/// End-to-end behaviour of the two-step deletion routes over the real SQLite
/// control store, legacy session service, account-email outbox, and the shared
/// permanent-deletion coordinator (with its external side effects recorded).
final class AccountDeletionXRPCTests: XCTestCase {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let handle = "alice.example.com"
    private static let password = "correct horse battery staple"
    private static let email = "alice@example.com"
    private static let requestPath = "/xrpc/com.atproto.server.requestAccountDelete"
    private static let deletePath = "/xrpc/com.atproto.server.deleteAccount"

    // MARK: requestAccountDelete

    func testOAuthCredentialsCannotRequestDeletion() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        try await fixture.run { client in
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "DPoP oauth-access-token", HTTPField.Name("DPoP")!: "proof"]
            ) { response in
                XCTAssertEqual(response.status, .forbidden)
                XCTAssertEqual(Self.errorCode(response), "Forbidden")
            }
        }
        let messages = try await fixture.deliverPending()
        XCTAssertTrue(messages.isEmpty)
        try await fixture.assertAccountIntact()
    }

    func testDPoPBoundAccessTokenSentAsBearerCannotRequestDeletion() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        func segment(_ json: String) -> String {
            Data(json.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let token = [
            segment(#"{"alg":"ES256","typ":"at+jwt"}"#),
            segment(#"{"sub":"\#(Self.did)","scope":"atproto","cnf":{"jkt":"thumbprint"}}"#),
            "c2lnbmF0dXJl",
        ].joined(separator: ".")
        try await fixture.run { client in
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer \(token)"]
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
        }
        let messages = try await fixture.deliverPending()
        XCTAssertTrue(messages.isEmpty)
        try await fixture.assertAccountIntact()
    }

    func testAppPasswordSessionCannotRequestDeletion() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let appPasswordToken = try await fixture.appPasswordAccessToken()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer \(appPasswordToken)"]
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidToken")
            }
        }
        let messages = try await fixture.deliverPending()
        XCTAssertTrue(messages.isEmpty)
        try await fixture.assertAccountIntact()
    }

    func testMissingOrForgedBearerCannotRequestDeletion() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        try await fixture.run { client in
            try await client.execute(uri: Self.requestPath, method: .post) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer not-a-session"]
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
        }
        let messages = try await fixture.deliverPending()
        XCTAssertTrue(messages.isEmpty)
    }

    func testFullAccessSessionRequestEmailsADeletionToken() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let token = try await fixture.fullAccessToken()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer \(token)"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let messages = try await fixture.deliverPending()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages.first?.to.value, Self.email)
        XCTAssertEqual(messages.first?.subject, "Confirm deletion of your Swan account")
        XCTAssertNotNil(messages.first.flatMap { Fixture.proof(in: $0.body) })
        try await fixture.assertAccountIntact()
    }

    func testRequestWithoutAnEmailAddressIsRefused() async throws {
        let fixture = try await Fixture.make(associateEmail: false)
        addTeardownBlock { await fixture.close() }
        let token = try await fixture.fullAccessToken()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer \(token)"]
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidRequest")
            }
        }
    }

    func testRequestIsRateLimitedPerAccount() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let token = try await fixture.fullAccessToken()
        try await fixture.run { client in
            for attempt in 1 ... 6 {
                try await client.execute(
                    uri: Self.requestPath,
                    method: .post,
                    headers: [.authorization: "Bearer \(token)"]
                ) { response in
                    if attempt <= 5 {
                        XCTAssertEqual(response.status, .ok, "attempt \(attempt)")
                    } else {
                        XCTAssertEqual(response.status, .tooManyRequests, "attempt \(attempt)")
                        XCTAssertEqual(Self.errorCode(response), "RateLimitExceeded")
                    }
                }
            }
        }
    }

    // MARK: deleteAccount

    func testCorrectPasswordAndTokenDeleteTheAccountAndASecondAttemptFails() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        let sessionToken = try await fixture.fullAccessToken()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
                XCTAssertEqual(Self.errorCode(response), "AuthenticationRequired")
            }
            // The session opened before deletion is dead.
            try await client.execute(
                uri: Self.requestPath,
                method: .post,
                headers: [.authorization: "Bearer \(sessionToken)"]
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
        }
        let tombstone = try await fixture.database.tombstone(did: Self.did)
        XCTAssertNotNil(tombstone)
        XCTAssertEqual(tombstone?.tombstone.reason, "account-holder-request")
        let account = try await fixture.database.account(did: Self.did)
        XCTAssertNil(account)
        let effects = await fixture.effects.snapshot()
        XCTAssertEqual(effects.plcTombstoned, [Self.did])
        XCTAssertEqual(effects.keysDestroyed, [Self.did])
        XCTAssertEqual(effects.dataDestroyed, [Self.did])
    }

    func testWrongPasswordLeavesTheAccountAndTokenIntact() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: "not the password", token: proof)
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
                XCTAssertEqual(Self.errorCode(response), "AuthenticationRequired")
            }
        }
        try await fixture.assertAccountIntact()
        // The token was not burned by the failed attempt.
        let outcome = try await fixture.database.consumeAccountDeletionProof(
            did: Self.did, proofDigest: fixture.digest(proof), now: Date()
        )
        XCTAssertEqual(outcome, .consumed)
    }

    func testAppPasswordIsNotAcceptedAsTheAccountPassword() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        let appPassword = try await fixture.issueAppPassword()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: appPassword, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
                XCTAssertEqual(Self.errorCode(response), "AuthenticationRequired")
            }
        }
        try await fixture.assertAccountIntact()
    }

    func testWrongTokenLeavesTheAccountIntact() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        _ = try await fixture.requestProof()
        let wrong = String(repeating: "A", count: 43)
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: wrong)
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidToken")
            }
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: "ABCDE-FGHIJ")
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidToken")
            }
        }
        try await fixture.assertAccountIntact()
    }

    func testExpiredTokenLeavesTheAccountIntact() async throws {
        let fixture = try await Fixture.make(tokenLifetime: 60)
        addTeardownBlock { await fixture.close() }
        // Issue the proof as of two minutes ago so it is already expired.
        let proof = try await fixture.requestProof(issuedAt: Date().addingTimeInterval(-120))
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
        }
        try await fixture.assertAccountIntact()
    }

    func testTokenIsSingleUseEvenWhenDeletionCouldNotStart() async throws {
        let fixture = try await Fixture.make(failFirstDeletion: true)
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidToken")
            }
        }
        try await fixture.assertAccountIntact()
    }

    func testTokenForAnotherAccountCannotDeleteThisOne() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let otherProof = try await fixture.requestProof(for: Fixture.otherDID)
        try await fixture.run { client in
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: otherProof)
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "InvalidToken")
            }
        }
        try await fixture.assertAccountIntact()
    }

    func testPasswordAttemptsAreRateLimited() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        let limitSeen = LimitSeen()
        try await fixture.run { client in
            for _ in 1 ... 12 {
                try await client.execute(
                    uri: Self.deletePath,
                    method: .post,
                    headers: Self.jsonHeaders,
                    body: Self.deleteBody(password: "guess", token: proof)
                ) { response in
                    if response.status == .tooManyRequests {
                        XCTAssertEqual(Self.errorCode(response), "RateLimitExceeded")
                        await limitSeen.mark()
                    } else {
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                }
            }
            // Once limited, even the right password is refused.
            try await client.execute(
                uri: Self.deletePath,
                method: .post,
                headers: Self.jsonHeaders,
                body: Self.deleteBody(password: Self.password, token: proof)
            ) { response in
                XCTAssertEqual(response.status, .tooManyRequests)
            }
        }
        let sawLimit = await limitSeen.value
        XCTAssertTrue(sawLimit)
        try await fixture.assertAccountIntact()
    }

    func testMalformedDeleteBodiesAreRejectedWithoutSideEffects() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let proof = try await fixture.requestProof()
        let bodies = [
            #"{"did":"\#(Self.did)","password":"\#(Self.password)"}"#,
            #"{"did":"not-a-did","password":"\#(Self.password)","token":"\#(proof)"}"#,
            #"{"did":"\#(Self.did)","password":"\#(Self.password)","token":"\#(proof)","extra":1}"#,
            #"{"did":"\#(Self.did)","password":null,"token":"\#(proof)"}"#,
        ]
        try await fixture.run { client in
            for body in bodies {
                try await client.execute(
                    uri: Self.deletePath,
                    method: .post,
                    headers: Self.jsonHeaders,
                    body: ByteBuffer(string: body)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest, body)
                    XCTAssertEqual(Self.errorCode(response), "InvalidRequest", body)
                }
            }
        }
        try await fixture.assertAccountIntact()
    }

    // MARK: composition

    func testComposedServerRoutesAndDescribesBothMethods() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let server = SwanHTTPServer(
            profile: try ProtocolProfile.load(
                from: Self.packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-01.json")
            ),
            configuration: .init(
                host: "127.0.0.1",
                port: 0,
                publicURL: URL(string: "https://pds.swan.example")!
            ),
            oauthRuntime: try SwanOAuthRuntime(
                controlStore: fixture.database,
                serverKey: Data(repeating: 0x71, count: 32)
            ),
            accountDeletionXRPC: fixture.server
        )
        let app = server.buildApplication(logger: Logger(label: "AccountDeletionXRPCTests.composed"))
        try await app.test(.live) { client in
            try await client.execute(uri: Self.requestPath, method: .post) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(Self.errorCode(response), "ExpiredToken")
            }
            try await client.execute(
                uri: "/xrpc/community.lexicon.service.describe",
                method: .get
            ) { response in
                let text = String(buffer: response.body)
                XCTAssertTrue(text.contains("com.atproto.server.requestAccountDelete"))
                XCTAssertTrue(text.contains("com.atproto.server.deleteAccount"))
            }
        }
    }

    // MARK: helpers

    private static var jsonHeaders: HTTPFields { [.contentType: "application/json"] }

    private static func deleteBody(password: String, token: String) -> ByteBuffer {
        let data = try! JSONSerialization.data(
            withJSONObject: ["did": did, "password": password, "token": token]
        )
        return ByteBuffer(data: data)
    }

    private static func errorCode(_ response: TestResponse) -> String? {
        let object = try? JSONSerialization.jsonObject(with: Data(buffer: response.body))
        return (object as? [String: Any])?["error"] as? String
    }

    fileprivate static func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    // MARK: Fixture

    private final class Fixture: @unchecked Sendable {
        static let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"

        let root: URL
        let database: SQLiteControlDatabase
        let sessions: DurableLegacySessionService
        let credentials: AppPasswordCredentials
        let recovery: AccountEmailRecoveryService
        let delivery: CapturingDelivery
        let codec: AccountEmailProofCodec
        let effects: DeletionEffects
        let server: SwanAccountDeletionXRPCServer

        private init(
            root: URL,
            database: SQLiteControlDatabase,
            sessions: DurableLegacySessionService,
            credentials: AppPasswordCredentials,
            recovery: AccountEmailRecoveryService,
            delivery: CapturingDelivery,
            codec: AccountEmailProofCodec,
            effects: DeletionEffects,
            server: SwanAccountDeletionXRPCServer
        ) {
            self.root = root
            self.database = database
            self.sessions = sessions
            self.credentials = credentials
            self.recovery = recovery
            self.delivery = delivery
            self.codec = codec
            self.effects = effects
            self.server = server
        }

        static func make(
            associateEmail: Bool = true,
            tokenLifetime: TimeInterval = 900,
            failFirstDeletion: Bool = false
        ) async throws -> Fixture {
            let root = FileManager.default.temporaryDirectory
                .appending(path: "AccountDeletionXRPCTests-\(UUID().uuidString)")
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let database = try await SQLiteControlDatabase(dataDirectory: root)
            let hasher = try LibsodiumArgon2idHasher()
            let seededAt = Date().addingTimeInterval(-600)
            for (did, handle, email) in [
                (AccountDeletionXRPCTests.did, AccountDeletionXRPCTests.handle, AccountDeletionXRPCTests.email),
                (otherDID, "bob.example.com", "bob@example.com"),
            ] {
                _ = try await database.createAccount(try AccountControlRegistration(
                    did: did,
                    canonicalHandle: handle,
                    passwordVerifier: try hasher.hash(AccountDeletionXRPCTests.password),
                    signingKey: try .init(purpose: .signing, generation: 1),
                    rotationKey: try .init(purpose: .rotation, generation: 1),
                    createdAt: seededAt
                ))
                if associateEmail {
                    try await database.associateEmail(
                        did: did, email: try AccountEmailAddress(email),
                        now: seededAt.addingTimeInterval(1)
                    )
                }
            }
            let credentials = try AppPasswordCredentials()
            let sessions = try DurableLegacySessionService(
                store: database,
                appPasswords: database,
                accountControlStore: database,
                credentials: credentials,
                serviceDID: "did:web:pds.swan.example",
                serverKey: Data(repeating: 0x6E, count: 32)
            )
            let accounts = DurableAccountDirectory(
                store: database,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
                loginAdmissionService: AccountLoginAdmissionService(
                    store: database,
                    key: try AccountLoginAdmissionKey(Data(repeating: 0x88, count: 32))
                ),
                authenticationFactors: database
            )
            let delivery = CapturingDelivery()
            let codec = AccountEmailProofCodec(
                key: try AccountEmailProofKey(Data(repeating: 0x42, count: 32))
            )
            let recovery = try AccountEmailRecoveryService(
                store: database,
                delivery: delivery,
                proofCodec: codec,
                hashExecutor: try Argon2idHashExecutor(hasher: hasher),
                tokenLifetime: tokenLifetime
            )
            let effects = DeletionEffects()
            let coordinator = AccountPermanentDeletionCoordinator(
                controlStore: database,
                keyStore: effects,
                quiescer: effects,
                plcTombstoner: effects,
                dataDestroyer: effects
            )
            let deletion: any AccountPermanentDeletionCoordinating = failFirstDeletion
                ? FailingOnceCoordinator(wrapped: coordinator)
                : coordinator
            let server = SwanAccountDeletionXRPCServer(
                sessions: sessions,
                accounts: accounts,
                controlStore: database,
                email: SwanAccountDeletionEmailAdapter(service: recovery, store: database),
                rateLimiter: SwanDurableAccountEmailXRPCRateLimiter(store: database, proofCodec: codec),
                deletion: deletion,
                deletionProgress: database,
                minimumFailedResponseDuration: .milliseconds(1)
            )
            return Fixture(
                root: root, database: database, sessions: sessions,
                credentials: credentials, recovery: recovery, delivery: delivery,
                codec: codec, effects: effects, server: server
            )
        }

        func close() async {
            try? await database.close()
            try? FileManager.default.removeItem(at: root)
        }

        func run(_ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void) async throws {
            let app = Application(
                router: server.buildRouter(),
                configuration: .init(address: .hostname("127.0.0.1", port: 0)),
                logger: Logger(label: "AccountDeletionXRPCTests")
            )
            try await app.test(.live) { client in try await body(client) }
        }

        func fullAccessToken() async throws -> String {
            try await sessions.issue(did: AccountDeletionXRPCTests.did, appPassword: nil).accessJWT
        }

        func issueAppPassword() async throws -> String {
            try await credentials.issue(
                did: AccountDeletionXRPCTests.did,
                name: "third-party-client",
                scopes: AppPasswordPreset.full.scopes(appViewAudience: "did:web:api.bsky.app#bsky_appview")
                    .joined(separator: " "),
                into: database
            ).password
        }

        func appPasswordAccessToken() async throws -> String {
            let secret = try await issueAppPassword()
            let record = try await credentials.resolve(
                did: AccountDeletionXRPCTests.did, password: secret, in: database
            )
            return try await sessions.issue(
                did: AccountDeletionXRPCTests.did,
                appPassword: try XCTUnwrap(record)
            ).accessJWT
        }

        /// Issues a deletion proof through the service (as the request route
        /// does) and returns the proof the delivered email carries.
        func requestProof(
            for did: String = AccountDeletionXRPCTests.did,
            issuedAt: Date = Date()
        ) async throws -> String {
            let email = try await database.associatedEmail(did: did)
            try await recovery.requestAccountDeletion(
                did: did, email: try XCTUnwrap(email), now: issuedAt
            )
            let messages = try await deliverPending(now: issuedAt)
            let message = try XCTUnwrap(messages.last)
            return try XCTUnwrap(Self.proof(in: message.body))
        }

        func deliverPending(now: Date = Date()) async throws -> [CapturingDelivery.Message] {
            while case .delivered = try await recovery.deliverNext(workerID: "test-worker", now: now) {}
            return await delivery.drain()
        }

        func digest(_ proof: String) throws -> Data {
            try codec.digest(proof: proof)
        }

        static func proof(in body: String) -> String? {
            let prefix = "Swan account deletion token: "
            guard let line = body.split(separator: "\n").first(where: { $0.hasPrefix(prefix) })
            else { return nil }
            return String(line.dropFirst(prefix.count))
        }

        func assertAccountIntact(file: StaticString = #filePath, line: UInt = #line) async throws {
            let account = try await database.account(did: AccountDeletionXRPCTests.did)
            XCTAssertEqual(account?.status, .active, file: file, line: line)
            XCTAssertEqual(account?.canonicalHandle, AccountDeletionXRPCTests.handle, file: file, line: line)
            let credential = try await database.credential(did: AccountDeletionXRPCTests.did)
            XCTAssertNotNil(credential, file: file, line: line)
            let job = try await database.deletionJob(did: AccountDeletionXRPCTests.did)
            XCTAssertNil(job, file: file, line: line)
            let effects = await effects.snapshot()
            XCTAssertTrue(effects.plcTombstoned.isEmpty, file: file, line: line)
            XCTAssertTrue(effects.dataDestroyed.isEmpty, file: file, line: line)
        }
    }
}

private actor LimitSeen {
    private(set) var value = false
    func mark() { value = true }
}

private actor CapturingDelivery: AccountEmailDelivery {
    nonisolated var cancellationContract: AccountEmailDeliveryCancellationContract { .bounded }

    struct Message: Sendable {
        let to: AccountEmailAddress
        let subject: String
        let body: String
    }

    private var messages: [Message] = []

    func deliver(to: AccountEmailAddress, subject: String, body: String) async throws {
        messages.append(.init(to: to, subject: subject, body: body))
    }

    func drain() -> [Message] {
        defer { messages.removeAll() }
        return messages
    }
}

/// Records the coordinator's external side effects in place of the PLC
/// directory, the key store, and the account data directory.
private actor DeletionEffects:
    AccountPermanentDeletionQuiescing,
    AccountPermanentDeletionPLCTombstoner,
    AccountPermanentDeletionDataDestroyer,
    AccountKeyDestructionStore
{
    struct Snapshot: Sendable {
        let plcTombstoned: [String]
        let keysDestroyed: [String]
        let dataDestroyed: [String]
    }

    private var plcTombstoned: [String] = []
    private var keysDestroyed: [String] = []
    private var dataDestroyed: [String] = []

    func quiesceAccount(did _: String) async throws {}

    func tombstonePLCIdentity(did: String, rotationKey _: AccountKeyReference) async throws {
        plcTombstoned.append(did)
    }

    func destroyAccountData(did: String) async throws {
        dataDestroyed.append(did)
    }

    func destroyAccountKeyMaterial(
        _ request: AccountKeyDestructionRequest
    ) async throws -> AccountKeyDestructionReport {
        keysDestroyed.append(request.accountDID)
        return AccountKeyDestructionReport(destroyedEnvelopeCount: 2, destroyedStagingCount: 0)
    }

    func snapshot() -> Snapshot {
        Snapshot(plcTombstoned: plcTombstoned, keysDestroyed: keysDestroyed, dataDestroyed: dataDestroyed)
    }
}

/// Fails before the coordinator starts on the first call only.
private actor FailingOnceCoordinator: AccountPermanentDeletionCoordinating {
    private let wrapped: any AccountPermanentDeletionCoordinating
    private var failed = false

    init(wrapped: any AccountPermanentDeletionCoordinating) {
        self.wrapped = wrapped
    }

    func beginAndResume(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        if !failed {
            failed = true
            throw AccountDeletionStoreError.unavailable
        }
        return try await wrapped.beginAndResume(did: did, declaration: declaration, now: now)
    }
}
