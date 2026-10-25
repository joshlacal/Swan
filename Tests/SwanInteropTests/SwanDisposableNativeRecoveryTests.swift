import Foundation
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
@testable import SwanInterop
import XCTest

final class SwanDisposableNativeRecoveryTests: XCTestCase, @unchecked Sendable {
    func testNativeBrokerAndSTARRecoveryAcrossBothRealHosts() async throws {
        guard let rawRoot = ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_LAB"],
              let rawAccounts = ProcessInfo.processInfo.environment["SWAN_REFERENCE_ACCOUNTS"] else {
            throw XCTSkip("requires disposable mixed-host proof and reference accounts")
        }
        let root = URL(fileURLWithPath: rawRoot, isDirectory: true)
        struct Account: Decodable { let name: String; let service: String; let handle: String; let password: String }
        struct Proof: Decodable { let receipts: [Receipt] }
        struct Receipt: Decodable { let direction: String; let space: String; let repository: String; let records: Int }
        struct Session: Decodable { let did: String; let accessJwt: String }
        let accounts = try JSONDecoder().decode([Account].self, from: Data(contentsOf: URL(fileURLWithPath: rawAccounts)))
        let alice = try XCTUnwrap(accounts.first { $0.name == "alice" })
        let member = try InteropXRPCClient(baseURL: URL(string: alice.service)!)
        let login = try await member.procedure("com.atproto.server.createSession", body: JSONSerialization.data(withJSONObject: ["identifier": alice.handle, "password": alice.password]), authorization: .none)
        XCTAssertEqual(login.status, 200)
        let session = try JSONDecoder().decode(Session.self, from: login.body)
        let proof = try JSONDecoder().decode(Proof.self, from: Data(contentsOf: root.appendingPathComponent("evidence/mixed-host-proof.json")))
        let referenceAuthority = try XCTUnwrap(accounts.first { $0.name == "authority" })
        let plc = try InteropHTTPClient(baseURL: URL(string: ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_PLC_URL"] ?? "http://localhost:16580")!)
        var evidence: [[String: Any]] = []
        for receipt in proof.receipts {
            let swanAuthority = receipt.direction.hasPrefix("swan-authority")
            let space = try SpaceURI(receipt.space)
            let authorityURL = URL(string: swanAuthority ? (ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_SERVER_URL"] ?? "https://localhost:16586") : referenceAuthority.service)!
            let repositoryURL = URL(string: swanAuthority ? alice.service : (ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_SERVER_URL"] ?? "https://localhost:16586"))!
            let ca = root.appendingPathComponent("tls/ca.pem")
            let authority = try InteropXRPCClient(baseURL: authorityURL, additionalTrustRootFile: ca)
            let credential = try await SpaceCredentialBroker(member: member, authority: authority).exchange(
                space: space, memberAuthorization: .bearer(token: session.accessJwt))
            let host = LiveInteropHost(label: receipt.direction,
                client: try InteropXRPCClient(baseURL: repositoryURL, additionalTrustRootFile: ca),
                authorization: .spaceCredential(credential), permissionedKEMKeyProvider: { did, _ in
                    let doc = try await plc.execute(method: .get, path: "/" + did)
                    guard doc.status == 200 else { throw SwanError.unavailable("disposable PLC unavailable") }
                    return try SpaceHostResolver.authorKEMKey(
                        from: JSONDecoder().decode(DIDDocument.self, from: doc.body), expectedDID: did)
                })
            let target = try PermissionedRemoteReplicaTarget(receiverDID: session.did, space: space, repositoryDID: receipt.repository)
            let directory = root.appendingPathComponent("native-recovery-" + UUID().uuidString)
            let database = try await SQLiteAccountDatabase(dataDirectory: directory, did: session.did)
            do {
                let provider = try PermissionedRemoteReplicaHTTPSourceProvider(host: host,
                    temporaryDirectory: directory.appendingPathComponent("spool"), spoolAdmission: PublicRepositorySpoolAdmission())
                let result = try await PermissionedRemoteReplicaRecoveryOrchestrator(database: database,
                    publicationAuthorization: { try await $0() }).recover(target: target,
                    requestID: UUID().uuidString, provider: provider,
                    profileID: "permissioned-data-0016-2026-10-22", expiresAt: Int64(Date().timeIntervalSince1970) + 120)
                XCTAssertEqual(result.recordCount, receipt.records)
                evidence.append(["direction": receipt.direction, "space": receipt.space,
                    "records": result.recordCount, "generation": result.head.generation,
                    "nativeCredentialExchange": true, "nativeSTARVerifiedAndPublished": true])
                try await database.close()
            } catch {
                try? await database.close()
                throw error
            }
        }
        XCTAssertEqual(evidence.count, 2)
        try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            .write(to: root.appendingPathComponent("evidence/native-mixed-host-recovery.json"), options: .atomic)
    }
}
