import Crypto
import Foundation
@testable import SwanAccounts
import XCTest

final class AccountKEMKeyProviderTests: XCTestCase {
    func testLegacySigningKeysCannotActAsKEMAndManualProjectionIsStable() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanKEM-\(UUID().uuidString)")
        let store = try FileAccountKeyStore(root: root,
            configuration: AccountKeyEncryptionConfiguration(activeKeyID: "test", activeKey: Data(repeating: 0x54, count: 32)))
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:web:alice.example"
        _ = try await AccountKeyProvisioner(keyStore: store).installInitial(accountDID: did,
            signingKey: P256.Signing.PrivateKey(), rotationKey: P256.Signing.PrivateKey())
        do {
            _ = try await AccountKEMKeyProvider(keyStore: store).privateKey(accountDID: did)
            XCTFail("signing key was reused as KEM")
        } catch {}
        let first = try await AccountKeyProvisioner(keyStore: store).provisionKEM(accountDID: did)
        let second = try await AccountKeyProvisioner(keyStore: store).provisionKEM(accountDID: did)
        XCTAssertEqual(first.rawRepresentation, second.rawRepresentation)
        let method = try await AccountKEMKeyProvider(keyStore: store).verificationMethod(accountDID: did)
        XCTAssertEqual(method.id, did + "#atproto_kem")
        XCTAssertEqual(method.type, "Multikey")
        XCTAssertEqual(method.controller, did)
        XCTAssertEqual("did:key:" + method.publicKeyMultibase, try AccountKEMKeyProvider.didKey(first.publicKey))
    }
}
