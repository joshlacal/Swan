import Foundation
import SwanCore
import XCTest
@testable import SwanInterop

/// Opt-in real HTTP/DPoP laboratory proof. Reads a disposable account's
/// owner-only password and writes only public identifiers to its evidence file.
final class SwanDisposableAuthorityProvisioningTests: XCTestCase, @unchecked Sendable {
    func testProvisionAuthorityThroughRealOAuth() async throws {
        guard let rootPath = ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_LAB"] else {
            throw XCTSkip("requires a running disposable Swan laboratory")
        }
        let root = URL(fileURLWithPath: rootPath, isDirectory: true)
        let issuer = URL(string: "https://localhost")!
        let redirect = URL(string: "http://127.0.0.1:16589/callback")!
        let scopes: Set<String> = ["atproto", "space:app.swan.test?authority=*&skey=*&manage=create&manage=update&manage=delete"]
        var clientID = URLComponents(string: "http://localhost")!
        clientID.queryItems = [URLQueryItem(name: "redirect_uri", value: redirect.absoluteString),
                              URLQueryItem(name: "scope", value: scopes.sorted().joined(separator: " "))]
        let wire = try InteropHTTPClient(baseURL: URL(string: "https://localhost:16586")!,
            additionalTrustRootFile: root.appendingPathComponent("tls/ca.pem"))
        let oauth = try SwanOAuthLabClient(issuer: issuer, clientID: clientID.url!, redirectURI: redirect,
            executeHandler: { method, target, headers, body, limit in
                var parts = URLComponents(url: target, resolvingAgainstBaseURL: false)!
                parts.scheme = nil; parts.host = nil; parts.port = nil
                return try await wire.execute(method: method, path: parts.string!, headers: headers,
                    body: body, maximumResponseBytes: limit)
            })
        let password = try String(contentsOf: root.appendingPathComponent("secrets/password"), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let token = try await oauth.authorizationCode(handle: "swan-oct22.test", password: password, scopes: scopes)
        let skey = "oauth" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let expectedSpace = "at:space/\(token.subject)/app.swan.test/\(skey)"
        let create: [String: Any] = ["spaceType": "app.swan.test", "skey": skey,
            "policy": ["$type": "com.atproto.memberspace.policy"]]
        let response = try await oauth.executeResource(token: token, method: .post,
            path: "/xrpc/com.atproto.space.createSpace", body: JSONSerialization.data(withJSONObject: create))
        XCTAssertEqual(response.status, 200, String(decoding: response.body, as: UTF8.self))
        let created = try XCTUnwrap(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
        XCTAssertEqual(created["space"] as? String, expectedSpace)
        let member = "did:plc:xx5pwgo7a7k3sjz4xzoau2bq"
        let memberResponse = try await oauth.executeResource(token: token, method: .post,
            path: "/xrpc/com.atproto.memberspace.putMembers", body: JSONSerialization.data(withJSONObject: [
                "space": expectedSpace, "members": [["did": member, "read": true, "write": true]]]))
        XCTAssertEqual(memberResponse.status, 200, String(decoding: memberResponse.body, as: UTF8.self))
        guard response.status == 200, memberResponse.status == 200 else { return }
        let evidence: [String: Any] = ["space": expectedSpace, "member": member, "authority": token.subject,
            "ownerAuthorization": "Real OAuth authorization code with PKCE and DPoP", "publicOrigin": issuer.absoluteString]
        try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            .write(to: root.appendingPathComponent("evidence/swan-authority-oauth.json"), options: .atomic)
    }
}
