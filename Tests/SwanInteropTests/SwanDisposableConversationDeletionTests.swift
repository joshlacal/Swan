import Foundation
import SwanCore
import SwanSpaces
import XCTest
@testable import SwanInterop

/// Opt-in deletion through the real authority owner's OAuth grant and DPoP key.
/// Uses only a disposable generation supplied by the cross-component lab.
final class SwanDisposableConversationDeletionTests: XCTestCase, @unchecked Sendable {
    func testDeleteExactConversationGenerationThroughRealOAuth() async throws {
        guard let rootPath = ProcessInfo.processInfo.environment["SWAN_DISPOSABLE_LAB"],
              let rawSpace = ProcessInfo.processInfo.environment["SWAN_CONVERSATION_DELETE_SPACE"] else {
            throw XCTSkip("requires a disposable DS generation registered at the Swan authority")
        }
        let space = try SpaceURI(rawSpace)
        let root = URL(fileURLWithPath: rootPath, isDirectory: true)
        let issuer = URL(string: "https://localhost")!
        let redirect = URL(string: "http://127.0.0.1:16589/callback")!
        let scopes: Set<String> = ["atproto", "space:blue.catbird.labyrinth.conversation?authority=*&skey=*&manage=delete"]
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
        XCTAssertEqual(space.authority, token.subject)
        let body = try JSONSerialization.data(withJSONObject: ["space": space.rawValue])
        var statuses: [Int] = []
        for _ in 0..<2 {
            let response = try await oauth.executeResource(token: token, method: .post,
                path: "/xrpc/com.atproto.simplespace.deleteSpace", body: body)
            XCTAssertEqual(response.status, 200, String(decoding: response.body, as: UTF8.self))
            statuses.append(response.status)
        }
        guard statuses == [200, 200] else { return }
        let evidence: [String: Any] = ["space": space.rawValue, "authority": token.subject,
            "ownerAuthorization": "Real OAuth authorization code with PKCE and DPoP",
            "deleteStatuses": statuses, "sameGenerationIdempotent": true]
        try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            .write(to: root.appendingPathComponent("evidence/conversation-owner-oauth-deletion.json"), options: .atomic)
    }
}
