import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts

/// A deliberately narrow service protocol: route assembly owns authentication
/// and this adapter owns HTTP policy; account/domain services remain injectable.
public protocol SwanAccountPortalServing: Sendable {
    func bootstrap(now: Date) async throws -> SwanAccountPortalBootstrap
    func portal(accountDID: String, now: Date) async throws -> SwanAccountPortalSnapshot
    func mutate(path: String, accountDID: String, now: Date) async throws -> SwanAccountPortalMutation
}

public struct SwanAccountPortalBootstrap: Codable, Sendable, Equatable {
    public let csrf: String
    public init(csrf: String) { self.csrf = csrf }
}

public struct SwanAccountPortalSnapshot: Codable, Sendable, Equatable {
    public struct Account: Codable, Sendable, Equatable { public let did: String; public let handle: String; public let email: String?; public let lifecycle: String }
    public struct Identity: Codable, Sendable, Equatable { public let method: String; public let handle: String; public let state: String }
    public struct Session: Codable, Sendable, Equatable { public let id: String; public let label: String; public let kind: String; public let lastSeen: String; public let current: Bool }
    public struct App: Codable, Sendable, Equatable { public let id: String; public let name: String; public let scopes: [String]; public let createdAt: String }
    public struct Password: Codable, Sendable, Equatable { public let name: String; public let scopes: [String]; public let createdAt: String; public let lastUsedAt: String? }
    public let account: Account
    public let identity: Identity?
    public let strength: String
    public let factors: [[String: String]]
    public let sessions: [Session]
    public let apps: [App]
    public let passwords: [Password]
}

public struct SwanAccountPortalMutation: Codable, Sendable, Equatable {
    public let accepted: Bool
    public let message: String
    public init(accepted: Bool = true, message: String = "Accepted") { self.accepted = accepted; self.message = message }
}

public struct SwanAccountPortalConfiguration: Sendable, Equatable {
    public let publicOrigin: URL
    public let staticDirectory: URL
    public init(publicOrigin: URL, staticDirectory: URL) throws {
        guard let components = URLComponents(url: publicOrigin, resolvingAgainstBaseURL: false),
              components.scheme != nil, components.host != nil,
              components.path.isEmpty || components.path == "/",
              components.query == nil, components.fragment == nil else {
            throw SwanAccountPortalHTTPError.invalidConfiguration
        }
        self.publicOrigin = publicOrigin
        self.staticDirectory = staticDirectory
    }
}

public enum SwanAccountPortalHTTPError: Error, Sendable, Equatable { case invalidConfiguration }

/// Registration for the public account prefix. Call this before any broad
/// public catch-all: API routes are registered first and therefore cannot be
/// mistaken for static pages.
public struct SwanAccountPortalHTTP: Sendable {
    private let configuration: SwanAccountPortalConfiguration
    private let sessions: SwanManagementSessionRuntime
    private let service: any SwanAccountPortalServing

    public init(configuration: SwanAccountPortalConfiguration, sessions: SwanManagementSessionRuntime, service: any SwanAccountPortalServing) {
        self.configuration = configuration
        self.sessions = sessions
        self.service = service
    }

    public func register(on router: Router<SwanHTTPRequestContext>) {
        router.get("/account/api/signup/policy") { _ , _ -> Response in
            accountJSON(.ok, SignupPolicyView())
        }
        router.get("/account/api/bootstrap") { [configuration, service] request, _ async -> Response in
            guard originPermits(request, expected: configuration.publicOrigin), fetchSiteAllows(request) else { return accountError(.forbidden) }
            do {
                let issued = try await service.bootstrap(now: Date())
                return accountJSON(.ok, issued, cookies: [preAuthCookie(issued.csrf)])
            } catch { return accountError(.serviceUnavailable) }
        }

        router.get("/account/api/portal") { [sessions, service] request, _ async -> Response in
            guard let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                  let metadata = try? await sessions.authenticate(sessionValue: session) else { return accountError(.unauthorized) }
            do { return accountJSON(.ok, try await service.portal(accountDID: metadata.accountDID, now: Date())) }
            catch { return accountError(.serviceUnavailable) }
        }

        // Register every read surface explicitly. They all share the same
        // sanitized snapshot until their domain adapter supplies a narrower
        // projection; none can fall through to the SPA.
        for path in ["session", "sessions", "profile", "identity", "app-passwords", "scope-presets", "factors", "connected-apps", "export", "migration"] {
            router.get("/account/api/\(path)") { [sessions, service] request, _ async -> Response in
                guard let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let metadata = try? await sessions.authenticate(sessionValue: session) else { return accountError(.unauthorized) }
                do { return accountJSON(.ok, try await service.portal(accountDID: metadata.accountDID, now: Date())) }
                catch { return accountError(.serviceUnavailable) }
            }
        }

        router.post("/account/api/login") { [configuration, sessions, service] request, _ async -> Response in
            guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                  let csrf = accountCookie(named: SwanManagementSessionRuntime.preAuthCookieName, request: request),
                  let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                  constantTime(csrf, header) else { return accountError(.forbidden) }
            // Password verification is intentionally delegated to the account
            // service; this adapter never logs or retains the JSON body.
            do {
                let mutation = try await service.mutate(path: "login", accountDID: "", now: Date())
                guard mutation.accepted else { return accountError(.unauthorized) }
                let issued = try await sessions.issue(accountDID: "pending")
                return accountJSON(.ok, mutation, cookies: [managementCookie(issued.sessionValue), csrfCookie(issued.csrfValue), expiredPreAuthCookie()])
            } catch { return accountError(.unauthorized) }
        }

        for path in ["logout", "profile", "identity", "app-passwords", "sessions/revoke-others", "connected-apps", "export", "migration", "lifecycle/delete", "step-up"] {
            router.on("/account/api/\(path)", method: .post) { [configuration, sessions, service] request, _ async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                      constantTime(csrf, header),
                      (try? await sessions.authenticate(sessionValue: session)) != nil,
                      (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else { return accountError(.forbidden) }
                do {
                    let metadata = try await sessions.authenticate(sessionValue: session)
                    let mutation = try await service.mutate(path: path, accountDID: metadata.accountDID, now: Date())
                    if path == "logout" { try await sessions.revoke(sessionValue: session) }
                    return accountJSON(.ok, mutation, cookies: path == "logout" ? [expiredManagementCookie(), expiredCSRFToken()] : [])
                } catch { return accountError(.serviceUnavailable) }
            }
        }

        let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
        for method in methods {
            router.on("/account/api/*", method: method) { _, _ -> Response in accountError(.notFound) }
            router.on("/account/api/*/*", method: method) { _, _ -> Response in accountError(.notFound) }
        }

        router.get("/account") { [configuration] _, _ -> Response in staticAccountResponse(configuration: configuration) }
        router.get("/account/auth-tokens.css") { [configuration] _, _ -> Response in staticAuthCSSResponse(configuration: configuration) }
        router.get("/account/*") { [configuration] _, _ -> Response in staticAccountResponse(configuration: configuration) }
    }
}

private struct SignupPolicyView: Encodable {
    let policy = "closed"
    let inviteCodeRequired = false
    let capabilities = [String]()
}

private func staticAccountResponse(configuration: SwanAccountPortalConfiguration) -> Response {
    let file = configuration.staticDirectory.appending(path: "index.html")
    guard let data = try? Data(contentsOf: file) else { return accountError(.serviceUnavailable) }
    return Response(status: .ok, headers: [.contentType: "text/html; charset=utf-8", .cacheControl: "no-cache", HTTPField.Name("Content-Security-Policy")!: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'"], body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func staticAuthCSSResponse(configuration: SwanAccountPortalConfiguration) -> Response {
    let file = configuration.staticDirectory.appending(path: "auth-tokens.css")
    guard let data = try? Data(contentsOf: file) else { return accountError(.serviceUnavailable) }
    return Response(status: .ok, headers: [.contentType: "text/css; charset=utf-8", .cacheControl: "public, max-age=3600"], body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func mutationHeadersAllow(_ request: Request, expectedOrigin: URL) -> Bool {
    sameOrigin(request, expected: expectedOrigin) && fetchSiteAllows(request, requireHeader: true) && (request.headers[.contentType]?.lowercased().hasPrefix("application/json") == true)
}

private func sameOrigin(_ request: Request, expected: URL) -> Bool {
    guard let origin = request.headers[HTTPField.Name("Origin")!], let expectedComponents = URLComponents(url: expected, resolvingAgainstBaseURL: false), let actual = URL(string: origin), let actualComponents = URLComponents(url: actual, resolvingAgainstBaseURL: false) else { return false }
    return actualComponents.scheme?.lowercased() == expectedComponents.scheme?.lowercased() && actualComponents.host?.lowercased() == expectedComponents.host?.lowercased() && (actualComponents.port ?? (actualComponents.scheme == "https" ? 443 : 80)) == (expectedComponents.port ?? (expectedComponents.scheme == "https" ? 443 : 80))
}

private func originPermits(_ request: Request, expected: URL) -> Bool {
    request.headers[HTTPField.Name("Origin")!] == nil || sameOrigin(request, expected: expected)
}

private func fetchSiteAllows(_ request: Request, requireHeader: Bool = false) -> Bool {
    guard let site = request.headers[HTTPField.Name("Sec-Fetch-Site")!] else { return !requireHeader }
    return site == "same-origin" || site == "none"
}

private func accountCookie(named name: String, request: Request) -> String? { request.headers[values: .cookie].first.flatMap { header in header.split(separator: ";").map(String.init).first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("\(name)=") }.map { String($0.trimmingCharacters(in: .whitespaces).dropFirst(name.count + 1)) } } }
private func constantTime(_ lhs: String, _ rhs: String) -> Bool { guard lhs.utf8.count == rhs.utf8.count else { return false }; var result: UInt8 = 0; for (a, b) in zip(lhs.utf8, rhs.utf8) { result |= a ^ b }; return result == 0 }

private func accountJSON(_ status: HTTPResponse.Status, _ body: some Encodable, cookies: [String] = []) -> Response { var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]; for cookie in cookies { headers.append(.init(name: HTTPField.Name("Set-Cookie")!, value: cookie)) }; let data = (try? JSONEncoder().encode(body)) ?? Data("{}".utf8); return Response(status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data))) }
private enum AccountStatus { case ok, unauthorized, forbidden, notFound, serviceUnavailable }
private func accountError(_ status: AccountStatus) -> Response { let code = switch status { case .unauthorized: "authentication_required"; case .forbidden: "request_not_allowed"; case .notFound: "not_found"; case .serviceUnavailable: "service_unavailable"; case .ok: "ok" }; let http: HTTPResponse.Status = switch status { case .unauthorized: .unauthorized; case .forbidden: .forbidden; case .notFound: .notFound; case .serviceUnavailable: .serviceUnavailable; case .ok: .ok }; return accountJSON(http, ["code": code, "message": code == "request_not_allowed" ? "Request not allowed." : "The account service is unavailable."]) }
private func managementCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=\(value); Path=/account; Secure; HttpOnly; SameSite=Strict" }
private func csrfCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func preAuthCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func expiredPreAuthCookie() -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
private func expiredManagementCookie() -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=; Path=/account; Secure; HttpOnly; SameSite=Strict; Max-Age=0" }
private func expiredCSRFToken() -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
