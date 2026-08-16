import Foundation
import Crypto
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts
import SwanCore

/// A deliberately narrow service protocol: route assembly owns authentication
/// and this adapter owns HTTP policy; account/domain services remain injectable.
public protocol SwanAccountPortalServing: Sendable {
    func bootstrap(now: Date) async throws -> SwanAccountPortalBootstrap
    func authenticate(handle: String, password: String, now: Date) async throws -> SwanAccountPortalAuthentication
    func portal(accountDID: String, now: Date) async throws -> SwanAccountPortalSnapshot
    func mutate(path: String, accountDID: String, now: Date) async throws -> SwanAccountPortalMutation
}

public struct SwanAccountPortalAuthentication: Sendable, Equatable {
    public let accountDID: String
    public let strength: AuthenticationStrength
    public init(accountDID: String, strength: AuthenticationStrength = .password) {
        self.accountDID = accountDID
        self.strength = strength
    }
}

private struct PortalLoginCredentials: Decodable {
    let handle: String
    let password: String
    enum CodingKeys: String, CodingKey, CaseIterable { case handle, password }
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(container.allKeys) == Set(CodingKeys.allCases) else { throw PortalRequestError.malformed }
        handle = try container.decode(String.self, forKey: .handle)
        password = try container.decode(String.self, forKey: .password)
        guard (1...2_048).contains(handle.utf8.count), (1...4_096).contains(password.utf8.count),
              !handle.utf8.contains(0), !password.utf8.contains(0) else { throw PortalRequestError.malformed }
    }
}

private enum PortalRequestError: Error { case malformed, tooLarge }

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
              components.scheme?.lowercased() == "https", components.host != nil,
              components.user == nil, components.password == nil,
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
        router.get("/account/api/bootstrap") { [configuration, sessions] request, _ async -> Response in
            guard originPermits(request, expected: configuration.publicOrigin), fetchSiteAllows(request) else { return accountError(.forbidden) }
            let token = await sessions.issuePreAuth()
            return accountJSON(.ok, SwanAccountPortalBootstrap(csrf: token), cookies: [preAuthCookie(token)])
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
        for path in ["session", "sessions", "profile", "identity", "app-passwords", "scope-presets", "factors", "connected-apps", "export", "migration", "signup/policy"] {
            router.get("/account/api/\(path)") { [sessions, service] request, _ async -> Response in
                guard let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let metadata = try? await sessions.authenticate(sessionValue: session) else { return accountError(.unauthorized) }
                do { return accountJSON(.ok, try await service.portal(accountDID: metadata.accountDID, now: Date())) }
                catch { return accountError(.serviceUnavailable) }
            }
        }

        router.post("/account/api/login") { [configuration, sessions, service] request, context async -> Response in
            guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                  let csrf = accountCookie(named: SwanManagementSessionRuntime.preAuthCookieName, request: request),
                  let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                  constantTime(csrf, header), await sessions.consumePreAuth(csrf) else { return accountError(.forbidden) }
            do {
                let admitted = try await collectAdmittedRequestBody(request, mediaType: .json, admission: .managementProcessShared, policy: .productionDefault, maximumBytes: 16 * 1024, termination: context.jsonWriteBodyTermination)
                defer { admitted.release() }
                guard let bytes = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes) else { throw PortalRequestError.malformed }
                let credentials = try JSONDecoder().decode(PortalLoginCredentials.self, from: Data(bytes))
                let authentication = try await service.authenticate(handle: credentials.handle, password: credentials.password, now: Date())
                let issued = try await sessions.issue(accountDID: authentication.accountDID, strength: authentication.strength)
                let snapshot = try await service.portal(accountDID: authentication.accountDID, now: Date())
                return accountJSON(.ok, snapshot, cookies: [managementCookie(issued.sessionValue), csrfCookie(issued.csrfValue), expiredPreAuthCookie()])
            } catch is PortalRequestError { return accountError(.badRequest) }
            catch { return accountError(.unauthorized) }
        }

        for path in ["signup/email/request", "signup/authorize", "signup", "logout", "profile", "identity", "app-passwords", "scopes/validate", "factors", "factors/recovery-codes/rotate", "factors/step-up", "connected-apps", "export", "export/request", "migration", "migration/request", "lifecycle/delete", "step-up", "sessions/revoke-others"] {
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

        for path in ["sessions", "identity", "app-passwords", "factors/passkeys", "factors/totp", "connected-apps"] {
            router.on("/account/api/\(path)", method: .delete) { [configuration, sessions, service] request, _ async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!], constantTime(csrf, header),
                      (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else { return accountError(.forbidden) }
                do {
                    let metadata = try await sessions.authenticate(sessionValue: session)
                    return accountJSON(.ok, try await service.mutate(path: path, accountDID: metadata.accountDID, now: Date()))
                } catch { return accountError(.serviceUnavailable) }
            }
        }

        let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
        for method in methods {
            router.on("/account/api/*", method: method) { _, _ -> Response in accountError(.notFound) }
            router.on("/account/api/*/*", method: method) { _, _ -> Response in accountError(.notFound) }
        }

        router.get("/account") { [configuration] _, _ -> Response in staticAccountResponse(configuration: configuration, requestPath: "/account") }
        router.get("/account/auth-tokens.css") { [configuration] _, _ -> Response in staticAuthCSSResponse(configuration: configuration) }
        router.get("/account/*") { [configuration] request, _ -> Response in staticAccountResponse(configuration: configuration, requestPath: request.uri.path) }
    }
}

private struct SignupPolicyView: Encodable {
    let policy = "closed"
    let inviteCodeRequired = false
    let capabilities = [String]()
}

private func staticAccountResponse(configuration: SwanAccountPortalConfiguration, requestPath: String) -> Response {
    let relative = String(requestPath.dropFirst("/account".count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let hasExtension = relative.contains(".")
    let safeRelative = relative.isEmpty ? "index.html" : relative
    guard !safeRelative.contains(".."), !safeRelative.contains("\\") else { return accountError(.notFound) }
    let file = configuration.staticDirectory.appending(path: safeRelative)
    let data: Data?
    let responsePath: String
    if let asset = try? Data(contentsOf: file) {
        data = asset; responsePath = safeRelative
    } else if !hasExtension {
        // Only extensionless navigations receive the SPA shell. Missing
        // scripts, styles, images, and source maps remain ordinary 404s.
        data = try? Data(contentsOf: configuration.staticDirectory.appending(path: "index.html")); responsePath = "index.html"
    } else {
        data = nil; responsePath = safeRelative
    }
    guard let data else { return accountError(.notFound) }
    let contentType = staticContentType(for: responsePath)
    let cache = hasExtension && !safeRelative.hasSuffix(".html") ? "public, max-age=31536000, immutable" : "no-cache"
    let csp = staticCSP(for: data, contentType: contentType)
    return Response(status: .ok, headers: [.contentType: contentType, .cacheControl: cache, HTTPField.Name("Content-Security-Policy")!: csp], body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func staticCSP(for data: Data, contentType: String) -> String {
    var scriptSource = "'self'"
    if contentType.hasPrefix("text/html"), let html = String(data: data, encoding: .utf8),
       let start = html.range(of: "<script>"), let end = html.range(of: "</script>", range: start.upperBound..<html.endIndex) {
        let script = String(html[start.upperBound..<end.lowerBound])
        let digest = Data(SHA256.hash(data: Data(script.utf8))).base64EncodedString()
        scriptSource += " 'sha256-\(digest)'"
    }
    return "default-src 'none'; script-src \(scriptSource); style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
}

private func staticContentType(for path: String) -> String {
    switch path.split(separator: ".").last?.lowercased() {
    case "html": "text/html; charset=utf-8"
    case "css": "text/css; charset=utf-8"
    case "js", "mjs": "text/javascript; charset=utf-8"
    case "json", "map": "application/json; charset=utf-8"
    case "svg": "image/svg+xml"
    case "png": "image/png"
    case "jpg", "jpeg": "image/jpeg"
    case "woff": "font/woff"
    case "woff2": "font/woff2"
    default: "application/octet-stream"
    }
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
    guard actualComponents.user == nil, actualComponents.password == nil,
          actualComponents.path.isEmpty || actualComponents.path == "/",
          actualComponents.query == nil, actualComponents.fragment == nil else { return false }
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
private enum AccountStatus { case ok, badRequest, unauthorized, forbidden, notFound, serviceUnavailable }
private func accountError(_ status: AccountStatus) -> Response { let code = switch status { case .badRequest: "invalid_request"; case .unauthorized: "authentication_required"; case .forbidden: "request_not_allowed"; case .notFound: "not_found"; case .serviceUnavailable: "service_unavailable"; case .ok: "ok" }; let http: HTTPResponse.Status = switch status { case .badRequest: .badRequest; case .unauthorized: .unauthorized; case .forbidden: .forbidden; case .notFound: .notFound; case .serviceUnavailable: .serviceUnavailable; case .ok: .ok }; return accountJSON(http, ["code": code, "message": code == "request_not_allowed" ? "Request not allowed." : code == "invalid_request" ? "Invalid request." : "The account service is unavailable."]) }
private func managementCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=\(value); Path=/account; Secure; HttpOnly; SameSite=Strict" }
private func csrfCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func preAuthCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func expiredPreAuthCookie() -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
private func expiredManagementCookie() -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=; Path=/account; Secure; HttpOnly; SameSite=Strict; Max-Age=0" }
private func expiredCSRFToken() -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
