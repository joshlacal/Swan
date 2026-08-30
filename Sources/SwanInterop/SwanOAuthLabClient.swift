import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanOAuth

/// A per-session P-256 DPoP key. The private key is intentionally not
/// Codable, printable, or accepted by fixture recording; it lives only for
/// the lifetime of the in-memory lab client.
public struct InteropDPoPKey: @unchecked Sendable {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        privateKey = P256.Signing.PrivateKey()
    }

    public var publicJWK: OAuthJSONWebKey {
        get throws {
            let bytes = privateKey.publicKey.x963Representation
            return try OAuthJSONWebKey(
                x: Data(bytes.dropFirst().prefix(32)).base64URLEncodedString(),
                y: Data(bytes.dropFirst(33).prefix(32)).base64URLEncodedString(),
                algorithm: nil,
                use: nil
            )
        }
    }

    public var thumbprint: String {
        get throws { try publicJWK.thumbprint() }
    }

    /// Creates a fresh proof for one exact request target. A new `jti` is
    /// generated every time, including retries after a nonce challenge.
    public func proof(
        method: String,
        target: URL,
        nonce: String,
        accessToken: String? = nil,
        now: Date = Date()
    ) throws -> String {
        guard !nonce.isEmpty, nonce.utf8.count <= 4_096,
              let normalizedMethod = method.uppercased().nilIfEmpty else {
            throw SwanError.malformed("DPoP proof inputs are invalid")
        }
        let header = Header(jwk: try publicJWK)
        var claims = Claims(
            method: normalizedMethod,
            target: try OAuthDPoPProofValidator.normalizedTarget(target),
            issuedAt: Int64(now.timeIntervalSince1970),
            jwtID: UUID().uuidString,
            nonce: nonce,
            accessTokenHash: nil
        )
        if let accessToken {
            guard !accessToken.isEmpty else { throw SwanError.malformed("DPoP access token is empty") }
            claims.ath = Data(SHA256.hash(data: Data(accessToken.utf8)))
                .base64URLEncodedString()
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let headerPart = try encoder.encode(header).base64URLEncodedString()
        let payloadPart = try encoder.encode(claims).base64URLEncodedString()
        let signingInput = Data("\(headerPart).\(payloadPart)".utf8)
        let signature = try P256WireSignature.sign(signingInput, using: privateKey)
        return "\(headerPart).\(payloadPart).\(signature.base64URLEncodedString())"
    }

    private struct Header: Encodable {
        let alg = "ES256"
        let typ = OAuthDPoPProofValidator.proofType
        let jwk: OAuthJSONWebKey
    }

    private struct Claims: Encodable {
        let htm: String
        let htu: String
        let iat: Int64
        let jti: String
        let nonce: String
        var ath: String?

        init(
            method: String,
            target: String,
            issuedAt: Int64,
            jwtID: String,
            nonce: String,
            accessTokenHash: String?
        ) {
            htm = method
            htu = target
            iat = issuedAt
            jti = jwtID
            self.nonce = nonce
            ath = accessTokenHash
        }
    }
}

public struct InteropOAuthToken: Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String?
    public let scope: Set<String>
    public let subject: String
    public let expiresIn: Int

    public init(
        accessToken: String,
        refreshToken: String?,
        scope: Set<String>,
        subject: String,
        expiresIn: Int
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.scope = scope
        self.subject = subject
        self.expiresIn = expiresIn
    }
}

/// An in-memory browser/DPoP driver for Swan's complete OAuth authorization
/// server. It deliberately exposes tokens only through an in-memory value and
/// never hands cookies, passwords, or proof material to the fixture recorder.
public actor SwanOAuthLabClient {
    public let issuer: URL
    public let clientID: URL
    public let redirectURI: URL
    public let dpopKey: InteropDPoPKey

    private let http: InteropHTTPClient
    private var nonce: String?
    private var cookies: [String: String] = [:]

    public init(
        issuer: URL,
        clientID: URL,
        redirectURI: URL,
        timeout: TimeInterval = 15,
        dpopKey: InteropDPoPKey = .init(),
        additionalTrustRootFile: URL? = nil,
        executeHandler: InteropHTTPExecuteHandler? = nil
    ) throws {
        try requireCredentialSafeTransport(issuer)
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.dpopKey = dpopKey
        http = try InteropHTTPClient(
            baseURL: issuer,
            timeout: timeout,
            additionalTrustRootFile: additionalTrustRootFile,
            executeHandler: executeHandler
        )
    }

    public func authorizationCode(
        handle: String,
        password: String,
        scopes: Set<String>,
        state: String = UUID().uuidString
    ) async throws -> InteropOAuthToken {
        let verifier = randomVerifier()
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let par = try await pushAuthorizationRequest(
            scopes: scopes,
            state: state,
            codeChallenge: challenge
        )
        let authorizePath = try Self.queryPath(
            "/oauth/authorize",
            [
                URLQueryItem(name: "client_id", value: clientID.absoluteString),
                URLQueryItem(name: "request_uri", value: par.requestURI),
            ]
        )
        let loginPage = try await http.execute(
            method: .get,
            path: authorizePath,
            headers: [
                "Accept": "text/html",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Dest": "document",
            ]
        )
        captureCookies(loginPage)

        // Swan renders a conventional HTML form. The pinned TypeScript
        // provider renders a client-side page and exposes the same flow as
        // same-origin JSON APIs instead. Keep the two protocols explicit so
        // a missing HTML field cannot silently weaken the reference provider's
        // CSRF/referrer/session checks.
        guard let loginHTML = String(data: loginPage.body, encoding: .utf8) else {
            throw InteropHTTPError.unexpectedContentType
        }
        guard loginHTML.contains("name=\"csrf\"") else {
            return try await referenceAuthorizationCode(
                authorizePath: authorizePath,
                requestURI: par.requestURI,
                handle: handle,
                password: password,
                scopes: scopes,
                verifier: verifier,
                state: state
            )
        }

        let loginCSRF = try hiddenFormValue(named: "csrf", in: loginPage.body)
        let loginBody = formEncode([
            ("csrf", loginCSRF), ("handle", handle), ("password", password),
        ])
        let consentPage = try await http.execute(
            method: .post,
            path: "/oauth/authorize",
            headers: browserHeaders(contentType: "application/x-www-form-urlencoded"),
            body: loginBody
        )
        captureCookies(consentPage)
        let consentCSRF = try hiddenFormValue(named: "csrf", in: consentPage.body)
        let redirect = try await http.execute(
            method: .post,
            path: "/oauth/authorize/consent",
            headers: browserHeaders(contentType: "application/x-www-form-urlencoded"),
            body: formEncode([("csrf", consentCSRF), ("decision", "approve")])
        )
        guard (300 ... 399).contains(redirect.status),
              let location = redirect.header("location"),
              let locationURL = URL(string: location),
              let components = URLComponents(url: locationURL, resolvingAgainstBaseURL: false),
              let code = components.queryItems?.first(where: { $0.name == "code" })?.value,
              components.queryItems?.first(where: { $0.name == "state" })?.value == state,
              Self.sameRedirectTarget(locationURL, expected: redirectURI) else {
            throw InteropHTTPError.unexpectedStatus(redirect.status)
        }
        return try await redeemAuthorizationCode(
            code: code,
            verifier: verifier,
            state: state
        )
    }

    public func refresh(_ token: InteropOAuthToken) async throws -> InteropOAuthToken {
        guard let refreshToken = token.refreshToken else {
            throw SwanError.unauthorized("refresh token is unavailable")
        }
        let body = formEncode([
            ("grant_type", "refresh_token"),
            ("client_id", clientID.absoluteString),
            ("refresh_token", refreshToken),
        ])
        return try await tokenRequest(body: body)
    }

    /// Produces a per-request authorization provider for a live interop host.
    /// The provider binds each proof to the exact method/URL supplied by the
    /// runner; the token and DPoP key remain inside this actor and are never
    /// passed to fixture serialization.
    public func authorizationProvider(
        for token: InteropOAuthToken
    ) -> InteropAuthorizationProvider {
        { [self] method, target, _ in
            try await self.resourceAuthorization(
                token: token,
                method: method.rawValue,
                target: target
            )
        }
    }

    /// Performs one resource request with a fresh DPoP proof and transparently
    /// retries once after a valid `DPoP-Nonce` challenge.
    public func resourceAuthorization(
        token: InteropOAuthToken,
        method: String,
        target: URL
    ) async throws -> InteropAuthorization {
        let targetPath = try resourcePath(target)
        guard let currentNonce = nonce else {
            let challenge = try await http.execute(
                method: method == "GET" ? .get : .post,
                path: targetPath,
                headers: ["Authorization": "DPoP " + token.accessToken]
            )
            guard let challenged = challenge.header("dpop-nonce") else {
                throw InteropHTTPError.unexpectedStatus(challenge.status)
            }
            nonce = challenged
            return try await resourceAuthorization(token: token, method: method, target: target)
        }
        let proof = try dpopKey.proof(
            method: method,
            target: target,
            nonce: currentNonce,
            accessToken: token.accessToken
        )
        return .dpop(accessToken: token.accessToken, proof: proof)
    }

    public func executeResource(
        token: InteropOAuthToken,
        method: InteropHTTPMethod,
        path: String,
        body: Data? = nil
    ) async throws -> InteropHTTPResponse {
        guard let target = URL(string: path, relativeTo: issuer)?.absoluteURL else {
            throw SwanError.malformed("resource path is invalid")
        }
        for attempt in 0..<2 {
            if nonce == nil {
                let challenge = try await http.execute(
                    method: method,
                    path: path,
                    headers: ["Authorization": "DPoP \(token.accessToken)"],
                    body: body
                )
                guard let challenged = challenge.header("dpop-nonce") else {
                    return challenge
                }
                self.nonce = challenged
            }
            guard let currentNonce = self.nonce else {
                throw SwanError.unavailable("DPoP nonce unavailable")
            }
            let proof = try dpopKey.proof(
                method: method.rawValue,
                target: target,
                nonce: currentNonce,
                accessToken: token.accessToken
            )
            var headers = ["Authorization": "DPoP \(token.accessToken)", "DPoP": proof]
            headers["Accept"] = "application/json"
            if body != nil { headers["Content-Type"] = "application/json" }
            let response = try await http.execute(method: method, path: path, headers: headers, body: body)
            if response.status == 401, let challenged = response.header("dpop-nonce"), attempt == 0 {
                self.nonce = challenged
                continue
            }
            return response
        }
        throw SwanError.unavailable("DPoP resource request exhausted nonce retries")
    }

    private struct PARResponse: Decodable {
        let requestURI: String
        private enum CodingKeys: String, CodingKey {
            case requestURI = "request_uri"
        }
    }

    private struct TokenResponse: Decodable {
        let accessToken: String
        let refreshToken: String?
        let scope: String
        let subject: String
        let expiresIn: Int
        private enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case scope, subject = "sub", expiresIn = "expires_in"
        }
    }

    private struct ReferenceSignInResponse: Decodable {
        struct Account: Decodable {
            let did: String
        }

        let account: Account
        let ephemeralToken: String?
    }

    private struct ReferenceConsentResponse: Decodable {
        let url: String
    }

    private func referenceAuthorizationCode(
        authorizePath: String,
        requestURI: String,
        handle: String,
        password: String,
        scopes: Set<String>,
        verifier: String,
        state: String
    ) async throws -> InteropOAuthToken {
        let authorizeURL = try absoluteURL(for: authorizePath)
        guard let csrf = cookies["csrf-token"], csrf.utf8.count == 24 else {
            throw SwanError.malformed("reference OAuth page did not set a CSRF cookie")
        }

        let signIn = try await http.execute(
            method: .post,
            path: "/@atproto/oauth-provider/~api/sign-in",
            headers: referenceAPIHeaders(
                authorizeURL: authorizeURL,
                csrf: csrf,
                authorization: nil
            ),
            body: try JSONEncoder().encode(
                ReferenceSignInRequest(
                    locale: "en",
                    username: handle,
                    password: password,
                    remember: false
                )
            )
        )
        guard (200 ... 299).contains(signIn.status) else {
            throw InteropHTTPError.unexpectedStatus(signIn.status)
        }
        captureCookies(signIn)
        let signedIn = try StrictJSON.decode(ReferenceSignInResponse.self, from: signIn.body)
        guard !signedIn.account.did.isEmpty,
              let ephemeralToken = signedIn.ephemeralToken,
              !ephemeralToken.isEmpty else {
            throw SwanError.malformed("reference OAuth sign-in did not return a bounded session")
        }

        guard let refreshedCSRF = cookies["csrf-token"], refreshedCSRF.utf8.count == 24 else {
            throw SwanError.malformed("reference OAuth sign-in lost its CSRF cookie")
        }
        let consent = try await http.execute(
            method: .post,
            path: "/@atproto/oauth-provider/~api/consent",
            headers: referenceAPIHeaders(
                authorizeURL: authorizeURL,
                csrf: refreshedCSRF,
                authorization: "Bearer \(ephemeralToken)"
            ),
            body: try JSONEncoder().encode(
                ReferenceConsentRequest(
                    did: signedIn.account.did,
                    scope: scopes.sorted().joined(separator: " ")
                )
            )
        )
        guard (200 ... 299).contains(consent.status) else {
            throw InteropHTTPError.unexpectedStatus(consent.status)
        }
        let consentResult = try StrictJSON.decode(ReferenceConsentResponse.self, from: consent.body)
        guard let redirectURL = URL(string: consentResult.url, relativeTo: issuer)?.absoluteURL,
              let redirectComponents = URLComponents(url: redirectURL, resolvingAgainstBaseURL: false),
              redirectComponents.path == "/oauth/authorize/redirect",
              redirectComponents.fragment == nil,
              redirectComponents.queryItems?.first(where: { $0.name == "redirect_mode" })?.value == "query",
              redirectComponents.queryItems?.first(where: { $0.name == "redirect_uri" })?.value == redirectURI.absoluteString,
              redirectComponents.queryItems?.first(where: { $0.name == "iss" })?.value == issuer.absoluteString,
              redirectComponents.queryItems?.first(where: { $0.name == "state" })?.value == state,
              let code = redirectComponents.queryItems?.first(where: { $0.name == "code" })?.value,
              !code.isEmpty,
              URLComponents(url: authorizeURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_uri" })?.value == requestURI else {
            throw SwanError.malformed("reference OAuth consent returned an invalid redirect")
        }

        // The pinned provider deliberately returns an issuer-local browser
        // URL from the JSON consent API. A browser navigates to that URL and
        // receives one 303 to the registered client redirect. Follow exactly
        // that one hop ourselves; never let AsyncHTTPClient follow an
        // unvalidated redirect or treat the API response as the final code.
        let redirectPath = try issuerRelativePath(
            redirectURL,
            expectedPath: "/oauth/authorize/redirect"
        )
        let redirectResponse = try await http.execute(
            method: .get,
            path: redirectPath,
            headers: referenceNavigationHeaders(authorizeURL: authorizeURL)
        )
        guard redirectResponse.status == 303,
              let location = redirectResponse.header("location"),
              let locationURL = URL(string: location, relativeTo: issuer)?.absoluteURL,
              let locationComponents = URLComponents(url: locationURL, resolvingAgainstBaseURL: false),
              let finalCode = locationComponents.queryItems?.first(where: { $0.name == "code" })?.value,
              !finalCode.isEmpty,
              locationComponents.queryItems?.first(where: { $0.name == "state" })?.value == state,
              Self.sameRedirectTarget(locationURL, expected: redirectURI) else {
            throw SwanError.malformed("reference OAuth redirect hop was invalid")
        }
        return try await redeemAuthorizationCode(
            code: finalCode,
            verifier: verifier,
            state: state
        )
    }

    private struct ReferenceConsentRequest: Encodable {
        let did: String
        let scope: String
    }

    private struct ReferenceSignInRequest: Encodable {
        let locale: String
        let username: String
        let password: String
        let remember: Bool
    }

    private func pushAuthorizationRequest(
        scopes: Set<String>,
        state: String,
        codeChallenge: String
    ) async throws -> PARResponse {
        let body = formEncode([
            ("client_id", clientID.absoluteString),
            ("redirect_uri", redirectURI.absoluteString),
            ("response_type", "code"),
            ("scope", scopes.sorted().joined(separator: " ")),
            ("state", state),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
        ])
        let initial = try await http.execute(
            method: .post,
            path: "/oauth/par",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )
        if let challenged = initial.header("dpop-nonce") {
            nonce = challenged
        }
        guard let nonce else { throw InteropHTTPError.unexpectedStatus(initial.status) }
        let target = issuer.appending(path: "oauth/par")
        let proof = try dpopKey.proof(method: "POST", target: target, nonce: nonce)
        let response = try await http.execute(
            method: .post,
            path: "/oauth/par",
            headers: [
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": proof,
            ],
            body: body
        )
        guard (200 ... 299).contains(response.status) else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
        return try StrictJSON.decode(PARResponse.self, from: response.body)
    }

    private func redeemAuthorizationCode(
        code: String,
        verifier: String,
        state: String
    ) async throws -> InteropOAuthToken {
        _ = state
        let body = formEncode([
            ("grant_type", "authorization_code"),
            ("client_id", clientID.absoluteString),
            ("redirect_uri", redirectURI.absoluteString),
            ("code", code),
            ("code_verifier", verifier),
        ])
        return try await tokenRequest(body: body)
    }

    private func tokenRequest(body: Data) async throws -> InteropOAuthToken {
        let initial = try await http.execute(
            method: .post,
            path: "/oauth/token",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )
        if let challenged = initial.header("dpop-nonce") {
            nonce = challenged
        }
        guard let nonce else { throw InteropHTTPError.unexpectedStatus(initial.status) }
        let proof = try dpopKey.proof(
            method: "POST",
            target: issuer.appending(path: "oauth/token"),
            nonce: nonce
        )
        let response = try await http.execute(
            method: .post,
            path: "/oauth/token",
            headers: [
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": proof,
            ],
            body: body
        )
        guard (200 ... 299).contains(response.status) else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
        let decoded = try StrictJSON.decode(TokenResponse.self, from: response.body)
        return InteropOAuthToken(
            accessToken: decoded.accessToken,
            refreshToken: decoded.refreshToken,
            scope: Set(decoded.scope.split(separator: " ").map(String.init)),
            subject: decoded.subject,
            expiresIn: decoded.expiresIn
        )
    }

    private func browserHeaders(contentType: String) -> [String: String] {
        var headers = ["Content-Type": contentType, "Accept": "text/html"]
        if let cookieHeader { headers["Cookie"] = cookieHeader }
        return headers
    }

    private var cookieHeader: String? {
        guard !cookies.isEmpty else { return nil }
        return cookies.keys.sorted().compactMap { name in
            guard let value = cookies[name] else { return nil }
            return "\(name)=\(value)"
        }.joined(separator: "; ")
    }

    private func captureCookies(_ response: InteropHTTPResponse) {
        guard let value = response.header("set-cookie") else { return }
        // InteropHTTPClient combines repeated headers with commas. The
        // reference provider's cookie values are bounded hex/JWT strings and
        // never contain commas, so splitting each Set-Cookie segment is safe
        // and avoids retaining attributes or secret response metadata.
        for segment in value.split(separator: ",") {
            guard let assignment = segment.split(separator: ";", maxSplits: 1).first,
                  let separator = assignment.firstIndex(of: "=") else { continue }
            let name = String(assignment[..<separator])
                .trimmingCharacters(in: .whitespaces)
            let cookieValue = String(assignment[assignment.index(after: separator)...])
                .trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { continue }
            if cookieValue.isEmpty {
                cookies.removeValue(forKey: name)
            } else {
                cookies[name] = cookieValue
            }
        }
    }

    private func referenceAPIHeaders(
        authorizeURL: URL,
        csrf: String,
        authorization: String?
    ) -> [String: String] {
        var headers = [
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": issuerOrigin,
            "Referer": authorizeURL.absoluteString,
            "Sec-Fetch-Mode": "same-origin",
            "Sec-Fetch-Site": "same-origin",
            "X-CSRF-Token": csrf,
        ]
        if let cookieHeader { headers["Cookie"] = cookieHeader }
        if let authorization { headers["Authorization"] = authorization }
        return headers
    }

    private func referenceNavigationHeaders(authorizeURL: URL) -> [String: String] {
        var headers = [
            "Accept": "text/html",
            "Referer": authorizeURL.absoluteString,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "document",
        ]
        if let cookieHeader { headers["Cookie"] = cookieHeader }
        return headers
    }

    private var issuerOrigin: String {
        var components = URLComponents()
        components.scheme = issuer.scheme
        components.host = issuer.host
        components.port = issuer.port
        return components.string ?? issuer.absoluteString
    }

    private func absoluteURL(for path: String) throws -> URL {
        guard path.first == "/", !path.hasPrefix("//"),
              let url = URL(string: path, relativeTo: issuer)?.absoluteURL,
              url.scheme?.lowercased() == issuer.scheme?.lowercased(),
              url.host?.lowercased() == issuer.host?.lowercased(),
              url.port == issuer.port else {
            throw SwanError.malformed("OAuth path escaped its issuer")
        }
        return url
    }

    private func issuerRelativePath(_ target: URL, expectedPath: String) throws -> String {
        guard let components = URLComponents(url: target, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == issuer.scheme?.lowercased(),
              components.host?.lowercased() == issuer.host?.lowercased(),
              components.port == issuer.port,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              components.path == expectedPath else {
            throw SwanError.malformed("OAuth redirect escaped its issuer")
        }
        return components.percentEncodedPath
            + (components.percentEncodedQuery.map { "?\($0)" } ?? "")
    }

    // The registered redirect URI may legitimately acquire OAuth response
    // query items (code/state/iss), so the expected query is a subset rather
    // than an exact match.  Userinfo is never part of a registered redirect
    // target, however.  Treating `https://user@client.example/callback` as
    // the same target would hand an attacker-controlled authority component
    // to the browser/HTTP stack even though URLComponents reports the same
    // host.  Keep this check independently of the query-subset rule.
    static func sameRedirectTarget(_ actual: URL, expected: URL) -> Bool {
        guard let actualComponents = URLComponents(url: actual, resolvingAgainstBaseURL: false),
              let expectedComponents = URLComponents(url: expected, resolvingAgainstBaseURL: false) else {
            return false
        }
        guard actualComponents.user == nil,
              actualComponents.password == nil,
              expectedComponents.user == nil,
              expectedComponents.password == nil else {
            return false
        }
        let expectedQueryMatches = expectedComponents.queryItems?.allSatisfy { expectedItem in
            actualComponents.queryItems?.contains(expectedItem) == true
        } ?? true
        return actualComponents.scheme?.lowercased() == expectedComponents.scheme?.lowercased()
            && actualComponents.host?.lowercased() == expectedComponents.host?.lowercased()
            && actualComponents.port == expectedComponents.port
            && actualComponents.percentEncodedPath == expectedComponents.percentEncodedPath
            && actualComponents.percentEncodedFragment == expectedComponents.percentEncodedFragment
            && expectedQueryMatches
    }

    private func resourcePath(_ target: URL) throws -> String {
        guard let targetComponents = URLComponents(url: target, resolvingAgainstBaseURL: false),
              targetComponents.host?.lowercased() == issuer.host?.lowercased() else {
            throw SwanError.malformed("resource target is outside OAuth issuer")
        }
        return targetComponents.percentEncodedPath
            + (targetComponents.percentEncodedQuery.map { "?\($0)" } ?? "")
    }

    /// Builds an XHR/browser query path without allowing nested URLs in a
    /// query value to become top-level parameters.  `URLComponents` leaves
    /// characters such as `?` and `&` unescaped when it is handed a
    /// `URLQueryItem` value, which is incorrect for the localhost OAuth
    /// client metadata URL (`client_id=http://localhost?...`).  A server then
    /// sees a truncated client id and rejects the otherwise valid PAR binding
    /// with a browser-looking error page.
    static func queryPath(_ path: String, _ items: [URLQueryItem]) throws -> String {
        guard !path.isEmpty, path.first == "/", !path.contains("#") else {
            throw InteropHTTPError.invalidURL
        }

        let query = items.map { item in
            "\(percentEncodeQueryComponent(item.name))=\(percentEncodeQueryComponent(item.value ?? ""))"
        }.joined(separator: "&")
        return query.isEmpty ? path : "\(path)?\(query)"
    }

    private static func percentEncodeQueryComponent(_ value: String) -> String {
        let hexadecimal = Array("0123456789ABCDEF".utf8)
        var encoded = String()
        encoded.reserveCapacity(value.utf8.count)
        for byte in value.utf8 {
            switch byte {
            case 0x41 ... 0x5A, 0x61 ... 0x7A, 0x30 ... 0x39,
                 0x2D, 0x2E, 0x5F, 0x7E:
                encoded.append(Character(UnicodeScalar(byte)))
            default:
                encoded.append("%")
                encoded.append(Character(UnicodeScalar(hexadecimal[Int(byte >> 4)])))
                encoded.append(Character(UnicodeScalar(hexadecimal[Int(byte & 0x0F)])))
            }
        }
        return encoded
    }

    private func hiddenFormValue(named name: String, in data: Data) throws -> String {
        guard let html = String(data: data, encoding: .utf8) else {
            throw InteropHTTPError.unexpectedContentType
        }
        let marker = "name=\"\(name)\""
        guard let nameRange = html.range(of: marker),
              let valueMarker = html[nameRange.upperBound...].range(of: "value=\"") else {
            throw SwanError.malformed("OAuth form is missing CSRF field")
        }
        let valueStart = valueMarker.upperBound
        guard let end = html[valueStart...].firstIndex(of: "\"") else {
            throw SwanError.malformed("OAuth form is malformed")
        }
        return String(html[valueStart..<end])
    }

    private func formEncode(_ values: [(String, String)]) -> Data {
        var components = URLComponents()
        components.queryItems = values.map { URLQueryItem(name: $0.0, value: $0.1) }
        return Data((components.percentEncodedQuery ?? "").utf8)
    }

    private func randomVerifier() -> String {
        var bytes = Data(repeating: 0, count: 32)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytesCompat($0) }
        return bytes.base64URLEncodedString()
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

private func SecRandomCopyBytesCompat(_ bytes: UnsafeMutableRawBufferPointer) -> Int32 {
    for index in bytes.indices { bytes[index] = UInt8.random(in: 0 ... 255) }
    return 0
}
