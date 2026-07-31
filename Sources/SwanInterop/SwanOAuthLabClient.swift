import Crypto
import Foundation
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
    private var cookie: String?

    public init(
        issuer: URL,
        clientID: URL,
        redirectURI: URL,
        timeout: TimeInterval = 15,
        dpopKey: InteropDPoPKey = .init(),
        additionalTrustRootFile: URL? = nil
    ) throws {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.dpopKey = dpopKey
        http = try InteropHTTPClient(
            baseURL: issuer,
            timeout: timeout,
            additionalTrustRootFile: additionalTrustRootFile
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
            headers: ["Accept": "text/html"]
        )
        captureCookie(loginPage)
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
        captureCookie(consentPage)
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
              let code = components.queryItems?.first(where: { $0.name == "code" })?.value else {
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
        if let cookie { headers["Cookie"] = cookie }
        return headers
    }

    private func captureCookie(_ response: InteropHTTPResponse) {
        guard let value = response.header("set-cookie"),
              let first = value.split(separator: ";", maxSplits: 1).first,
              !first.isEmpty else { return }
        cookie = String(first)
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
