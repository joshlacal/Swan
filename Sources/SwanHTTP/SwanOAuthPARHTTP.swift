import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import SwanCore
import SwanOAuth

/// The bounded wire size for the intentionally small localhost PAR bridge.
/// It accommodates a maximally-sized compact DPoP proof while preventing an
/// unauthenticated caller from making the public router buffer an arbitrary
/// form body.
enum SwanLocalhostPARHTTP {
    static let maximumFormBytes = 48 * 1024
    static let requestLifetime: TimeInterval = 90
    static let dpopNonceHeader = HTTPField.Name("DPoP-Nonce")!
}

private enum LocalhostPARRequestError: Error {
    case malformed
    case payloadTooLarge
}

private struct LocalhostPARForm: Sendable {
    let clientID: URL
    let redirectURI: URL
    /// Non-optional: an absent `scope` is rejected at form parse rather than
    /// substituted with the client's registered set (§6.5.9(b)).
    let scopes: Set<String>
    let state: String
    let codeChallenge: String
}

private struct LocalhostPARSuccess: Encodable {
    let requestURI: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case requestURI = "request_uri"
        case expiresIn = "expires_in"
    }
}

private struct LocalhostPARError: Encodable {
    let error: String
}

private struct UntrustedDPoPNonce: Decodable {
    let nonce: String
}

/// Registers the only intentionally live OAuth alpha endpoint. It is called
/// only after `SwanLocalhostPARConfiguration` has validated an HTTPS issuer,
/// and registration is absent entirely unless the caller opted in.
func registerLocalhostPAREndpoint(
    on router: Router<BasicRequestContext>,
    configuration: SwanLocalhostPARConfiguration,
    runtime: SwanOAuthRuntime,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    registerLocalhostPAREndpoint(
        on: router,
        issuer: configuration.issuer,
        runtime: runtime,
        requestBodyAdmission: requestBodyAdmission
    )
}

/// Internal overload used by the complete localhost browser bridge. Its
/// public configuration has already validated the same issuer, so we avoid a
/// force-try while retaining one exact PAR handler implementation.
func registerLocalhostPAREndpoint(
    on router: Router<BasicRequestContext>,
    issuer: URL,
    runtime: SwanOAuthRuntime,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    router.post("/oauth/par") { request, context async -> Response in
        await handleLocalhostPAR(
            request: request,
            context: context,
            issuer: issuer,
            runtime: runtime,
            requestBodyAdmission: requestBodyAdmission
        )
    }
}

private func handleLocalhostPAR(
    request: Request,
    context: SwanHTTPRequestContext,
    issuer: URL,
    runtime: SwanOAuthRuntime,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
    let form: LocalhostPARForm
    do {
        form = try await parseLocalhostPARForm(
            from: request,
            context: context,
            requestBodyAdmission: requestBodyAdmission
        )
    } catch let failure as SwanRequestBodyCollectionFailure {
        return switch failure {
        case .invalidRequest: localhostPARError(.badRequest)
        case .payloadTooLarge: localhostPARError(.contentTooLarge)
        case .unavailable:
            localhostPARError(.serviceUnavailable, error: "temporarily_unavailable")
        }
    } catch let error as LocalhostPARRequestError {
        return switch error {
        case .malformed:
            localhostPARError(.badRequest)
        case .payloadTooLarge:
            localhostPARError(.contentTooLarge)
        }
    } catch {
        return localhostPARError(.badRequest)
    }

    // The nonce claim is deliberately read only to bind an untrusted proof to
    // the validator. The validator verifies the JWT signature, re-decodes the
    // payload with duplicate-member rejection, validates the nonce MAC and
    // lifetime, then compares the signed claim to this candidate.
    guard let proof = singleDPoPProof(from: request.headers),
          let presentedNonce = untrustedNonce(from: proof) else {
        return localhostPARNonceChallenge(runtime: runtime)
    }
    let dpopProof: OAuthValidatedDPoPProof
    do {
        let validator = try OAuthDPoPProofValidator(runtime: runtime)
        let target = issuer.appending(path: "oauth/par")
        let binding = try OAuthDPoPRequest(
            method: "POST",
            target: target,
            serverNonce: presentedNonce
        )
        dpopProof = try await validator.validate(proof, request: binding)
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostPARError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        // Missing, malformed, expired, invalid, and replayed proofs all get
        // the same no-store challenge and fresh nonce. Do not distinguish a
        // DPoP predicate in a network-visible response.
        return localhostPARNonceChallenge(runtime: runtime)
    } catch {
        return localhostPARNonceChallenge(runtime: runtime)
    }

    do {
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: form.clientID)
        let client = OAuthResolvedClientMetadata(metadata: metadata, keySet: nil)
        let session = try OAuthValidatedSession(
            issuer: issuer.absoluteString,
            client: client,
            redirectURI: form.redirectURI,
            // §6.5.9(b): this used to read `form.scopes ?? metadata.scopes`, so
            // a PAR with no `scope` parameter at all was silently granted the
            // client's ENTIRE registered set. `parseLocalhostPARForm` now
            // rejects an absent `scope`, matching the remote path (whose
            // `oauthServerScopes(fields["scope"] ?? "")` rejects the empty
            // string) and upstream (`request-manager.ts:177` → empty set → hard
            // `InvalidScopeError` at `:241`).
            //
            // §9-D21 makes this a precondition rather than a cleanup: client
            // metadata is now validated lexically only, so the registered set is
            // "strings the client typed", not a vetted set. Substituting it for
            // an absent request would grant an UNVETTED set, because the
            // semantic admission checks that would have caught a malformed or
            // unknown scope live one layer later, on the path this substitution
            // bypassed.
            scopes: form.scopes,
            dpopProof: dpopProof
        )
        let requestURI = try await runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: form.state,
            codeChallengeS256: form.codeChallenge,
            lifetime: SwanLocalhostPARHTTP.requestLifetime
        )
        return localhostPARJSON(
            .created,
            LocalhostPARSuccess(
                requestURI: requestURI,
                expiresIn: Int(SwanLocalhostPARHTTP.requestLifetime)
            )
        )
    } catch let error as OAuthScopeAdmissionError {
        // A scope admission failure is a 400, not the 503 the generic arm below
        // would produce. The code comes from the error so this bridge and the
        // remote AS report the same thing; it describes the request's own text
        // and discloses nothing about the deployment (§4.8).
        return localhostPARError(.badRequest, error: error.oauthErrorCode)
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostPARError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        // This endpoint has no client-specific OAuth error surface. In
        // particular, state reuse and a malformed local virtual document are
        // deliberately indistinguishable to the caller.
        return localhostPARError(.badRequest)
    } catch {
        // Durable control-plane availability is distinct from malformed form
        // input but still has no secret- or deployment-shaped detail.
        return localhostPARError(.serviceUnavailable, error: "temporarily_unavailable")
    }
}

private func parseLocalhostPARForm(
    from request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> LocalhostPARForm {
    let body = try await collectAdmittedRequestBody(
        request,
        mediaType: .formURLEncoded,
        admission: requestBodyAdmission.admission,
        policy: requestBodyAdmission.policy,
        maximumBytes: SwanLocalhostPARHTTP.maximumFormBytes,
        termination: context.jsonWriteBodyTermination
    )
    defer { withExtendedLifetime(body) {} }
    guard body.readableBytes > 0,
          let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
        throw LocalhostPARRequestError.malformed
    }
    let fields = try strictFormFields(bytes)
    return try validateLocalhostPARFields(fields)
}

private func isFormURLEncoded(_ headers: HTTPFields) -> Bool {
    let values = headers[values: .contentType]
    guard values.count == 1 else { return false }
    let pieces = values[0].split(separator: ";", omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    guard pieces.first?.lowercased() == "application/x-www-form-urlencoded" else {
        return false
    }
    // A UTF-8 charset is the only optional media-type parameter this bounded
    // decoder understands. Unknown parameters could change form semantics.
    return pieces.count == 1 || pieces.count == 2 && pieces[1].lowercased() == "charset=utf-8"
}

private func strictFormFields(_ bytes: [UInt8]) throws -> [String: String] {
    guard bytes.count <= SwanLocalhostPARHTTP.maximumFormBytes else {
        throw LocalhostPARRequestError.payloadTooLarge
    }
    var values: [String: String] = [:]
    var componentStart = 0
    for index in 0 ... bytes.count {
        if index == bytes.count || bytes[index] == UInt8(ascii: "&") {
            guard index > componentStart else { throw LocalhostPARRequestError.malformed }
            let component = bytes[componentStart ..< index]
            guard let separator = component.firstIndex(of: UInt8(ascii: "=")),
                  separator != component.startIndex else {
                throw LocalhostPARRequestError.malformed
            }
            let key = try strictFormDecode(component[..<separator])
            let value = try strictFormDecode(component[component.index(after: separator)...])
            guard values[key] == nil else { throw LocalhostPARRequestError.malformed }
            values[key] = value
            componentStart = index + 1
        }
    }
    return values
}

private func strictFormDecode(_ encoded: some Collection<UInt8>) throws -> String {
    var decoded = [UInt8]()
    decoded.reserveCapacity(encoded.count)
    var iterator = encoded.makeIterator()
    while let byte = iterator.next() {
        switch byte {
        case UInt8(ascii: "+"):
            decoded.append(UInt8(ascii: " "))
        case UInt8(ascii: "%"):
            guard let high = iterator.next(), let low = iterator.next(),
                  let highNibble = hexNibble(high), let lowNibble = hexNibble(low) else {
                throw LocalhostPARRequestError.malformed
            }
            decoded.append(highNibble << 4 | lowNibble)
        case 0 ... 31, 127:
            throw LocalhostPARRequestError.malformed
        default:
            decoded.append(byte)
        }
    }
    guard let value = String(bytes: decoded, encoding: .utf8),
          !value.utf8.contains(0) else {
        throw LocalhostPARRequestError.malformed
    }
    return value
}

private func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case UInt8(ascii: "0") ... UInt8(ascii: "9"): byte - UInt8(ascii: "0")
    case UInt8(ascii: "A") ... UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
    case UInt8(ascii: "a") ... UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
    default: nil
    }
}

private func validateLocalhostPARFields(_ fields: [String: String]) throws -> LocalhostPARForm {
    let required: Set<String> = [
        "client_id", "redirect_uri", "response_type", "scope", "state",
        "code_challenge", "code_challenge_method",
    ]
    // `login_hint` and `prompt` are hints ATProto clients send with every
    // sign-in (the atproto-oauth Rust crate includes the typed handle as
    // `login_hint` unconditionally). This server always presents the
    // interactive login form — a conforming answer to `login`, `consent`,
    // and `select_account`, but not to `none`, which demands a silent
    // answer it can never give, so `none` stays refused.
    // `response_mode` is sent unconditionally by `@atproto/oauth-client-node`,
    // which defaults it to `query`. Refusing the parameter refuses every client
    // built on that library before it can even reach the DPoP stage. Only
    // `query` is accepted: this server hands the code back as query parameters
    // on the client's redirect URI, so accepting `fragment` or `form_post`
    // would promise a delivery it does not implement.
    let permitted: Set<String> = [
        "client_id", "redirect_uri", "response_type", "scope", "state",
        "code_challenge", "code_challenge_method", "login_hint", "prompt",
        "response_mode",
    ]
    guard fields.keys.allSatisfy({ permitted.contains($0) }),
          required.subtracting(["scope"]).isSubset(of: Set(fields.keys)),
          fields["login_hint"].map({ !$0.isEmpty && $0.utf8.count <= 2_048 }) ?? true,
          fields["prompt"].map({ ["login", "consent", "select_account"].contains($0) }) ?? true,
          fields["response_mode"].map({ $0 == "query" }) ?? true,
          fields["response_type"] == "code",
          fields["code_challenge_method"] == "S256",
          let clientIDText = fields["client_id"],
          let redirectURIText = fields["redirect_uri"],
          let state = fields["state"],
          let codeChallenge = fields["code_challenge"],
          clientIDText.utf8.count <= 4_096,
          redirectURIText.utf8.count <= 4_096,
          state.utf8.count > 0, state.utf8.count <= 4_096,
          validS256Challenge(codeChallenge),
          let clientID = URL(string: clientIDText), clientID.absoluteString == clientIDText,
          let redirectURI = URL(string: redirectURIText), redirectURI.absoluteString == redirectURIText else {
        throw LocalhostPARRequestError.malformed
    }
    let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
    // An absent `scope` is a malformed request, not "grant everything declared"
    // (§6.5.9(b)). The subset check itself has moved to stage C inside
    // `OAuthScopeAdmissionPolicy`, which canonicalises both sides (§9-D7).
    guard let scopes = try OAuthClientMetadata.localhostRequestedScopes(fields["scope"]),
          metadata.matchesRedirectURI(redirectURI) else {
        throw LocalhostPARRequestError.malformed
    }
    return LocalhostPARForm(
        clientID: clientID,
        redirectURI: redirectURI,
        scopes: scopes,
        state: state,
        codeChallenge: codeChallenge
    )
}

private func validS256Challenge(_ value: String) -> Bool {
    value.utf8.count == 43 && value.utf8.allSatisfy { byte in
        (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
            (48 ... 57).contains(byte) || byte == 45 || byte == 95
    }
}

private func singleDPoPProof(from headers: HTTPFields) -> String? {
    let name = HTTPField.Name("DPoP")!
    let values = headers[values: name]
    guard values.count == 1,
          !values[0].isEmpty,
          values[0].utf8.count <= 32_768,
          !values[0].utf8.contains(0) else {
        return nil
    }
    return values[0]
}

private func untrustedNonce(from proof: String) -> String? {
    let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3,
          let payload = try? OAuthBase64URL.decode(String(parts[1]), maxBytes: 16_384),
          let claims = try? JSONDecoder().decode(UntrustedDPoPNonce.self, from: payload),
          !claims.nonce.isEmpty,
          claims.nonce.utf8.count <= 4_096,
          !claims.nonce.utf8.contains(0) else {
        return nil
    }
    return claims.nonce
}

private func localhostPARNonceChallenge(runtime: SwanOAuthRuntime) -> Response {
    var headers = HTTPFields()
    headers[.contentType] = "application/json"
    headers[.cacheControl] = "no-store"
    headers[SwanLocalhostPARHTTP.dpopNonceHeader] = runtime.dpopNonceService.issue()
    headers[.wwwAuthenticate] = "DPoP error=\"use_dpop_nonce\""
    let data = (try? JSONEncoder().encode(LocalhostPARError(error: "use_dpop_nonce"))) ?? Data("{}".utf8)
    return Response(status: .badRequest, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func localhostPARError(
    _ status: HTTPResponse.Status,
    error: String = "invalid_request"
) -> Response {
    localhostPARJSON(status, LocalhostPARError(error: error))
}

private func localhostPARJSON(_ status: HTTPResponse.Status, _ body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
