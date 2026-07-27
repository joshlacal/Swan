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
    runtime: SwanOAuthRuntime
) {
    router.post("/oauth/par") { request, _ async -> Response in
        await handleLocalhostPAR(
            request: request,
            issuer: configuration.issuer,
            runtime: runtime
        )
    }
}

private func handleLocalhostPAR(
    request: Request,
    issuer: URL,
    runtime: SwanOAuthRuntime
) async -> Response {
    let form: LocalhostPARForm
    do {
        form = try await parseLocalhostPARForm(from: request)
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
            scopes: ["atproto"],
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

private func parseLocalhostPARForm(from request: Request) async throws -> LocalhostPARForm {
    guard isFormURLEncoded(request.headers) else {
        throw LocalhostPARRequestError.malformed
    }
    let lengths = request.headers[values: .contentLength]
    guard lengths.count <= 1 else { throw LocalhostPARRequestError.malformed }
    if let length = lengths.first {
        guard let value = Int(length), value >= 0 else {
            throw LocalhostPARRequestError.malformed
        }
        guard value <= SwanLocalhostPARHTTP.maximumFormBytes else {
            throw LocalhostPARRequestError.payloadTooLarge
        }
    }
    let body: ByteBuffer
    do {
        body = try await request.body.collect(upTo: SwanLocalhostPARHTTP.maximumFormBytes)
    } catch is NIOTooManyBytesError {
        throw LocalhostPARRequestError.payloadTooLarge
    } catch {
        throw LocalhostPARRequestError.malformed
    }
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
    let allowed: Set<String> = [
        "client_id", "redirect_uri", "response_type", "scope", "state",
        "code_challenge", "code_challenge_method",
    ]
    guard Set(fields.keys) == allowed,
          fields["response_type"] == "code",
          fields["scope"] == "atproto",
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
    guard metadata.matchesRedirectURI(redirectURI) else {
        throw LocalhostPARRequestError.malformed
    }
    return LocalhostPARForm(
        clientID: clientID,
        redirectURI: redirectURI,
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
