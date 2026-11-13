import Foundation
import Hummingbird
import HTTPTypes
import SwanOAuth

struct SpaceResponseMACContext: Sendable {
    let request: SpaceMACHeaders.Request
    let sharedSecret: Data
}

/// Called only after route authentication. Credential reads require their
/// profile's request; owner OAuth reads may opt in. Other tags are ignored.
func spaceResponseMACRequest(
    request: Request,
    author: String,
    profile: SpaceMACHeaders.Profile,
    provider: (any SpaceRepositoryCommitSigner)?
) async throws -> SpaceResponseMACContext? {
    let values = request.headers[values: HTTPField.Name(SpaceMACHeaders.requestHeader)!]
    let credentialRead = try spaceCredentialSchemeToken(from: request.headers) != nil
    do {
        guard let requested = try SpaceMACHeaders.parseRequest(values, profile: profile) else {
            if credentialRead { throw SpaceMACHeaders.HeaderError.invalidSpaceMAC }
            return nil
        }
        guard let provider else { throw SpaceMACHeaders.HeaderError.invalidSpaceMAC }
        return try await SpaceResponseMACContext(
            request: requested,
            sharedSecret: provider.sharedSecret(author: author, keyID: requested.keyID)
        )
    } catch {
        throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
    }
}

func withSpaceResponseMAC(
    _ response: Response,
    headers mac: SpaceMACHeaders.ResponseHeaders?
) -> Response {
    var response = response
    appendHeader(SpaceMACHeaders.requestHeader, named: "Vary", to: &response.headers)
    if let mac {
        response.headers[HTTPField.Name(mac.coveredHeaderName)!] = mac.coveredHeaderValue
        response.headers[HTTPField.Name(SpaceMACHeaders.signatureInputHeader)!] = mac.signatureInput
        response.headers[HTTPField.Name(SpaceMACHeaders.signatureHeader)!] = mac.signature
    }
    return response
}

private func appendHeader(
    _ value: String,
    named name: String,
    to headers: inout HTTPFields
) {
    let field = HTTPField.Name(name)!
    var values = headers[field]?
        .split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespaces) } ?? []
    guard !values.contains(where: { $0.caseInsensitiveCompare(value) == .orderedSame }) else {
        return
    }
    values.append(value)
    headers[field] = values.joined(separator: ", ")
}
