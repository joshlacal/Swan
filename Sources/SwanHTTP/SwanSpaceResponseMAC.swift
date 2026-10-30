import Foundation
import Hummingbird
import HTTPTypes
import PetrelCrypto
import SwanOAuth
import SwanSpaces

/// Called only after route authentication. Credential reads require a MAC
/// exchange even on pages which do not carry a terminal commit. Owner OAuth
/// reads can opt in without changing their existing authorization policy.
func spaceResponseMACSecret(
    request: Request,
    author: String,
    type: SpaceMACHeaders.MACType,
    provider: (any SpaceRepositoryCommitSigner)?
) async throws -> Data? {
    let values = request.headers[values: HTTPField.Name(SpaceMACHeaders.requestHeader)!]
    let credentialRead = try spaceCredentialSchemeToken(from: request.headers) != nil
    guard !values.isEmpty || credentialRead else { return nil }
    guard values.count == 1, let provider else { throw SpaceMACHeaders.HeaderError.badSpaceMAC }
    do {
        let wanted = try SpaceMACHeaders.parseWantMAC(values[0], type: type)
        return try await provider.sharedSecret(author: author, keyShare: wanted.keyShare)
    } catch {
        throw SpaceMACHeaders.HeaderError.badSpaceMAC
    }
}

func withSpaceResponseMAC(
    _ response: Response,
    mac: Data?,
    type: SpaceMACHeaders.MACType
) throws -> Response {
    var response = response
    let vary = HTTPField.Name("Vary")!
    let existing = response.headers[vary].map { $0 + ", " } ?? ""
    response.headers[vary] = existing + SpaceMACHeaders.requestHeader
    if let mac {
        response.headers[HTTPField.Name(SpaceMACHeaders.responseHeader)!] =
            try SpaceMACHeaders.formatMAC(mac, type: type)
    }
    response.headers[.accessControlExposeHeaders] = "DPoP-Nonce, WWW-Authenticate, Atproto-Space-Mac"
    return response
}
