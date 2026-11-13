import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces

/// One fresh HPKE export for one HTTP request. Never persist the shared
/// secret or reuse this value for another page, retry, or endpoint.
struct PermissionedSpaceMACRequest: Sendable {
    let authorKEMKey: String
    let macRequest: SpaceMACHeaders.Request
    let sharedSecret: Data

    var header: String { macRequest.headerValue }

    var verifierIdentity: String {
        get throws { try Self.verifierIdentity(authorKEMKey: authorKEMKey) }
    }

    static func verifierIdentity(authorKEMKey: String) throws -> String {
        let key = try P256DIDKey(authorKEMKey).publicKey
        let domain = Data("swan.atproto-kem.v1\0".utf8)
        return "key-sha256:" + Hex.encode(Data(SHA256.hash(data: domain + key.compressedRepresentation)))
    }

    static func prepare(
        host: LiveInteropHost,
        repositoryDID: String,
        profile: SpaceMACHeaders.Profile,
        forceRefresh: Bool
    ) async throws -> Self {
        let key: String
        if let resolve = host.permissionedKEMKeyProvider {
            key = try await resolve(repositoryDID, forceRefresh)
        } else if let pinned = host.permissionedKEMKey {
            key = pinned
        } else {
            throw InteropHTTPError.transportFailure
        }
        let exchange = try SpaceMACKeyAgreement.send(authorKeyID: key)
        return Self(
            authorKEMKey: key,
            macRequest: try SpaceMACHeaders.makeRequest(
                keyID: exchange.keyID,
                profile: profile
            ),
            sharedSecret: exchange.sharedSecret
        )
    }

    func verify(
        _ commit: ComAtprotoSpaceDefs.Commit,
        space: SpaceURI,
        author: String,
        response: InteropHTTPResponse
    ) throws -> SpaceRepositoryCommit {
        let value = try SpaceRepositoryCommit(
            ver: commit.ver,
            repo: commit.repo.didString(),
            space: SpaceURI(commit.space.uriString()),
            rev: commit.rev.toString(),
            data: commit.data.data
        )
        try verify(value, space: space, author: author, response: response)
        return value
    }

    func verify(
        _ commit: SpaceRepositoryCommit,
        space: SpaceURI,
        author: String,
        response: InteropHTTPResponse
    ) throws {
        guard commit.repo == author, commit.space == space else {
            throw SpaceSTARError.wrongRepository
        }
        try SpaceMACHeaders.verifyCommit(
            commit,
            request: macRequest,
            sharedSecret: sharedSecret,
            coveredHeader: response.header(SpaceMACHeaders.commitHeader),
            signatureInput: response.header(SpaceMACHeaders.signatureInputHeader),
            signature: response.header(SpaceMACHeaders.signatureHeader)
        )
    }
}

package struct PermissionedSpaceMACResponse: Sendable {
    package let response: InteropHTTPResponse
    let request: PermissionedSpaceMACRequest
    let commit: SpaceRepositoryCommit?
}

/// Authentication-only network seam. It retries a failed response MAC once
/// after a cache-bypassing DID lookup, using a new HPKE export for the retry.
/// Error responses are returned for the endpoint's normal status handling.
package enum PermissionedSpaceMACHTTP {
    static func record(
        host: LiveInteropHost,
        query: [String: String],
        expectedURI: SpaceRecordURI,
        authorization: @Sendable () async throws -> InteropAuthorization
    ) async throws -> InteropHTTPResponse {
        for attempt in 0 ..< 2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host,
                repositoryDID: expectedURI.author,
                profile: .record,
                forceRefresh: attempt > 0
            )
            let response = try await host.client.query(
                "com.atproto.space.getRecord",
                query: query,
                authorization: authorization(),
                acceptSignature: request.header
            )
            guard (200 ... 299).contains(response.status) else { return response }
            guard response.header("content-type")?.lowercased().contains("json") == true else {
                throw InteropHTTPError.unexpectedContentType
            }
            let record = try StrictJSON.decode(
                ComAtprotoSpaceGetRecord.Output.self,
                from: response.body
            )
            guard record.uri.uriString() == expectedURI.rawValue else {
                throw SpaceSTARError.wrongRepository
            }
            // Bind the header's CID to the canonical bytes returned in the body.
            _ = try PermissionedRemoteReplicaIncrementalVerifier.canonicalValue(
                record.value,
                cid: record.cid
            )
            do {
                try SpaceMACHeaders.verifyRecord(
                    uri: record.uri.uriString(),
                    cid: record.cid.string,
                    request: request.macRequest,
                    sharedSecret: request.sharedSecret,
                    coveredHeader: response.header(SpaceMACHeaders.recordHeader),
                    signatureInput: response.header(SpaceMACHeaders.signatureInputHeader),
                    signature: response.header(SpaceMACHeaders.signatureHeader)
                )
                return response
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                continue
            }
        }
        throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
    }

    static func streamSTAR(
        host: LiveInteropHost,
        query: [String: String],
        space: SpaceURI,
        author: String,
        destination: URL,
        maximumBytes: Int,
        authorization: @Sendable () async throws -> InteropAuthorization
    ) async throws -> PermissionedSpaceMACResponse {
        for attempt in 0 ..< 2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host,
                repositoryDID: author,
                profile: .commit,
                forceRefresh: attempt > 0
            )
            let response = try await host.client.stream(
                "com.atproto.space.getRepo",
                query: query,
                authorization: authorization(),
                to: destination,
                maximumResponseBytes: maximumBytes,
                acceptSignature: request.header
            )
            guard (200 ... 299).contains(response.status) else {
                return .init(response: response, request: request, commit: nil)
            }
            guard response.header("content-type")?.lowercased()
                .split(separator: ";").first?
                .trimmingCharacters(in: .whitespaces) == SpaceSTARCodec.mediaType else {
                throw InteropHTTPError.unexpectedContentType
            }
            let handle = try FileHandle(forReadingFrom: destination)
            let prefix: Data
            do {
                prefix = try handle.read(
                    upToCount: SpaceSTARLimits.maximumMetadataBytes + 10
                ) ?? Data()
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            let commit = try SpaceSTARCodec.decodeMetadataPrefix(
                prefix,
                space: space,
                author: author
            )
            do {
                try request.verify(
                    commit,
                    space: space,
                    author: author,
                    response: response
                )
                return .init(response: response, request: request, commit: commit)
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                try FileManager.default.removeItem(at: destination)
            }
        }
        throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
    }

    package static func query(
        host: LiveInteropHost,
        nsid: String,
        query: [String: String],
        space: SpaceURI,
        author: String,
        authorization: @Sendable () async throws -> InteropAuthorization,
        commit: @Sendable (Data) throws -> ComAtprotoSpaceDefs.Commit?
    ) async throws -> PermissionedSpaceMACResponse {
        for attempt in 0 ..< 2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host,
                repositoryDID: author,
                profile: .commit,
                forceRefresh: attempt > 0
            )
            let response = try await host.client.query(
                nsid,
                query: query,
                authorization: authorization(),
                acceptSignature: request.header
            )
            guard (200 ... 299).contains(response.status) else {
                return .init(response: response, request: request, commit: nil)
            }
            guard response.header("content-type")?.lowercased().contains("json") == true else {
                throw InteropHTTPError.unexpectedContentType
            }
            do {
                guard let value = try commit(response.body) else {
                    throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
                }
                let verified = try request.verify(
                    value,
                    space: space,
                    author: author,
                    response: response
                )
                return .init(response: response, request: request, commit: verified)
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                continue
            }
        }
        throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
    }
}
