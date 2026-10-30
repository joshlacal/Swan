import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces

/// One fresh KEM exchange for one HTTP request. Never persist the shared
/// secret or reuse this value for another page, retry, or endpoint.
struct PermissionedSpaceMACRequest: Sendable {
    let authorKEMKey: String
    let keyShare: String
    let sharedSecret: Data

    var header: String {
        get throws { try SpaceMACHeaders.formatWantMAC(keyShare: keyShare, type: .repository) }
    }

    var verifierIdentity: String {
        get throws { try Self.verifierIdentity(authorKEMKey: authorKEMKey) }
    }

    static func verifierIdentity(authorKEMKey: String) throws -> String {
        let key = try P256DIDKey(authorKEMKey).publicKey
        let domain = Data("swan.atproto-kem.v1\0".utf8)
        return "key-sha256:" + Hex.encode(Data(SHA256.hash(data: domain + key.compressedRepresentation)))
    }

    static func prepare(host: LiveInteropHost, repositoryDID: String, forceRefresh: Bool) async throws -> Self {
        let key: String
        if let resolve = host.permissionedKEMKeyProvider {
            key = try await resolve(repositoryDID, forceRefresh)
        } else if let pinned = host.permissionedKEMKey {
            key = pinned
        } else {
            throw InteropHTTPError.transportFailure
        }
        let exchange = try SpaceMAC.encapsulate(authorKey: key)
        return Self(authorKEMKey: key, keyShare: exchange.keyShare, sharedSecret: exchange.sharedSecret)
    }

    func verify(
        _ commit: ComAtprotoSpaceDefs.Commit, space: SpaceURI, author: String,
        header: String?
    ) throws -> SpaceRepositoryCommit {
        let value = try SpaceRepositoryCommit(
            ver: commit.ver, repo: commit.repo.didString(),
            space: SpaceURI(commit.space.uriString()), rev: commit.rev.toString(), data: commit.data.data
        )
        try verify(value, space: space, author: author, header: header)
        return value
    }

    func verify(_ commit: SpaceRepositoryCommit, space: SpaceURI, author: String, header: String?) throws {
        guard commit.repo == author, commit.space == space else { throw SpaceSTARError.wrongRepository }
        let mac = try SpaceMACHeaders.parseMAC(header, type: .repository)
        try SpaceMAC.verify(mac: mac, expected: commit.mac(sharedSecret: sharedSecret))
    }
}

package struct PermissionedSpaceMACResponse: Sendable {
    package let response: InteropHTTPResponse
    let request: PermissionedSpaceMACRequest
    let commit: SpaceRepositoryCommit?
}

/// Authentication-only network seam. It retries a failed MAC once after a
/// cache-bypassing KEM lookup, using a new ephemeral key for that retry.
/// Error responses are returned for the endpoint's normal status handling.
package enum PermissionedSpaceMACHTTP {
    static func record(
        host: LiveInteropHost, query: [String: String], expectedURI: SpaceRecordURI,
        authorization: @Sendable () async throws -> InteropAuthorization
    ) async throws -> InteropHTTPResponse {
        for attempt in 0..<2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host, repositoryDID: expectedURI.author, forceRefresh: attempt > 0
            )
            let response = try await host.client.query(
                "com.atproto.space.getRecord", query: query, authorization: authorization(),
                spaceWantMAC: SpaceMACHeaders.formatWantMAC(keyShare: request.keyShare, type: .record)
            )
            guard (200...299).contains(response.status) else { return response }
            guard response.header("content-type")?.lowercased().contains("json") == true else {
                throw InteropHTTPError.unexpectedContentType
            }
            let record = try StrictJSON.decode(ComAtprotoSpaceGetRecord.Output.self, from: response.body)
            guard record.uri.uriString() == expectedURI.rawValue else { throw SpaceSTARError.wrongRepository }
            // Authentication binds the URI and CID. Recompute that CID from
            // canonical record bytes before accepting the response value.
            _ = try PermissionedRemoteReplicaIncrementalVerifier.canonicalValue(record.value, cid: record.cid)
            do {
                try SpaceMAC.verify(
                    mac: SpaceMACHeaders.parseMAC(response.header(SpaceMACHeaders.responseHeader), type: .record),
                    expected: SpaceMAC.record(sharedSecret: request.sharedSecret, uri: record.uri.uriString(), cid: record.cid.bytes)
                )
                return response
            } catch SpaceMAC.Failure.mismatch where attempt == 0 {
                continue
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                continue
            }
        }
        throw SpaceMAC.Failure.mismatch
    }

    static func streamSTAR(
        host: LiveInteropHost, query: [String: String], space: SpaceURI, author: String,
        destination: URL, maximumBytes: Int,
        authorization: @Sendable () async throws -> InteropAuthorization
    ) async throws -> PermissionedSpaceMACResponse {
        for attempt in 0..<2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host, repositoryDID: author, forceRefresh: attempt > 0
            )
            let response = try await host.client.stream(
                "com.atproto.space.getRepo", query: query,
                authorization: authorization(), to: destination,
                maximumResponseBytes: maximumBytes, spaceWantMAC: request.header
            )
            guard (200...299).contains(response.status) else {
                return .init(response: response, request: request, commit: nil)
            }
            guard response.header("content-type")?.lowercased().split(separator: ";").first?.trimmingCharacters(in: .whitespaces) == SpaceSTARCodec.mediaType else {
                throw InteropHTTPError.unexpectedContentType
            }
            let handle = try FileHandle(forReadingFrom: destination)
            let prefix: Data
            do {
                prefix = try handle.read(upToCount: SpaceSTARLimits.maximumMetadataBytes + 10) ?? Data()
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            let commit = try SpaceSTARCodec.decodeMetadataPrefix(prefix, space: space, author: author)
            do {
                try request.verify(commit, space: space, author: author, header: response.header(SpaceMACHeaders.responseHeader))
                return .init(response: response, request: request, commit: commit)
            } catch SpaceMAC.Failure.mismatch where attempt == 0 {
                try FileManager.default.removeItem(at: destination)
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                try FileManager.default.removeItem(at: destination)
            }
        }
        throw SpaceMAC.Failure.mismatch
    }

    package static func query(
        host: LiveInteropHost, nsid: String, query: [String: String],
        space: SpaceURI, author: String,
        authorization: @Sendable () async throws -> InteropAuthorization,
        commit: @Sendable (Data) throws -> ComAtprotoSpaceDefs.Commit?
    ) async throws -> PermissionedSpaceMACResponse {
        for attempt in 0..<2 {
            let request = try await PermissionedSpaceMACRequest.prepare(
                host: host, repositoryDID: author, forceRefresh: attempt > 0
            )
            let response = try await host.client.query(
                nsid, query: query, authorization: authorization(), spaceWantMAC: request.header
            )
            guard (200...299).contains(response.status) else {
                return .init(response: response, request: request, commit: nil)
            }
            guard response.header("content-type")?.lowercased().contains("json") == true else {
                throw InteropHTTPError.unexpectedContentType
            }
            let value = try commit(response.body)
            do {
                if let value {
                    let verified = try request.verify(
                        value, space: space, author: author,
                        header: response.header(SpaceMACHeaders.responseHeader)
                    )
                    return .init(response: response, request: request, commit: verified)
                }
                // Only listRepoOps can omit the commit. Every page still got
                // its own request header; a commitless page has no MAC header.
                guard nsid == "com.atproto.space.listRepoOps",
                      response.header(SpaceMACHeaders.responseHeader) == nil else {
                    throw SpaceMACHeaders.HeaderError.badSpaceMAC
                }
                return .init(response: response, request: request, commit: nil)
            } catch SpaceMAC.Failure.mismatch where attempt == 0 {
                continue
            } catch is SpaceMACHeaders.HeaderError where attempt == 0 {
                continue
            }
        }
        throw SpaceMAC.Failure.mismatch
    }
}
