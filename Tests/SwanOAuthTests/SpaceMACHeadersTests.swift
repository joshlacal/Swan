import Crypto
import Foundation
import PetrelCrypto
import SwanOAuth
import SwanSpaces
import XCTest

final class SpaceMACHeadersTests: XCTestCase {
    func testRFC9180ExportOnlyP256Vector() throws {
        let enc = try data(
            hex: "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d"
        )
        let author = try P256.KeyAgreement.PrivateKey(rawRepresentation: data(
            hex: "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346"
        ))
        let keyID = P256DIDKey(
            publicKey: try P256.Signing.PublicKey(x963Representation: enc)
        ).value
        let secret = try SpaceMACKeyAgreement.receive(
            authorPrivateKey: author,
            keyID: keyID
        )
        XCTAssertEqual(
            secret,
            try data(
                hex: "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d"
            )
        )
        let commit = try SpaceRepositoryCommit(
            repo: "did:plc:repositoryabcdefghij",
            space: SpaceURI(
                "at://did:plc:authorityabcdefghijk/space/app.swan.test/mac"
            ),
            rev: "222222222222a",
            data: Data(repeating: 0x42, count: 32)
        )
        let response = try SpaceMACHeaders.commitResponse(
            commit,
            request: SpaceMACHeaders.makeRequest(
                keyID: keyID,
                profile: .commit
            ),
            sharedSecret: secret
        )
        XCTAssertEqual(
            response.signature,
            "mac=:xCPECWbx8rgn1iZ9L7/E2FoV5gckdutbG+crTBD+du4=:"
        )
    }

    func testRequestParsingByTagAndStrictProfileRequirements() throws {
        let keyID = try didKey(P256.KeyAgreement.PrivateKey())
        let request = try SpaceMACHeaders.makeRequest(
            keyID: keyID,
            profile: .commit,
            label: "chosen"
        )
        XCTAssertEqual(
            request.headerValue,
            #"chosen=("atproto-space-commit";sf);keyid="\#(keyID)";tag="atproto-space-commit""#
        )
        XCTAssertEqual(
            try SpaceMACHeaders.parseRequest(
                [request.headerValue],
                profile: .commit
            ),
            request
        )

        let other = #"other=("atproto-space-record";sf);keyid="\#(keyID)";tag="atproto-space-record";nonce="ignored""#
        XCTAssertNil(try SpaceMACHeaders.parseRequest([other], profile: .commit))
        XCTAssertEqual(
            try SpaceMACHeaders.parseRequest(
                [other, request.headerValue],
                profile: .commit
            ),
            request
        )

        let failures = [
            "",
            #"a=("atproto-space-commit");keyid="\#(keyID)";tag="atproto-space-commit""#,
            #"a=("atproto-space-record";sf);keyid="\#(keyID)";tag="atproto-space-commit""#,
            #"a=("atproto-space-commit";sf);keyid="did:key:invalid";tag="atproto-space-commit""#,
            #"a=("atproto-space-commit";sf);keyid="\#(keyID)";tag="atproto-space-commit";alg="sha-256""#,
            #"a=("atproto-space-commit";sf);keyid="\#(keyID)";tag="atproto-space-commit";created=1"#,
            request.headerValue + ", second=" + request.signatureParameters,
        ]
        for value in failures {
            XCTAssertThrowsError(
                try SpaceMACHeaders.parseRequest([value], profile: .commit),
                value
            ) {
                XCTAssertEqual(
                    $0 as? SpaceMACHeaders.HeaderError,
                    .invalidSpaceMAC
                )
            }
        }

        let withAlgorithm = request.headerValue + #";alg="hmac-sha256""#
        XCTAssertEqual(
            try XCTUnwrap(
                SpaceMACHeaders.parseRequest([withAlgorithm], profile: .commit)
            ).keyID,
            keyID
        )
    }

    func testCommitAndRecordProfilesRoundTripAndRejectMismatches() throws {
        let author = P256.KeyAgreement.PrivateKey()
        let exchange = try SpaceMACKeyAgreement.send(
            authorKeyID: try didKey(author)
        )
        let received = try SpaceMACKeyAgreement.receive(
            authorPrivateKey: author,
            keyID: exchange.keyID
        )
        XCTAssertEqual(received, exchange.sharedSecret)

        let commitRequest = try SpaceMACHeaders.makeRequest(
            keyID: exchange.keyID,
            profile: .commit,
            label: "client"
        )
        let commit = try SpaceRepositoryCommit(
            repo: "did:plc:repositoryabcdefghij",
            space: SpaceURI(
                "at://did:plc:authorityabcdefghijk/space/app.swan.test/mac"
            ),
            rev: "222222222222a",
            data: Data(repeating: 0x42, count: 32)
        )
        let commitHeaders = try SpaceMACHeaders.commitResponse(
            commit,
            request: commitRequest,
            sharedSecret: received
        )
        XCTAssertEqual(commitHeaders.coveredHeaderName, "Atproto-Space-Commit")
        XCTAssertEqual(
            commitHeaders.coveredHeaderValue,
            #"ver=1, repo="did:plc:repositoryabcdefghij", space="at://did:plc:authorityabcdefghijk/space/app.swan.test/mac", rev="222222222222a", data=:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=:"#
        )
        XCTAssertTrue(commitHeaders.signatureInput.hasPrefix("client="))
        XCTAssertTrue(commitHeaders.signature.hasPrefix("client=:"))
        let otherInput = try SpaceMACHeaders.makeRequest(
            keyID: exchange.keyID,
            profile: .record,
            label: "other"
        )
        try SpaceMACHeaders.verifyCommit(
            commit,
            request: commitRequest,
            sharedSecret: received,
            coveredHeader: commitHeaders.coveredHeaderValue,
            signatureInput: otherInput.headerValue + ", "
                + commitHeaders.signatureInput,
            signature: "other=:AA==:, " + commitHeaders.signature
        )
        for invalidInput in [
            commitHeaders.signatureInput + ", duplicate="
                + commitRequest.signatureParameters,
            #"client=("atproto-space-record";sf);keyid="\#(exchange.keyID)";tag="atproto-space-commit""#,
            commitHeaders.signatureInput + ";alg=\"sha-256\"",
        ] {
            XCTAssertThrowsError(try SpaceMACHeaders.verifyCommit(
                commit,
                request: commitRequest,
                sharedSecret: received,
                coveredHeader: commitHeaders.coveredHeaderValue,
                signatureInput: invalidInput,
                signature: commitHeaders.signature
            ))
        }
        try verify(commit, request: commitRequest, secret: received, headers: commitHeaders)

        var wrongSecret = received
        wrongSecret[wrongSecret.startIndex] ^= 1
        XCTAssertThrowsError(
            try verify(
                commit,
                request: commitRequest,
                secret: wrongSecret,
                headers: commitHeaders
            )
        )
        let differentCommit = try SpaceRepositoryCommit(
            repo: commit.repo,
            space: commit.space,
            rev: "222222222222b",
            data: commit.data
        )
        XCTAssertThrowsError(
            try verify(
                differentCommit,
                request: commitRequest,
                secret: received,
                headers: commitHeaders
            )
        )

        let otherExchange = try SpaceMACKeyAgreement.send(
            authorKeyID: try didKey(author)
        )
        let mismatchedKeyInput = commitHeaders.signatureInput.replacingOccurrences(
            of: exchange.keyID,
            with: otherExchange.keyID
        )
        XCTAssertThrowsError(try SpaceMACHeaders.verifyCommit(
            commit,
            request: commitRequest,
            sharedSecret: received,
            coveredHeader: commitHeaders.coveredHeaderValue,
            signatureInput: mismatchedKeyInput,
            signature: commitHeaders.signature
        ))

        let recordRequest = try SpaceMACHeaders.makeRequest(
            keyID: exchange.keyID,
            profile: .record
        )
        let uri = commit.space.rawValue
            + "/did:plc:repositoryabcdefghij/app.swan.test/record"
        let cid = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
        let recordHeaders = try SpaceMACHeaders.recordResponse(
            uri: uri,
            cid: cid,
            request: recordRequest,
            sharedSecret: received
        )
        try SpaceMACHeaders.verifyRecord(
            uri: uri,
            cid: cid,
            request: recordRequest,
            sharedSecret: received,
            coveredHeader: recordHeaders.coveredHeaderValue,
            signatureInput: recordHeaders.signatureInput,
            signature: recordHeaders.signature
        )
        XCTAssertThrowsError(try SpaceMACHeaders.verifyRecord(
            uri: uri,
            cid: cid + "changed",
            request: recordRequest,
            sharedSecret: received,
            coveredHeader: recordHeaders.coveredHeaderValue,
            signatureInput: recordHeaders.signatureInput,
            signature: recordHeaders.signature
        ))
    }

    private func verify(
        _ commit: SpaceRepositoryCommit,
        request: SpaceMACHeaders.Request,
        secret: Data,
        headers: SpaceMACHeaders.ResponseHeaders
    ) throws {
        try SpaceMACHeaders.verifyCommit(
            commit,
            request: request,
            sharedSecret: secret,
            coveredHeader: headers.coveredHeaderValue,
            signatureInput: headers.signatureInput,
            signature: headers.signature
        )
    }

    private func didKey(_ key: P256.KeyAgreement.PrivateKey) throws -> String {
        P256DIDKey(
            publicKey: try P256.Signing.PublicKey(
                x963Representation: key.publicKey.x963Representation
            )
        ).value
    }

    private func data(hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else {
            throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
        }
        var bytes = Data()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< end], radix: 16) else {
                throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
            }
            bytes.append(byte)
            index = end
        }
        return bytes
    }
}
