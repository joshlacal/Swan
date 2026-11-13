import Crypto
import Foundation
import PetrelCrypto
import SwanSpaces

/// RFC 9421 response-MAC profile used by AT Protocol Spaces.
public enum SpaceMACHeaders {
    public static let requestHeader = "Accept-Signature"
    public static let signatureInputHeader = "Signature-Input"
    public static let signatureHeader = "Signature"
    public static let commitHeader = "Atproto-Space-Commit"
    public static let recordHeader = "Atproto-Space-Record"
    public static let algorithm = "hmac-sha256"
    private static let maximumFieldBytes = 8 * 1_024

    public enum Profile: String, Sendable, Equatable {
        case commit = "atproto-space-commit"
        case record = "atproto-space-record"

        public var coveredHeader: String {
            switch self {
            case .commit: SpaceMACHeaders.commitHeader
            case .record: SpaceMACHeaders.recordHeader
            }
        }
    }

    public struct Request: Sendable, Equatable {
        public let label: String
        public let keyID: String
        public let profile: Profile
        public let signatureParameters: String

        public var headerValue: String { "\(label)=\(signatureParameters)" }
    }

    public struct ResponseHeaders: Sendable, Equatable {
        public let coveredHeaderName: String
        public let coveredHeaderValue: String
        public let signatureInput: String
        public let signature: String
    }

    /// All failures have one fixed diagnostic and map to `InvalidSpaceMac`.
    public enum HeaderError: Error, Sendable, Equatable {
        case invalidSpaceMAC
    }

    public static func makeRequest(
        keyID: String,
        profile: Profile,
        label: String = "mac"
    ) throws -> Request {
        guard validDictionaryKey(label), (try? P256DIDKey(keyID)) != nil else {
            throw HeaderError.invalidSpaceMAC
        }
        var componentParameters = StructuredFieldParameters()
        componentParameters.set("sf", .boolean(true))
        var parameters = StructuredFieldParameters()
        parameters.set("keyid", .string(keyID))
        parameters.set("tag", .string(profile.rawValue))
        let signatureParameters = StructuredFieldSerializer.serialize(
            StructuredFieldInnerList(
                items: [.init(value: .string(profile.rawValue), parameters: componentParameters)],
                parameters: parameters
            )
        )
        return Request(
            label: label,
            keyID: keyID,
            profile: profile,
            signatureParameters: signatureParameters
        )
    }

    /// Finds the one request tagged for `profile`. Members with other tags are
    /// ignored; malformed fields and duplicate matching members are rejected.
    public static func parseRequest(
        _ values: [String],
        profile: Profile
    ) throws -> Request? {
        guard !values.isEmpty else { return nil }
        let combined = values.joined(separator: ", ")
        guard !combined.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              combined.utf8.count <= maximumFieldBytes else {
            throw HeaderError.invalidSpaceMAC
        }
        let dictionary: StructuredFieldDictionary
        do {
            dictionary = try StructuredFieldParser.parseDictionary(combined)
        } catch {
            throw HeaderError.invalidSpaceMAC
        }
        let tagged = taggedMembers(in: dictionary, profile: profile)
        guard tagged.count <= 1 else { throw HeaderError.invalidSpaceMAC }
        guard let (label, input) = tagged.first else { return nil }
        guard input.items.count == 1,
              exactComponent(input.items[0], profile: profile) else {
            throw HeaderError.invalidSpaceMAC
        }
        for parameter in input.parameters.entries {
            switch parameter.key {
            case "keyid", "tag", "alg": break
            default: throw HeaderError.invalidSpaceMAC
            }
        }
        if let algorithm = input.parameters["alg"],
           algorithm != .string(Self.algorithm) {
            throw HeaderError.invalidSpaceMAC
        }
        guard case let .string(keyID)? = input.parameters["keyid"],
              (try? P256DIDKey(keyID)) != nil else {
            throw HeaderError.invalidSpaceMAC
        }
        return Request(
            label: label,
            keyID: keyID,
            profile: profile,
            signatureParameters: StructuredFieldSerializer.serialize(input)
        )
    }

    public static func parseRequest(
        _ value: String?,
        profile: Profile
    ) throws -> Request? {
        try parseRequest(value.map { [$0] } ?? [], profile: profile)
    }

    public static func commitResponse(
        _ commit: SpaceRepositoryCommit,
        request: Request,
        sharedSecret: Data
    ) throws -> ResponseHeaders {
        var fields = StructuredFieldDictionary()
        fields.set("ver", item(.integer(Int64(commit.ver))))
        fields.set("repo", item(.string(commit.repo)))
        fields.set("space", item(.string(commit.space.rawValue)))
        fields.set("rev", item(.string(commit.rev)))
        fields.set("data", item(.byteSequence(commit.data)))
        return try response(
            profile: .commit,
            fields: fields,
            request: request,
            sharedSecret: sharedSecret
        )
    }

    public static func recordResponse(
        uri: String,
        cid: String,
        request: Request,
        sharedSecret: Data
    ) throws -> ResponseHeaders {
        var fields = StructuredFieldDictionary()
        fields.set("uri", item(.string(uri)))
        fields.set("cid", item(.string(cid)))
        return try response(
            profile: .record,
            fields: fields,
            request: request,
            sharedSecret: sharedSecret
        )
    }

    public static func verifyCommit(
        _ commit: SpaceRepositoryCommit,
        request: Request,
        sharedSecret: Data,
        coveredHeader: String?,
        signatureInput: String?,
        signature: String?
    ) throws {
        let fields = try verify(
            profile: .commit,
            request: request,
            sharedSecret: sharedSecret,
            coveredHeader: coveredHeader,
            signatureInput: signatureInput,
            signature: signature
        )
        guard bareItem(fields, "ver") == .integer(Int64(commit.ver)),
              bareItem(fields, "repo") == .string(commit.repo),
              bareItem(fields, "space") == .string(commit.space.rawValue),
              bareItem(fields, "rev") == .string(commit.rev),
              bareItem(fields, "data") == .byteSequence(commit.data) else {
            throw HeaderError.invalidSpaceMAC
        }
    }

    public static func verifyRecord(
        uri: String,
        cid: String,
        request: Request,
        sharedSecret: Data,
        coveredHeader: String?,
        signatureInput: String?,
        signature: String?
    ) throws {
        let fields = try verify(
            profile: .record,
            request: request,
            sharedSecret: sharedSecret,
            coveredHeader: coveredHeader,
            signatureInput: signatureInput,
            signature: signature
        )
        guard bareItem(fields, "uri") == .string(uri),
              bareItem(fields, "cid") == .string(cid) else {
            throw HeaderError.invalidSpaceMAC
        }
    }

    private static func response(
        profile: Profile,
        fields: StructuredFieldDictionary,
        request: Request,
        sharedSecret: Data
    ) throws -> ResponseHeaders {
        guard request.profile == profile, sharedSecret.count == SHA256.byteCount else {
            throw HeaderError.invalidSpaceMAC
        }
        let covered = serialize(fields)
        let base = signatureBase(
            profile: profile,
            coveredHeader: covered,
            signatureParameters: request.signatureParameters
        )
        let mac = Data(HMAC<SHA256>.authenticationCode(
            for: base,
            using: SymmetricKey(data: sharedSecret)
        ))
        return ResponseHeaders(
            coveredHeaderName: profile.coveredHeader,
            coveredHeaderValue: covered,
            signatureInput: request.headerValue,
            signature: "\(request.label)=:\(mac.base64EncodedString()):"
        )
    }

    private static func verify(
        profile: Profile,
        request: Request,
        sharedSecret: Data,
        coveredHeader: String?,
        signatureInput: String?,
        signature: String?
    ) throws -> StructuredFieldDictionary {
        guard request.profile == profile,
              sharedSecret.count == SHA256.byteCount,
              let coveredHeader,
              let signatureInput,
              let signature,
              coveredHeader.utf8.count <= maximumFieldBytes,
              signatureInput.utf8.count <= maximumFieldBytes,
              signature.utf8.count <= maximumFieldBytes else {
            throw HeaderError.invalidSpaceMAC
        }
        let fields: StructuredFieldDictionary
        let inputs: StructuredFieldDictionary
        let signatures: StructuredFieldDictionary
        do {
            fields = try StructuredFieldParser.parseDictionary(coveredHeader)
            inputs = try StructuredFieldParser.parseDictionary(signatureInput)
            signatures = try StructuredFieldParser.parseDictionary(signature)
        } catch {
            throw HeaderError.invalidSpaceMAC
        }
        let tagged = taggedMembers(in: inputs, profile: profile)
        guard tagged.count == 1 else { throw HeaderError.invalidSpaceMAC }
        let (label, input) = tagged[0]
        guard input.items.count == 1,
              exactComponent(input.items[0], profile: profile) else {
            throw HeaderError.invalidSpaceMAC
        }
        if let algorithm = input.parameters["alg"],
           algorithm != .string(Self.algorithm) {
            throw HeaderError.invalidSpaceMAC
        }
        if let keyID = input.parameters["keyid"],
           keyID != .string(request.keyID) {
            throw HeaderError.invalidSpaceMAC
        }
        guard case let .item(signatureItem)? = signatures[label],
              case let .byteSequence(mac) = signatureItem.value,
              signatureItem.parameters.isEmpty,
              mac.count == SHA256.byteCount else {
            throw HeaderError.invalidSpaceMAC
        }
        let base = signatureBase(
            profile: profile,
            coveredHeader: serialize(fields),
            signatureParameters: StructuredFieldSerializer.serialize(input)
        )
        guard HMAC<SHA256>.isValidAuthenticationCode(
            mac,
            authenticating: base,
            using: SymmetricKey(data: sharedSecret)
        ) else {
            throw HeaderError.invalidSpaceMAC
        }
        return fields
    }

    private static func taggedMembers(
        in dictionary: StructuredFieldDictionary,
        profile: Profile
    ) -> [(String, StructuredFieldInnerList)] {
        dictionary.entries.compactMap { entry in
            guard case let .innerList(input) = entry.value,
                  input.parameters["tag"] == .string(profile.rawValue) else {
                return nil
            }
            return (entry.key, input)
        }
    }

    private static func exactComponent(
        _ item: StructuredFieldItem,
        profile: Profile
    ) -> Bool {
        item.value == .string(profile.rawValue)
            && item.parameters.entries.count == 1
            && item.parameters["sf"] == .boolean(true)
    }

    private static func signatureBase(
        profile: Profile,
        coveredHeader: String,
        signatureParameters: String
    ) -> Data {
        Data(
            """
            "\(profile.rawValue)";sf: \(coveredHeader)
            "@signature-params": \(signatureParameters)
            """.utf8
        )
    }

    private static func item(_ value: StructuredFieldBareItem) -> StructuredFieldMember {
        .item(.init(value: value, parameters: .init()))
    }

    private static func bareItem(
        _ dictionary: StructuredFieldDictionary,
        _ key: String
    ) -> StructuredFieldBareItem? {
        guard case let .item(item)? = dictionary[key] else { return nil }
        return item.value
    }

    /// Canonical RFC 8941 dictionary serialization. Entry order is preserved,
    /// as required when the result is used as an RFC 9421 `sf` component.
    private static func serialize(_ dictionary: StructuredFieldDictionary) -> String {
        dictionary.entries.map { entry in
            switch entry.value {
            case let .item(item):
                if item.value == .boolean(true) {
                    return entry.key + StructuredFieldSerializer.serialize(item.parameters)
                }
                return "\(entry.key)=\(StructuredFieldSerializer.serialize(item))"
            case let .innerList(list):
                return "\(entry.key)=\(StructuredFieldSerializer.serialize(list))"
            }
        }.joined(separator: ", ")
    }

    private static func validDictionaryKey(_ value: String) -> Bool {
        guard let first = value.utf8.first,
              (first == UInt8(ascii: "*") || (0x61 ... 0x7a).contains(first)) else {
            return false
        }
        return value.utf8.dropFirst().allSatisfy {
            (0x61 ... 0x7a).contains($0) || (0x30 ... 0x39).contains($0)
                || Array("_-.*".utf8).contains($0)
        }
    }
}
