import Crypto
import Foundation
import PetrelCrypto

/// October 22 credential presentation profile of HTTP Message Signatures.
/// Covers the exact Authorization and Atproto-Space-Audience field bytes,
/// requires tag=atproto-space-credential, and verifies the credential's P-256
/// cnf.kid. Credential exchange carries its key identifier in the JSON body.
/// Ordinary OAuth DPoP is separate.
public enum SpaceHTTPSignature {
    public static let label = "atproto-space-credential"
    public static let algorithm = "ecdsa-p256-sha256"
    public static let authorizationComponent = "authorization"
    public static let audienceComponent = "atproto-space-audience"
    public static let audienceFieldName = "Atproto-Space-Audience"
    public static let signatureInputFieldName = "Signature-Input"
    public static let signatureFieldName = "Signature"
    /// Bounds each combined signature field before structured-field parsing.
    public static let maximumFieldBytes = 8 * 1_024

    /// The four header values used for credential presentation.
    public struct Headers: Sendable, Equatable {
        public let authorization: String
        public let audience: String?
        public let signatureInput: String
        public let signature: String
    }

    /// The canonical P-256 `did:key` of a signing key.
    public static func keyID(for key: P256.Signing.PrivateKey) -> String {
        P256DIDKey(publicKey: key.publicKey).value
    }

    /// Signs a credential presentation. A non-nil audience is required.
    /// The emitted signature input is the reference's minimal form; a
    /// verifier accepts any additional parameters a client chooses to add.
    public static func sign(
        authorization: String,
        audience: String? = nil,
        key: P256.Signing.PrivateKey
    ) throws -> Headers {
        guard audience != nil,
              authorization.lowercased().hasPrefix("atproto-space-credential ") else {
            throw SpaceHTTPSignatureError.wrongCoveredComponents
        }
        let signatureParams = "(\"\(authorizationComponent)\" \"\(audienceComponent)\");tag=\"\(label)\""
        let base = signatureBase(
            authorization: authorization,
            audience: audience,
            signatureParams: signatureParams
        )
        let signature = try P256WireSignature.sign(base, using: key)
        return Headers(
            authorization: authorization,
            audience: audience,
            signatureInput: "\(label)=\(signatureParams)",
            signature: "\(label)=:\(signature.base64EncodedString()):"
        )
    }

    /// Verifies an `atproto-space-credential` signature and returns the P-256 `did:key`
    /// that produced it.
    ///
    /// Every argument is the complete list of field lines received for that
    /// header, so duplicates are visible. `credentialKeyID == nil` selects the
    /// unsupported legacy shape; a non-nil value selects
    /// credential use, where `audience` must hold exactly one line.
    public static func verify(
        authorization: [String],
        audience: [String]?,
        signatureInput: [String],
        signature: [String],
        credentialKeyID: String?
    ) throws -> String {
        guard credentialKeyID != nil, authorization.count == 1 else {
            throw SpaceHTTPSignatureError.duplicateOrMissingField
        }
        let authorizationValue = trimmedFieldValue(authorization[0])
        guard authorizationValue.lowercased().hasPrefix("atproto-space-credential ") else {
            throw SpaceHTTPSignatureError.duplicateOrMissingField
        }
        var audienceValue: String?
        if credentialKeyID != nil {
            guard let audience, audience.count == 1 else {
                throw SpaceHTTPSignatureError.duplicateOrMissingField
            }
            let value = trimmedFieldValue(audience[0])
            guard !value.isEmpty else {
                throw SpaceHTTPSignatureError.duplicateOrMissingField
            }
            audienceValue = value
        }

        guard !signatureInput.isEmpty, !signature.isEmpty else {
            throw SpaceHTTPSignatureError.malformedSignature
        }
        // RFC 9110 §5.3: repeated field lines combine with ", ".
        let combinedInput = signatureInput.joined(separator: ", ")
        let combinedSignature = signature.joined(separator: ", ")
        guard combinedInput.utf8.count <= maximumFieldBytes,
              combinedSignature.utf8.count <= maximumFieldBytes else {
            throw SpaceHTTPSignatureError.malformedSignature
        }
        let inputDictionary: StructuredFieldDictionary
        let signatureDictionary: StructuredFieldDictionary
        do {
            inputDictionary = try StructuredFieldParser.parseDictionary(combinedInput)
            signatureDictionary = try StructuredFieldParser.parseDictionary(combinedSignature)
        } catch {
            throw SpaceHTTPSignatureError.malformedSignature
        }
        let tagged = inputDictionary.entries.filter { entry in
            let parameters = switch entry.value {
            case let .item(item): item.parameters
            case let .innerList(list): list.parameters
            }
            return parameters["tag"] == .string(label)
        }
        guard tagged.count == 1,
              case let .innerList(input) = tagged[0].value,
              case let .item(signatureItem)? = signatureDictionary[tagged[0].key],
              case let .byteSequence(signatureBytes) = signatureItem.value,
              signatureItem.parameters.isEmpty else {
            throw SpaceHTTPSignatureError.malformedSignature
        }

        let expectedComponents = [authorizationComponent, audienceComponent]
        let components: [String?] = input.items.map { item in
            guard item.parameters.isEmpty, case let .string(name) = item.value else {
                return nil
            }
            return name
        }
        guard components == expectedComponents.map(Optional.some) else {
            throw SpaceHTTPSignatureError.wrongCoveredComponents
        }
        guard input.parameters["tag"] == .string(label) else {
            throw SpaceHTTPSignatureError.malformedSignature
        }
        if let alg = input.parameters["alg"] {
            guard alg == .string(algorithm) else {
                throw SpaceHTTPSignatureError.unsupportedAlgorithm
            }
        }
        let suppliedKeyID: String?
        switch input.parameters["keyid"] {
        case nil:
            suppliedKeyID = nil
        case let .string(value)?:
            suppliedKeyID = value
        case .some:
            // A token, byte sequence, or other non-string keyid can never
            // name a did:key; it never equals a credential's cnf.kid either.
            guard credentialKeyID == nil else {
                throw SpaceHTTPSignatureError.keyMismatch
            }
            throw SpaceHTTPSignatureError.invalidKey
        }
        guard let signingKeyID = credentialKeyID ?? suppliedKeyID else {
            throw SpaceHTTPSignatureError.invalidKey
        }
        let publicKey: P256.Signing.PublicKey
        do {
            publicKey = try P256DIDKey(signingKeyID).publicKey
        } catch {
            throw SpaceHTTPSignatureError.invalidKey
        }
        if let credentialKeyID, let suppliedKeyID, suppliedKeyID != credentialKeyID {
            throw SpaceHTTPSignatureError.keyMismatch
        }

        let base = signatureBase(
            authorization: authorizationValue,
            audience: audienceValue,
            signatureParams: StructuredFieldSerializer.serialize(input)
        )
        guard signatureBytes.count == P256WireSignature.rawByteCount,
              let ecdsa = try? P256WireSignature.decodeMalleabilityTolerant(signatureBytes),
              publicKey.isValidSignature(ecdsa, for: base) else {
            throw SpaceHTTPSignatureError.invalidSignature
        }
        return signingKeyID
    }

    /// The RFC 9421 signature base: one line per covered component, then the
    /// `@signature-params` line, joined by LF with no trailing LF.
    static func signatureBase(
        authorization: String,
        audience: String?,
        signatureParams: String
    ) -> Data {
        var lines = ["\"\(authorizationComponent)\": \(trimmedFieldValue(authorization))"]
        if let audience {
            lines.append("\"\(audienceComponent)\": \(trimmedFieldValue(audience))")
        }
        lines.append("\"@signature-params\": \(signatureParams)")
        return Data(lines.joined(separator: "\n").utf8)
    }

    private static func trimmedFieldValue(_ value: String) -> String {
        value.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
    }
}

/// Fixed diagnostic vocabulary for a rejected `atproto-space-credential` signature. All
/// cases surface on the wire as `BadSpaceSignature`; none carries request
/// material.
public enum SpaceHTTPSignatureError: Error, Sendable, Equatable {
    case duplicateOrMissingField
    case malformedSignature
    case wrongCoveredComponents
    case unsupportedAlgorithm
    case invalidKey
    case keyMismatch
    case invalidSignature
}

// MARK: - RFC 8941 structured fields (the subset signatures need)

/// A bare item. Decimals keep their canonical serialization so the signature
/// base reproduces RFC 8941 §4.1.5 without floating-point rounding.
enum StructuredFieldBareItem: Equatable, Sendable {
    case integer(Int64)
    case decimal(String)
    case string(String)
    case token(String)
    case byteSequence(Data)
    case boolean(Bool)
}

/// Parameters keep insertion order; a repeated key overwrites the value in
/// place (RFC 8941 §4.2.3.2), exactly like the reference's ordered `Map`.
struct StructuredFieldParameters: Equatable, Sendable {
    private(set) var entries: [(key: String, value: StructuredFieldBareItem)] = []

    var isEmpty: Bool { entries.isEmpty }

    subscript(key: String) -> StructuredFieldBareItem? {
        entries.first(where: { $0.key == key })?.value
    }

    mutating func set(_ key: String, _ value: StructuredFieldBareItem) {
        if let index = entries.firstIndex(where: { $0.key == key }) {
            entries[index].value = value
        } else {
            entries.append((key, value))
        }
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.entries.elementsEqual(rhs.entries) { $0.key == $1.key && $0.value == $1.value }
    }
}

struct StructuredFieldItem: Equatable, Sendable {
    var value: StructuredFieldBareItem
    var parameters: StructuredFieldParameters
}

struct StructuredFieldInnerList: Equatable, Sendable {
    var items: [StructuredFieldItem]
    var parameters: StructuredFieldParameters
}

enum StructuredFieldMember: Equatable, Sendable {
    case item(StructuredFieldItem)
    case innerList(StructuredFieldInnerList)
}

/// A dictionary whose repeated keys overwrite earlier values, as RFC 8941
/// §4.2.2 requires.
struct StructuredFieldDictionary: Sendable {
    private(set) var entries: [(key: String, value: StructuredFieldMember)] = []

    subscript(key: String) -> StructuredFieldMember? {
        entries.first(where: { $0.key == key })?.value
    }

    mutating func set(_ key: String, _ value: StructuredFieldMember) {
        if let index = entries.firstIndex(where: { $0.key == key }) {
            entries[index].value = value
        } else {
            entries.append((key, value))
        }
    }
}

enum StructuredFieldParseError: Error, Equatable {
    case invalid
}

/// A strict RFC 8941 §4.2 parser over the bytes of one combined field value.
struct StructuredFieldParser {
    private let bytes: [UInt8]
    private var index = 0

    private init(_ text: String) {
        bytes = Array(text.utf8)
    }

    static func parseDictionary(_ text: String) throws -> StructuredFieldDictionary {
        var parser = StructuredFieldParser(text)
        parser.discardSpaces()
        let dictionary = try parser.dictionary()
        parser.discardSpaces()
        guard parser.isAtEnd else { throw StructuredFieldParseError.invalid }
        return dictionary
    }

    private var isAtEnd: Bool { index >= bytes.count }
    private var peek: UInt8? { isAtEnd ? nil : bytes[index] }

    private mutating func consume() -> UInt8? {
        guard let byte = peek else { return nil }
        index += 1
        return byte
    }

    private mutating func discardSpaces() {
        while peek == 0x20 { index += 1 }
    }

    private mutating func discardOptionalWhitespace() {
        while peek == 0x20 || peek == 0x09 { index += 1 }
    }

    private mutating func dictionary() throws -> StructuredFieldDictionary {
        var dictionary = StructuredFieldDictionary()
        while !isAtEnd {
            let key = try self.key()
            if peek == UInt8(ascii: "=") {
                index += 1
                dictionary.set(key, try itemOrInnerList())
            } else {
                dictionary.set(key, .item(.init(value: .boolean(true), parameters: try parameters())))
            }
            discardOptionalWhitespace()
            if isAtEnd { return dictionary }
            guard consume() == UInt8(ascii: ",") else { throw StructuredFieldParseError.invalid }
            discardOptionalWhitespace()
            if isAtEnd { throw StructuredFieldParseError.invalid }
        }
        return dictionary
    }

    private mutating func itemOrInnerList() throws -> StructuredFieldMember {
        if peek == UInt8(ascii: "(") {
            return .innerList(try innerList())
        }
        return .item(try item())
    }

    private mutating func innerList() throws -> StructuredFieldInnerList {
        guard consume() == UInt8(ascii: "(") else { throw StructuredFieldParseError.invalid }
        var items: [StructuredFieldItem] = []
        while !isAtEnd {
            discardSpaces()
            if peek == UInt8(ascii: ")") {
                index += 1
                return .init(items: items, parameters: try parameters())
            }
            items.append(try item())
            guard peek == 0x20 || peek == UInt8(ascii: ")") else {
                throw StructuredFieldParseError.invalid
            }
        }
        throw StructuredFieldParseError.invalid
    }

    private mutating func item() throws -> StructuredFieldItem {
        let value = try bareItem()
        return .init(value: value, parameters: try parameters())
    }

    private mutating func parameters() throws -> StructuredFieldParameters {
        var parameters = StructuredFieldParameters()
        while peek == UInt8(ascii: ";") {
            index += 1
            discardSpaces()
            let key = try self.key()
            var value = StructuredFieldBareItem.boolean(true)
            if peek == UInt8(ascii: "=") {
                index += 1
                value = try bareItem()
            }
            parameters.set(key, value)
        }
        return parameters
    }

    private mutating func key() throws -> String {
        guard let first = peek, Self.isLowercaseAlpha(first) || first == UInt8(ascii: "*") else {
            throw StructuredFieldParseError.invalid
        }
        var output: [UInt8] = []
        while let byte = peek,
              Self.isLowercaseAlpha(byte) || Self.isDigit(byte)
              || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-")
              || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "*") {
            output.append(byte)
            index += 1
        }
        return String(decoding: output, as: UTF8.self)
    }

    private mutating func bareItem() throws -> StructuredFieldBareItem {
        guard let first = peek else { throw StructuredFieldParseError.invalid }
        if first == UInt8(ascii: "-") || Self.isDigit(first) {
            return try integerOrDecimal()
        }
        if first == UInt8(ascii: "\"") { return .string(try string()) }
        if Self.isAlpha(first) || first == UInt8(ascii: "*") { return .token(token()) }
        if first == UInt8(ascii: ":") { return .byteSequence(try byteSequence()) }
        if first == UInt8(ascii: "?") { return .boolean(try boolean()) }
        throw StructuredFieldParseError.invalid
    }

    private mutating func integerOrDecimal() throws -> StructuredFieldBareItem {
        var isDecimal = false
        var negative = false
        var digits: [UInt8] = []
        if peek == UInt8(ascii: "-") {
            index += 1
            negative = true
        }
        guard let first = peek, Self.isDigit(first) else { throw StructuredFieldParseError.invalid }
        while let byte = peek {
            if Self.isDigit(byte) {
                digits.append(byte)
                index += 1
            } else if !isDecimal, byte == UInt8(ascii: ".") {
                guard digits.count <= 12 else { throw StructuredFieldParseError.invalid }
                digits.append(byte)
                index += 1
                isDecimal = true
            } else {
                break
            }
            if !isDecimal, digits.count > 15 { throw StructuredFieldParseError.invalid }
            if isDecimal, digits.count > 16 { throw StructuredFieldParseError.invalid }
        }
        let text = String(decoding: digits, as: UTF8.self)
        if !isDecimal {
            guard let magnitude = Int64(text) else { throw StructuredFieldParseError.invalid }
            return .integer(negative ? -magnitude : magnitude)
        }
        guard digits.last != UInt8(ascii: ".") else { throw StructuredFieldParseError.invalid }
        let pieces = text.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 2, pieces[1].count <= 3 else { throw StructuredFieldParseError.invalid }
        // RFC 8941 §4.1.5 canonical form: no leading integer zeros, no
        // trailing fractional zeros, at least one digit on each side.
        let integerPart = pieces[0].drop(while: { $0 == "0" })
        var fractionPart = Substring(pieces[1])
        while fractionPart.last == "0" { fractionPart.removeLast() }
        let integerText = integerPart.isEmpty ? "0" : String(integerPart)
        let fractionText = fractionPart.isEmpty ? "0" : String(fractionPart)
        let isZero = integerText == "0" && fractionText == "0"
        return .decimal("\(negative && !isZero ? "-" : "")\(integerText).\(fractionText)")
    }

    private mutating func string() throws -> String {
        guard consume() == UInt8(ascii: "\"") else { throw StructuredFieldParseError.invalid }
        var output: [UInt8] = []
        while let byte = consume() {
            if byte == UInt8(ascii: "\\") {
                guard let next = consume(),
                      next == UInt8(ascii: "\"") || next == UInt8(ascii: "\\") else {
                    throw StructuredFieldParseError.invalid
                }
                output.append(next)
            } else if byte == UInt8(ascii: "\"") {
                return String(decoding: output, as: UTF8.self)
            } else if byte < 0x20 || byte > 0x7e {
                throw StructuredFieldParseError.invalid
            } else {
                output.append(byte)
            }
        }
        throw StructuredFieldParseError.invalid
    }

    private mutating func token() -> String {
        var output: [UInt8] = []
        while let byte = peek,
              Self.isTokenCharacter(byte) || byte == UInt8(ascii: ":") || byte == UInt8(ascii: "/") {
            output.append(byte)
            index += 1
        }
        return String(decoding: output, as: UTF8.self)
    }

    private mutating func byteSequence() throws -> Data {
        guard consume() == UInt8(ascii: ":") else { throw StructuredFieldParseError.invalid }
        var encoded: [UInt8] = []
        while let byte = consume() {
            if byte == UInt8(ascii: ":") {
                var text = String(decoding: encoded, as: UTF8.self)
                text.append(String(repeating: "=", count: (4 - text.count % 4) % 4))
                guard let data = Data(base64Encoded: text) else {
                    throw StructuredFieldParseError.invalid
                }
                return data
            }
            guard Self.isAlpha(byte) || Self.isDigit(byte)
                || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "/")
                || byte == UInt8(ascii: "=") else {
                throw StructuredFieldParseError.invalid
            }
            encoded.append(byte)
        }
        throw StructuredFieldParseError.invalid
    }

    private mutating func boolean() throws -> Bool {
        guard consume() == UInt8(ascii: "?") else { throw StructuredFieldParseError.invalid }
        switch consume() {
        case UInt8(ascii: "1"): return true
        case UInt8(ascii: "0"): return false
        default: throw StructuredFieldParseError.invalid
        }
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (0x30 ... 0x39).contains(byte)
    }

    private static func isLowercaseAlpha(_ byte: UInt8) -> Bool {
        (0x61 ... 0x7a).contains(byte)
    }

    private static func isAlpha(_ byte: UInt8) -> Bool {
        isLowercaseAlpha(byte) || (0x41 ... 0x5a).contains(byte)
    }

    private static func isTokenCharacter(_ byte: UInt8) -> Bool {
        if isAlpha(byte) || isDigit(byte) { return true }
        return Array("!#$%&'*+-.^_`|~".utf8).contains(byte)
    }
}

/// RFC 8941 §4.1 serialization of an inner list, used to rebuild the
/// `@signature-params` line from the parsed `Signature-Input` member.
enum StructuredFieldSerializer {
    static func serialize(_ list: StructuredFieldInnerList) -> String {
        "(" + list.items.map(serialize).joined(separator: " ") + ")" + serialize(list.parameters)
    }

    static func serialize(_ item: StructuredFieldItem) -> String {
        serialize(item.value) + serialize(item.parameters)
    }

    static func serialize(_ parameters: StructuredFieldParameters) -> String {
        parameters.entries.map { entry in
            if entry.value == .boolean(true) { return ";\(entry.key)" }
            return ";\(entry.key)=\(serialize(entry.value))"
        }.joined()
    }

    static func serialize(_ value: StructuredFieldBareItem) -> String {
        switch value {
        case let .integer(number):
            String(number)
        case let .decimal(canonical):
            canonical
        case let .string(text):
            "\"" + text.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        case let .token(token):
            token
        case let .byteSequence(data):
            ":" + data.base64EncodedString() + ":"
        case let .boolean(flag):
            flag ? "?1" : "?0"
        }
    }
}
