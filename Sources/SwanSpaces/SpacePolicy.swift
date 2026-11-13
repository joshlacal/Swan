import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif
import Petrel
import SwanCore

/// The October 29 2026 space `policy`: an open union discriminated by
/// `$type`. Swan implements the three baseline policies every PDS must
/// support. A policy value is always normalized: defaults are filled in and
/// unknown fields are dropped, so what is stored is exactly what is enforced
/// (proposal 0016 section 1f, upstream `space-policy/policy.ts`).
public enum SpacePolicy: Sendable, Equatable, Hashable {
    case personal
    case member(MemberSpacePolicy)
    case managed(ManagedSpacePolicy)

    public static let personalType = "com.atproto.personalspace.policy"
    public static let memberType = "com.atproto.memberspace.policy"
    public static let managedType = "com.atproto.managedspace.policy"

    /// The record collections the authority's PDS publishes a space's
    /// configuration to. They are written only from the configuration, so a
    /// direct write to either collection is refused in any repository.
    public static let policyRecordCollection = "com.atproto.space.policy"
    public static let policyRecordKey = "self"
    public static let memberRecordCollection = "com.atproto.memberspace.member"
    public static let publishedCollections: Set<String> = [
        policyRecordCollection,
        memberRecordCollection,
    ]

    public var typeIdentifier: String {
        switch self {
        case .personal: Self.personalType
        case .member: Self.memberType
        case .managed: Self.managedType
        }
    }

    /// Whether `publishPolicy` asks for a `com.atproto.space.policy/self`
    /// record in the authority's repository.
    public var publishesPolicy: Bool {
        switch self {
        case .personal: false
        case let .member(policy): policy.publishPolicy
        case let .managed(policy): policy.publishPolicy
        }
    }

    /// Whether `publishMembers` asks for one member record per member.
    public var publishesMembers: Bool {
        if case let .member(policy) = self { return policy.publishMembers }
        return false
    }

    /// Only a memberspace with `publicRead` authorizes any user to read, and
    /// so it is the only policy that issues a credential without a
    /// delegation token naming the user.
    public var isPublicRead: Bool {
        if case let .member(policy) = self { return policy.publicRead }
        return false
    }

    /// Only memberspace restricts apps, judged by the attested client: an
    /// app that presents no attestation is never one of the allowed apps.
    public func isAppAuthorized(clientID: String?) -> Bool {
        guard case let .member(policy) = self,
              let allowedApps = policy.allowedApps else {
            return true
        }
        guard let clientID else { return false }
        return allowedApps.contains(clientID)
    }

    /// Parses and normalizes a wire policy (an already JSON-decoded object).
    /// An unknown `$type` is ``SpacePolicyError/unsupportedPolicy``; a known
    /// policy with a wrongly typed field is ``SpacePolicyError/invalidPolicy``.
    /// Fields the policy does not define are dropped.
    public static func normalized(jsonObject value: Any) throws -> SpacePolicy {
        guard let object = value as? [String: Any],
              let type = object["$type"] as? String else {
            throw SpacePolicyError.invalidPolicy
        }
        switch type {
        case personalType:
            return .personal
        case memberType:
            let allowedApps: [String]?
            if let raw = object["allowedApps"] {
                guard let values = raw as? [Any] else { throw SpacePolicyError.invalidPolicy }
                var apps: [String] = []
                apps.reserveCapacity(values.count)
                for item in values {
                    guard let app = item as? String,
                          SpacePolicyValidation.isValidAppIdentifier(app) else {
                        throw SpacePolicyError.invalidPolicy
                    }
                    apps.append(app)
                }
                allowedApps = apps
            } else {
                allowedApps = nil
            }
            return .member(try MemberSpacePolicy(
                publicRead: try optionalBool(object["publicRead"]),
                publicWrite: try optionalBool(object["publicWrite"]),
                allowedApps: allowedApps,
                publishPolicy: try optionalBool(object["publishPolicy"]),
                publishMembers: try optionalBool(object["publishMembers"])
            ))
        case managedType:
            guard let managingApp = object["managingApp"] as? String,
                  SpacePolicyValidation.isValidManagingAppService(managingApp) else {
                throw SpacePolicyError.invalidPolicy
            }
            return .managed(try ManagedSpacePolicy(
                managingApp: managingApp,
                publishPolicy: try optionalBool(object["publishPolicy"])
            ))
        default:
            throw SpacePolicyError.unsupportedPolicy
        }
    }

    /// The JSON wire form, with every default filled in.
    public var jsonObject: [String: Any] {
        switch self {
        case .personal:
            return ["$type": Self.personalType]
        case let .member(policy):
            var object: [String: Any] = [
                "$type": Self.memberType,
                "publicRead": policy.publicRead,
                "publicWrite": policy.publicWrite,
                "publishPolicy": policy.publishPolicy,
                "publishMembers": policy.publishMembers,
            ]
            if let allowedApps = policy.allowedApps {
                object["allowedApps"] = allowedApps
            }
            return object
        case let .managed(policy):
            return [
                "$type": Self.managedType,
                "managingApp": policy.managingApp,
                "publishPolicy": policy.publishPolicy,
            ]
        }
    }

    /// The DRISL (canonical DAG-CBOR) data-model value, for published
    /// records and space meta archives.
    public var cborValue: OrderedCBORMap {
        switch self {
        case .personal:
            return OrderedCBORMap(entries: [(key: "$type", value: Self.personalType)])
        case let .member(policy):
            var entries: [(key: String, value: Any)] = [
                (key: "$type", value: Self.memberType),
                (key: "publicRead", value: policy.publicRead),
                (key: "publicWrite", value: policy.publicWrite),
                (key: "publishPolicy", value: policy.publishPolicy),
                (key: "publishMembers", value: policy.publishMembers),
            ]
            if let allowedApps = policy.allowedApps {
                entries.append((key: "allowedApps", value: allowedApps))
            }
            return OrderedCBORMap(entries: entries)
        case let .managed(policy):
            return OrderedCBORMap(entries: [
                (key: "$type", value: Self.managedType),
                (key: "managingApp", value: policy.managingApp),
                (key: "publishPolicy", value: policy.publishPolicy),
            ])
        }
    }

    /// The canonical `com.atproto.space.policy` record value `{ policy }`.
    public func policyRecordValue() throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: Self.policyRecordCollection),
            (key: "policy", value: cborValue),
        ]))
    }

    /// The canonical `com.atproto.memberspace.member` record value.
    public static func memberRecordValue(read: Bool, write: Bool) throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: memberRecordCollection),
            (key: "read", value: read),
            (key: "write", value: write),
        ]))
    }

    /// The record key a member's published record uses. Until Lexicon has a
    /// DID record-key format, a did:web with a percent-encoded port is keyed
    /// without the encoding (`did:web:localhost%3A2583` becomes
    /// `did:web:localhost:2583`), as the reference `didToRecordKey` does.
    public static func memberRecordKey(for did: String) -> String {
        guard did.hasPrefix("did:web:") else { return did }
        return did.replacingOccurrences(of: "%3A", with: ":")
            .replacingOccurrences(of: "%3a", with: ":")
    }

    /// The inverse of ``memberRecordKey(for:)``: a did:web whose host part
    /// carries a port is percent-encoded again.
    public static func memberDID(fromRecordKey rkey: String) -> String? {
        guard rkey.hasPrefix("did:") else { return nil }
        guard rkey.hasPrefix("did:web:") else { return rkey }
        let rest = rkey.dropFirst("did:web:".count)
        var parts = rest.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard let host = parts.first, !host.isEmpty else { return nil }
        if parts.count >= 2, let port = parts.dropFirst().first,
           !port.isEmpty, port.utf8.allSatisfy({ (48 ... 57).contains($0) }) {
            parts.removeFirst(2)
            let head = "\(host)%3A\(port)"
            return (["did:web:" + head] + parts).joined(separator: ":")
        }
        return rkey
    }

    private static func optionalBool(_ value: Any?) throws -> Bool {
        guard let value else { return false }
        guard isJSONBoolean(value), let bool = value as? Bool else {
            throw SpacePolicyError.invalidPolicy
        }
        return bool
    }

    /// `JSONSerialization` bridges both `true` and `1` to `NSNumber`, and
    /// `1 as? Bool` succeeds; only a JSON boolean is a policy flag.
    public static func isJSONBoolean(_ value: Any) -> Bool {
        #if canImport(CoreFoundation)
        if let number = value as? NSNumber {
            return CFGetTypeID(number) == CFBooleanGetTypeID()
        }
        return value is Bool
        #else
        return value is Bool
        #endif
    }
}

/// `com.atproto.memberspace.policy`, with every field defaulted.
public struct MemberSpacePolicy: Sendable, Equatable, Hashable {
    public let publicRead: Bool
    public let publicWrite: Bool
    /// Normalized to a sorted, duplicate-free list. `nil` (omitted) admits
    /// any app; an empty list admits none.
    public let allowedApps: [String]?
    public let publishPolicy: Bool
    public let publishMembers: Bool

    public init(
        publicRead: Bool = false,
        publicWrite: Bool = false,
        allowedApps: [String]? = nil,
        publishPolicy: Bool = false,
        publishMembers: Bool = false
    ) throws {
        if let allowedApps {
            guard allowedApps.count <= SimpleSpaceLimits.maximumClientAllowListEntries else {
                throw SpacePolicyError.invalidPolicy
            }
            self.allowedApps = Array(Set(allowedApps)).sorted()
        } else {
            self.allowedApps = nil
        }
        self.publicRead = publicRead
        self.publicWrite = publicWrite
        self.publishPolicy = publishPolicy
        self.publishMembers = publishMembers
    }
}

/// `com.atproto.managedspace.policy`. Every user decision, for reads and
/// writes, is deferred to `managingApp` through
/// `com.atproto.managedspace.checkAccess`.
public struct ManagedSpacePolicy: Sendable, Equatable, Hashable {
    public let managingApp: String
    public let publishPolicy: Bool

    public init(managingApp: String, publishPolicy: Bool = false) throws {
        guard SpacePolicyValidation.isValidManagingApp(managingApp) else {
            throw SpacePolicyError.invalidPolicy
        }
        self.managingApp = managingApp
        self.publishPolicy = publishPolicy
    }

    /// The DID part of `managingApp`, without any service fragment.
    public var managingAppDID: String {
        String(managingApp.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0])
    }

    /// The service fragment, when `managingApp` names one.
    public var managingAppFragment: String? {
        let parts = managingApp.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        return parts.count == 2 ? String(parts[1]) : nil
    }
}

public enum SpacePolicyError: Error, Sendable, Equatable {
    /// The `$type` names a policy this host does not implement.
    case unsupportedPolicy
    /// A known policy carries a field of the wrong shape.
    case invalidPolicy
    /// A member-list method was called on a space another policy governs.
    case policyMismatch
}

public enum SpacePolicyValidation {
    /// Lexicon `uri` format, matching `@atproto/syntax`'s absolute-URI gate.
    public static func isValidURI(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 2_048,
              let colon = value.firstIndex(of: ":"),
              colon != value.startIndex,
              value[..<colon].utf8.allSatisfy({
                  ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A)
                      || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F
              }) else {
            return false
        }
        var remainder = value[value.index(after: colon)...]
        if remainder.hasPrefix("//") {
            remainder = remainder.dropFirst(2)
        }
        guard let first = remainder.unicodeScalars.first,
              first.value != 0x2F,
              !CharacterSet.whitespacesAndNewlines.contains(first) else {
            return false
        }
        return remainder.unicodeScalars.allSatisfy {
            !CharacterSet.whitespacesAndNewlines.contains($0)
                && !CharacterSet.controlCharacters.contains($0)
        }
    }

    public static func isValidAppIdentifier(_ identifier: String) -> Bool {
        isValidURI(identifier)
    }

    /// Stored pre-November rows may contain a bare DID, so this tolerant
    /// validator remains available for loading and reporting them.
    public static func isValidManagingApp(_ value: String) -> Bool {
        guard value.utf8.count <= 2_048 else { return false }
        let parts = value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        guard SpaceURI.isValidDID(String(parts[0])) else { return false }
        if parts.count == 2 {
            guard isValidServiceFragment(parts[1]) else { return false }
        }
        return true
    }

    /// New policies require the named DID service, never a bare DID.
    public static func isValidManagingAppService(_ value: String) -> Bool {
        let parts = value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        return parts.count == 2
            && SpaceURI.isValidDID(String(parts[0]))
            && isValidServiceFragment(parts[1])
            && value.utf8.count <= 2_048
    }

    private static func isValidServiceFragment(_ fragment: Substring) -> Bool {
        !fragment.isEmpty && fragment.utf8.count <= 256
            && fragment.utf8.allSatisfy { byte in
                (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A)
                    || (byte >= 0x61 && byte <= 0x7A)
                    || byte == 0x2D || byte == 0x2E || byte == 0x5F || byte == 0x7E
                    || byte == 0x3A
            }
    }
}

/// The JSON wire form, with every default filled in (`getSpace`,
/// `exportSpaceMeta` diagnostics, lab tooling).
extension SpacePolicy: Encodable {
    private enum CodingKeys: String, CodingKey {
        case type = "$type"
        case publicRead, publicWrite, allowedApps, publishPolicy, publishMembers, managingApp
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(typeIdentifier, forKey: .type)
        switch self {
        case .personal:
            break
        case let .member(policy):
            try container.encode(policy.publicRead, forKey: .publicRead)
            try container.encode(policy.publicWrite, forKey: .publicWrite)
            try container.encodeIfPresent(policy.allowedApps, forKey: .allowedApps)
            try container.encode(policy.publishPolicy, forKey: .publishPolicy)
            try container.encode(policy.publishMembers, forKey: .publishMembers)
        case let .managed(policy):
            try container.encode(policy.managingApp, forKey: .managingApp)
            try container.encode(policy.publishPolicy, forKey: .publishPolicy)
        }
    }
}
