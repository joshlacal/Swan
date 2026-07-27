import Foundation
import Petrel
import SwanCore

/// Maps a configured service-JWT audience to the one locally hosted account
/// which may receive a durable space-deletion tombstone. The map is startup
/// configuration; an incoming JWT can never name or open an arbitrary DID.
public struct SwanSpaceNotificationRecipientBindings: Sendable, Equatable {
    private let accountsByServiceIdentity: [String: String]

    public static let empty = SwanSpaceNotificationRecipientBindings(
        uncheckedAccountsByServiceIdentity: [:]
    )

    public init(bindings: [String: String]) throws {
        guard bindings.count <= 1_024 else {
            throw SwanError.malformed("notification recipient bindings exceed their bound")
        }
        var selected: [String: String] = [:]
        for (identity, account) in bindings {
            guard Self.validServiceIdentity(identity),
                  (try? DID(didString: account)) != nil,
                  selected[identity] == nil else {
                throw SwanError.malformed("notification recipient binding is invalid")
            }
            selected[identity] = account
        }
        accountsByServiceIdentity = selected
    }

    public func account(forServiceIdentity identity: String) -> String? {
        accountsByServiceIdentity[identity]
    }

    private init(uncheckedAccountsByServiceIdentity: [String: String]) {
        accountsByServiceIdentity = uncheckedAccountsByServiceIdentity
    }

    /// Mirrors the bounded service-JWT audience grammar without pretending a
    /// recipient service identity must itself be a DID. The pinned TS PDS
    /// currently stores the raw registered endpoint as this identity.
    private static func validServiceIdentity(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && value.utf8.allSatisfy {
            $0 >= 0x21 && $0 <= 0x7e
        }
    }
}
