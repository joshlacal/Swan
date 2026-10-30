import Foundation
import SwanCore

/// The RECORD-ONLY subset of ``SpacePermission`` (the SwanSpaces *domain*
/// permission at `SwanSpaces.swift:175-182`, not the SwanCore OAuth grammar
/// type of the same name).
///
/// Introduced because the domain enum carries `case manage`, and a total,
/// non-throwing `record(_:action:collection:)` over it would have to map
/// `.manage` to *something*. Today that path is closed by construction —
/// `scopeAllows` requires `parameters["action"] == action`
/// (`SwanSpaces.swift:325`) and `"manage"` is never a legal `action=` value, so
/// `SpaceAuthorizationPolicy.require(..., permission: .manage)` is
/// unsatisfiable for every scope. Leaving that as advice would leave the
/// illegal state REPRESENTABLE, and if it were ever routed to
/// `.manage(SpaceManageOp)` a `manage=`-bearing grant would newly authorize a
/// *record* operation. Remove the state instead of documenting it (§6.2).
public enum SpaceRecordAction: Sendable, Hashable {
    case readSelf, read, create, update, delete

    /// Fails for `.manage` — the ONE case that must not become a record target.
    public init?(_ permission: SpacePermission) {
        switch permission {
        case .readSelf: self = .readSelf
        case .read: self = .read
        case .create: self = .create
        case .update: self = .update
        case .delete: self = .delete
        case .manage: return nil
        }
    }
}

public extension SpaceScopeTarget {
    /// A record-plane target. Reads carry request metadata for callers but
    /// ignore collection restrictions when matching OAuth grants. A write
    /// must name its collection; otherwise this returns nil and denies it.
    static func record(
        _ space: SpaceURI,
        action: SpaceRecordAction,
        collection: String?
    ) -> SpaceScopeTarget? {
        let operation: Operation
        switch action {
        case .read:
            operation = .read(aggregate: collection == nil, collection: collection)
        case .readSelf:
            operation = .readSelf(aggregate: collection == nil, collection: collection)
        case .create, .update, .delete:
            guard let collection else { return nil }
            let verb: Operation.RecordWrite = switch action {
            case .create: .create
            case .update: .update
            default: .delete
            }
            operation = .write(verb, collection: collection)
        }
        return SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: operation
        )
    }

    /// A single-blob read target. Like all space reads, it ignores the
    /// collection parameter. OAuth policy separately enforces own-repo access.
    static func blobRead(_ space: SpaceURI) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: .read(aggregate: false, collection: nil)
        )
    }

    /// The `space.getSpace` and `memberspace.listMembers` owner reads accept read_self and
    /// read grants regardless of their collection parameters.
    static func spaceDescriptionRead(_ space: SpaceURI) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: .readSelf(aggregate: false, collection: nil)
        )
    }

    /// A space-lifecycle target. `manage=` is a DISJOINT vocabulary from
    /// `action=` (`space-permission.ts:32-36`); the mapping must keep `.manage`
    /// routing to the `manage=` parameter and never to `action=`.
    static func manage(
        _ space: SpaceURI,
        operation: SimpleSpaceManagementOperation
    ) -> SpaceScopeTarget {
        let op: SpaceManageOp = switch operation {
        case .create: .create
        case .update: .update
        case .delete: .delete
        }
        return SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: .manage(op)
        )
    }

    /// The whole-space-read delegation exchange (§6.2, §5.6.3).
    ///
    /// Collapsing the current three-`String` signature
    /// (`spaceType:authority:skey:`, `SwanCore.swift:258-263`) to one validated
    /// `SpaceURI` removes the argument-order bug that signature admits.
    static func delegationExchange(_ space: SpaceURI) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: .delegationExchange
        )
    }
}
