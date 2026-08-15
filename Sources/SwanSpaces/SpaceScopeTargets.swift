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
    /// A record-plane target.
    ///
    /// `collection == nil` means an AGGREGATE surface — a read that returns
    /// rows across collections. Today's rule (`SwanSpaces.swift:329-341`) is
    /// that such a read requires an *unqualified or wildcard* collection grant,
    /// because "aggregate surfaces must not silently censor their response".
    /// §6.5.5 rules that this travels on the TARGET as an explicit flag, not in
    /// the generic matcher.
    ///
    /// **This is a Swan HARDENING of an upstream rule, not a Swan invention,
    /// and upstream's rule is the opposite** — which is what makes the
    /// hardening necessary. Upstream reads are unconditionally
    /// collection-independent: `space-permission.ts:104-110` takes the `read` /
    /// `read_self` arms *before* `collectionAllows` is ever consulted
    /// (`:112-115`), and the test "read_self is not constrained by collection"
    /// (`:320-327`) pins that. It must stay visible.
    ///
    /// A write with no collection is unrepresentable upstream
    /// (`space-permission.ts:70-74` makes `collection` non-optional in the
    /// write arm) and is a denial here: `nil` is returned so the caller throws
    /// rather than silently widening.
    ///
    /// **Why `aggregate` is DERIVED from `collection == nil` rather than taken
    /// as a parameter, and why that is faithful to the rule being ported.**
    /// §6.5.5 calls the flag "explicit", which invites a later reader to add an
    /// `aggregate:` argument and let callers pass it. Do not — the derivation
    /// *is* the ported rule. Today's behaviour lives in one branch,
    /// `SwanSpaces.swift:329-341`, and that branch is selected by exactly this
    /// condition: `guard let collection else { …aggregate rule… }`. The caller
    /// never had a separate say. `collection` reaches here as `uri?.collection`
    /// (`SwanSpaces.swift:261-266`), so "no record URI in hand" and "this
    /// surface spans collections" are the same fact, and a `nil` collection is
    /// the only way an aggregate surface can present itself.
    ///
    /// Taking the flag as a parameter would let a caller pass
    /// `aggregate: false` beside a `nil` collection and silently opt out of the
    /// hardening — a widening reachable from one mistaken argument, at a call
    /// site that would still compile and still look correct. Deriving it makes
    /// that state unrepresentable, the same principle `SpaceRecordAction`
    /// applies to `.manage` above.
    ///
    /// Pinned by `testAggregateReadRefusesACollectionQualifiedGrant`, which
    /// fails under the literal §5.6.2 port.
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

    /// A single-blob read target — **Erratum 03's one deliberate exception**
    /// to the rule above that `aggregate` is derived from `collection == nil`.
    ///
    /// A blob fetch arrives with no record URI, so `record(_:action:collection:)`
    /// classified it as an aggregate read and §6.5.5 refused every
    /// collection-qualified grant. But "no record URI in hand" and "this
    /// surface spans collections" are NOT the same fact here: a blob is one
    /// content-addressed object whose row is already namespace-scoped to the
    /// space — nothing about fetching it enumerates or censors a
    /// cross-collection response, which is the hazard §6.5.5 exists for.
    /// And post-Erratum-02 the same grant can exchange for a whole-space
    /// credential and read the identical bytes through the credential arm, so
    /// the aggregate classification refused conformant clients (bulleted.app's
    /// six-collection grant, `getBlob` 401) while protecting nothing.
    ///
    /// This constructor is for SINGLE-blob retrieval only. Any surface that
    /// answers with a set spanning collections keeps `record` and its derived
    /// aggregate flag — do not reach for this to quiet a §6.5.5 refusal on a
    /// listing.
    static func blobRead(_ space: SpaceURI) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: space.spaceType,
            authority: space.authority,
            skey: space.skey,
            operation: .read(aggregate: false, collection: nil)
        )
    }

    /// The `simplespace.getSpace` configuration read — the same deliberate
    /// exception ``blobRead(_:)`` makes to the derived-aggregate rule, for the
    /// same reason. The read answers with ONE configuration object for one
    /// space; nothing about it enumerates or censors a cross-collection
    /// record response, which is the hazard §6.5.5 exists for. The live
    /// reference gates this surface on `action=read_self` and its read arms
    /// are collection-independent, so a collection-qualified grant that can
    /// read its own records can also describe the space they live in.
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
