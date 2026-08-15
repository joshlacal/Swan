import Foundation
import XCTest
@testable import SwanCore
@testable import SwanSpaces

/// Pins the ergonomic target layer (§6.2, §6.5.5): where the aggregate flag is
/// decided, and the two illegal states that are removed by construction rather
/// than documented.
final class SpaceScopeTargetTests: XCTestCase {
    private static let space = try! SpaceURI(
        authority: "did:plc:user",
        spaceType: "x.y.z",
        skey: "self"
    )

    // MARK: - The aggregate flag is DERIVED, and derived here

    /// §6.5.5 puts the decision in this factory, "**not** into the generic
    /// matcher". These assertions are what stop a later reader from adding an
    /// `aggregate:` parameter and letting a caller pass `aggregate: false`
    /// beside a `nil` collection — which would opt out of the hardening from a
    /// single mistaken argument at a call site that still compiles.
    func testAggregateIsDerivedFromAnAbsentCollection() {
        guard let target = SpaceScopeTarget.record(Self.space, action: .read, collection: nil),
              case let .read(aggregate, collection) = target.operation else {
            return XCTFail("a collection-free read must produce a .read operation")
        }
        XCTAssertTrue(aggregate, "no collection in hand == an aggregate surface")
        XCTAssertNil(collection)
    }

    func testANamedCollectionIsNotAggregate() {
        guard let target = SpaceScopeTarget.record(
            Self.space, action: .read, collection: "app.example.records"
        ), case let .read(aggregate, collection) = target.operation else {
            return XCTFail("a collection-qualified read must produce a .read operation")
        }
        XCTAssertFalse(aggregate)
        XCTAssertEqual(collection, "app.example.records")
    }

    /// `read_self` carries the same two hardenings as `read` (§6.5.5).
    func testReadSelfCarriesTheSameDerivation() {
        guard let target = SpaceScopeTarget.record(Self.space, action: .readSelf, collection: nil),
              case let .readSelf(aggregate, collection) = target.operation else {
            return XCTFail("expected a .readSelf operation")
        }
        XCTAssertTrue(aggregate)
        XCTAssertNil(collection)
    }

    // MARK: - Illegal states removed by construction

    /// A write naming no collection is unrepresentable upstream
    /// (`space-permission.ts:70-74` makes `collection` non-optional in the
    /// write arm). Here it is a DENIAL — `nil`, so the caller throws — rather
    /// than a silently widened collection-free write.
    func testAWriteWithNoCollectionIsRefusedRatherThanWidened() {
        for action: SpaceRecordAction in [.create, .update, .delete] {
            XCTAssertNil(
                SpaceScopeTarget.record(Self.space, action: action, collection: nil),
                "\(action) with no collection must not produce a target"
            )
        }
    }

    /// The ONE domain permission that must never become a record target. Today
    /// that path is closed by construction; leaving it as advice would keep the
    /// illegal state representable, and routing `.manage` to
    /// `.manage(SpaceManageOp)` would let a `manage=`-bearing grant newly
    /// authorize a *record* operation (§6.2).
    func testManageIsNotARecordAction() {
        XCTAssertNil(SpaceRecordAction(SwanSpaces.SpacePermission.manage))
        for permission: SwanSpaces.SpacePermission in [.read, .readSelf, .create, .update, .delete] {
            XCTAssertNotNil(SpaceRecordAction(permission))
        }
    }

    /// `manage=` and `action=` are disjoint vocabularies
    /// (`space-permission.ts:32-36`); the mapping must route lifecycle ops to
    /// the manage parameter and never to an action.
    func testManagementTargetsRouteToTheManageOperation() {
        let pairs: [(SimpleSpaceManagementOperation, SpaceManageOp)] = [
            (.create, .create), (.update, .update), (.delete, .delete),
        ]
        for (domain, expected) in pairs {
            guard case let .manage(op) = SpaceScopeTarget
                .manage(Self.space, operation: domain).operation else {
                return XCTFail("expected a .manage operation")
            }
            XCTAssertEqual(op, expected)
        }
    }

    /// Collapsing the old three-`String` signature to one validated `SpaceURI`
    /// is what removes the argument-order bug it admitted (§6.5.4).
    func testDelegationExchangeCarriesTheSpaceTupleUnaltered() {
        let target = SpaceScopeTarget.delegationExchange(Self.space)
        XCTAssertEqual(target.type, Self.space.spaceType)
        XCTAssertEqual(target.authority, Self.space.authority)
        XCTAssertEqual(target.skey, Self.space.skey)
        guard case .delegationExchange = target.operation else {
            return XCTFail("expected a .delegationExchange operation")
        }
    }

    // MARK: - Erratum 03: the single-blob read target and its policy arm

    private static let author = "did:plc:user"

    private func collectionQualifiedReadPermissions() -> SwanScopePermissions {
        let scope = "space:x.y.z?authority=\(Self.author)&skey=self&action=read&collection=app.example.records"
        return SwanScopePermissions(
            rawScopes: [scope],
            subject: Self.author,
            statedKeys: [scope: ["authority", "skey", "action", "collection"]]
        )
    }

    /// The one deliberate `aggregate: false` + `collection: nil` combination.
    /// It exists ONLY on this constructor — `record` still derives aggregate
    /// from the absent collection, pinned above.
    func testBlobReadTargetIsNonAggregateAndCollectionFree() {
        let target = SpaceScopeTarget.blobRead(Self.space)
        XCTAssertEqual(target.type, Self.space.spaceType)
        XCTAssertEqual(target.authority, Self.space.authority)
        XCTAssertEqual(target.skey, Self.space.skey)
        guard case let .read(aggregate, collection) = target.operation else {
            return XCTFail("expected a .read operation")
        }
        XCTAssertFalse(aggregate, "one content-addressed blob is not an aggregate surface")
        XCTAssertNil(collection)
    }

    /// The Bulleted regression: a collection-qualified read grant fetches a
    /// blob (was 401 under the aggregate classification).
    func testRequireBlobReadAcceptsACollectionQualifiedOAuthGrant() throws {
        try SpaceAuthorizationPolicy.requireBlobRead(
            space: Self.space,
            author: Self.author,
            authorization: .accountOAuth(
                subject: Self.author,
                permissions: collectionQualifiedReadPermissions()
            )
        )
    }

    /// The reclassification widens nothing across accounts: a foreign token
    /// subject still never reaches another author's blobs.
    func testRequireBlobReadRefusesAForeignSubject() {
        XCTAssertThrowsError(
            try SpaceAuthorizationPolicy.requireBlobRead(
                space: Self.space,
                author: Self.author,
                authorization: .accountOAuth(
                    subject: "did:plc:other",
                    permissions: collectionQualifiedReadPermissions()
                )
            )
        )
    }

    /// Nor does it widen across verbs: a write-only grant has no `read` and
    /// opens nothing.
    func testRequireBlobReadRefusesAWriteOnlyGrant() {
        let scope = "space:x.y.z?authority=\(Self.author)&skey=self&action=create&collection=app.example.records"
        let permissions = SwanScopePermissions(
            rawScopes: [scope],
            subject: Self.author,
            statedKeys: [scope: ["authority", "skey", "action", "collection"]]
        )
        XCTAssertThrowsError(
            try SpaceAuthorizationPolicy.requireBlobRead(
                space: Self.space,
                author: Self.author,
                authorization: .accountOAuth(subject: Self.author, permissions: permissions)
            )
        )
    }

    /// Every non-OAuth arm delegates to the ordinary `.read` policy: a space
    /// credential still opens blobs, a delegation token and the public
    /// context still never do.
    func testRequireBlobReadDelegatesNonOAuthArmsUnchanged() throws {
        let grant = SpaceGrant(
            subject: "did:plc:member",
            space: Self.space,
            permissions: [.read],
            expiresAt: Date().addingTimeInterval(60)
        )
        try SpaceAuthorizationPolicy.requireBlobRead(
            space: Self.space,
            author: Self.author,
            authorization: .spaceCredential(grant)
        )
        XCTAssertThrowsError(
            try SpaceAuthorizationPolicy.requireBlobRead(
                space: Self.space,
                author: Self.author,
                authorization: .spaceDelegation(subject: Self.author, space: Self.space)
            )
        )
        XCTAssertThrowsError(
            try SpaceAuthorizationPolicy.requireBlobRead(
                space: Self.space,
                author: Self.author,
                authorization: .public
            )
        )
    }
}
