import XCTest

@testable import SwanCore

/// The invariant that makes an action-less `space:` grant safe to admit.
///
/// ## Why this file exists
///
/// §9-D21 retires `isIssuableQualified`, so a `space:` grant naming no `action=`
/// is now admitted at PAR and minted into a durable token. `action` defaults to
/// `SPACE_DEFAULT_ACTIONS`, which **contains `create`, `update` and `delete`**
/// — so read as a list of verbs, such a grant looks like a whole-repository
/// write capability that no client ever asked for.
///
/// It is not one, and the reason is a single line: `collection` defaults to `[]`,
/// and the write arm of `matches(_:)` requires `collectionAllows(_:)`, which is
/// `contains(.any) || contains(.nsid(c))` — both false on an empty list, for
/// every collection. Upstream states the same rule as prose: "Empty means no
/// write targets, not 'all collections'" (`space-permission.ts:193-198`).
///
/// That refusal is load-bearing and, before this file, ungreppable: nothing in
/// the tree asserted it, and the admission layer deliberately does **not**
/// re-check it (§6.2's rule fires on a *stated* write action, because an
/// effective-set reading would also reject `manage=`-only grants and bare
/// `space:<type>`, both of which the spec requires be admitted).
///
/// ## The Phase-2 hazard this is positioned to catch
///
/// `withDefaultCollections` (§5.6.4 `expandSpaceCollections`) materialises a
/// grant's collections from the space's declared list. It is **not wired today**
/// — positive control: `grep -rn 'withDefaultCollections\|expandSpaceCollections'
/// Sources` returns only a doc-comment reference. The day it is, an
/// unstated-`action` grant gains collections and its *defaulted* write verbs go
/// live against every one of them, with no client having typed `create`. The
/// last test here pins that mechanism explicitly so the expansion cannot be
/// wired without someone reading it.
final class SpaceWriteTargetInvariantTests: XCTestCase {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let spaceType = "app.example.doc"
    private let collection = "app.example.record"

    private func target(
        _ operation: SpaceScopeTarget.Operation,
        skey: String = "k"
    ) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: spaceType,
            authority: authority,
            skey: skey,
            operation: operation
        )
    }

    // MARK: the premise — the write verbs really are in the defaulted set

    func testAnUnstatedActionGrantCarriesTheDefaultedWriteVerbs() throws {
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        // If this ever stops being true the rest of this file is moot, and the
        // §6.2 analysis that justified keeping the `wasStated("action")` gate
        // needs redoing — so assert the premise rather than assuming it.
        XCTAssertEqual(Set(grant.action), Set(SPACE_DEFAULT_ACTIONS))
        XCTAssertTrue(grant.action.contains(.create))
        XCTAssertTrue(grant.action.contains(.update))
        XCTAssertTrue(grant.action.contains(.delete))
        XCTAssertTrue(grant.collection.isEmpty, "no collection was stated or defaulted in")
    }

    // MARK: the invariant — and it authorizes no write target

    func testAnUnstatedActionGrantAuthorizesNoWriteTarget() throws {
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        for verb in [SpaceScopeTarget.Operation.RecordWrite.create, .update, .delete] {
            XCTAssertFalse(
                grant.matches(target(.write(verb, collection: collection))),
                """
                A grant that named no `action=` must authorize no write, however \
                many write verbs the schema defaulted into it. The refusal comes \
                from `collectionAllows` on an empty collection list — NOT from \
                the admission layer, which deliberately admits this shape.
                """
            )
        }
    }

    func testABareSpaceGrantAuthorizesNoWriteTarget() throws {
        // The other shape that used to be refused at issuance by
        // `isIssuableQualified` and is now admitted and fenced instead.
        let grant = try SpacePermission.parse("space:\(spaceType)")
        XCTAssertFalse(grant.matches(target(.write(.create, collection: collection))))
        XCTAssertFalse(grant.matches(target(.write(.delete, collection: collection))))
    }

    func testAnUnstatedActionGrantIsStillAWorkingReadGrant() throws {
        // The refusal above must be specific to writes. If this fails, the
        // grant is inert rather than read-only and admitting it is pointless.
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        XCTAssertTrue(grant.matches(target(.read(aggregate: false, collection: nil))))
    }

    // MARK: the positive control — a collection is what activates a write

    func testAStatedCollectionIsWhatAuthorizesTheWrite() throws {
        // Without this, every assertion above would also pass if writes were
        // globally broken. This isolates the empty collection as the cause.
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=create&collection=\(collection)"
        )
        XCTAssertTrue(grant.matches(target(.write(.create, collection: collection))))
        XCTAssertFalse(
            grant.matches(target(.write(.create, collection: "app.example.other"))),
            "a named collection authorizes that collection and no other"
        )
    }

    func testAWildcardCollectionAuthorizesAnyCollection() throws {
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=create&collection=*"
        )
        XCTAssertTrue(grant.matches(target(.write(.create, collection: "anything.at.all"))))
    }

    // MARK: the Phase-2 tripwire

    func testExpandingCollectionsWouldActivateDefaultedWrites() throws {
        // CHARACTERISATION, not a guard: it pins the mechanism rather than
        // preventing it, because the expansion is not wired yet and there is
        // nothing to prevent.
        //
        // Read it as the requirement it implies. `withDefaultCollections` is
        // §5.6.4's `expandSpaceCollections`. Applied to a grant whose write
        // verbs came only from the schema default, it produces a permission that
        // authorizes writes the client never asked for. So when that expansion
        // is wired into mint, it MUST NOT expand for actions the client did not
        // state — or must drop defaulted write verbs when it materialises
        // collections. `wasStated("action")` is durable through the persistence
        // path, so the information needed to make that decision is available.
        //
        // If this test starts failing, someone has fixed the hazard. Good —
        // delete it and put a real guard assertion here.
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        XCTAssertFalse(grant.matches(target(.write(.create, collection: collection))))

        let expanded = grant.withDefaultCollections([.nsid(collection)])
        XCTAssertTrue(
            expanded.matches(target(.write(.create, collection: collection))),
            """
            Expansion turned a read-shaped grant into a write-capable one purely \
            from schema defaults. This is why §5.6.4 must consult provenance \
            before it materialises collections.
            """
        )
    }
}
