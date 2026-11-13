import Foundation
import Testing
@testable import SwanCore

/// Vectors from `scopes/space-permission.test.ts`. Copied inline per
/// docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.6.
@Suite("space: family")
struct OAuthScopesSpaceTests {
    // MARK: parse defaults (SP1-SP28)

    @Test
    func spaceParsesWithFullDefaults() throws {
        // SP1
        let p = try SpacePermission.parse("space:com.atmoboards.forum")
        #expect(p.spaceType == .nsid("com.atmoboards.forum"))
        #expect(p.authority == .unresolvedSelf)
        #expect(p.skey == .any)
        #expect(p.collection == [])
        #expect(p.action == [.read, .create, .update, .delete])
        #expect(p.manage == [])
    }

    @Test
    func spaceParsesWildcardTypeAndConcreteAuthority() throws {
        // SP2, SP3
        let a = try SpacePermission.parse("space:*?authority=did:plc:abc123xyz")
        #expect(a.spaceType == .any && a.authority == .did("did:plc:abc123xyz"))
        let b = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(b.authority == .any)
    }

    @Test
    func namedSpaceTypeUsesTheNewKeyWhilePositionalFormIsUnchanged() throws {
        let named = try SpacePermission.parse("space?spaceType=com.atmoboards.forum")
        #expect(named.spaceType == .nsid("com.atmoboards.forum"))
        #expect(try named.canonicalScopeString() == "space:com.atmoboards.forum")
        #expect(throws: ScopeParseError.self) {
            try SpacePermission.parse("space?type=com.atmoboards.forum")
        }
    }

    @Test
    func spaceParsesAllFiveNamedFields() throws {
        // SP4
        let p = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create&action=update"
        )
        #expect(p.authority == .did("did:plc:abc123xyz"))
        #expect(p.skey == .key("default"))
        #expect(p.collection == [.nsid("com.atmoboards.thread")])
        #expect(p.action == [.create, .update])
    }

    @Test
    func spaceCollectionWildcardDoesNotChangeDefaultActionList() throws {
        // SP5, SP6, SP9
        let a = try SpacePermission.parse("space:com.atmoboards.forum?collection=*")
        #expect(a.action == [.read, .create, .update, .delete])

        let b = try SpacePermission.parse("space:com.atmoboards.forum?action=read_self&collection=*")
        #expect(b.action == [.readSelf])

        let c = try SpacePermission.parse("space:com.atmoboards.forum")
        #expect(c.collection == [])
    }

    @Test
    func spaceParsesManage() throws {
        // SP7, SP8
        let p = try SpacePermission.parse("space:com.atmoboards.forum?manage=update&manage=delete")
        #expect(p.manage == [.update, .delete])
        #expect(throws: ScopeParseError.self) { try SpacePermission.parse("space:com.example.x?manage=bogus") }
    }

    @Test
    func spaceRejectsMalformedInputs() {
        // SP10-SP16, SP21-SP26 (excluding accepted skey vectors, tested below)
        for scope in [
            "space:foo bar", "space:short", "space:*?authority=not-a-did", "space:*?authority=did:",
            "space:com.example.x?action=bogus", "space:com.example.x?collection=not_an_nsid",
            "space:com.example.x?skey=", "space:com.example.x?skey=hello%20world",
            "space:com.example.x?skey=.", "space:com.example.x?skey=..",
            "space:com.example.x?skey=a%2Fb", "space:com.example.x?skey=a%23b",
            "space:com.example.x?skey=" + String(repeating: "x", count: 513),
            "repo:com.example.x", "whatever",
        ] {
            #expect(throws: ScopeParseError.self) { try SpacePermission.parse(scope) }
        }
    }

    @Test
    func spaceAcceptsUpstreamRecordKeyVectors() throws {
        // SP17-SP20
        #expect(try SpacePermission.parse("space:com.example.x?skey=self").skey == .key("self"))
        #expect(try SpacePermission.parse("space:com.example.x?skey=3jui7kd54zh2y").skey == .key("3jui7kd54zh2y"))
        #expect(try SpacePermission.parse("space:com.example.x?skey=a.b-c_d~e:f").skey == .key("a.b-c_d~e:f"))
        let long = String(repeating: "x", count: 512)
        #expect(try SpacePermission.parse("space:com.example.x?skey=" + long).skey == .key(long))
    }

    // MARK: matching (M1-M24)

    /// Plain, unqualified read/readSelf — neither Swan hardening (§6.5.5)
    /// engaged. Most vectors below are upstream's, which know nothing of
    /// `aggregate`/`collection`, so this is the right default.
    private static let plainRead = SpaceScopeTarget.Operation.read(aggregate: false, collection: nil)
    private static let plainReadSelf = SpaceScopeTarget.Operation.readSelf(aggregate: false, collection: nil)

    private func target(
        type: String = "com.atmoboards.forum", authority: String = "did:plc:abc",
        skey: String = "default", operation: SpaceScopeTarget.Operation
    ) -> SpaceScopeTarget {
        SpaceScopeTarget(type: type, authority: authority, skey: skey, operation: operation)
    }

    @Test
    func spaceAnyAuthorityMatchesReadWhenActionRead() throws {
        // M1-M4
        let m1 = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(m1.matches(target(operation: Self.plainRead)))

        let m2 = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=create")
        #expect(!m2.matches(target(operation: Self.plainRead)))

        let m3 = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read")
        #expect(m3.matches(target(operation: Self.plainRead)))
        #expect(!m3.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))
    }

    @Test
    func spaceOmittedCollectionBlocksAllWritesEvenWithActionCreate() throws {
        // M5, M6, M7 — the anti-widening property.
        let m5 = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(!m5.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))

        let m6 = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&collection=*")
        #expect(m6.matches(target(operation: .write(.create, collection: "any.collection.name"))))
        #expect(m6.matches(target(operation: .write(.update, collection: "another.one.here"))))
    }

    @Test
    func spaceManageIsIndependentOfActionAndCollection() throws {
        // M8-M11
        let grant = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read&manage=update")
        #expect(grant.matches(target(operation: .manage(.update))))
        #expect(!grant.matches(target(operation: .manage(.delete))))

        let noManage = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read")
        #expect(!noManage.matches(target(operation: .manage(.update))))

        let bare = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(!bare.matches(target(operation: .manage(.update))))
    }

    @Test
    func spaceReadImpliesReadSelfButNotReverse() throws {
        // M12-M15
        let readGrant = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read")
        #expect(readGrant.matches(target(operation: Self.plainReadSelf)))

        let readSelfGrant = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read_self")
        #expect(readSelfGrant.matches(target(operation: Self.plainReadSelf)))
        #expect(!readSelfGrant.matches(target(operation: Self.plainRead)))

        let qualified = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&action=read_self&collection=com.atmoboards.thread"
        )
        #expect(qualified.matches(target(operation: Self.plainReadSelf))) // reads are collection-independent
    }

    @Test
    func spaceWriteNeedsBothVerbAndCollectionMembership() throws {
        // M16, M17
        let grant = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&collection=com.atmoboards.thread&action=create"
        )
        #expect(grant.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))
        #expect(!grant.matches(target(operation: .write(.create, collection: "com.atmoboards.reply"))))
    }

    @Test
    func spaceWildcardTypeMatchesAnyConcreteType() throws {
        // M18, M19
        let grant = try SpacePermission.parse("space:*?authority=did:plc:abc")
        #expect(grant.matches(target(operation: Self.plainRead)))
        #expect(grant.matches(target(type: "com.example.different", operation: Self.plainRead)))
    }

    @Test
    func spaceConcreteAuthorityAndSkeyMustMatchExactly() throws {
        // M20, M21
        let grant = try SpacePermission.parse("space:com.atmoboards.forum?authority=did:plc:abc&skey=default")
        #expect(!grant.matches(target(authority: "did:plc:other", operation: Self.plainRead)))
        #expect(!grant.matches(target(skey: "other", operation: Self.plainRead)))
    }

    @Test
    func spaceUnresolvedSelfFailsClosed() throws {
        // M22, M23, M24
        let unresolved = try SpacePermission.parse("space:com.atmoboards.forum")
        #expect(!unresolved.matches(target(operation: Self.plainRead)))

        let toResolve = try SpacePermission.parse("space:com.atmoboards.forum?action=read")
        let resolved = toResolve.withResolvedAuthority("did:plc:abc")
        #expect(resolved.matches(target(operation: Self.plainRead)))
        #expect(!resolved.matches(target(authority: "did:plc:other", operation: Self.plainRead)))
    }

    // MARK: Proposal 0016 — reads ignore collections

    @Test
    func aggregateReadIgnoresTheGrantCollection() throws {
        let bare = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read")
        #expect(bare.matches(target(operation: .read(aggregate: true, collection: nil))))

        let wildcardCollection = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&action=read&collection=*"
        )
        #expect(wildcardCollection.matches(target(operation: .read(aggregate: true, collection: nil))))

        let qualified = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&action=read&collection=com.atmoboards.thread"
        )
        #expect(qualified.matches(target(operation: .read(aggregate: true, collection: nil))))
    }

    @Test
    func collectionQualifiedReadIgnoresTheRequestedCollection() throws {
        let bare = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read")
        #expect(bare.matches(target(operation: .read(aggregate: false, collection: "com.atmoboards.thread"))))

        let qualified = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&action=read&collection=com.atmoboards.reply"
        )
        #expect(qualified.matches(target(operation: .read(aggregate: false, collection: "com.atmoboards.thread"))))
        #expect(qualified.matches(target(operation: .read(aggregate: false, collection: "com.atmoboards.reply"))))
    }

    @Test
    func readSelfIgnoresCollectionsWithoutGrantingReadOrWrite() throws {
        let grant = try SpacePermission.parse(
            "space:com.atmoboards.forum?authority=*&action=read_self&collection=com.atmoboards.reply"
        )
        #expect(grant.matches(target(operation: .readSelf(aggregate: true, collection: nil))))
        #expect(grant.matches(target(operation: .readSelf(aggregate: false, collection: "com.atmoboards.thread"))))
        #expect(!grant.matches(target(operation: Self.plainRead)))
        #expect(!grant.matches(target(operation: .write(.create, collection: "com.atmoboards.reply"))))
        #expect(!grant.matches(target(operation: .delegationExchange)))
    }

    // MARK: scopeNeeded (§5.6.6)

    @Test
    func spaceScopeNeededMatchesUpstreamVectors() throws {
        #expect(try SpacePermission.scopeNeeded(for: target(operation: Self.plainRead))
            == "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read")
        #expect(try SpacePermission.scopeNeeded(
            for: target(operation: .write(.create, collection: "com.atmoboards.thread"))
        ) == "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&collection=com.atmoboards.thread&action=create")
        // manage: action pinned to read_self, NOT omitted / NOT the default list.
        #expect(try SpacePermission.scopeNeeded(for: target(operation: .manage(.update)))
            == "space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read_self&manage=update")
    }

    @Test
    func spaceDelegationExchangeScopeNeededIsByteIdenticalToReadArm() throws {
        let read = try SpacePermission.scopeNeeded(for: target(operation: Self.plainRead))
        let delegation = try SpacePermission.scopeNeeded(for: target(operation: .delegationExchange))
        #expect(read == delegation)
    }

    @Test
    func spaceScopeNeededAntiWideningProperty() throws {
        // The narrowest grant scopeNeeded produces must satisfy the request it
        // was built for, and must NOT satisfy an unrelated write when no
        // collection was named.
        let operations: [SpaceScopeTarget.Operation] = [
            Self.plainRead,
            Self.plainReadSelf,
            .write(.create, collection: "com.atmoboards.thread"),
            .manage(.delete),
        ]
        for operation in operations {
            let string = try SpacePermission.scopeNeeded(for: target(operation: operation))
            let reparsed = try SpacePermission.parse(string)
            #expect(reparsed.matches(target(operation: operation)))
            if case .write = operation {} else {
                #expect(!reparsed.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))
            }
        }
    }

    // MARK: canonicalisation / round-trip

    @Test
    func spaceRoundTripsBareAndFullyQualifiedGrants() throws {
        #expect(try SpacePermission.parse("space:com.atmoboards.forum").canonicalScopeString()
            == "space:com.atmoboards.forum")
        let full = "space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create"
        #expect(try SpacePermission.parse(full).canonicalScopeString() == full)
    }

    @Test
    func spaceAuthorityWildcardSurvivesRoundTripButSkeyWildcardIsDropped() throws {
        // The single highest-value non-upstream vector in the suite
        // (space_permission.rs:1058-1126, esp. :1064-1073).
        let parsed = try SpacePermission.parse("space:com.example.type?authority=*&skey=*")
        let canonical = try parsed.canonicalScopeString()
        #expect(canonical == "space:com.example.type?authority=*") // skey=* dropped (equals default)
        #expect(try SpacePermission.parse(canonical).canonicalScopeString() == canonical) // idempotent
    }

    @Test
    func spaceWithDefaultCollectionsIsNoOpWhenAlreadyQualified() throws {
        let bare = try SpacePermission.parse("space:com.atmoboards.forum")
        let withDefaults = bare.withDefaultCollections([.nsid("com.atmoboards.thread"), .nsid("com.atmoboards.reply")])
        #expect(withDefaults.collection == [.nsid("com.atmoboards.thread"), .nsid("com.atmoboards.reply")])

        let alreadyQualified = try SpacePermission.parse("space:com.atmoboards.forum?collection=com.atmoboards.thread")
        #expect(alreadyQualified.withDefaultCollections([.nsid("com.atmoboards.reply")]).collection
            == [.nsid("com.atmoboards.thread")])

        let wildcard = try SpacePermission.parse("space:com.atmoboards.forum?collection=*")
        #expect(wildcard.withDefaultCollections([.nsid("com.atmoboards.reply")]).collection == [.any])

        #expect(bare.withDefaultCollections([]).collection == []) // empty default list is a no-op
    }

    @Test
    func withDefaultCollectionsPassesActionThroughUnchanged() throws {
        // Upstream parity, and the pin against re-adding a write-verb guard
        // here. `space-permission.ts:134-146` passes `this.action` through as
        // the 5th constructor argument; `:211` wires SPACE_DEFAULT_ACTIONS as
        // the schema default for `action`. So a bare `space:<type>` grant is
        // WRITABLE after expansion — that is what the scope means, not an
        // oversight in it.
        //
        // A guard dropping the write verbs when `action` was unstated was
        // written here and reverted: a schema default applies exactly when the
        // client did not state the parameter, so such a guard makes the
        // create/update/delete half of SPACE_DEFAULT_ACTIONS unreachable for
        // every grant that could ever exist. See `withDefaultCollections`'s
        // doc comment.
        let unstatedAction = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(!unstatedAction.scopeParameters.wasStated("action"))
        #expect(unstatedAction.action == [.read, .create, .update, .delete]) // the default, pre-expansion

        let expanded = unstatedAction.withDefaultCollections([.nsid("com.atmoboards.thread")])
        #expect(expanded.collection == [.nsid("com.atmoboards.thread")])
        #expect(expanded.action == [.read, .create, .update, .delete]) // untouched
        // Expansion is what arms the write verbs, by supplying the targets the
        // empty `collection` list previously denied them. Asserted through
        // `.matches` rather than the action array, because the array alone
        // would also pass if `collectionAllows` were broken.
        #expect(expanded.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))
        #expect(expanded.matches(target(operation: .write(.update, collection: "com.atmoboards.thread"))))
        #expect(expanded.matches(target(operation: .write(.delete, collection: "com.atmoboards.thread"))))
        #expect(expanded.matches(target(authority: "did:plc:anyone", operation: Self.plainRead)))

        // Negative control: expansion widens only to the collections it was
        // given. A collection the space never declared stays refused, so the
        // assertions above are about THESE targets, not about `matches`
        // having become permissive.
        #expect(!expanded.matches(target(operation: .write(.create, collection: "com.atmoboards.undeclared"))))

        // A STATED action is likewise passed through verbatim — expansion
        // never widens the verb set beyond what the grant already carried.
        let statedAction = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=create")
        #expect(statedAction.scopeParameters.wasStated("action"))
        let statedExpanded = statedAction.withDefaultCollections([.nsid("com.atmoboards.thread")])
        #expect(statedExpanded.action == [.create])
        #expect(statedExpanded.matches(target(operation: .write(.create, collection: "com.atmoboards.thread"))))
        #expect(!statedExpanded.matches(target(operation: .write(.delete, collection: "com.atmoboards.thread"))))

        let statedReadSelf = try SpacePermission.parse("space:com.atmoboards.forum?authority=*&action=read_self")
        let readSelfExpanded = statedReadSelf.withDefaultCollections([.nsid("com.atmoboards.thread")])
        #expect(readSelfExpanded.action == [.readSelf])
    }

    @Test
    func withDefaultCollectionsDoesNotInventProvenanceOnUntouchedFields() throws {
        // The second §9-D23 regression this function had to avoid: an
        // earlier version rebuilt its result through the public memberwise
        // initializer, which marks every field `.stated` unconditionally —
        // so `authority` would come out of expansion looking client-stated
        // even though it was never written. Assert the durable bit directly
        // rather than reasoning about it.
        let neverStatedAuthority = try SpacePermission.parse("space:com.atmoboards.forum?skey=*&action=read")
        #expect(!neverStatedAuthority.scopeParameters.wasStated("authority"))
        #expect(!neverStatedAuthority.scopeParameters.wasStated("manage"))
        #expect(neverStatedAuthority.scopeParameters.wasStated("skey"))
        #expect(neverStatedAuthority.scopeParameters.wasStated("action"))

        let expanded = neverStatedAuthority.withDefaultCollections([.nsid("com.atmoboards.thread")])
        // Untouched fields keep BOTH their value and their original
        // provenance — this is the assertion the earlier, buggy version
        // would have failed.
        #expect(!expanded.scopeParameters.wasStated("authority"))
        #expect(!expanded.scopeParameters.wasStated("manage"))
        #expect(expanded.scopeParameters.wasStated("skey"))
        #expect(expanded.scopeParameters.wasStated("action")) // value narrowed elsewhere; provenance carried forward
        #expect(expanded.authority == .unresolvedSelf) // value also unchanged
        // The materialised `collection` itself is `.defaulted`, never
        // `.stated` — the client didn't write it, Phase 2 did.
        #expect(!expanded.scopeParameters.wasStated("collection"))

        // Confirm, rather than reason about, the structural fact any
        // delegation-fence implementation depends on: an expanded grant's
        // `collection` is non-empty regardless of provenance, so clause 2 of
        // such a fence (which this file no longer implements itself — it
        // lives at the resource-plane facade, §9-D23) fails on VALUE alone.
        // Preserving provenance correctly cannot be what flips that clause;
        // the value itself already blocks it.
        #expect(!expanded.collection.isEmpty)
    }

    @Test
    func spaceWithResolvedAuthorityIsIdempotentAndPreservesConcreteAuthority() throws {
        let selfGrant = try SpacePermission.parse("space:com.atmoboards.forum")
        let resolved = selfGrant.withResolvedAuthority("did:plc:abc123xyz")
        #expect(resolved.authority == .did("did:plc:abc123xyz"))
        #expect(resolved.withResolvedAuthority("did:plc:different").authority == .did("did:plc:abc123xyz")) // idempotent

        let concrete = try SpacePermission.parse("space:com.atmoboards.forum?authority=did:plc:existing")
        #expect(concrete.withResolvedAuthority("did:plc:abc123xyz").authority == .did("did:plc:existing")) // unchanged

        let wildcard = try SpacePermission.parse("space:com.atmoboards.forum?authority=*")
        #expect(wildcard.withResolvedAuthority("did:plc:abc123xyz").authority == .any) // unchanged
    }

    @Test
    func resolvingSelfFailsClosedOnNilSubjectAndDelegatesOtherwise() throws {
        // §6.1: `nil` subject == fail closed — the grant comes back unresolved
        // and therefore matches nothing (§5.6.3 step 2).
        let selfGrant = try SpacePermission.parse("space:com.atmoboards.forum")
        let unresolved = selfGrant.resolvingSelf(as: nil)
        #expect(unresolved.authority == .unresolvedSelf)
        #expect(!unresolved.matches(target(operation: Self.plainRead)))

        // A concrete subject delegates to withResolvedAuthority.
        let resolved = selfGrant.resolvingSelf(as: "did:plc:abc123xyz")
        #expect(resolved.authority == .did("did:plc:abc123xyz"))

        // Idempotent under repeated calls, including a mixed nil-then-concrete
        // sequence a caller might run once at mint and again at match time.
        #expect(resolved.resolvingSelf(as: "did:plc:different").authority == .did("did:plc:abc123xyz"))
        #expect(resolved.resolvingSelf(as: nil).authority == .did("did:plc:abc123xyz"))
    }

    // MARK: §9-D23 / delegation-fence relocation — the facade owns the fence now

    @Test
    func delegationExchangeMatchAlwaysReturnsFalseRegardlessOfGrantShape() throws {
        // The delegation fence moved OFF the parser and onto the resource-plane
        // facade (`SwanScopePermissions`), which composes it from DURABLE
        // provenance bits plus an ordinary `.read` match — see this file's
        // `Operation.delegationExchange` doc comment and §9-D23. A
        // `SpacePermission` re-parsed from a persisted string can never be
        // trusted to answer this question itself (mint-time `self` resolution
        // makes a defaulted `authority` look stated; canonicalisation deletes
        // a stated `skey=*`), so `matches(_:)` must return `false` here
        // unconditionally — even for what LOOKS like the exact literal grant.
        let target = { (skey: String) in
            SpaceScopeTarget(type: "com.x.y", authority: "did:plc:abc", skey: skey, operation: .delegationExchange)
        }

        // What would have been the exact, literal, minimal grant.
        let exact = try SpacePermission.parse("space:com.x.y?authority=did:plc:abc&skey=*&action=read")
        #expect(!exact.matches(target("*")))

        // A defaulted (never-stated) action list.
        let defaultedAction = try SpacePermission.parse("space:com.x.y?authority=did:plc:abc")
        #expect(!defaultedAction.matches(target("irrelevant")))

        // A grant that resolved `self` -> the requested authority (the exact
        // §9-D23 amplification scenario).
        let resolved = try SpacePermission.parse("space:com.x.y?skey=*&action=read")
            .withResolvedAuthority("did:plc:abc")
        #expect(!resolved.matches(target("*")))

        // A wildcard-everything grant.
        let wildcard = try SpacePermission.parse("space:*?authority=*&skey=*&action=read")
        #expect(!wildcard.matches(target("*")))
    }

    @Test
    func withResolvedAuthorityPreservesDefaultedProvenanceNotJustTheValue() throws {
        // This is the exact regression §9-D23 exists to prevent: resolving
        // `self` must change ONLY the value of `authority`, never whether the
        // client stated it. A grant with `authority` DEFAULTED (never written)
        // must still show `authority` as defaulted after resolution, so a
        // facade-level fence reading durable provenance off this grant
        // continues to see "not stated" rather than "stated" post-mint.
        let defaultedAuthority = try SpacePermission.parse("space:com.x.y?skey=*&action=read")
        #expect(!defaultedAuthority.scopeParameters.wasStated("authority"))

        let resolved = defaultedAuthority.withResolvedAuthority("did:plc:USER")
        #expect(resolved.authority == .did("did:plc:USER")) // value changed
        #expect(!resolved.scopeParameters.wasStated("authority")) // statedness UNCHANGED

        // Mirror case: a LITERALLY stated authority stays stated post-resolution
        // (resolution is a no-op here since it's already concrete, but the
        // provenance-preservation contract must hold regardless).
        let statedAuthority = try SpacePermission.parse("space:com.x.y?authority=did:plc:USER&skey=*&action=read")
        #expect(statedAuthority.scopeParameters.wasStated("authority"))
        let noOpResolve = statedAuthority.withResolvedAuthority("did:plc:OTHER")
        #expect(noOpResolve.authority == .did("did:plc:USER")) // unchanged (already concrete)
        #expect(noOpResolve.scopeParameters.wasStated("authority"))
    }

    @Test
    func statedSkeyWildcardSurvivesCanonicalisationForTheListingFenceWitness() throws {
        // Mirror case from §9-D23: canonical serialisation deletes `skey=*`
        // because it equals the default, but the PARSED VALUES (pre-format)
        // must still report it as stated — this is what a persistence layer
        // reading straight off the parse (not re-parsing the canonical string)
        // must preserve.
        let parsed = try SpacePermission.parse("space:com.x.y?authority=*&skey=*&action=read")
        #expect(parsed.scopeParameters.wasStated("skey"))
        let canonical = try parsed.canonicalScopeString()
        #expect(!canonical.contains("skey")) // deleted by canonicalisation
        // Re-parsing the canonical string is where the DESTRUCTION happens —
        // pinning it so nobody "fixes" the encoder into re-adding skey=* and
        // silently changes this contract.
        let reparsed = try SpacePermission.parse(canonical)
        #expect(!reparsed.scopeParameters.wasStated("skey"))
    }

    @Test
    func provenanceAccessorsExposeRawCaseAndStatedKeySet() throws {
        // Accessors consumers outside SwanCore depend on (§9-D23's "expose
        // whatever accessor the fences need"): `provenance(for:)` returns the
        // exact case (not just a bool), and `statedKeys` enumerates every
        // physically-written key — both are what a durable persistence layer
        // needs to serialise "which keys were stated" beside the grant.
        let parsed = try SpacePermission.parse("space:com.x.y?authority=did:plc:abc&action=read")
        #expect(parsed.scopeParameters.provenance(for: "authority") == .stated)
        #expect(parsed.scopeParameters.provenance(for: "skey") == .defaulted)
        #expect(parsed.scopeParameters.provenance(for: "nonexistent") == nil)
        #expect(parsed.scopeParameters.statedKeys == ["spaceType", "authority", "action"])
    }
}
