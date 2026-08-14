import Foundation
import Testing
@testable import SwanCore

/// Phase 2 expansion (§5.7.3) and its vectors (§5.7.6).
///
/// Fixtures are decoded from **JSON literals**, not built with the in-memory
/// initializers, so every vector also exercises the `Decodable` path that gives
/// `spaceType` its remap and `inheritAud: true` its boolean type. Building them
/// with `LexiconValue.string("true")` would pass while the wire path was broken.
///
/// Vectors transcribed from
/// `packages/oauth/oauth-scopes/src/scopes/include-scope.test.ts`
/// (`.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`).
@Suite("include: expansion (Phase 2, §5.7.3)")
struct OAuthScopesIncludeExpansionTests {
    // MARK: - Helpers

    private func permissionSet(_ json: String) throws -> LexiconPermissionSet {
        try JSONDecoder().decode(LexiconPermissionSet.self, from: Data(json.utf8))
    }

    /// Upstream's `compilePermissions` (`include-scope.test.ts:165-168`).
    private func compile(_ scope: String, _ json: String) throws -> [String] {
        try IncludeScope.parse(scope).expandToScopeStrings(permissionSet(json))
    }

    private let auth = "include:com.example.calendar.auth"

    // MARK: - isParentAuthorityOf (§5.7.6, include-scope.test.ts:117-158)

    @Test
    func isParentAuthorityOfAcceptsSameAndChildAuthorities() throws {
        let scope = try IncludeScope.parse("include:com.example.foo.auth")
        #expect(scope.isParentAuthorityOf("com.example.foo.identifier"))
        #expect(scope.isParentAuthorityOf("com.example.foo.bar.baz"))
        #expect(scope.isParentAuthorityOf("com.example.foo.bar.baz.quz"))
    }

    @Test
    func isParentAuthorityOfRejectsShortSiblingAndForeignNSIDs() throws {
        let scope = try IncludeScope.parse("include:com.example.foo.auth")
        // Shorter than the group prefix (`:159-161`).
        #expect(!scope.isParentAuthorityOf("com"))
        #expect(!scope.isParentAuthorityOf("com.example"))
        // Siblings of the root domain.
        #expect(!scope.isParentAuthorityOf("com.example.bar"))
        #expect(!scope.isParentAuthorityOf("com.example.bar.foo"))
        #expect(!scope.isParentAuthorityOf("com.example.bar.qux"))
        // Other domains.
        #expect(!scope.isParentAuthorityOf("com.atproto.foo"))
        #expect(!scope.isParentAuthorityOf("com.atproto.foo.auth"))
        #expect(!scope.isParentAuthorityOf("com.atproto.foo.bar"))
    }

    @Test
    func isParentAuthorityOfAlwaysRejectsTheBareWildcard() throws {
        // `:144-146` — a permission set may never grant "everything", whatever
        // the include's own NSID is.
        for nsid in ["include:com.example.foo.auth", "include:com.example.bar", "include:a.b.c.d.e"] {
            #expect(!(try IncludeScope.parse(nsid).isParentAuthorityOf("*")))
        }
    }

    @Test
    func isParentAuthorityOfIsByteSafeOnUnvalidatedInput() throws {
        // `other` reaches this function straight from a lexicon document, so it
        // is not necessarily ASCII, not necessarily an NSID, and may be empty.
        // The requirement is that no unit mismatch and no index arithmetic can
        // make any of these true or trap.
        let scope = try IncludeScope.parse("include:com.example.foo.auth")
        #expect(!scope.isParentAuthorityOf(""))
        #expect(!scope.isParentAuthorityOf("."))
        #expect(!scope.isParentAuthorityOf("com.example.foo."))
        #expect(!scope.isParentAuthorityOf("com.example.foo"))
        #expect(!scope.isParentAuthorityOf("\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}"))
        // One byte past the group prefix is the shortest accepted candidate.
        #expect(scope.isParentAuthorityOf("com.example.foo.a"))
        // Non-ASCII beyond the group prefix: 18 UTF-8 bytes, 17 UTF-16 units,
        // and the ASCII prefix matches either way, so byte units and upstream's
        // code-unit count agree. Pinned so a future "just use Character
        // distance" edit has to face a case where the three units differ.
        #expect(scope.isParentAuthorityOf("com.example.foo.\u{00E9}"))
        // The straddling case: 16 UTF-8 bytes, 15 UTF-16 units, 15 Characters.
        // The length guard rejects under bytes; the prefix check rejects under
        // every unit. Both answers are false, which is the invariant that
        // matters — the guard may never be the ONLY thing standing between an
        // arbitrary string and a grant.
        #expect(!scope.isParentAuthorityOf("com.example.fo\u{00E9}"))
    }

    // MARK: - Gate 1: families that never expand (§5.7.6)

    @Test
    func blobEntriesAreDroppedWhetherValidOrNot() throws {
        // `:170-215` — both the well-formed and the malformed blob entry.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"blob","accept":["image/*"]}]}
        """) == [])
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"blob","accept":"image/*"}]}
        """) == [])
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"blob","accept":["image/*"],"extra":"property"}]}
        """) == [])
    }

    @Test
    func accountAndIdentityEntriesAreRejectedEvenWithValidSyntax() throws {
        // `:578-633`. The upstream suite first proves the syntax IS valid for
        // those families (`:586-594`, `:615-622`) so the rejection is not a
        // false negative; the Swan equivalent of that control is below.
        let accountJSON = """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"account","attr":"email","action":["read"]}]}
        """
        let identityJSON = """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"identity","attr":"handle"}]}
        """
        #expect(try compile(auth, accountJSON) == [])
        #expect(try compile(auth, identityJSON) == [])

        // Positive control: the same entries DO parse as their own families
        // through the same adapter, so the `[]` above is gate 1 and not a
        // silently broken adapter.
        let account = try permissionSet(accountJSON).permissions[0]
        let accountPermission = try AccountPermission(
            parameters: AccountPermission.schema.parse(LexPermissionSyntax(permission: account))
        )
        #expect(accountPermission.attr == .email)

        let identity = try permissionSet(identityJSON).permissions[0]
        let identityPermission = try IdentityPermission(
            parameters: IdentityPermission.schema.parse(LexPermissionSyntax(permission: identity))
        )
        #expect(identityPermission.attr == .handle)
    }

    @Test
    func unknownResourcesAreDropped() throws {
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"nonsense","collection":["com.example.calendar.event"]}]}
        """) == [])
    }

    // MARK: - rpc (§5.7.6, include-scope.test.ts:218-443)

    @Test
    func rpcWildcardAudienceExpands() throws {
        // `:220-234` and its duplicate `:411-425`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":"*",
           "lxm":["com.example.calendar.listEvents"]}]}
        """) == ["rpc:com.example.calendar.listEvents?aud=*"])
    }

    @Test
    func rpcInheritsTheIncludesAudience() throws {
        // `:236-262` — the written-out vector. The splice at `:96-103` requires
        // ALL THREE of `inheritAud === true`, `aud === undefined`, and a non-nil
        // `self.aud`; the three tests below drop one condition each.
        #expect(try compile("\(auth)?aud=did:web:example.com#foo", """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","inheritAud":true,
           "lxm":["com.example.calendar.listEvents"]},
          {"type":"permission","resource":"rpc","inheritAud":true,
           "lxm":["com.example.calendar.getEventDetails"]}]}
        """) == [
            "rpc:com.example.calendar.listEvents?aud=did:web:example.com%23foo",
            "rpc:com.example.calendar.getEventDetails?aud=did:web:example.com%23foo",
        ])
    }

    @Test
    func rpcDropsAnUnsplicedInheritAud() throws {
        // `:395-409` "un-specified inherited-aud" — no `?aud=` on the include,
        // so no splice, so `inheritAud` survives as an unknown key (§4.6).
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","inheritAud":true,
           "lxm":["com.example.calendar.listEvents"]}]}
        """) == [])
    }

    @Test
    func rpcDropsInheritAudSpelledAsAnythingButTheBooleanTrue() throws {
        // `:97` is `=== true`. `1` and `"true"` are not it, and neither may be
        // coerced into it by the adapter — a coercion would splice an audience
        // into an entry upstream drops.
        for spelling in ["1", "\"true\"", "false", "[true]"] {
            #expect(try compile("\(auth)?aud=did:web:example.com#foo", """
            {"type":"permission-set","permissions":[
              {"type":"permission","resource":"rpc","inheritAud":\(spelling),
               "lxm":["com.example.calendar.listEvents"]}]}
            """) == [], "inheritAud spelled \(spelling) must not splice")
        }
    }

    @Test
    func rpcRejectsAConcreteAudience() throws {
        // `:266-280`, and the same gate closes `:282-296` (invalid lxm syntax),
        // `:298-313` (extra properties), `:315-328` (missing lxm),
        // `:359-377` (both inheritAud and aud), `:379-393` (invalid authority).
        for entry in [
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo","lxm":["com.example.calendar.listEvents"]}"#,
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo","lxm":"com.example.calendar.listEvents"}"#,
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo","lxm":["com.example.calendar.listEvents"],"extra":"property"}"#,
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo"}"#,
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo","inheritAud":true,"lxm":["com.example.calendar.listEvents"]}"#,
            #"{"type":"permission","resource":"rpc","aud":"did:web:example.com#foo","lxm":["com.atproto.moderation.createReport"]}"#,
        ] {
            #expect(try compile("\(auth)?aud=did:web:example.com#bar", """
            {"type":"permission-set","permissions":[\(entry)]}
            """) == [], "entry \(entry)")
        }
    }

    @Test
    func rpcDropsEntriesMissingRequiredParameters() throws {
        // `:330-343` missing "aud"; `:345-357` missing "aud" and "lxm".
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","lxm":["com.example.calendar.listEvents"]}]}
        """) == [])
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[{"type":"permission","resource":"rpc"}]}
        """) == [])
    }

    @Test
    func rpcAuthorityGateAppliesToEveryLxm() throws {
        // `:427-441` "wildcard-aud for invalid authority" — the grant parses,
        // gate 3 drops it.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":"*",
           "lxm":["com.atproto.moderation.createReport"]}]}
        """) == [])
        // Swan-authored: `.every`, so one foreign lxm drops the entry that
        // carries it even though its sibling is in-namespace.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":"*",
           "lxm":["com.example.calendar.listEvents","com.atproto.moderation.createReport"]}]}
        """) == [])
    }

    // MARK: - repo (§5.7.6, include-scope.test.ts:445-576)

    @Test
    func repoValidPermissionExpands() throws {
        // `:447-461`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "action":["create","update","delete"]}]}
        """) == ["repo:com.example.calendar.event"])
    }

    @Test
    func repoPartialActionsCanonicalise() throws {
        // `:463-489` — pins declaration order, action re-ordering into
        // REPO_ACTIONS order, and the multi-collection non-positional form.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "action":["delete","update"]},
          {"type":"permission","resource":"repo",
           "collection":["com.example.calendar.event","com.example.calendar.rsvp"],
           "action":["delete","create"]}]}
        """) == [
            "repo:com.example.calendar.event?action=update&action=delete",
            "repo?collection=com.example.calendar.event&collection=com.example.calendar.rsvp&action=create&action=delete",
        ])
    }

    /// **THE ARITY VECTOR** (`include-scope.test.ts:493-507`, §5.7.6's
    /// `scalar-where-array`). A `collection` given as a bare scalar where an
    /// array is required is `getMulti` -> `null` -> whole-entry rejection.
    /// Stringify the scalar into a one-element array and this `[]` becomes a
    /// live `repo:` create/update/delete grant — the widening §5.7.3 gate 3
    /// exists to stop. Asserted explicitly, and asserted twice: once end to end,
    /// once at the adapter, so a regression names the layer it broke in.
    @Test
    func repoScalarWhereAnArrayIsRequiredRejectsTheWholeEntry() throws {
        let json = """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":"com.example.calendar.event",
           "action":["create","update","delete"]}]}
        """
        #expect(try compile(auth, json) == [])

        let entry = try permissionSet(json).permissions[0]
        let syntax = LexPermissionSyntax(permission: entry)
        // The adapter must report "present but not an array", never "absent"
        // and never a one-element list.
        #expect(syntax.getMulti("collection") == .rejected)
        #expect(syntax.getMulti("collection") != .values(["com.example.calendar.event"]))
        // ... and the schema must turn that into a throw, not a default.
        #expect(throws: ScopeParseError.self) {
            try RepoPermission.schema.parse(syntax)
        }
        // The companion fixture at `:509-523`: `action: 'all'`. Not itself a
        // widening (`'all'` fails RepoAction's validate either way), but the
        // same mechanism.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "action":"all"}]}
        """) == [])
    }

    @Test
    func repoInvalidActionValuesRejectTheEntry() throws {
        // `:525-539`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "action":["create","update","manage"]}]}
        """) == [])
    }

    @Test
    func repoInvalidAuthorityIsDropped() throws {
        // `:541-555`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["app.bsky.feed.post"],
           "action":["create","update","delete"]}]}
        """) == [])
    }

    /// `'permissions with one valid and one invalid authority'`
    /// (`include-scope.test.ts:557-574`) — **as upstream actually writes it**:
    /// ONE entry whose `collection` array holds one in-namespace and one
    /// out-of-namespace NSID, expecting `[]`, because `isAllowedPermission`
    /// applies `.every` over that entry's own collections (`:125`).
    ///
    /// §5.7.6 describes this row as "a two-entry repo set" yielding "a one-element
    /// array". That description does not match the cited fixture in any of the
    /// three checkouts available here. The lane reports the discrepancy and
    /// asserts BOTH: upstream's fixture verbatim, and — as the property §5.7.6
    /// was reaching for — a Swan-authored two-entry set proving the gate is per
    /// ENTRY rather than per SET.
    @Test
    func repoAuthorityGateIsPerEntryAndUsesEveryWithinAnEntry() throws {
        // Upstream verbatim: one entry, two collections, one foreign -> [].
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo",
           "collection":["com.example.calendar.event","app.bsky.feed.post"],
           "action":["create","update","delete"]}]}
        """) == [])

        // Swan-authored: two entries, one entirely in-namespace and one
        // entirely foreign. A per-SET gate yields [] here and passes every
        // other include vector; only this one distinguishes it.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "action":["create","update","delete"]},
          {"type":"permission","resource":"repo","collection":["app.bsky.feed.post"],
           "action":["create","update","delete"]}]}
        """) == ["repo:com.example.calendar.event"])

        // Same property across families and across a gate-2 failure: a dropped
        // entry never takes its siblings with it.
        #expect(try compile("\(auth)?aud=did:web:example.com#foo", """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"blob","accept":["image/*"]},
          {"type":"permission","resource":"repo","collection":"com.example.calendar.event"},
          {"type":"permission","resource":"space","spaceType":"*"},
          {"type":"permission","resource":"rpc","inheritAud":true,
           "lxm":["com.example.calendar.listEvents"]},
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group"}]}
        """) == [
            "rpc:com.example.calendar.listEvents?aud=did:web:example.com%23foo",
            "space:com.example.calendar.group",
        ])
    }

    // MARK: - space (§5.7.6, include-scope.test.ts:636-743)

    /// Pins §5.7.3 gate 1, the `spaceType` -> `type` remap
    /// (`include-scope.test.ts:638-652`). Without it, `space`'s required `type`
    /// (§5.6.2) is absent from every upstream fixture, `parse` throws
    /// `.missingRequiredParameter`, and no space permission is ever expanded.
    @Test
    func spaceTypeOnlyExpandsAndPinsTheSpaceTypeRemap() throws {
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group",
           "action":["read","create","update","delete"]}]}
        """) == ["space:com.example.calendar.group"])
    }

    @Test
    func spaceTypeSurfacesOnlyForSpaceResources() throws {
        // The remap is scoped to `resource == "space"` (`syntax-lexicon.ts:29`).
        // A repo entry carrying `spaceType` must NOT gain a `type`, and
        // `spaceType` must stay filtered (`:36`) rather than becoming an unknown
        // key that drops a valid entry.
        let space = LexPermissionSyntax(permission: LexiconPermission(
            resource: "space", fields: ["spaceType": .string("com.example.calendar.group")]
        ))
        #expect(space.getSingle("type") == .present("com.example.calendar.group"))
        #expect(space.getSingle("spaceType") == .absent)
        #expect(space.keys() == ["type"])

        let repo = LexPermissionSyntax(permission: LexiconPermission(
            resource: "repo",
            fields: ["collection": .list([.string("com.example.calendar.event")]),
                     "spaceType": .string("com.example.calendar.group")]
        ))
        #expect(repo.getSingle("type") == .absent)
        #expect(repo.keys() == ["collection"])
        // ... so the entry still expands rather than dying on an unknown key.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":["com.example.calendar.event"],
           "spaceType":"com.example.calendar.group"}]}
        """) == ["repo:com.example.calendar.event"])
    }

    @Test
    func reservedKeysAreFilteredRatherThanRejectingTheEntry() throws {
        // §5.7.3 gate 2. Every upstream fixture carries `type: 'permission'` and
        // `resource: ...`; under §4.6's unknown-key rule either key would kill
        // every entry. `keys()` must not surface them.
        let repo = LexPermissionSyntax(permission: LexiconPermission(
            type: "permission", resource: "repo",
            fields: ["collection": .list([.string("com.example.calendar.event")])]
        ))
        #expect(repo.keys() == ["collection"])
        #expect(repo.getSingle("resource") == .absent)
        #expect(repo.getSingle("type") == .absent)
        #expect(repo.prefix == "repo")
        #expect(repo.positional == nil)
    }

    @Test
    func spaceTypeAndCollectionExpands() throws {
        // `:654-671`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group",
           "collection":["com.example.calendar.event"],"action":["create","update"]}]}
        """) == [
            "space:com.example.calendar.group?collection=com.example.calendar.event&action=create&action=update",
        ])
    }

    @Test
    func spaceTypeOutsideTheIncludeNamespaceIsDropped() throws {
        // `:675-688`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"app.bsky.group"}]}
        """) == [])
    }

    @Test
    func wildcardSpaceTypeIsTooBroadForAPermissionSet() throws {
        // `:690-703`.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"*"}]}
        """) == [])
    }

    @Test
    func spaceCollectionsAreAuthorityExempt() throws {
        // `:706-742` — proposal 0016: the space TYPE must be under the set's
        // authority; collections may be foreign or a wildcard.
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group",
           "collection":["app.bsky.feed.post"]}]}
        """) == ["space:com.example.calendar.group?collection=app.bsky.feed.post"])
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group",
           "collection":["*"]}]}
        """) == ["space:com.example.calendar.group?collection=*"])
    }

    @Test
    func spaceEntriesCarryProvenanceForTheSwanFences() throws {
        // §9-D23: `wasStated` must reflect what the lexicon entry NAMED, not
        // what the schema defaulted, or the delegation/listing fences silently
        // widen for include-derived space grants exactly as they would for a
        // parsed one.
        let expanded = try IncludeScope.parse(auth).expand(permissionSet("""
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"space","spaceType":"com.example.calendar.group",
           "skey":"*"}]}
        """))
        guard case let .space(permission)? = expanded.first else {
            Issue.record("expected one space permission, got \(expanded)")
            return
        }
        #expect(permission.scopeParameters.wasStated("skey"))
        #expect(!permission.scopeParameters.wasStated("authority"))
        #expect(!permission.scopeParameters.wasStated("action"))
    }

    // MARK: - LexiconValue: ParamValue = string | number | boolean (§5.7.3 gate 4)

    @Test
    func lexiconValueKeepsScalarsTyped() throws {
        let set = try permissionSet("""
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","inheritAud":true,"count":1,"ratio":1.5,
           "name":"x","list":["a","b"],"nested":[["a"]]}]}
        """)
        let fields = set.permissions[0].fields
        // A boolean must NOT arrive as the number 1, and a number must NOT
        // arrive as a boolean — `inheritAud === true` is an identity check.
        #expect(fields["inheritAud"] == .bool(true))
        #expect(fields["count"] == .number(1))
        #expect(fields["ratio"] == .number(1.5))
        #expect(fields["name"] == .string("x"))
        #expect(fields["list"] == .list([.string("a"), .string("b")]))
        #expect(fields["nested"] == .list([.list([.string("a")])]))
        // Arity is not erased by the stringifier either.
        #expect(LexiconValue.bool(true).scalarText == "true")
        #expect(LexiconValue.number(1).scalarText == "1")
        #expect(LexiconValue.number(1.5).scalarText == "1.5")
        #expect(LexiconValue.list([.string("a")]).scalarText == nil)
    }

    @Test
    func lexiconValueDoesNotTrapOnOutOfRangeNumbers() throws {
        // `String(Int(_:))` traps outside Int's range, and this value comes from
        // an attacker-reachable document. Rejection is fine; a crash is not.
        let set = try permissionSet("""
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":[1e300,-1e300]}]}
        """)
        let collection = set.permissions[0].fields["collection"]
        #expect(collection?.scalarText == nil)
        if case let .list(items)? = collection {
            for item in items { _ = item.scalarText }
        }
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"repo","collection":[1e300]}]}
        """) == [])
    }

    @Test
    func aNullFieldFailsTheDocumentRatherThanSilentlyWideningIt() throws {
        // Fail-closed divergence, documented on `LexiconPermission`: upstream
        // drops the entry, Swan refuses the document. Either way the entry never
        // becomes a grant, which is the property that matters.
        #expect(throws: (any Error).self) {
            try permissionSet("""
            {"type":"permission-set","permissions":[
              {"type":"permission","resource":"repo","collection":null}]}
            """)
        }
    }

    @Test
    func arrayWhereASingleValueIsRequiredRejectsTheWholeEntry() throws {
        // The mirror of the scalar-where-array vector: `getSingle` returns
        // upstream `null` for an array (`syntax-lexicon.ts:53-57`). `aud` is
        // single-valued, so `["*"]` must reject rather than collapse to `"*"`.
        let syntax = LexPermissionSyntax(permission: try permissionSet("""
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":["*"],
           "lxm":["com.example.calendar.listEvents"]}]}
        """).permissions[0])
        #expect(syntax.getSingle("aud") == .repeated([]))
        #expect(throws: ScopeParseError.self) {
            try RpcPermission.schema.parse(syntax)
        }
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":["*"],
           "lxm":["com.example.calendar.listEvents"]}]}
        """) == [])
    }

    // MARK: - Swan-side surface

    @Test
    func expandReturnsTypedPermissionsNotOnlyStrings() throws {
        // P2-F consumes `[IncludedPermission]`; the string form is a convenience
        // over it, not the other way round.
        let expanded = try IncludeScope.parse("\(auth)?aud=did:web:example.com#foo")
            .expand(permissionSet("""
            {"type":"permission-set","permissions":[
              {"type":"permission","resource":"repo","collection":["com.example.calendar.event"]},
              {"type":"permission","resource":"rpc","inheritAud":true,
               "lxm":["com.example.calendar.listEvents"]},
              {"type":"permission","resource":"space","spaceType":"com.example.calendar.group"}]}
            """))
        #expect(expanded.count == 3)
        guard case let .repo(repo) = expanded[0] else {
            Issue.record("expected repo, got \(expanded[0])"); return
        }
        #expect(repo.collection == [.nsid("com.example.calendar.event")])
        #expect(repo.action == REPO_ACTIONS)
        guard case let .rpc(rpc) = expanded[1] else {
            Issue.record("expected rpc, got \(expanded[1])"); return
        }
        #expect(rpc.aud == .service("did:web:example.com#foo"))
        #expect(rpc.lxm == [.nsid("com.example.calendar.listEvents")])
        guard case let .space(space) = expanded[2] else {
            Issue.record("expected space, got \(expanded[2])"); return
        }
        #expect(space.type == .nsid("com.example.calendar.group"))
        #expect(space.authority == .unresolvedSelf)
    }

    @Test
    func anEmptyPermissionSetExpandsToNothingWithoutFailing() throws {
        // §5.7.5: "every entry dropped -> empty expansion" is NOT an error. The
        // caller owes a `.warn` AND §5.7.2's consent string; expansion itself
        // must not throw.
        #expect(try compile(auth, #"{"type":"permission-set","permissions":[]}"#) == [])
        #expect(try compile(auth, """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"blob","accept":["image/*"]}]}
        """) == [])
    }

    @Test
    func permissionSetDecodesItsDiscriminatorAndOptionalProse() throws {
        // `type` must survive decode: `lexicon-manager.ts:126-129` keys its
        // "not a permission set" rejection off it, and P2-E needs it.
        let set = try permissionSet("""
        {"type":"permission-set","title":"Calendar","detail":"Manage events",
         "title:lang":{"fr":"Agenda"},"detail:lang":{"fr":"Gerer"},
         "permissions":[{"type":"permission","resource":"blob","accept":["image/*"]}]}
        """)
        #expect(set.type == "permission-set")
        #expect(set.title == "Calendar")
        #expect(set.detail == "Manage events")
        #expect(set.permissions.count == 1)
        #expect(set.permissions[0].type == "permission")
        #expect(set.permissions[0].resource == "blob")
        #expect(set.permissions[0].fields.keys.sorted() == ["accept"])
    }

    /// Swan accepts `include:<nsid>?aud=*` where upstream does not
    /// (`include-scope.ts:183-187` validates `aud` with `isAtprotoDidRefAbsolute`
    /// alone). Until §5.7.1 is reconciled, the splice must not carry that
    /// wildcard into an `rpc:` grant: `this.aud === '*'` is unreachable upstream,
    /// so there is no upstream behaviour to match, and `rpc:<lxm>?aud=*` is
    /// strictly wider than anything the include could have expressed.
    @Test
    func aWildcardIncludeAudienceIsNotSplicedIntoAnRpcGrant() throws {
        #expect(try compile("\(auth)?aud=*", """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","inheritAud":true,
           "lxm":["com.example.calendar.listEvents"]}]}
        """) == [])
        // An entry that names `aud: "*"` itself is unaffected — that is
        // upstream's own `:220-234` vector and stays expandable.
        #expect(try compile("\(auth)?aud=*", """
        {"type":"permission-set","permissions":[
          {"type":"permission","resource":"rpc","aud":"*",
           "lxm":["com.example.calendar.listEvents"]}]}
        """) == ["rpc:com.example.calendar.listEvents?aud=*"])
    }
}
