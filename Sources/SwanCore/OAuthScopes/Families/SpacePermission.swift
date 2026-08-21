/// `space:` — Swan's core surface. Source:
/// `oauth-scopes/scopes/space-permission.ts:14-286`. This is the family
/// `bulleted.app` uses and the one Swan already has a divergent implementation
/// of.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.6.
public enum SpaceAction: String, Sendable, Hashable, CaseIterable {
    case readSelf = "read_self"
    case read, create, update, delete
}

/// Canonical order — normalization FILTERS this list, so the declaration order
/// here is the serialization order (space-permission.ts:14-20, :212-214).
public let SPACE_ACTIONS: [SpaceAction] = [.readSelf, .read, .create, .update, .delete]

/// `read_self` is omitted because `read` already implies it (:24-30).
public let SPACE_DEFAULT_ACTIONS: [SpaceAction] = [.read, .create, .update, .delete]

/// A DISJOINT enum from SpaceAction: same three verb names, different targets
/// (space lifecycle/metadata, not records). space-permission.ts:32-36.
public enum SpaceManageOp: String, Sendable, Hashable, CaseIterable {
    case create, update, delete
}

public let SPACE_MANAGE_OPS: [SpaceManageOp] = [.create, .update, .delete]

public enum SpaceTypeParam: Sendable, Hashable {
    case any // "*"
    case nsid(String) // space-permission.ts:40-42

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .nsid(value): value
        }
    }
}

public enum SpaceAuthorityParam: Sendable, Hashable {
    case any // "*"
    /// Wire value "self". NOT spelled `case self` — `.self` is a metatype
    /// expression in Swift and `x == .self` will not compile. The name also
    /// carries the fail-closed property: an UNRESOLVED self matches nothing.
    case unresolvedSelf
    case did(String) // space-permission.ts:47-51

    public var stringValue: String {
        switch self {
        case .any: "*"
        case .unresolvedSelf: "self"
        case let .did(value): value
        }
    }
}

public enum SpaceSkeyParam: Sendable, Hashable {
    case any // "*"
    case key(String) // record-key syntax, :53-56

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .key(value): value
        }
    }
}

public enum SpaceCollectionParam: Sendable, Hashable, Comparable {
    case any // "*"
    case nsid(String) // space-permission.ts:58-61

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .nsid(value): value
        }
    }

    public static func < (lhs: SpaceCollectionParam, rhs: SpaceCollectionParam) -> Bool {
        lhs.stringValue < rhs.stringValue
    }
}

public struct SpacePermission: ScopePermission {
    /// Positional key. single, required, no default.
    public let type: SpaceTypeParam
    /// single, not required, default .unresolvedSelf (:183). NOT `.any` —
    /// "the difference between 'my bookmarks' and 'everyone's bookmarks'"
    /// (atproto-crates space_permission.rs:199-206).
    public let authority: SpaceAuthorityParam
    /// single, not required, default .any (:189).
    public let skey: SpaceSkeyParam
    /// multiple, not required, default [] (:198).
    /// Empty means NO WRITE TARGETS — it does not mean "all collections".
    public let collection: [SpaceCollectionParam]
    /// multiple, not required, default SPACE_DEFAULT_ACTIONS (:211).
    public let action: [SpaceAction]
    /// multiple, not required, default [] (:220).
    public let manage: [SpaceManageOp]

    /// The exact parsed/defaulted values, INCLUDING PROVENANCE. This is the
    /// source of truth for `scopeParameters` and therefore for `wasStated` —
    /// see ScopeParameterValues's doc comment and §9-D23. It must never be
    /// re-derived from `type`/`authority`/… alone, because those typed fields
    /// cannot distinguish "the client wrote `authority=self`" from "the client
    /// wrote nothing and the schema default supplied `self`".
    private let parameters: ScopeParameterValues

    public init(
        type: SpaceTypeParam,
        authority: SpaceAuthorityParam = .unresolvedSelf,
        skey: SpaceSkeyParam = .any,
        collection: [SpaceCollectionParam] = [],
        action: [SpaceAction] = SPACE_DEFAULT_ACTIONS,
        manage: [SpaceManageOp] = []
    ) {
        self.type = type
        self.authority = authority
        self.skey = skey
        self.collection = collection
        self.action = action
        self.manage = manage
        self.parameters = Self.buildParameters(
            type: type, authority: authority, skey: skey,
            collection: collection, action: action, manage: manage
        )
    }

    /// Internal-only: reconstructs a value with an EXPLICIT `ScopeParameterValues`
    /// rather than a freshly synthesised (all-`.stated`) one. This is what lets
    /// `withResolvedAuthority` change `authority`'s VALUE while preserving its
    /// original provenance (§9-D23) — the public initializer above cannot do
    /// this, because it always states everything it is given.
    private init(
        type: SpaceTypeParam,
        authority: SpaceAuthorityParam,
        skey: SpaceSkeyParam,
        collection: [SpaceCollectionParam],
        action: [SpaceAction],
        manage: [SpaceManageOp],
        scopeParameters: ScopeParameterValues
    ) {
        self.type = type
        self.authority = authority
        self.skey = skey
        self.collection = collection
        self.action = action
        self.manage = manage
        self.parameters = scopeParameters
    }

    private static func buildParameters(
        type: SpaceTypeParam, authority: SpaceAuthorityParam, skey: SpaceSkeyParam,
        collection: [SpaceCollectionParam], action: [SpaceAction], manage: [SpaceManageOp]
    ) -> ScopeParameterValues {
        var values = ScopeParameterValues()
        values.set("type", [type.stringValue])
        values.set("authority", [authority.stringValue])
        values.set("skey", [skey.stringValue])
        values.set("collection", collection.map(\.stringValue))
        values.set("action", action.map(\.rawValue))
        values.set("manage", manage.map(\.rawValue))
        return values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        guard let typeRaw = parameters.single("type") else {
            throw .missingRequiredParameter(prefix: Self.schema.prefix, key: "type")
        }
        self.type = typeRaw == "*" ? .any : .nsid(typeRaw)

        let authorityRaw = parameters.single("authority") ?? "self"
        self.authority = switch authorityRaw {
        case "*": .any
        case "self": .unresolvedSelf
        default: .did(authorityRaw)
        }

        let skeyRaw = parameters.single("skey") ?? "*"
        self.skey = skeyRaw == "*" ? .any : .key(skeyRaw)

        self.collection = parameters.multiple("collection").map { $0 == "*" ? .any : .nsid($0) }

        let actionRaw = parameters.has("action") ? parameters.multiple("action") : SPACE_DEFAULT_ACTIONS.map(\.rawValue)
        let action = actionRaw.compactMap(SpaceAction.init(rawValue:))
        guard action.count == actionRaw.count else {
            throw .invalidParameterValue(prefix: Self.schema.prefix, key: "action", value: actionRaw.joined(separator: ","))
        }
        self.action = action

        let manageRaw = parameters.multiple("manage")
        let manage = manageRaw.compactMap(SpaceManageOp.init(rawValue:))
        guard manage.count == manageRaw.count else {
            throw .invalidParameterValue(prefix: Self.schema.prefix, key: "manage", value: manageRaw.joined(separator: ","))
        }
        self.manage = manage

        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "space",
        positionalKey: "type",
        parameters: [
            .init(key: "type", arity: .single, isRequired: true,
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            .init(key: "authority", arity: .single, defaultValue: ["self"],
                  validate: { $0 == "*" || $0 == "self" || AtprotoSyntax.isValidDID($0) }),
            .init(key: "skey", arity: .single, defaultValue: ["*"],
                  validate: { $0 == "*" || AtprotoSyntax.isValidRecordKey($0) }),
            .init(key: "collection", arity: .multiple, defaultValue: [],
                  normalize: { $0.contains("*") && $0.count > 1 ? ["*"] : Array(Set($0)).sorted() },
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            .init(key: "action", arity: .multiple,
                  defaultValue: SPACE_DEFAULT_ACTIONS.map(\.rawValue),
                  normalize: { given in SpaceAction.allCases.map(\.rawValue).filter(given.contains) },
                  validate: { SpaceAction(rawValue: $0) != nil }),
            .init(key: "manage", arity: .multiple, defaultValue: [],
                  normalize: { given in SpaceManageOp.allCases.map(\.rawValue).filter(given.contains) },
                  validate: { SpaceManageOp(rawValue: $0) != nil }),
        ]
    )
}

// MARK: - Request-side target (§5.6.2)

/// Upstream encodes four match arms as a TypeScript discriminated union
/// (`space-permission.ts:63-76`); a Swift enum makes the switch exhaustive
/// rather than a chain of `undefined` checks. Match targets are plain value
/// structs of `String`s (§3) — never `SpaceURI`, which lives in `SwanSpaces`
/// and would invert the dependency.
public struct SpaceScopeTarget: Sendable, Hashable {
    public enum Operation: Sendable, Hashable {
        /// Whole-space read. Upstream is collection-independent
        /// (space-permission.ts:104-107); Swan adds two hardenings, both
        /// carried explicitly on the case rather than folded into the generic
        /// matcher (§6.5.5):
        ///   - `aggregate`: an AGGREGATE surface (e.g. listSpaces) must not
        ///     silently censor its response, so it requires an unqualified or
        ///     wildcard collection GRANT — SwanSpaces.swift:329-341.
        ///   - `collection`: a caller MAY additionally scope the request to one
        ///     collection; a grant naming no collections still satisfies this
        ///     (reads stay collection-independent by default), matching
        ///     upstream. `nil` means "no collection filter on the request".
        case read(aggregate: Bool, collection: String?)
        /// Own-repo read. Same two hardenings as `.read` (§6.5.5).
        case readSelf(aggregate: Bool, collection: String?)
        /// Record write. `collection` is REQUIRED here by construction —
        /// upstream makes it non-optional only in the write arm (:70-74).
        case write(RecordWrite, collection: String)
        /// Space-lifecycle op. Never checked against `action` or `collection` (:100-102).
        case manage(SpaceManageOp)
        /// The whole-space-read delegation exchange. A HARDENING of a real
        /// upstream concept (`pds/src/api/com/atproto/space/util.ts:104-126`,
        /// `assertSpaceRead`), not a Swan invention — see §5.6.3.
        ///
        /// **This case's grant is decided at the RESOURCE-PLANE FACADE, not
        /// here — see `matches(_:)` below and §9-D23.** Provenance
        /// (`wasStated`) is not durable across mint/persist/reload when read
        /// off a re-parsed `SpacePermission`; only the facade holds it
        /// durably, so `matches(_:)` returns `false` unconditionally for this
        /// case rather than consulting `scopeParameters` a second time.
        case delegationExchange

        public enum RecordWrite: Sendable, Hashable {
            case create, update, delete
            var asAction: SpaceAction {
                switch self {
                case .create: .create
                case .update: .update
                case .delete: .delete
                }
            }
        }
    }

    public let type: String // concrete NSID
    public let authority: String // concrete DID
    public let skey: String // concrete record key
    public let operation: Operation

    public init(type: String, authority: String, skey: String, operation: Operation) {
        self.type = type
        self.authority = authority
        self.skey = skey
        self.operation = operation
    }
}

// MARK: - Matching (§5.6.3)

extension SpacePermission {
    /// Port of space-permission.ts:91-116, evaluated in the same order.
    public func matches(_ target: SpaceScopeTarget) -> Bool {
        // 1. type
        switch type {
        case .any: break
        case let .nsid(t): guard t == target.type else { return false }
        }

        // 2. authority. `target.authority` is always a concrete DID, so an
        //    UNRESOLVED `self` matches nothing. Fail closed —
        //    space-permission.ts:92-93, test "an unresolved `self` authority
        //    matches nothing" (:380-384), space_permission.rs:1574-1584.
        switch authority {
        case .any: break
        case .unresolvedSelf: return false
        case let .did(d): guard d == target.authority else { return false }
        }

        // 3. skey
        switch skey {
        case .any: break
        case let .key(k): guard k == target.skey else { return false }
        }

        // 4-8. operation
        switch target.operation {
        case let .manage(op):
            // Collection and action are irrelevant to a manage check (:100-102).
            return manage.contains(op)

        case let .read(aggregate, requestCollection):
            // Reads are collection-independent by default (:104-107); the two
            // Swan hardenings below are opt-in via the case payload (§6.5.5).
            guard action.contains(.read) else { return false }
            return collectionGate(aggregate: aggregate, requestCollection: requestCollection)

        case let .readSelf(aggregate, requestCollection):
            // `read` implies `read_self`, but not the reverse (:108-110).
            guard action.contains(.read) || action.contains(.readSelf) else { return false }
            return collectionGate(aggregate: aggregate, requestCollection: requestCollection)

        case let .write(verb, collection):
            // Writes need BOTH the verb AND a collection target (:112-115).
            guard action.contains(verb.asAction) else { return false }
            return collectionAllows(collection)

        case .delegationExchange:
            // Deliberately `false`, always — see the case's doc comment and
            // §9-D23. The delegation fence needs the ORIGINAL parse-time
            // provenance (`wasStated`), and a `SpacePermission` reconstructed
            // from a persisted/re-parsed scope string cannot be trusted to
            // carry it: mint resolves `self` -> a concrete DID and persists
            // it, and canonical serialisation deletes stated values equal to
            // their defaults (`skey=*`, `authority=self`) — both directions
            // destroy exactly the bit this arm would need. The resource-plane
            // facade (`SwanScopePermissions`, §6.1) owns this decision instead,
            // composed from durable provenance bits held OUTSIDE the parser
            // plus an ordinary `matches(_:, operation: .read(aggregate: false,
            // collection: nil))` call on the resolved grant.
            return false
        }
    }

    /// Shared post-action-gate logic for `.read` / `.readSelf` (§6.5.5). Both
    /// Swan hardenings are opt-in via the case payload; when neither applies
    /// the read stays collection-independent, matching upstream.
    private func collectionGate(aggregate: Bool, requestCollection: String?) -> Bool {
        if aggregate {
            // SwanSpaces.swift:329-341 — an aggregate surface (e.g. listSpaces)
            // must not silently censor its response, so it requires an
            // unqualified or wildcard collection GRANT.
            return collection.isEmpty || collection.contains(.any)
        }
        if let requestCollection {
            // A caller MAY scope a single-space read to one collection. A
            // grant naming no collections at all still satisfies it — reads
            // stay collection-independent by default (upstream's rule); a
            // grant that DOES name collections must include this one.
            return collection.isEmpty || collectionAllows(requestCollection)
        }
        return true
    }

    /// space-permission.ts:118-123. `.any` is exact membership in the set, not
    /// a glob. An EMPTY collection list allows nothing.
    private func collectionAllows(_ collection: String) -> Bool {
        if self.collection.contains(.any) { return true }
        return self.collection.contains(.nsid(collection))
    }

    public var hasCollections: Bool { !collection.isEmpty } // :125-127
    public var isSelfAuthority: Bool { authority == .unresolvedSelf } // :148-150
}

// MARK: - Issuance-time rewrites (§5.6.4) — both pure; neither does I/O

extension SpacePermission {
    /// space-permission.ts:134-146. No-op when the grant already names
    /// collections (including `collection=*`) or the declaration list is empty.
    ///
    /// **`action` is passed through UNCHANGED, matching upstream — and a
    /// write-verb guard here was tried and deliberately REVERTED.** Read this
    /// before adding one back, because the reasoning that motivates it is
    /// correct right up to the point where it isn't.
    ///
    /// The tempting guard: a bare grant that never states `action` gets
    /// `SPACE_DEFAULT_ACTIONS` (`read, create, update, delete`) from the schema
    /// default (§5.6.2). Today that is inert, because the write arm of
    /// `matches(_:)` requires BOTH `action.contains(verb.asAction)` AND
    /// `collectionAllows(collection)`, and an empty `collection` list allows
    /// nothing. This function is the one place that changes that — so
    /// materialising collections is exactly what arms write verbs the client
    /// never typed. That reads like a privilege escalation, and a guard
    /// dropping the write verbs when `action` was unstated was written on that
    /// basis.
    ///
    /// **Why it was wrong.** A schema default applies precisely when the client
    /// did not state the parameter. Such a guard strips write verbs precisely
    /// when the client did not state the parameter. Those are the same
    /// condition, so the `create`/`update`/`delete` half of
    /// `SPACE_DEFAULT_ACTIONS` becomes unreachable for every grant that ever
    /// existed — not narrowed in an edge case, but dead. Upstream's own
    /// `withDefaultCollections` (`space-permission.ts:134-146`) passes
    /// `this.action` through as the 5th constructor argument, and `:211` wires
    /// `SPACE_DEFAULT_ACTIONS` as the schema default for `action`, so a bare
    /// `space:<type>` grant IS writable after expansion upstream. That is the
    /// meaning of the scope, not an oversight in it.
    ///
    /// Swan applying the guard unilaterally would issue a token strictly weaker
    /// than the identical scope string yields on any conformant AS, silently —
    /// and §5.7.5(b) names *minting a grant narrower than the user consented
    /// to* as the outcome to avoid, which is the very thing the guard produced.
    /// The legitimate answer to "the user may not realise this grants writes"
    /// is the consent renderer (§9-D19) saying so, not a token that quietly
    /// disagrees with the screen that authorised it.
    ///
    /// **The RETURN must not re-invent provenance either.** An earlier
    /// version of this function built its result through the public
    /// memberwise initializer, which marks every field `.stated`
    /// unconditionally (`buildParameters`) — so `authority` (and every other
    /// untouched field) would come out of expansion looking client-stated
    /// even when it never was. That is the exact §9-D23 "provenance invented"
    /// failure re-entering through a rebuild instead of a re-parse. This
    /// version threads the existing `parameters` through the private,
    /// explicit-`scopeParameters` initializer instead (the same pattern
    /// `withResolvedAuthority` uses just below), updating only the one key
    /// that actually changes: `collection`'s new value is necessarily
    /// `.defaulted` — an empty multi-valued list (the precondition for even
    /// reaching this function, via `!hasCollections`) can only arise from an
    /// absent key, never a stated-but-empty one (a stated multi-value key that
    /// resolves to zero entries is `.emptyMultiValuedParameter` at parse
    /// time), so there is no other provenance it could have carried.
    /// Every other key (`type`, `authority`, `skey`, `action`, `manage`) is
    /// untouched in both value and provenance.
    public func withDefaultCollections(_ collections: [SpaceCollectionParam]) -> SpacePermission {
        guard !hasCollections, !collections.isEmpty else { return self }
        var updatedParameters = parameters
        let collectionProvenance = parameters.provenance(for: "collection") ?? .defaulted
        updatedParameters.set("collection", collections.map(\.stringValue), collectionProvenance)
        return SpacePermission(
            type: type, authority: authority, skey: skey,
            collection: collections, action: action, manage: manage,
            scopeParameters: updatedParameters
        )
    }

    /// space-permission.ts:156-166. The matcher is context-free and cannot do
    /// this itself; the caller supplies the granting user's DID at token mint
    /// (§6.4).
    ///
    /// **Provenance-preserving (§9-D23).** Resolving `self` changes `authority`'s
    /// VALUE only — never whether the client stated it. A naive rebuild through
    /// the public memberwise initializer would mark `authority` `.stated`
    /// unconditionally, which would let a `self`-defaulted grant look literal
    /// to any consumer reading `wasStated("authority")` post-resolution — the
    /// exact amplification the facade's durable-provenance delegation fence
    /// (§9-D23, §6.1) exists to refuse. See ScopeParameterValues's doc comment
    /// for the worked example.
    public func withResolvedAuthority(_ userDID: String) -> SpacePermission {
        guard authority == .unresolvedSelf else { return self }
        var updatedParameters = parameters
        let provenance = parameters.provenance(for: "authority") ?? .defaulted
        updatedParameters.set("authority", [userDID], provenance)
        return SpacePermission(
            type: type, authority: .did(userDID), skey: skey,
            collection: collection, action: action, manage: manage,
            scopeParameters: updatedParameters
        )
    }

    /// `self`'s resolver at the type level (§6.1, spec line 3771). `nil`
    /// subject == FAIL CLOSED: the grant is returned unchanged with its
    /// authority still `.unresolvedSelf`, and `matches` returns `false` on
    /// that (§5.6.3 step 2), per `space_permission.rs:1574-1584`. A concrete
    /// subject delegates to `withResolvedAuthority`, which is idempotent and
    /// a no-op on an already-concrete authority
    /// (`space-permission.test.ts:424-430`), so calling this more than once
    /// — e.g. once at mint and again at match time, belt-and-braces against a
    /// row written by an older binary or a grant built directly from a raw
    /// set — is free.
    public func resolvingSelf(as subject: String?) -> SpacePermission {
        guard let subject else { return self } // fail closed
        return withResolvedAuthority(subject)
    }
}

// MARK: - scopeNeeded (§5.6.6)

extension SpacePermission {
    /// space-permission.ts:252-281. For a manage request, `action` is pinned to
    /// [.readSelf] — the narrowest expressible action — rather than omitted,
    /// because omitting it would default to the full record action list and
    /// suggest read/write over every record (:258-260).
    ///
    /// FOUR arms, not upstream's three. `SpaceScopeTarget.Operation` carries a
    /// Swan-specific fifth case, `.delegationExchange`, which must emit the
    /// string the resource-plane facade's delegation fence accepts (§9-D23,
    /// §6.1) — all four of `authority`, `skey`, `action=read` stated, and no
    /// `collection`:
    ///
    ///     space:<type>?authority=<did>&skey=<skey>&action=read
    ///
    /// Note this is byte-identical to the `.read` arm's output for the same
    /// tuple, and that is correct: the two differ in what a GRANT must look
    /// like, not in what the caller should have asked for.
    ///
    /// Does **not** validate its input (§5.4, ported from
    /// `repo-permission.test.ts:104-116`) — builds the parameter set directly
    /// so a caller degrading a denial (§6.1's `requireSpace`) still gets a
    /// formattable string for a malformed target.
    public static func scopeNeeded(for target: SpaceScopeTarget) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("type", [target.type])
        values.set("authority", [target.authority])
        values.set("skey", [target.skey])
        switch target.operation {
        case .read(_, _), .delegationExchange:
            // A bare (no-collection) grant already satisfies a collection-
            // qualified or aggregate read request (§6.5.5's `collectionGate`
            // treats an empty grant collection list as unrestricted), so the
            // minimal grant never needs to state `collection` here even when
            // the target's own `collection`/`aggregate` payload is set.
            values.set("action", [SpaceAction.read.rawValue])
        case .readSelf(_, _):
            values.set("action", [SpaceAction.readSelf.rawValue])
        case let .write(verb, collection):
            values.set("collection", [collection])
            values.set("action", [verb.asAction.rawValue])
        case let .manage(op):
            values.set("action", [SpaceAction.readSelf.rawValue])
            values.set("manage", [op.rawValue])
        }
        return try schema.format(values)
    }
}
