import Foundation

// MARK: - Ported PDS route → permission map (§6.5.10, §9-D16)
//
// This map is PORTED from the pinned upstream PDS, not authored. §9-D16 rules
// that an upstream request-time enforcement model exists; the earlier premise
// that it did not was false, and false because `packages/pds` was missing from
// the truncated export (§2 constraint 5). Ground truth, re-run against the
// pinned tree at `packages/pds/src` while writing this file:
//
//     grep -rn 'authorize:' --include='*.ts' .            -> 67
//     grep -rn 'permissions.assertRpc'      --include='*.ts' . -> 15
//     grep -rn 'permissions.assertRepo'     --include='*.ts' . ->  5
//     grep -rn 'permissions.assertIdentity' --include='*.ts' . ->  4
//     grep -rn 'permissions.assertAccount'  --include='*.ts' . ->  2
//     grep -rn 'permissions.assertSpace'    --include='*.ts' . ->  2
//     grep -rn 'permissions.assertBlob'     --include='*.ts' . ->  1
//
// The space plane funnels through one shared helper, `assertSpaceScope`
// (`api/com/atproto/space/util.ts:87-100`), which derives `(type, authority,
// skey)` from the space URI and spreads the caller's op. `assertSpaceRead`
// (`:109-127`) wraps it with the own-repo-vs-whole-space split and the
// deliberate `RepoNotFound` non-oracle at `:118-124`.
//
// PORTED — Swan enforces these today, through this facade:
//
//   | Swan endpoint                          | upstream route + assert                                   |
//   |----------------------------------------|-----------------------------------------------------------|
//   | com.atproto.space.createRecord         | space/createRecord.ts:40  assertSpaceScope(action:create)  |
//   | com.atproto.space.putRecord            | space/putRecord.ts:49     assertSpaceScope(create|update)  |
//   | com.atproto.space.deleteRecord         | space/deleteRecord.ts:35  assertSpaceScope(action:delete)  |
//   | com.atproto.space.applyWrites          | space/applyWrites.ts:104  per write, not per request       |
//   | com.atproto.space.get*/list* (7 routes)| space/util.ts:109-127     assertSpaceRead -> read_self     |
//   | com.atproto.space.getDelegationToken   | space/getDelegationToken.ts:22 assertSpaceScope(read)      |
//   | com.atproto.space.listSpaces           | space/listSpaces.ts:20-25 assertSpace(filters-as-target)   |
//   | com.atproto.simplespace.{create,update,| simplespace/{createSpace:22,updateSpace:16,deleteSpace:17, |
//   |   delete}Space, {add,remove}Member     |   addMember:18,removeMember:17} assertSpaceScope(manage:)  |
//   | com.atproto.simplespace.getSpace,      | simplespace/{getSpace.ts:25,listMembers.ts:20}             |
//   |   listMembers                          |   assertSpaceScope(action:read_self)                       |
//
// Two of these carry a DOCUMENTED SWAN HARDENING of the upstream rule, not an
// invention (§6.2, §5.6.3, §9-D16). Upstream's read arm is
// collection-independent (`oauth-scopes/src/scopes/space-permission.ts:104-107`)
// and `read` is in its default action set (`:207-211`), so upstream exchanges a
// credential for a bare `space:<type>` and for a collection-qualified read.
// Swan refuses both:
//   * getDelegationToken -> `isExactReadOnlyDelegationGrant` (§5.6.3)
//   * listSpaces         -> `allowsSpaceListing` (§6.1)
//
// NOT YET PORTED — the four non-space families below have named upstream port
// targets, and `hasResourceScope` must not be widened to admit any of them
// until the corresponding Swan route actually calls the matching `allowsX`
// (§6.1, §9-D12):
//
//   assertRepo     -> repo/{createRecord.ts:64, putRecord.ts:82 AND :86,
//                     deleteRecord.ts:60, applyWrites.ts:118}
//                     Swan: SwanPublicRepositoryMutationXRPC.swift:449-450,
//                     which today guards every repo write with
//                     `scopes.contains("atproto")` and nothing else.
//   assertBlob     -> repo/uploadBlob.ts:16, `mime` from the Content-Type
//                     HEADER, never the body. Swan: same single guard.
//   assertRpc      -> pipethrough.ts:66-68 plus 14 per-route sites. Porting
//                     requires the `scopeAud`/`tokenAud` split at
//                     pipethrough.ts:101-106. Swan: SwanXRPCPipethrough.swift:524.
//   assertIdentity -> identity/{updateHandle.ts:13, signPlcOperation.ts:16,
//                     submitPlcOperation.ts:12,
//                     requestPlcOperationSignature.ts:14}. Swan serves none of
//                     these (SwanPublicUnavailableXRPC.swift:37-47).
//   assertAccount  -> server/requestEmailConfirmation.ts:18 (attr:email,
//                     action:manage) and repo/importRepo.ts:25. The first has a
//                     LIVE Swan counterpart at SwanAccountEmailXRPC.swift and is
//                     the cheapest `account:` port.
//
// LOCAL POLICY — Swan-specific, no upstream counterpart. A row may appear here
// only with the positive control that found no counterpart, run against
// `packages/pds` (§6.5.10's own rule):
//
//   com.atproto.space.notifySpaceDeleted
//     control: `ls packages/pds/src/api/com/atproto/space/` -> 20 entries
//     (applyWrites, createRecord, deleteRecord, getBlob, getDelegationToken,
//     getLatestCommit, getRecord, getRepo, getSpaceCredential, index,
//     listBlobs, listRecords, listRepoOps, listRepos, listSpaces, notifyWrite,
//     putRecord, registerNotify, unregisterNotify, util) — no notifySpaceDeleted.
//   com.atproto.simplespace.checkUserAccess
//     control: `ls packages/pds/src/api/com/atproto/simplespace/` -> addMember,
//     createSpace, deleteSpace, getSpace, index, listMembers, removeMember,
//     updateSpace — no checkUserAccess.
//
// Routes that exist upstream but carry NO scope assert are a credential-plane
// check, not an unenforced route: getSpaceCredential (delegationTokenAuth),
// registerNotify / unregisterNotify / listRepos (spaceCredentialAuth),
// notifyWrite (serviceAuth). Classifying them as "unenforced" is a reading
// error (§6.5.10).

/// A frozen, request-scoped answer to "may this token do X".
///
/// Constructed once per authenticated request from durable token state and
/// never mutated. Parsing is EAGER: a stored scope string that does not parse
/// is recorded in `rejected` and grants nothing (mirroring `scopes.rs:1160-1162`
/// and `scopes-set.test.ts:42-47`) rather than silently re-failing to parse on
/// every match. The raw strings are retained verbatim so persistence and audit
/// surfaces never see a re-serialized value.
///
/// Swan takes the Rust shape — `subject` bound into the value (§6.1,
/// `atproto-oauth/src/scopes.rs:1166-1174`) — rather than upstream TypeScript's
/// per-call threading, because the matcher is reached from *inside* an actor
/// (`SwanSQLite.swift:9290`, `:11628`, `:11647`) where re-deriving a subject
/// would mean another `await` (§2 constraint 1).
///
/// DO NOT add a memoizing cache. A cache needs an actor or a lock, which would
/// make `allowsSpace` async, which would make `SpaceAuthorizationPolicy.require`
/// async, which would ripple into `requireRead`/`requireWrite` and every
/// repository operation in SwanSQLite. The work being cached is parsing <= 64
/// tokens of <= 1024 bytes, once per request, in the same request that just did
/// an ES256 verification and at least two SQLite round trips.
public struct SwanScopePermissions: Sendable, Equatable, Hashable {
    /// Exactly the strings the durable token family carries, unmodified.
    public let rawScopes: Set<String>

    /// The account DID this grant was issued to. `space:` grants naming
    /// `authority=self` resolve against this and ONLY this; a permissions value
    /// with no subject fails closed on every `self` grant, matching
    /// `self_matches_nothing_without_a_subject`
    /// (`atproto-oauth/src/scopes/space_permission.rs:1579-1584`).
    public let subject: String?

    /// DURABLE provenance: for each raw scope string, the set of parameter keys
    /// the client LITERALLY WROTE. §9-D23 is a blocker and this is its seam.
    ///
    /// **This must be loaded from storage. It must NEVER be reconstructed by
    /// re-parsing a persisted scope string.** A canonical scope string is a
    /// lossy projection in *both* directions, and each direction breaks one
    /// fence:
    ///
    ///  * *provenance invented* — `space:x.y.z?skey=*&action=read` has
    ///    `authority` defaulted, so `isExactReadOnlyDelegationGrant` correctly
    ///    refuses. Mint resolves `self` and persists
    ///    `space:x.y.z?authority=did:plc:USER&skey=*&action=read`. Re-parsed,
    ///    all three keys look literal and the delegation fence flips
    ///    **false -> true** — exactly the amplification it exists to stop.
    ///  * *provenance destroyed* — canonical serialisation deletes values equal
    ///    to their defaults, so a stated `skey=*` vanishes and the listing
    ///    fence can never fire again.
    ///
    /// Deliberately a plain `[String: Set<String>]` rather than a named type:
    /// it is the narrowest possible seam onto the durable record, so the
    /// persistence layer owns the schema and this layer owns only the question
    /// "was this key stated".
    ///
    /// **Absent means FAIL CLOSED.** A scope with no entry here has an empty
    /// stated-key set, so every provenance clause of both fences refuses. A
    /// missing bit denies; it never grants.
    public let statedKeys: [String: Set<String>]

    /// Retained for logging only — never consulted by a match. Upstream throws
    /// this information away (`filter(isAtprotoOauthScope)`,
    /// `request-manager.ts:184`); Swan keeps it so a narrowed grant is greppable.
    public let rejected: [String: ScopeParseError]

    /// A parsed grant kept beside BOTH its verbatim source string and its
    /// durable stated-key set.
    ///
    /// The three travel together on purpose. If the fences reached a parsed
    /// permission's own parameter bag instead, they would be reading
    /// parser-side provenance — which on a persisted, `self`-resolved grant is
    /// precisely the §9-D23 "provenance invented" defect. Keeping `statedKeys`
    /// on the grant makes the durable bits the only provenance in reach.
    private struct Grant: Sendable {
        let raw: String
        let scope: AtprotoScope
        let statedKeys: Set<String>
    }

    private let grants: [Grant]

    /// - Parameters:
    ///   - rawScopes: the token family's effective scope strings, verbatim.
    ///   - subject: the account DID the grant was issued to, or `nil` at a
    ///     floor check that has not resolved `self` yet (§6.5.2).
    ///   - statedKeys: durable provenance, keyed by raw scope string. Loaded
    ///     from storage — see the property doc. Defaults to empty, which is
    ///     fail-closed for both fences.
    public init(
        rawScopes: Set<String>,
        subject: String?,
        statedKeys: [String: Set<String>] = [:]
    ) {
        self.rawScopes = rawScopes
        self.subject = subject
        self.statedKeys = statedKeys
        // Sort so `grants` is a deterministic function of the inputs and
        // equality is stable across Set iteration order.
        var grants: [Grant] = []
        var rejected: [String: ScopeParseError] = [:]
        for value in rawScopes.sorted() {
            do {
                grants.append(
                    Grant(
                        raw: value,
                        scope: try AtprotoScope.parse(value),
                        statedKeys: statedKeys[value] ?? []
                    )
                )
            } catch {
                rejected[value] = error
            }
        }
        self.grants = grants
        self.rejected = rejected
    }

    /// `grants` and `rejected` are pure, deterministic functions of
    /// `rawScopes`, `subject` and `statedKeys`, so equality over the inputs is
    /// equality over the value. Spelling it out rather than synthesising it
    /// also keeps `Hashable` off `AtprotoScope` and `ScopeParseError`, which
    /// are the grammar layer's types to shape.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawScopes == rhs.rawScopes
            && lhs.subject == rhs.subject
            && lhs.statedKeys == rhs.statedKeys
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawScopes)
        hasher.combine(subject)
        hasher.combine(statedKeys)
    }

    /// The base AT Protocol session scope. An explicit predicate rather than a
    /// `rawScopes.contains` at each call site: three files spell this today
    /// (`OAuthValidatedSession.swift:91-95`,
    /// `DurableOAuthTokenService.swift:1246-1250`,
    /// `SwanOAuthResourceAuthorization.swift:206-210`) and they must not drift
    /// apart again.
    public var hasBaseATProtocolScope: Bool { rawScopes.contains("atproto") }

    /// True when this grant carries something the AT Protocol resource plane
    /// **enforces**. Replaces the three copies of `hasATProtocolResourceScope`
    /// — and must replace them with *the same accept set*, not a wider one.
    ///
    /// ## Why this is `atproto` or `space:` ONLY, and not "any recognised family"
    ///
    /// The predicate this replaces is
    /// `SwanOAuthResourceAuthorization.swift:206-210` and its two twins:
    ///
    ///     scopes.contains("atproto") || scopes.contains { isQualified($0) }
    ///
    /// i.e. `atproto` **OR a qualified `space:` grant** — nothing else. That
    /// floor is the ONLY scope check several routes perform. Verified, each
    /// discarding the scope set entirely:
    ///
    ///   * `SwanHTTP/SwanSpaceXRPC.swift:77` — `guard case let .accountOAuth(subject, _)`
    ///   * `SwanHTTP/SwanSpaceBlobXRPC.swift:340` — `case let .accountOAuth(subject, _) where subject == author: return`
    ///   * `SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:288` — identical shape
    ///   * `SwanHTTP/SwanSimpleSpaceXRPC.swift:426-427`; `SwanSpaceXRPC.swift:403, 492, 879`
    ///   * `SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2519-2520, 2584, 2634`
    ///
    /// After §8 Stage C a remote client may register `identity:handle` or
    /// `blob:image/*`. Such a token would then pass the floor and reach blob
    /// upload and repository sync on its own repo, which perform **no further
    /// scope check**. A dead surface that nonetheless satisfies the
    /// authorization floor is not dead — it is an unenforced grant that opens
    /// routes.
    ///
    /// **Widening this predicate and wiring those routes are one change, not
    /// two.** The route-map block at the top of this file names, per family,
    /// which upstream `assert*` each Swan endpoint must grow first. Today the
    /// answer for `repo:`/`blob:` is one line:
    /// `SwanPublicRepositoryMutationXRPC.swift:449-450` guards every repo write
    /// and every blob upload with `scopes.contains("atproto")` and nothing else.
    ///
    /// **§9-D21's retirement of `isIssuableQualified` does not license widening
    /// this.** That removes a *registration-layer* check; it says nothing about
    /// the resource plane. Read the retirement as permission to widen here and
    /// the exact hazard the retired gate was accidentally covering — a
    /// registered `blob:image/*` reaching an unguarded upload route —
    /// reappears one layer down.
    public var hasResourceScope: Bool {
        hasBaseATProtocolScope || grants.contains { grant in
            if case .space = grant.scope { return true }
            return false
        }
    }
}

// MARK: - space

public extension SwanScopePermissions {
    /// The ordinary space matcher (§5.6.3), plus the delegation fence, which is
    /// evaluated HERE rather than inside `SpacePermission.matches`.
    ///
    /// ## Divergence from §5.6.3's literal placement, ruled by §9-D23
    ///
    /// §5.6.3 spells `isExactReadOnlyDelegationGrant` as a `private var` on
    /// `SpacePermission` reading `scopeParameters.wasStated(...)` — i.e.
    /// parser-side provenance. On a *persisted* grant that is exactly the
    /// §9-D23 "provenance invented" failure: mint resolves `self` and persists
    /// `space:x.y.z?authority=did:plc:USER&skey=*&action=read`, whose re-parse
    /// makes all three keys look literal, flipping the fence false -> true.
    /// §9-D23 is explicit and is marked a blocker — "provenance is never
    /// reconstructed from a serialised scope string", and "the two fences
    /// consult the stored bits". The fence therefore lives at the layer that
    /// holds the durable bits, which is this one.
    ///
    /// The clause set is unchanged. `matches` with the operation rewritten to
    /// `.read` reproduces §5.6.3 steps 1-3 exactly (type, authority, skey) plus
    /// `action.contains(.read)`, which the fence has already established more
    /// strictly as `action == [.read]`.
    func allowsSpace(_ target: SpaceScopeTarget) -> Bool {
        grants.contains { grant in
            guard case let .space(permission) = grant.scope else { return false }
            // Resolving `self` changes the VALUE, never the statedness
            // (§9-D23). A `nil` subject leaves `.unresolvedSelf`, which
            // `matches` refuses at step 2 (§5.6.3, `space_permission.rs:1574-1584`).
            let resolved = permission.resolvingSelf(as: subject)
            guard case .delegationExchange = target.operation else {
                return resolved.matches(target)
            }
            guard Self.isExactReadOnlyDelegationGrant(
                resolved,
                statedKeys: grant.statedKeys
            ) else { return false }
            return resolved.matches(
                SpaceScopeTarget(
                    type: target.type,
                    authority: target.authority,
                    skey: target.skey,
                    // `aggregate: false`, `collection: nil` — a delegation
                    // exchange is a whole-space read: not an aggregate surface,
                    // and not collection-filtered. The fence above has already
                    // established the stricter `action == [.read]` and that no
                    // collection is named, so this call contributes only
                    // §5.6.3 steps 1-3 (type, authority, skey).
                    operation: .read(aggregate: false, collection: nil)
                )
            )
        }
    }

    /// **Never propagates a `ScopeParseError`.** `scopeNeeded` does not validate
    /// its input (§5.6.6) and its final `canonicalString()` throws
    /// `.notAScopeToken` whenever `target.skey`/`target.collection` carries a
    /// byte the encoders leave raw. If that throw escaped, `requireSpace` would
    /// surface a **denial** as an `unavailable` — `SpaceAuthorizationPolicy.require`
    /// is plain `throws` and propagates, and the handlers map non-`SwanError`
    /// throws to `unavailable` (`SwanSpaceXRPC.swift:73-75`,
    /// `SwanSpaceDelegationXRPC.swift:74-76`). An attacker could then
    /// distinguish "denied, well-formed target" from "denied, odd target" —
    /// exactly the oracle `SwanOAuthResourceAuthorization.swift:9-16` forbids
    /// and §9-D6 preserves. Degrade the formatting failure into the same opaque
    /// denial.
    func requireSpace(_ target: SpaceScopeTarget) throws {
        guard allowsSpace(target) else {
            throw ScopeDenied(needed: Self.spaceScopeNeeded(for: target))
        }
    }

    /// The delegation fence (§5.6.3), reading DURABLE provenance (§9-D23).
    ///
    /// Every clause maps to a clause of `permitsWholeSpaceRead`
    /// (`SwanCore.swift:270-279`); none may be dropped. **This fence is where
    /// the retired `isIssuableQualified` gate's job now lives (§9-D21), and it
    /// must not be re-litigated as redundant with a gate that no longer
    /// exists.** Q9 moved those refusals from layer 1 (registration, which
    /// grants nothing and therefore cannot see what is being asked) to layer 4
    /// (the resource plane, which has the concrete operation in front of it).
    /// This predicate and `allowsSpaceListing` ARE that layer-4 handling.
    ///
    /// Every clause tests statedness — a PROVENANCE test, not a value test. A
    /// defaulted `[read]` and a stated `[read]` carry the same value and must
    /// not carry the same authority.
    ///
    /// Swan's hardening over upstream, clause by clause (§6.2): upstream's read
    /// arm is collection-independent (`space-permission.ts:104-107`, no
    /// `collectionAllows` call) so upstream *does* let
    /// `space:<t>?action=read&collection=x` be exchanged for a whole-space
    /// credential; and upstream's default action set contains `read`
    /// (`:25-30`, `:207-211`) so a bare `space:<t>` is exchangeable upstream.
    /// Swan refuses both. That refusal is the substance of `SwanCore.swift:246-257`.
    internal static func isExactReadOnlyDelegationGrant(
        _ grant: SpacePermission,
        statedKeys: Set<String>
    ) -> Bool {
        // 1. `action` was named explicitly, and names exactly [read].
        //    Not "contains read"; not a defaulted list.
        //    <- SwanCore.swift:277 `parameters["action"] == "read"`
        guard statedKeys.contains("action"), grant.action == [.read] else { return false }
        // 2. The grant names no collection at all — a collection-qualified
        //    grant (INCLUDING `collection=*`) must never be amplifiable into a
        //    credential that reads every member repository.
        //    <- SwanCore.swift:246-257 (doc comment) and :279 (key-set equality)
        guard grant.collection.isEmpty, !statedKeys.contains("collection") else { return false }
        // 3. No `manage` list. Today `hasAction != hasManage`
        //    (`SwanCore.swift:243`) makes an action+manage grant unparseable,
        //    so admitting one here would widen even though the manage list is
        //    never consulted for a read.
        guard grant.manage.isEmpty, !statedKeys.contains("manage") else { return false }
        // 4. `authority` and `skey` were both named.
        //    <- SwanCore.swift:279 `Set(keys) == ["authority","skey","action"]`
        //       and :243 `requiredKeys == ["authority","skey"]`
        return statedKeys.contains("authority") && statedKeys.contains("skey")
    }

    /// The listing fence (§6.1), replacing `permitsAggregateSpaceList`
    /// (`SwanCore.swift:290-309`).
    ///
    /// **Upstream HAS an analogue.** `packages/pds/src/api/com/atproto/space/listSpaces.ts:20-25`
    /// asserts `assertSpace({ type: type ?? '*', authority: authority ?? '*',
    /// skey: '*', action: 'read_self' })` — it makes the *request filters* the
    /// match target and defaults each absent filter to `'*'`. Its comment at
    /// `:16-18` states Swan's own rationale in upstream's words: "No one space
    /// to check against, so the filters are the target: an unfiltered listing
    /// needs a wildcard grant." The inverse matching is not a special rule
    /// upstream — it falls out of `SpacePermission.matches`
    /// (`space-permission.ts:94-98`), where a *concrete* grant dimension fails
    /// against a literal `'*'` target.
    ///
    /// Two clauses are Swan's own and are HARDENINGS, not inherited:
    ///
    ///  * **The literal-`skey=*` / literal-single-`action=read` requirement.**
    ///    Upstream's defaults are `skey` -> `'*'` and `action` ->
    ///    `SPACE_DEFAULT_ACTIONS` (`space-permission.ts:186-191`, `:207-211`,
    ///    `:25-30`), so a *bare* `space:<type>` satisfies upstream's assert with
    ///    no query string at all. Swan refuses that. This is exactly the
    ///    "default `self` / `skey=*` / default action sets amplifying" hazard
    ///    §9-D21 names as the reason retiring `isIssuableQualified` is safe: the
    ///    danger did not disappear, it moved here. **Deleting this fence and
    ///    deleting that gate in the same release removes both halves.**
    ///  * **`action == [.read]` exactly**, where upstream accepts `read_self`
    ///    too (`space-permission.ts:108-110`).
    ///
    /// Must NOT be folded into `allowsSpace`; it exists because the list route
    /// refuses to fetch broadly and then censor rows (`SwanCore.swift:320-323`).
    ///
    /// Reads DURABLE provenance (§9-D23): under the new grammar `skey`
    /// *defaults* to `["*"]` and `action` defaults to a list *containing*
    /// `read`, so without the stated-key witness a bare `space:<t>` grant would
    /// silently start satisfying `listSpaces?type=<t>&authority=<self>`.
    func allowsSpaceListing(type: String?, authority: String?) -> Bool {
        let requestedType = type ?? "*"
        let requestedAuthority = authority ?? "*"
        return grants.contains { grant in
            guard case let .space(permission) = grant.scope else { return false }
            let resolved = permission.resolvingSelf(as: subject)
            let stated = grant.statedKeys
            // 1. Exactly the three keys, all STATED — today's key-set equality.
            guard stated.contains("authority"), stated.contains("skey"), stated.contains("action"),
                  !stated.contains("collection"), !stated.contains("manage") else { return false }
            // 2. LITERAL `skey=*` and LITERAL single `action=read`.
            guard resolved.skey == .any, resolved.action == [.read] else { return false }
            // 3. aggregateDimension on type and authority (SwanCore.swift:324-327):
            //    a wildcard REQUEST is satisfied only by a wildcard GRANT. An
            //    unresolved `self` authority renders as "self", which no
            //    concrete request and no `*` request can match — fail closed.
            return Self.aggregateDimension(resolved.type.stringValue, covers: requestedType)
                && Self.aggregateDimension(resolved.authority.stringValue, covers: requestedAuthority)
        }
    }

    /// The scope string a denied listing would have needed. For LOGS ONLY
    /// (§6.5.8, §9-D6) — it never reaches the wire.
    static func spaceListingScopeNeeded(type: String?, authority: String?) -> String {
        "space:\(type ?? "*")?authority=\(authority ?? "*")&skey=*&action=read"
    }

    /// Verbatim `SwanCore.swift:324-327`.
    private static func aggregateDimension(_ grant: String?, covers requested: String) -> Bool {
        if requested == "*" { return grant == "*" }
        return grant == requested || grant == "*"
    }

    /// `scopeNeeded` for LOGS ONLY, with the §5.6.6/§6.1 degradation applied:
    /// a target the encoders cannot render becomes an opaque placeholder rather
    /// than a thrown error, so a denial never becomes an `unavailable`.
    private static func spaceScopeNeeded(for target: SpaceScopeTarget) -> String {
        (try? SpacePermission.scopeNeeded(for: target)) ?? "space:<unrenderable target>"
    }
}

// MARK: - repo, rpc, blob, account, identity
//
// §9-D12: the six families ship now even though Swan enforces only `space:`.
// They are NOT YET PORTED rather than dead — upstream wires every one of them
// (see the route map at the top of this file). Until the corresponding Swan
// route calls the matching `allowsX`, these are reached only by tests, and
// `hasResourceScope` must NOT be widened to admit their families.

public extension SwanScopePermissions {
    func allowsRepo(_ target: RepoPermission.Target) -> Bool {
        grants.contains { grant in
            guard case let .repo(permission) = grant.scope else { return false }
            return permission.matches(target)
        }
    }

    func requireRepo(_ target: RepoPermission.Target) throws {
        guard allowsRepo(target) else {
            throw ScopeDenied(
                needed: (try? RepoPermission.scopeNeeded(for: target)) ?? "repo:<unrenderable target>"
            )
        }
    }

    func allowsRPC(_ target: RpcPermission.Target) -> Bool {
        grants.contains { grant in
            guard case let .rpc(permission) = grant.scope else { return false }
            return permission.matches(target)
        }
    }

    func requireRPC(_ target: RpcPermission.Target) throws {
        guard allowsRPC(target) else {
            throw ScopeDenied(
                needed: (try? RpcPermission.scopeNeeded(for: target)) ?? "rpc:<unrenderable target>"
            )
        }
    }

    func allowsBlob(_ target: BlobPermission.Target) -> Bool {
        grants.contains { grant in
            guard case let .blob(permission) = grant.scope else { return false }
            return permission.matches(target)
        }
    }

    func requireBlob(_ target: BlobPermission.Target) throws {
        guard allowsBlob(target) else {
            throw ScopeDenied(
                needed: (try? BlobPermission.scopeNeeded(for: target)) ?? "blob:<unrenderable target>"
            )
        }
    }

    func allowsAccount(_ target: AccountPermission.Target) -> Bool {
        grants.contains { grant in
            guard case let .account(permission) = grant.scope else { return false }
            return permission.matches(target)
        }
    }

    func requireAccount(_ target: AccountPermission.Target) throws {
        guard allowsAccount(target) else {
            throw ScopeDenied(
                needed: (try? AccountPermission.scopeNeeded(for: target)) ?? "account:<unrenderable target>"
            )
        }
    }

    func allowsIdentity(_ target: IdentityPermission.Target) -> Bool {
        grants.contains { grant in
            guard case let .identity(permission) = grant.scope else { return false }
            return permission.matches(target)
        }
    }

    func requireIdentity(_ target: IdentityPermission.Target) throws {
        guard allowsIdentity(target) else {
            throw ScopeDenied(
                needed: (try? IdentityPermission.scopeNeeded(for: target)) ?? "identity:<unrenderable target>"
            )
        }
    }
}

/// Carries the minimal satisfying scope for LOGS AND TESTS ONLY.
///
/// `SwanOAuthResourceAuthorization.swift:9-16` states Swan's rule for this
/// boundary: "every invalid, expired, replayed, token-binding, and
/// account-lifecycle predicate becomes the same denial. This avoids turning the
/// protected-resource boundary into a DPoP or account-status oracle."
/// Upstream's `ScopeMissingError` is `expose = true` with `status = 403`
/// (`scope-missing-error.ts`) and echoes the needed scope to the caller; Swan
/// deliberately does not (§9-D6). Every HTTP adapter maps this to its own
/// opaque per-route code and logs `needed` server-side at `.info` with the
/// route path (§6.5.8).
public struct ScopeDenied: Error, Sendable, Equatable {
    public let needed: String

    public init(needed: String) {
        self.needed = needed
    }
}
