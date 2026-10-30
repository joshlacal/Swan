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
//   | com.atproto.space.{create,update,      | October 29 (5d88b414): assertSpaceOwner(manage:)           |
//   |   delete}Space, removeWriter,          |   (the retired simplespace lifecycle routes used the same  |
//   |   memberspace.{put,remove}Member       |   manage: verbs)                                           |
//   | com.atproto.space.getSpace,            | space/getSpace.ts, memberspace/listMembers.ts              |
//   |   memberspace.listMembers              |   assertSpaceOwner(action:read_self)                       |
//
// Two of these carry a DOCUMENTED SWAN HARDENING of the upstream rule, not an
// invention (§6.2, §5.6.3, §9-D16). Upstream's read arm is
// collection-independent (`oauth-scopes/src/scopes/space-permission.ts:104-107`)
// and `read` is in its default action set (`:207-211`), so upstream exchanges a
// credential for a bare `space:<type>` and for a collection-qualified read.
// Swan refuses both:
//   * getDelegationToken -> `isExchangeableDelegationGrant` (§5.6.3)
//   * listSpaces         -> `allowsSpaceListing` (§6.1)
//
// ALSO PORTED — repo, blob and rpc landed with the app-password enforcement
// work. Each route calls the matching `requireX` and maps `ScopeDenied` to its
// own opaque code via `SwanHTTP/ScopeEnforcement.swift`:
//
//   assertRepo     -> repo/{createRecord.ts:64, putRecord.ts:82 AND :86,
//                     deleteRecord.ts:60, applyWrites.ts:118}
//                     Swan: each route in SwanPublicRepositoryMutationXRPC
//                     asserts AFTER decoding its input, because `collection`
//                     lives in the body and the authorizer runs on headers
//                     alone. putRecord asserts BOTH create and update;
//                     applyWrites asserts per write, not per request.
//   assertBlob     -> repo/uploadBlob.ts:16, `mime` from the Content-Type
//                     HEADER, never the body. Swan: same file, on the
//                     SANITIZED mime, which is the value actually stored.
//   assertRpc      -> pipethrough.ts:66-68 plus 14 per-route sites, with the
//                     `scopeAud`/`tokenAud` split at pipethrough.ts:101-106.
//                     Swan: SwanXRPCPipethrough step 3b, after authentication
//                     and before the body is buffered, so an out-of-scope
//                     method never reaches the mint at step 6.
//
// The transition arms these depend on are ported into the matchers themselves —
// see `hasTransitionGeneric` and the `allows*` docs below. Without them every
// credential in the wild would be denied, since transition scopes yield no
// `.repo`/`.rpc`/`.blob` grant.
//
// STILL NOT PORTED — `hasResourceScope` must not be widened to admit these
// until the corresponding Swan route actually calls the matching `allowsX`
// (§6.1, §9-D12):
//
// NOT SERVED AT ALL, and a trap for whoever serves it first:
// `com.atproto.server.getServiceAuth`. Swan has no implementation and answers
// 404 through the `com.atproto.server.*` guard (verified against a
// `describeServer` positive control). It is listed here because it is a
// scope-LAUNDERING primitive — it converts a narrow PDS credential into a token
// a DIFFERENT service will honour — and because the obvious port reproduces a
// live upstream hole.
//
// tranquil checks `lxm` only when it is supplied, and requires it only for
// OAuth. A scoped app password that simply OMITS `lxm` therefore falls through
// with no check at all and receives a token with `lxm: None`, which the
// audience honours for any method; its own "post-only" preset, which grants
// zero `rpc:` scopes, can obtain one. The 60-second lifetime bounds the damage
// without closing the hole.
//
// If Swan serves this: require `lxm` from EVERY non-full-access credential, and
// validate both `aud` and `lxm` against the granted `rpc:` scopes. Note
// `RpcPermission.matches` compares `aud` as an exact string
// (`rpc-permission.ts:43-49`) — there is no fragment stripping — so the caller
// must present the same `did#fragment` form the pipethrough builds.
//
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
    ///    `authority` defaulted, so `isExchangeableDelegationGrant` correctly
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

    /// Upstream space-scope semantics, set only under `swan serve
    /// --enable-spaces-open-interop` (Josh, 2026-10-01, decision B(d)). When
    /// `true`, the two Swan-specific fences relax to upstream's rules: a
    /// DEFAULTED `action` (read/create/update/delete) satisfies
    /// getDelegationToken and listSpaces, and a wildcard-type grant may
    /// exchange a delegation. Value coverage (type/authority/skey) and the
    /// listing fence's wildcard-request rule are unchanged. `false` (the
    /// default) is Swan's hardened §5.6.3 / §6.1 behaviour.
    public private(set) var upstreamSpaceDefaults = false

    /// A copy evaluated under upstream space-scope semantics.
    public func withUpstreamSpaceDefaults() -> SwanScopePermissions {
        var copy = self
        copy.upstreamSpaceDefaults = true
        return copy
    }

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
        // NORMALIZE: a scope mapped to an EMPTY stated-key set and a scope with
        // no entry at all are the same fact — "this grant stated nothing" — and
        // both fail every provenance clause identically. Keeping both spellings
        // would make `==` disagree with behaviour: a value built from a durable
        // record (which lists every scope, `atproto` included, with an empty set
        // for the parameterless ones) would compare unequal to a semantically
        // identical value built with `[:]`. That is not hypothetical — it is
        // what `OAuthResourceAuthorizationTests` compares. Dropping empty sets
        // makes equality a function of what the value actually decides.
        self.statedKeys = statedKeys.filter { !$0.value.isEmpty }
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
            && lhs.upstreamSpaceDefaults == rhs.upstreamSpaceDefaults
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawScopes)
        hasher.combine(subject)
        hasher.combine(statedKeys)
        hasher.combine(upstreamSpaceDefaults)
    }

    /// The base AT Protocol session scope. An explicit predicate rather than a
    /// `rawScopes.contains` at each call site: three files spell this today
    /// (`OAuthValidatedSession.swift:91-95`,
    /// `DurableOAuthTokenService.swift:1246-1250`,
    /// `SwanOAuthResourceAuthorization.swift:206-210`) and they must not drift
    /// apart again.
    public var hasBaseATProtocolScope: Bool { rawScopes.contains("atproto") }

    // MARK: - Transition scopes
    //
    // Ported from `oauth-scopes/src/scope-permissions-transition.ts`, whose
    // overrides let the three `transition:` scopes stand in for the modern
    // families. Upstream models this as a SUBCLASS, but the PDS constructs it
    // UNCONDITIONALLY for every OAuth credential — `auth-verifier.ts:658`,
    // `new ScopePermissionsTransition(scope?.split(' '))`, with no alternative
    // branch. There is therefore no "transition mode" to select between: the
    // overrides ARE the behaviour of every OAuth credential upstream, so Swan
    // folds them into the base matcher rather than reproducing an inheritance
    // hierarchy that only ever has one instantiated shape.
    //
    // These read `rawScopes` rather than `grants`, matching upstream's
    // `this.scopes.has(...)` and the `hasBaseATProtocolScope` idiom directly
    // above. All three are parameterless exact strings, so there is no
    // provenance question and nothing for a parse to lose.

    /// `transition:generic` — the pre-permissioned-data catch-all.
    public var hasTransitionGeneric: Bool { rawScopes.contains("transition:generic") }

    /// `transition:email` — grants exactly `account:email?action=read`.
    public var hasTransitionEmail: Bool { rawScopes.contains("transition:email") }

    /// `transition:chat.bsky` — grants exactly the `chat.bsky.*` RPC arm.
    public var hasTransitionChatBsky: Bool { rawScopes.contains("transition:chat.bsky") }

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
    /// §5.6.3 spells `isExchangeableDelegationGrant` as a `private var` on
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
    ///
    /// ## No transition arm, deliberately
    ///
    /// Every sibling matcher in this file grew a `transition:` arm ported from
    /// `scope-permissions-transition.ts`. This one does NOT, and that is the
    /// same decision upstream made — it overrides `allowsSpace` to call `super`
    /// and nothing else, purely so the omission reads as a decision rather than
    /// an oversight (`:55-62`): *"`transition:generic` predates permissioned
    /// data, so a legacy token must never reach a space."*
    ///
    /// Swan has a second reason to hold this line: an app password defaults to
    /// `transition:generic` when it names no scopes, so a transition arm here
    /// would silently hand every legacy bearer credential the permissioned-data
    /// surface. Do not add one.
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
            guard Self.isExchangeableDelegationGrant(
                resolved,
                statedKeys: grant.statedKeys,
                upstreamDefaults: upstreamSpaceDefaults
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
    /// **§5.6.3 AMENDED (2026-08-15, Josh: option 2 — see Erratum 02 in the
    /// scopes design doc).** The sealed fence demanded the grant be EXACTLY
    /// `?authority=X&skey=Y&action=read` — action exactly `[read]`, no
    /// collection, no manage, authority and skey both stated. No real client's
    /// registered scopes produce that shape (Bulleted's `spaceAccess`
    /// expansion states authority/collection/action with a four-action list),
    /// so every conformant delegation exchange 401'd. Upstream's read arm is
    /// collection-independent and satisfied by any grant whose actions include
    /// `read` (`space-permission.ts:104-107`).
    ///
    /// The amended contract, per the ruling:
    /// 1. `action` was STATED and contains `read` — the §9-D21 bare-grant
    ///    witness survives (a defaulted action list contains `read` and must
    ///    still refuse), and extra write verbs alongside `read` are not an
    ///    escalation for a credential that only reads: the caller already
    ///    holds them. `read_self` alone remains non-exchangeable (§7.2 D7).
    /// 2. The grant's space TYPE is concrete — Swan's hardening over upstream,
    ///    kept from the ruling's option 2: a wildcard-type grant must not mint
    ///    credentials for arbitrary space types.
    /// 3. Value coverage (type/authority/skey) stays with `matches` in
    ///    `allowsSpace` — §5.6.3 steps 1-3 are unchanged.
    ///
    /// **What was knowingly conceded** (Erratum 02, do not re-litigate as an
    /// oversight): a collection-qualified read grant now exchanges for a
    /// whole-space read credential, upstream's documented semantics. The
    /// original analysis (`SwanCore.swift:246-257`) was CORRECT — this is a
    /// protocol credential-model limitation, not a retraction: the space
    /// credential cannot carry collection restrictions, so the conversion is
    /// lossy. The satisfactory long-term fix is a credential that carries the
    /// originating grant's collection set, not a stricter predicate here.
    internal static func isExchangeableDelegationGrant(
        _ grant: SpacePermission,
        statedKeys: Set<String>,
        upstreamDefaults: Bool = false
    ) -> Bool {
        // Upstream (`getDelegationToken.ts`: assertSpaceRef action 'read'):
        // any grant whose effective — stated or defaulted — actions include
        // read, any type. Only under `--enable-spaces-open-interop`.
        if upstreamDefaults {
            return grant.action.contains(.read)
        }
        // 1. Stated action containing read (provenance witness — a missing
        //    bit denies; it never grants).
        guard statedKeys.contains("action"), grant.action.contains(.read) else { return false }
        // 2. Concrete space type.
        guard case .nsid = grant.type else { return false }
        return true
    }

    /// The listing fence (§6.1), replacing `permitsAggregateSpaceList`
    /// (`SwanCore.swift:290-309`).
    ///
    /// **Upstream HAS an analogue.** `packages/pds/src/api/com/atproto/space/listSpaces.ts:20-25`
    /// asserts `assertSpace({ type: spaceType ?? '*', authority: authority ?? '*',
    /// skey: '*', action: 'read_self' })` — it makes the *request filters* the
    /// match target and defaults each absent filter to `'*'`. Its comment at
    /// `:16-18` states Swan's own rationale in upstream's words: "No one space
    /// to check against, so the filters are the target: an unfiltered listing
    /// needs a wildcard grant." The inverse matching is not a special rule
    /// upstream — it falls out of `SpacePermission.matches`
    /// (`space-permission.ts:94-98`), where a *concrete* grant dimension fails
    /// against a literal `'*'` target.
    ///
    /// One clause is Swan's own HARDENING, not inherited: the stated-`action`
    /// witness. Upstream's defaults are `skey` -> `'*'` and `action` ->
    /// `SPACE_DEFAULT_ACTIONS` (`space-permission.ts:186-191`, `:207-211`,
    /// `:25-30`), so a *bare* `space:<type>` satisfies upstream's assert with
    /// no query string at all. Swan refuses that. This is exactly the
    /// "default `self` / `skey=*` / default action sets amplifying" hazard
    /// §9-D21 names as the reason retiring `isIssuableQualified` is safe: the
    /// danger did not disappear, it moved here. **Deleting this fence and
    /// deleting that gate in the same release removes both halves.**
    ///
    /// Must NOT be folded into `allowsSpace`; it exists because the list route
    /// refuses to fetch broadly and then censor rows (`SwanCore.swift:320-323`).
    ///
    /// Reads DURABLE provenance (§9-D23): under the new grammar `skey`
    /// *defaults* to `["*"]` and `action` defaults to a list *containing*
    /// `read`, so without the stated-key witness a bare `space:<t>` grant would
    /// silently start satisfying `listSpaces?spaceType=<t>&did=<self>`.
    /// **§6.1 AMENDED (2026-08-15, Josh: "Amend").** The original fence
    /// additionally required stated `authority`+`skey` with literal `skey=*`,
    /// action exactly `[.read]`, and no stated `collection`/`manage`. That
    /// shape was unreachable by real clients: bulleted.app's permission set
    /// expands to a stated-`collection`, four-action space grant, and its
    /// direct scope uses `read_self` — which upstream itself accepts for
    /// every `space.get*/list*` route (`space/util.ts:109-127`,
    /// `assertSpaceRead`). The route also self-scopes: `hostedSpaces` takes
    /// the token's own subject, so a listing is an inventory OF SELF, never
    /// of another account. What remains load-bearing from §9-D21 is the
    /// STATED-`action` witness: under the new grammar `action` *defaults* to
    /// a list containing `read`, so without the witness a bare
    /// `space:<type>` would silently satisfy listing. It still cannot.
    func allowsSpaceListing(type: String?, authority: String?) -> Bool {
        let requestedType = type ?? "*"
        let requestedAuthority = authority ?? "*"
        return grants.contains { grant in
            guard case let .space(permission) = grant.scope else { return false }
            let resolved = permission.resolvingSelf(as: subject)
            // 1. The action list is STATED (the §9-D21 witness — a bare or
            //    defaulted grant never lists) and grants a read: `read` or
            //    upstream's `read_self`, which suffices for a route that
            //    only ever lists the subject's own spaces.
            //    Under `--enable-spaces-open-interop` the witness is dropped
            //    and a defaulted action list suffices, as upstream.
            guard upstreamSpaceDefaults || grant.statedKeys.contains("action"),
                  resolved.action.contains(.read) || resolved.action.contains(.readSelf)
            else { return false }
            // 2. aggregateDimension on type and authority (SwanCore.swift:324-327):
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
        "space:\(type ?? "*")?authority=\(authority ?? "*")&action=read"
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
// §9-D12: all six families ship. `space:`, `repo:`, `blob:` and `rpc:` are now
// enforced by real routes (see the route map at the top of this file);
// `identity:` and `account:` remain reached only by tests, and
// `hasResourceScope` must NOT be widened to admit those two until their routes
// call the matching `allowsX`.

public extension SwanScopePermissions {
    /// `scope-permissions-transition.ts:47-53`: `transition:generic` allows any
    /// repo write, on any collection, with any action.
    func allowsRepo(_ target: RepoPermission.Target) -> Bool {
        if hasTransitionGeneric { return true }
        return grants.contains { grant in
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

    /// `scope-permissions-transition.ts:64-80`. Three arms, in upstream's order:
    /// `transition:generic` with the `*` wildcard `lxm`; `transition:generic`
    /// for any `lxm` OUTSIDE `chat.bsky.`; and `transition:chat.bsky` for any
    /// `lxm` INSIDE it. The split is the whole reason DMs are the one thing a
    /// non-privileged legacy credential cannot reach.
    ///
    /// Neither arm consults `aud` — upstream's overrides ignore it, so a
    /// transition credential is audience-unrestricted. That is the pre-existing
    /// legacy contract, not a widening introduced here; `getServiceAuth` is
    /// where it is fenced.
    func allowsRPC(_ target: RpcPermission.Target) -> Bool {
        if hasTransitionGeneric, target.lxm == "*" { return true }
        if hasTransitionGeneric, !target.lxm.hasPrefix("chat.bsky.") { return true }
        if hasTransitionChatBsky, target.lxm.hasPrefix("chat.bsky.") { return true }
        return grants.contains { grant in
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

    /// `scope-permissions-transition.ts:39-45`: `transition:generic` allows any
    /// blob mime. Note this bypasses `BlobPermission.matches`'s concrete-mime
    /// gate, so a transition credential may upload a blob whose declared mime a
    /// modern `blob:` grant would refuse outright. That is upstream's behaviour.
    func allowsBlob(_ target: BlobPermission.Target) -> Bool {
        if hasTransitionGeneric { return true }
        return grants.contains { grant in
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

    /// `scope-permissions-transition.ts:27-37`: `transition:email` grants
    /// EXACTLY `email` + `read`. It does not imply `manage`, and it says nothing
    /// about `repo` or `status`.
    func allowsAccount(_ target: AccountPermission.Target) -> Bool {
        if target.attr == .email, target.action == .read, hasTransitionEmail { return true }
        return grants.contains { grant in
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
