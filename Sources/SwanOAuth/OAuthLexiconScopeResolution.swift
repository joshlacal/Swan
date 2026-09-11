import Foundation
import SwanCore
import SwanStorage

/// §5.7.5 — the **three call sites** of lexicon resolution, and the two of them
/// that exist.
///
/// 1. **PAR / `/oauth/authorize`.** ``expandIncludes(_:resolver:stage:)`` with
///    ``OAuthScopeResolutionStage/pushedAuthorizationRequest``. Every `include:`
///    must resolve or the request is refused; the surviving expansion is what
///    the consent payload is built from, so `include:` → `space:` happens
///    **before** space types are extracted for display.
/// 2. **Token mint / refresh.** ``resolvingLexiconGrants`` — (a) `include:` →
///    concrete, (b) ``expandSpaceCollections``, (c) `resolveSpaceSelfAuthority`,
///    in that order, after §6.3 stage C.
///    Default collection changes reach existing sessions on refresh, using
///    the original requested scopes. An issued access token retains its
///    materialized collection set until then. This matches the reference
///    provider's `buildTokenScope` calls at issuance and rotation.
/// 3. **Request time (resource plane): NEVER.** This is structural rather than a
///    convention, and the structure is visible from here: nothing in this file
///    is reachable from `SwanOAuthResourceAuthorization`. A bearer token's
///    stored scopes are already expanded, self-resolved and
///    collection-materialised by the time they reach a route, so a resource
///    request performs **zero** outbound I/O for authorization. Pinned
///    executably by `testResourcePlaneAuthorizationPerformsNoLexiconResolution`,
///    which mints through a counting resolver and asserts the count does not
///    advance across a resource request — a doc comment cannot notice the day
///    someone adds an `await resolver.resolve(…)` to a match path.
///
/// **Why the two live call sites report different OAuth error codes for the
/// same root cause.** Upstream raises `InvalidScopeError` from
/// `request-manager.ts:293-312` at PAR and `InvalidRequestError` from
/// `token-manager.ts:135-138` at mint. Swan matches, deliberately, for interop:
/// a client that special-cases `invalid_scope` on the authorize leg and
/// `invalid_request` on the token leg behaves the same against Swan as against
/// a reference AS. Unifying them would be tidier and would be a divergence, so
/// ``OAuthScopeResolutionStage`` carries the code and the failure carries the
/// condition.

// MARK: - Stage

/// Which call site is resolving. Its ONLY job is the OAuth error code, because
/// that is the only thing §5.7.5 makes stage-dependent — the conditions, the
/// budgets and the drop rules are identical on both legs.
public enum OAuthScopeResolutionStage: Sendable, Equatable {
    /// `invalid_scope` (`request-manager.ts:293-312`).
    case pushedAuthorizationRequest
    /// `invalid_request` (`token-manager.ts:135-138`). **Not** `invalid_scope`,
    /// for the same root cause. See this file's header.
    case tokenMint

    public var oauthErrorCode: String {
        switch self {
        case .pushedAuthorizationRequest: "invalid_scope"
        case .tokenMint: "invalid_request"
        }
    }
}

// MARK: - Failure

/// What refused a resolution, independent of which leg saw it.
///
/// Every case here is HARD. None of them is a silent drop: §5.7.5's drop rows
/// describe entries *within a successfully proved document* that fail their own
/// family's parse or authority gate, and `IncludeScope.expand` already applies
/// those. A failure at this level means the document was never established as
/// belonging to the authority's signed repo — there is nothing to drop entries
/// from, and letting one reach a drop path would let an attacker-controlled PDS
/// choose which of a user's permissions survive by selectively corrupting
/// proofs.
public enum OAuthScopeResolutionFailure: Error, Sendable, Equatable, CustomStringConvertible {
    /// An `include:<nsid>` whose document could not be established.
    /// `SwanLexiconResolution.unresolvable` — which is itself the closed set of
    /// `SwanLexiconResolverFailure`, proof failures included.
    case includeUnresolvable(nsid: String)
    /// Proved, but `defs.main` is not a `permission-set`
    /// (`lexicon-manager.ts:126-129`).
    case includeNotAPermissionSet(nsid: String)
    /// A bare `space:<type>` whose declaration could not be established
    /// (`lexicon-manager.ts:68-73`). **Throws rather than passing the bare grant
    /// through** — see ``OAuthLexiconScopeResolution/expandSpaceCollections``.
    case spaceTypeUnresolvable(nsid: String)
    /// Proved, but `defs.main` is not a `space` (`lexicon-manager.ts:156-159`).
    case spaceTypeNotASpace(nsid: String)
    /// Space declarations may list concrete NSIDs from any namespace, but
    /// cannot declare wildcard or malformed collection defaults.
    case spaceTypeInvalidCollections(nsid: String)
    /// The EXPANDED-GRANT count cap or the 10 s group deadline (§5.7.4). A
    /// property of the request, never of an authority — which is why it is not
    /// cached against any NSID.
    case budget(SwanLexiconResolutionBudgetError)
    /// An expansion produced a scope string that will not serialise. Structurally
    /// unreachable — every producer round-trips through a validated family
    /// parse — and represented rather than force-unwrapped because the input is
    /// a remote document.
    case unserialisableExpansion(nsid: String)

    /// Renders without echoing an attacker-chosen string beyond the NSID that is
    /// already in the client's own request (§4.8).
    public var description: String {
        switch self {
        case let .includeUnresolvable(nsid): "permission set \(nsid) could not be resolved"
        case let .includeNotAPermissionSet(nsid): "lexicon \(nsid) is not a permission set"
        case let .spaceTypeUnresolvable(nsid): "space type \(nsid) could not be resolved"
        case let .spaceTypeNotASpace(nsid): "lexicon \(nsid) is not a space"
        case let .spaceTypeInvalidCollections(nsid): "space type \(nsid) has invalid collections"
        case let .budget(error): "lexicon resolution budget exceeded: \(error)"
        case let .unserialisableExpansion(nsid): "expansion of \(nsid) did not serialise"
        }
    }
}

/// A resolution failure bound to the leg that saw it, so the wire code is a
/// property of the value rather than of the `catch` block that happens to
/// receive it — the same discipline ``OAuthScopeAdmissionError/oauthErrorCode``
/// applies, and for the same reason: two call sites that choose their own codes
/// drift.
public struct OAuthScopeResolutionError: Error, Sendable, Equatable, CustomStringConvertible {
    public let stage: OAuthScopeResolutionStage
    public let failure: OAuthScopeResolutionFailure

    public init(stage: OAuthScopeResolutionStage, failure: OAuthScopeResolutionFailure) {
        self.stage = stage
        self.failure = failure
    }

    public var oauthErrorCode: String { stage.oauthErrorCode }
    public var description: String { failure.description }
}

// MARK: - Result

/// The outcome of `include:` expansion: the rewritten set, plus the NSIDs whose
/// expansion produced **nothing**.
public struct OAuthExpandedScopeSet: Sendable, Equatable {
    /// `include:` strings removed, their concrete `repo:` / `rpc:` / `space:`
    /// grants inserted (`lexicon-manager.ts:52-56` — the include does not
    /// survive into the token).
    public let scopes: Set<String>

    /// Sorted NSIDs of every `include:` that resolved successfully and expanded
    /// to zero grants.
    ///
    /// **This is not an error** (§5.7.5): the include contributes nothing and the
    /// request proceeds. It is carried out of this type rather than only logged
    /// because the row demands BOTH — a `.warn` for the operator AND a rendered
    /// consent line for the person authorizing, using §5.7.2's canonical string
    /// naming the NSID. A `.warn` alone leaves the authorizing user looking at a
    /// consent page from which the permission set has silently vanished.
    public let emptyExpansions: [String]

    /// Provenance for the newly-created scope strings: for each, the parameter
    /// keys the **lexicon document** physically wrote.
    ///
    /// Expansion must not invent statedness (§9-D23). An include-derived grant's
    /// author is the permission-set document, so its `wasStated` bits are the
    /// document's — not `.stated` for everything (which would flip the
    /// delegation fence open on a grant nobody wrote that way) and not empty
    /// (which would fail closed on a grant the document did state exactly).
    public let provenance: OAuthScopeProvenance

    public init(
        scopes: Set<String>,
        emptyExpansions: [String] = [],
        provenance: OAuthScopeProvenance = OAuthScopeProvenance()
    ) {
        self.scopes = scopes
        self.emptyExpansions = emptyExpansions
        self.provenance = provenance
    }
}

// MARK: - Transformations

public enum OAuthLexiconScopeResolution {
    // MARK: (a) include: → concrete

    /// **(a)** — `include:<nsid>` → the concrete `repo:` / `rpc:` / `space:`
    /// grants the permission set stands for (`lexicon-manager.ts:45-56`).
    ///
    /// Resolution failure is HARD on both legs: an unresolvable or
    /// non-permission-set document throws, carrying the stage's error code.
    /// **An empty expansion is not a failure** — it is reported through
    /// ``OAuthExpandedScopeSet/emptyExpansions``.
    ///
    /// `resolver == nil` means no lexicon authority is configured for this
    /// deployment. The set is then returned **unchanged**, which is Phase-1
    /// behaviour: `include:` parses, persists, and grants nothing (§9-D4's stated
    /// cost, pinned by `testIncludeScopesAuthorizeSuccessfullyThenGrantNothing`).
    /// It is deliberately a pass-through rather than a rejection, because
    /// rejecting would make an operator turning resolution *off* — or never
    /// turning it on — break clients that authorize successfully today; the
    /// divergence from a conformant AS is recorded rather than converted into an
    /// outage. Configuring a resolver is what closes it.
    public static func expandIncludes(
        _ scopes: Set<String>,
        resolver: (any SwanLexiconResolving)?,
        stage: OAuthScopeResolutionStage,
        provenance: OAuthScopeProvenance = OAuthScopeProvenance()
    ) async throws -> OAuthExpandedScopeSet {
        guard let resolver else {
            return OAuthExpandedScopeSet(scopes: scopes, provenance: provenance)
        }
        // A scope that does not parse is carried verbatim rather than rejected
        // here: stage B already rejected unparseable *requested* scopes, and a
        // HELD unparseable scope grants nothing and must not fail a refresh
        // (§9-D5).
        var includes: [(raw: String, scope: IncludeScope)] = []
        for raw in scopes.sorted() {
            guard case let .include(include)? = try? AtprotoScope.parse(raw) else { continue }
            includes.append((raw, include))
        }
        guard !includes.isEmpty else {
            return OAuthExpandedScopeSet(scopes: scopes, provenance: provenance)
        }

        let resolutions: [String: SwanLexiconResolution]
        do {
            resolutions = try await resolver.resolveAll(
                includes.map(\.scope.nsid), population: .includes
            )
        } catch let error as SwanLexiconResolutionBudgetError {
            throw OAuthScopeResolutionError(stage: stage, failure: .budget(error))
        }

        var effective = scopes
        var rekeyed = provenance
        var empty: [String] = []
        for (raw, include) in includes {
            let nsid = include.nsid
            // `resolveAll` returns one entry per DISTINCT nsid, so a missing key
            // is unreachable; `.unresolvable` is the honest reading if it ever is
            // not, because it fails the request rather than widening it.
            switch resolutions[nsid] ?? .unresolvable {
            case .unresolvable:
                throw OAuthScopeResolutionError(
                    stage: stage, failure: .includeUnresolvable(nsid: nsid)
                )
            case let .resolved(document, _, _):
                guard case let .permissionSet(set) = document else {
                    throw OAuthScopeResolutionError(
                        stage: stage, failure: .includeNotAPermissionSet(nsid: nsid)
                    )
                }
                effective.remove(raw)
                let permissions = include.expand(set)
                if permissions.isEmpty { empty.append(nsid) }
                for permission in permissions {
                    guard let string = try? permission.canonicalScopeString() else {
                        throw OAuthScopeResolutionError(
                            stage: stage, failure: .unserialisableExpansion(nsid: nsid)
                        )
                    }
                    effective.insert(string)
                    rekeyed.record(statedKeys(of: permission), for: string)
                }
            }
        }
        // The retired `include:` strings still hold slots in the carried map;
        // `restricted` drops them so no provenance key outlives its scope.
        rekeyed = rekeyed.restricted(to: effective)
        return OAuthExpandedScopeSet(
            scopes: effective, emptyExpansions: empty.sorted(), provenance: rekeyed
        )
    }

    // MARK: (b) expandSpaceCollections

    /// **(b)** — a PORT of `lexicon-manager.ts:74-95`, not an invention.
    ///
    /// Rewrites every bare `space:<type>` grant to carry the type's declared
    /// collections. The shape is upstream's, line for line: collect each non-`*`
    /// `space:` type whose grant `!hasCollections`; if none, return the scopes
    /// unchanged **without any I/O**; fetch the spaces; then map each scope,
    /// returning it unchanged if it does not parse as a space grant, if
    /// `type == '*'`, or if it already `hasCollections`; returning it unchanged
    /// if the space declares no collections; otherwise
    /// `parsed.withDefaultCollections(space.collections)`.
    ///
    /// **This is NOT include-specific.** It iterates *every* `space:` scope in
    /// the token, include-derived or not — which is why filing it under "Phase 2"
    /// left Phase 1 with a silent grant-narrowing rather than merely an
    /// unimplemented feature: bulleted.app's `space:` scope contains no
    /// `include:` and is affected.
    ///
    /// **It THROWS when a declaration cannot be resolved, and that direction is
    /// deliberate** (`lexicon-manager.ts:68-73`, and the upstream test
    /// `'throws when a space type cannot be resolved'`). The tempting shortcut —
    /// "if we can't prove it, leave the bare grant alone" — inverts it: leaving
    /// the grant unmaterialised lets an unreachable or hostile authority silently
    /// *widen* what a bare `space:<type>` covers, and mints a token narrower than
    /// the user consented to. Failing the request is the honest outcome.
    ///
    /// **An empty declared collection list is NOT an error**
    /// (`lexicon-manager.test.ts:178-187`): a read-only space type is a
    /// legitimate declaration, and the bare grant passes through unchanged.
    ///
    /// **`type=*` is skipped** (`:80`, `:90`) — it names no one type, so there is
    /// no declaration to expand from.
    ///
    /// **What this does to the grant's VERBS, and why there is no guard here.**
    /// `withDefaultCollections` passes `action` through unchanged, matching
    /// upstream, so a bare `space:<type>` grant **is writable after expansion**.
    /// That is the intended outcome of this function, not a hazard it should
    /// defend against: a guard dropping write verbs when `action` was unstated
    /// was written and deliberately reverted (`315e4b7e`), because "the client did
    /// not state `action`" is precisely the condition under which the schema
    /// default applies, so the guard made `create`/`update`/`delete` unreachable
    /// for every grant that ever existed. Read that function's doc comment before
    /// re-adding one.
    ///
    /// `resolver == nil` returns the scopes unchanged — the Phase-1 divergence,
    /// same rationale as (a). See ``expandIncludes(_:resolver:stage:provenance:)``.
    public static func expandSpaceCollections(
        _ scopes: Set<String>,
        resolver: (any SwanLexiconResolving)?,
        stage: OAuthScopeResolutionStage,
        provenance: OAuthScopeProvenance = OAuthScopeProvenance()
    ) async throws -> OAuthExpandedScopeSet {
        guard let resolver else {
            return OAuthExpandedScopeSet(scopes: scopes, provenance: provenance)
        }
        var bare: Set<String> = []
        for raw in scopes {
            guard case let .space(permission)? = try? AtprotoScope.parse(raw),
                  case let .nsid(type) = permission.type,
                  !permission.hasCollections else { continue }
            bare.insert(type)
        }
        // `if (nsids.size === 0) return scopes.slice()` — no fetch, no cache
        // read, no budget check. A token with no bare space grant costs nothing.
        guard !bare.isEmpty else {
            return OAuthExpandedScopeSet(scopes: scopes, provenance: provenance)
        }

        let resolutions: [String: SwanLexiconResolution]
        do {
            // The SECOND, separately-bounded population (§5.7.4): space types are
            // not `include:`-derived, and a 64-token set can name up to 64
            // distinct ones. Sharing the include cap would leave them unbounded.
            resolutions = try await resolver.resolveAll(bare, population: .spaceTypes)
        } catch let error as SwanLexiconResolutionBudgetError {
            throw OAuthScopeResolutionError(stage: stage, failure: .budget(error))
        }

        var spaces: [String: LexiconSpace] = [:]
        for type in bare.sorted() {
            switch resolutions[type] ?? .unresolvable {
            case .unresolvable:
                throw OAuthScopeResolutionError(
                    stage: stage, failure: .spaceTypeUnresolvable(nsid: type)
                )
            case let .resolved(document, _, _):
                guard case let .space(space) = document else {
                    throw OAuthScopeResolutionError(
                        stage: stage, failure: .spaceTypeNotASpace(nsid: type)
                    )
                }
                guard space.collections.allSatisfy(AtprotoSyntax.isValidNSID) else {
                    throw OAuthScopeResolutionError(
                        stage: stage, failure: .spaceTypeInvalidCollections(nsid: type)
                    )
                }
                spaces[type] = space
            }
        }

        var effective: Set<String> = []
        var rekeyed = provenance
        for raw in scopes {
            guard case let .space(permission)? = try? AtprotoScope.parse(raw),
                  case let .nsid(type) = permission.type,
                  !permission.hasCollections,
                  let declared = spaces[type], !declared.collections.isEmpty else {
                effective.insert(raw)
                continue
            }
            let expanded = permission.withDefaultCollections(
                declared.collections.map(SpaceCollectionParam.nsid)
            )
            guard let rewritten = try? expanded.canonicalScopeString() else {
                throw OAuthScopeResolutionError(
                    stage: stage, failure: .unserialisableExpansion(nsid: type)
                )
            }
            effective.insert(rewritten)
            // Materialisation changes the VALUE of `collection`, never whether
            // the client stated it (§9-D23). `withDefaultCollections` preserves
            // that inside the permission; this preserves it in the durable map,
            // which is keyed by the scope STRING and so has to follow the rewrite.
            rekeyed = rekeyed.rekeyed(from: raw, to: rewritten)
        }
        return OAuthExpandedScopeSet(
            scopes: effective, provenance: rekeyed.restricted(to: effective)
        )
    }

    // MARK: - Call site 2 — the three transformations in order

    /// §5.7.5 call site 2, whole: (a) `include:` → concrete, (b)
    /// ``expandSpaceCollections``, (c) `resolveSpaceSelfAuthority`.
    ///
    /// **The order is load-bearing in both directions.** (a) before (b): an
    /// include-derived bare `space:` grant must be materialised too, and it does
    /// not exist until (a) has run. (b) before (c): `withDefaultCollections`
    /// no-ops on a grant that already `hasCollections`, and (c) rewrites the
    /// scope STRING, so running it first would leave (b) matching against a
    /// different key in the provenance map for no benefit.
    ///
    /// It runs **after** §6.3 stage C, which compares *raw requested* against
    /// *registered* — both sides must still be in `include:` form for that
    /// comparison to mean anything, so this cannot move earlier.
    ///
    /// `binding.scopesRequested` keeps the client's own bytes; `binding.scopes`
    /// becomes the expanded grant (§9-D8/§6.7).
    public static func resolvingLexiconGrants(
        _ binding: OAuthClientBinding,
        subject: String,
        resolver: (any SwanLexiconResolving)?,
        provenance: OAuthScopeProvenance? = nil,
        budget: OAuthScopeBudget = .expandedGrant
    ) async throws -> OAuthClientBinding {
        let carried = provenance ?? binding.scopeProvenance ?? OAuthScopeProvenance()
        let includes = try await expandIncludes(
            binding.scopes, resolver: resolver,
            stage: .tokenMint, provenance: carried
        )
        let materialised = try await expandSpaceCollections(
            includes.scopes, resolver: resolver,
            stage: .tokenMint, provenance: includes.provenance
        )
        let rewritten = materialised.scopes == binding.scopes
            ? binding
            : binding.withEffectiveScopes(
                materialised.scopes, provenance: materialised.provenance
            )
        // (c). Stage F already owns `self` → subject and the EXPANDED-GRANT
        // budget; running it here rather than duplicating it keeps one
        // implementation of both.
        return try OAuthScopeAdmissionPolicy.resolvingSelfAuthority(
            rewritten,
            subject: subject,
            provenance: materialised.provenance,
            budget: budget
        )
    }

    // MARK: - Provenance

    /// The parameter keys an expanded permission's own document physically
    /// wrote. The mirror of `OAuthScopeAdmissionPolicy.statedKeys(of:)` for the
    /// three families an include can produce.
    static func statedKeys(of permission: IncludedPermission) -> Set<String> {
        switch permission {
        case let .repo(p): p.scopeParameters.statedKeys
        case let .rpc(p): p.scopeParameters.statedKeys
        case let .space(p): p.scopeParameters.statedKeys
        }
    }
}
