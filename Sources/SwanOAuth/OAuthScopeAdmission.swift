import Foundation
import SwanCore
import SwanStorage

/// A bounded scope budget.
///
/// **There are two of these, and they must stay two** (spec §9-D17, §9-D9's
/// third correction) even while the numbers coincide, because they measure
/// different strings, are enforced in different places, and blame different
/// parties:
///
/// | budget | measures | enforced at | at fault |
/// |---|---|---|---|
/// | ``rawInput`` | exactly the bytes the client sent, before any Swan transformation | the wire tokenizers | the client — `invalid_request` at PAR |
/// | ``expandedGrant`` | what Swan holds *after its own* transformations: `self` → subject DID, and (Phase 2) `include:` expansion and `expandSpaceCollections` | token mint and persistence | **Swan** — its expansion grew a legal request past the limit |
///
/// The motivating failure is asymmetric and real: an 80-byte
/// `include:com.example.permission-set`, or a bare `space:com.example.type`,
/// passes PAR comfortably and then inflates. Collapsing the two into one
/// constant makes that look like the client's fault and leaves no error case to
/// tell them apart. Phase 1 expands only `self`, which is bounded by a DID and
/// cannot inflate materially — so the split costs nothing today and is exactly
/// the thing that would be missing on the day `include:` lands.
///
/// Swan's budgets are published in `docs/` rather than advertised through an
/// invented OAuth metadata field (§6.6, §9-D17): upstream's `oauthScopeSchema`
/// (`oauth-types/src/oauth-scope.ts:17-19`) is `OAUTH_SCOPE_REGEXP` and nothing
/// else — no byte cap, no token cap — so a conformant client can build a legal
/// scope Swan refuses.
public struct OAuthScopeBudget: Sendable, Equatable, Hashable {
    public let bytesPerScope: Int
    public let scopeCount: Int
    public let bytesPerSet: Int

    public init(bytesPerScope: Int, scopeCount: Int, bytesPerSet: Int) {
        self.bytesPerScope = bytesPerScope
        self.scopeCount = scopeCount
        self.bytesPerSet = bytesPerSet
    }

    /// Measured against the client's own bytes, at the wire. Replaces four
    /// disagreeing caps (256 remote / 4096 localhost / 256 persistence /
    /// 7…4096 syntax, §6.4).
    public static let rawInput = OAuthScopeBudget(
        bytesPerScope: 1024,
        scopeCount: 64,
        bytesPerSet: 8192
    )

    /// Measured against what Swan holds after its own rewrites.
    public static let expandedGrant = OAuthScopeBudget(
        bytesPerScope: 1024,
        scopeCount: 64,
        bytesPerSet: 8192
    )
}

/// Failures of the OAuth scope admission pipeline (spec §4.8, §6.3).
///
/// The `oauthErrorCode` split is the point of the type: `invalid_scope` is new
/// to Swan and describes the *request's own text*, so it leaks nothing
/// server-side; `invalid_request` is retained wherever a precise code would
/// disclose a server-side fact — notably ``notRegistered``, which would
/// otherwise reveal the client's registration
/// (`SwanOAuthAuthorizationServerHTTP.swift:256-259` records that reasoning).
public enum OAuthScopeAdmissionError: Error, Sendable, Equatable, CustomStringConvertible {
    // Stage A / A′ — the wire tokenizers. RAW-INPUT budget.
    case emptyScopeRequest
    case duplicateScope
    case notAScopeToken
    case tooManyScopes(count: Int, limit: Int)
    case rawScopeTooLong(bytes: Int, limit: Int)
    case rawRequestTooLong(bytes: Int, limit: Int)
    /// The literal token `openid`, rejected at the tokenizer. It cannot be left
    /// to stage B: `AtprotoScope.parse` throws `.unknownPrefix` on it first, so
    /// a later check would be unreachable and the wire would report the wrong
    /// reason (§4.8).
    case forbiddenScope

    // Stage B — grammar parse.
    case unparseableScope(ScopeParseError)

    // Stage C — requested ⊆ declared.
    case notRegistered

    // Stage E — the base-scope floor.
    case missingBaseScope
    /// A `space:` grant naming a write action but no collection at all. The one
    /// invariant re-homed here from the retired `isIssuableQualified`
    /// (`SwanCore.swift:192-195`).
    case writeActionWithoutCollection

    // Stage F / G — EXPANDED-GRANT budget. Swan's own expansion overflowed.
    case expandedScopeTooLong(bytes: Int, limit: Int)
    case expandedGrantTooManyScopes(count: Int, limit: Int)
    case expandedGrantTooLong(bytes: Int, limit: Int)

    /// The OAuth error code this failure surfaces on the wire.
    public var oauthErrorCode: String {
        switch self {
        case .emptyScopeRequest, .duplicateScope, .notAScopeToken,
             .tooManyScopes, .rawScopeTooLong, .rawRequestTooLong,
             .notRegistered,
             .expandedScopeTooLong, .expandedGrantTooManyScopes, .expandedGrantTooLong:
            "invalid_request"
        case .forbiddenScope, .unparseableScope, .missingBaseScope,
             .writeActionWithoutCollection:
            "invalid_scope"
        }
    }

    /// Renders without echoing an attacker-chosen string into the log line;
    /// associated values are for structured logging only (§4.8).
    public var description: String {
        switch self {
        case .emptyScopeRequest: "scope request is empty"
        case .duplicateScope: "scope request repeats a scope"
        case .notAScopeToken: "scope request contains a non RFC 6749 scope-token"
        case let .tooManyScopes(count, limit): "scope request has \(count) scopes, limit \(limit)"
        case let .rawScopeTooLong(bytes, limit): "requested scope is \(bytes) bytes, limit \(limit)"
        case let .rawRequestTooLong(bytes, limit): "scope request is \(bytes) bytes, limit \(limit)"
        case .forbiddenScope: "scope request contains the forbidden token openid"
        case let .unparseableScope(error): "requested scope did not parse: \(error)"
        case .notRegistered: "requested scope is not registered"
        case .missingBaseScope: "scope request carries no base AT Protocol scope"
        case .writeActionWithoutCollection:
            "a space grant naming a write action must name a collection"
        case let .expandedScopeTooLong(bytes, limit):
            "expanded scope is \(bytes) bytes, limit \(limit)"
        case let .expandedGrantTooManyScopes(count, limit):
            "expanded grant has \(count) scopes, limit \(limit)"
        case let .expandedGrantTooLong(bytes, limit):
            "expanded grant is \(bytes) bytes, limit \(limit)"
        }
    }
}

/// Stage A and A′ — the one wire tokenizer.
///
/// Swan had two, and they disagreed. The remote path
/// (`SwanOAuthAuthorizationServerHTTP.oauthServerScopes`) capped tokens at 256
/// bytes; the localhost bridge (`OAuthClientMetadata.localhostRequestedScopes`)
/// capped at 4096 **and carried a second issuance gate**,
/// `value == "atproto" || isIssuableQualified(value)`. That gate is deleted, not
/// re-expressed over the new parser (§9-D21): A′ is a tokenizer and a raw-input
/// budget, exactly like A, and every semantic question moves to stage B/E.
///
/// Both used `$0 > 0x20 && $0 < 0x7F`, which admits `"` (0x22) and `\` (0x5C)
/// that RFC 6749 §3.3 excludes; both now use ``ScopeToken/isScopeToken(_:)``,
/// a strict narrowing of the existing accept set.
public enum OAuthScopeTokenizer {
    /// Splits, dedupes and budget-checks a raw `scope` parameter. Performs no
    /// semantic validation whatsoever — that is stage B's job, one layer later,
    /// where the request is actually in front of the server.
    public static func tokenize(
        _ raw: String,
        budget: OAuthScopeBudget = .rawInput
    ) throws(OAuthScopeAdmissionError) -> Set<String> {
        // The whole-set budget belongs HERE and not at persistence: the hazard
        // it names — 64 × 1024 = 64 KB — is a wire hazard, and by persistence
        // the request has already been tokenized, parsed, and (Phase 2)
        // triggered lexicon resolution (§6.4).
        guard raw.utf8.count <= budget.bytesPerSet else {
            throw .rawRequestTooLong(bytes: raw.utf8.count, limit: budget.bytesPerSet)
        }
        let values = raw.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard !values.isEmpty else { throw .emptyScopeRequest }
        guard values.count <= budget.scopeCount else {
            throw .tooManyScopes(count: values.count, limit: budget.scopeCount)
        }
        guard values.count == Set(values).count else { throw .duplicateScope }
        for value in values {
            guard ScopeToken.isScopeToken(value) else { throw .notAScopeToken }
            guard value.utf8.count <= budget.bytesPerScope else {
                throw .rawScopeTooLong(bytes: value.utf8.count, limit: budget.bytesPerScope)
            }
            // `openid` is a legal scope-token, so the charset check above passes
            // it; the literal rejection is what upstream does at
            // `request-manager.ts:243-248`.
            guard value != "openid" else { throw .forbiddenScope }
        }
        return Set(values)
    }
}

/// The outcome of admitting a client's requested scope set: the requested bytes,
/// the parse that produced them, and the provenance that parse witnessed.
///
/// Provenance leaves this type and is persisted; it is **never** re-derived from
/// a scope string later (§9-D23).
public struct OAuthScopeAdmission: Sendable, Equatable {
    /// Exactly what the client asked for, unmodified.
    public let requestedScopes: Set<String>
    /// Which parameter keys the client physically wrote, keyed by the requested
    /// scope string. Re-keyed onto the effective string by stage F.
    public let provenance: OAuthScopeProvenance

    public init(requestedScopes: Set<String>, provenance: OAuthScopeProvenance) {
        self.requestedScopes = requestedScopes
        self.provenance = provenance
    }
}

/// Stages B, C, E and F of the stage table (§6.3).
///
/// Everything here runs at PAR/authorize or at token mint. Nothing here matches;
/// nothing here knows about a route. The four-layer boundary (§9-D21) is the
/// point: registration is lexical and grants nothing, admission decides what may
/// be asked for, mint resolves and expands, and only the resource plane matches.
public enum OAuthScopeAdmissionPolicy {
    /// Stage B + C + E, in that order.
    ///
    /// - Parameters:
    ///   - requested: the tokenized request, straight from stage A/A′.
    ///   - declared: the client's registered `scope` set. Under §9-D21 this has
    ///     been validated **lexically only**, so it is "a set of strings the
    ///     client typed", not a vetted set — which is exactly why stage B runs
    ///     over `requested` and never over `declared`.
    public static func admit(
        requested: Set<String>,
        declaredBy declared: Set<String>
    ) throws(OAuthScopeAdmissionError) -> OAuthScopeAdmission {
        // Stage B — every requested scope must parse. Swan rejects where
        // upstream silently drops (`request-manager.ts:177-185`, §9-D5): a
        // silent drop would hand back an `atproto`-only token and then produce
        // an opaque 401 at the resource plane with nothing in the OAuth response
        // pointing at the cause.
        var parsed: [String: AtprotoScope] = [:]
        var provenance = OAuthScopeProvenance()
        for scope in requested {
            let value: AtprotoScope
            do {
                value = try AtprotoScope.parse(scope)
            } catch {
                throw .unparseableScope(error)
            }
            try requireCollectionForWriteActions(value)
            parsed[scope] = value
            provenance.record(statedKeys(of: value), for: scope)
        }

        // Stage C — requested ⊆ declared, both sides canonicalised (§9-D7). A
        // client may legitimately spell the same grant differently in its
        // metadata and its request; without canonicalisation the canonical form
        // itself would introduce false negatives.
        //
        // A *registered* value that does not parse is KEPT and compared as its
        // raw bytes, never silently dropped the way upstream's normaliser drops
        // it — dropping can lock a client out over a scope it is not currently
        // asking for.
        guard isCanonicalSubset(requested, of: declared) else { throw .notRegistered }

        // Stage E — the base-scope floor. Swan's floor is `atproto` OR a
        // `space:` grant, which is LOOSER than upstream's unconditional
        // `atproto` (`request-manager.ts:241-243`). That divergence is
        // deliberate and recorded (§4.8): tightening it would break every
        // existing space-only session in production.
        guard parsed.values.contains(where: isBaseOrResourceScope) else {
            throw .missingBaseScope
        }

        return OAuthScopeAdmission(requestedScopes: requested, provenance: provenance)
    }

    /// Stage C — requested ⊆ declared, with **both sides canonicalised**
    /// (§9-D7).
    ///
    /// A client can legitimately spell the same grant differently in its
    /// metadata and its request; without canonicalisation the canonical form
    /// itself introduces false negatives.
    ///
    /// The asymmetry is deliberate: a *registered* value that does not parse is
    /// **kept and compared as its raw bytes**, never dropped. Upstream's
    /// `normalizeAtprotoOauthScope` (`atproto-oauth-scope.ts:55-62`) drops it,
    /// which would turn a subset check that passes today into a rejection and
    /// lock a client out over a scope it is not currently asking for. Requested
    /// values cannot reach here unparseable — stage B already rejected them.
    ///
    /// A raw-bytes match is also accepted, so a value whose canonical form fails
    /// to re-parse (§4.5's `blob`/`+` lossiness) compares raw on both sides
    /// rather than being treated as absent.
    public static func isCanonicalSubset(
        _ requested: Set<String>,
        of declared: Set<String>
    ) -> Bool {
        let canonicalDeclared = Set(declared.map(canonicalisedOrRaw))
        return requested.allSatisfy { scope in
            declared.contains(scope) || canonicalDeclared.contains(canonicalisedOrRaw(scope))
        }
    }

    /// Stage F — resolve `authority=self` against the subject the grant is being
    /// minted for, and re-key provenance onto the rewritten string.
    ///
    /// Swan resolves at mint **and** re-resolves at match time, deliberately
    /// (§6.4): mint-time rewrite makes the persisted grant usable, because an
    /// unresolved `self` matches nothing; match-time re-resolution keeps a row
    /// written by an older binary failing closed rather than matching silently.
    /// The rewrite is idempotent (`space-permission.test.ts:424-430`), so
    /// running it twice is free.
    ///
    /// Only scopes that actually change are rewritten. Every other requested
    /// byte is carried through untouched, so a grant with no `self` in it
    /// persists `scopes_requested` as NULL and refreshes exactly as before.
    ///
    /// Provenance is passed in and preserved: resolution changes the VALUE,
    /// never the statedness (§9-D23). Re-deriving it from the rewritten string
    /// would report a defaulted `authority` as stated and flip the delegation
    /// fence open.
    public static func resolvingSelfAuthority(
        _ binding: OAuthClientBinding,
        subject: String,
        provenance: OAuthScopeProvenance? = nil,
        budget: OAuthScopeBudget = .expandedGrant
    ) throws(OAuthScopeAdmissionError) -> OAuthClientBinding {
        let carried = provenance ?? binding.scopeProvenance ?? OAuthScopeProvenance()
        var effective: Set<String> = []
        var rekeyed = carried
        var changed = false

        for scope in binding.scopes {
            // A scope that does not parse is carried verbatim: a HELD scope that
            // does not parse grants nothing and must not fail anything (§9-D5,
            // match layer). Only newly-minted grants are gated on parsing, and
            // that gate is stage B, before this point.
            guard let parsed = try? AtprotoScope.parse(scope),
                  case let .space(permission) = parsed,
                  permission.isSelfAuthority else {
                effective.insert(scope)
                continue
            }
            let resolved = permission.withResolvedAuthority(subject)
            guard let rewritten = try? resolved.canonicalScopeString() else {
                effective.insert(scope)
                continue
            }
            effective.insert(rewritten)
            rekeyed = rekeyed.rekeyed(from: scope, to: rewritten)
            changed = changed || rewritten != scope
        }

        try enforceExpandedGrantBudget(effective, budget: budget)
        guard changed || binding.scopeProvenance == nil else { return binding }
        return binding.withEffectiveScopes(effective, provenance: rekeyed)
    }

    /// The EXPANDED-GRANT budget. This fails at mint, attributed to Swan's own
    /// expansion, rather than surfacing as a 500-shaped persistence error for a
    /// request the server had already accepted at PAR (§6.4).
    public static func enforceExpandedGrantBudget(
        _ scopes: Set<String>,
        budget: OAuthScopeBudget = .expandedGrant
    ) throws(OAuthScopeAdmissionError) {
        guard scopes.count <= budget.scopeCount else {
            throw .expandedGrantTooManyScopes(count: scopes.count, limit: budget.scopeCount)
        }
        var total = 0
        for scope in scopes {
            let bytes = scope.utf8.count
            guard bytes <= budget.bytesPerScope else {
                throw .expandedScopeTooLong(bytes: bytes, limit: budget.bytesPerScope)
            }
            // Separators, as the wire would count them.
            total += bytes + (total == 0 ? 0 : 1)
        }
        guard total <= budget.bytesPerSet else {
            throw .expandedGrantTooLong(bytes: total, limit: budget.bytesPerSet)
        }
    }

    /// Stage G's INSERT half: every element of a newly-minted grant must parse.
    ///
    /// New tokens are entirely under the new grammar's control, so this is a
    /// real tightening with no back-compat surface. The UPDATE/reload half is
    /// deliberately NOT this function — see ``rejectionsInHeldGrant(_:)``.
    public static func admitNewlyMintedGrant(
        _ scopes: Set<String>,
        budget: OAuthScopeBudget = .expandedGrant
    ) throws(OAuthScopeAdmissionError) {
        try enforceExpandedGrantBudget(scopes, budget: budget)
        for scope in scopes {
            do { _ = try AtprotoScope.parse(scope) } catch { throw .unparseableScope(error) }
        }
    }

    /// Stage G's additive half: which elements of an already-held grant do not
    /// parse.
    ///
    /// This **reports**, it does not reject. The only per-element INSERT gate
    /// Swan ever had was `validScope` — non-empty, ≤ 256 bytes, no whitespace,
    /// no control characters — and the resource-scope check beside it is an OR
    /// over the set, so `{atproto, <junk>}` was always accepted. A live family
    /// may therefore legitimately hold an unparseable companion scope, and a
    /// full re-parse gate on a rewrite would permanently lock that session out.
    /// It would also contradict §9-D5 in the same document, which rules that a
    /// held unparseable scope silently grants nothing.
    ///
    /// The caller logs the returned list with the family id and fails only if
    /// the post-rotation set would have *zero* parseable scopes. A rotation must
    /// never be the thing that ends a session.
    public static func rejectionsInHeldGrant(
        _ scopes: Set<String>
    ) -> [String: ScopeParseError] {
        var rejected: [String: ScopeParseError] = [:]
        for scope in scopes {
            do { _ = try AtprotoScope.parse(scope) } catch { rejected[scope] = error }
        }
        return rejected
    }

    /// Swan's resource-scope floor: `atproto`, or any `space:` grant. Kept
    /// deliberately narrow — under §8 Stage C a remote client may register
    /// `identity:handle` or `blob:image/*`, and such a token passing the floor
    /// would reach blob upload and repository sync, which perform no further
    /// scope check (§6.1).
    private static func isBaseOrResourceScope(_ scope: AtprotoScope) -> Bool {
        switch scope {
        case .atproto, .space: true
        default: false
        }
    }

    /// The one invariant re-homed from the retired `isIssuableQualified`
    /// (`SwanCore.swift:192-195`): only a read may be collection-free, because a
    /// write action with no concrete collection is a latent whole-repository
    /// capability.
    ///
    /// It moves to PAR/authorize and lives NOWHERE earlier (§6.2's tail): a
    /// registration-time copy would be semantic policy at layer 1, which §9-D21
    /// retires. Upstream expresses the same intent as a *default* rather than a
    /// gate — `collection` defaults to `[]` with the comment "Empty means no
    /// write targets, not 'all collections'" (`space-permission.ts:193-198`) —
    /// so upstream mints a grant authorizing no writes where Swan refuses the
    /// request (§9-D5).
    ///
    /// `read_self` is collection-free here where the old gate required a
    /// collection, matching §7.3 row D7: only `create`/`update`/`delete` need one.
    private static func requireCollectionForWriteActions(
        _ scope: AtprotoScope
    ) throws(OAuthScopeAdmissionError) {
        guard case let .space(permission) = scope else { return }
        // Only a STATED write action trips this. `action` defaults to the full
        // record list, so testing the parsed value alone would reject every
        // grant that named none — including a `manage=`-only grant, which asks
        // for no record write at all. A defaulted action set beside the default
        // empty `collection` is upstream's "no write targets, not all
        // collections" (`space-permission.ts:193-198`) and authorizes nothing;
        // there is nothing there to refuse. The invariant is about what the
        // client asked for, which is what provenance witnesses.
        guard permission.scopeParameters.wasStated("action") else { return }
        let writes: Set<SpaceAction> = [.create, .update, .delete]
        guard permission.action.contains(where: writes.contains) else { return }
        guard !permission.collection.isEmpty else { throw .writeActionWithoutCollection }
    }

    private static func canonicalisedOrRaw(_ scope: String) -> String {
        guard let parsed = try? AtprotoScope.parse(scope),
              let canonical = try? parsed.canonicalScopeString() else {
            return scope
        }
        return canonical
    }

    /// The parameter keys a parse witnessed as physically written. A free
    /// function rather than an extension on `AtprotoScope`, so this file adds
    /// no member to a type another lane owns.
    private static func statedKeys(of scope: AtprotoScope) -> Set<String> {
        switch scope {
        case .atproto, .transitionEmail, .transitionGeneric, .transitionChatBsky:
            []
        case let .account(p): p.scopeParameters.statedKeys
        case let .blob(p): p.scopeParameters.statedKeys
        case let .identity(p): p.scopeParameters.statedKeys
        case let .include(s): s.scopeParameters.statedKeys
        case let .repo(p): p.scopeParameters.statedKeys
        case let .rpc(p): p.scopeParameters.statedKeys
        case let .space(p): p.scopeParameters.statedKeys
        }
    }
}
