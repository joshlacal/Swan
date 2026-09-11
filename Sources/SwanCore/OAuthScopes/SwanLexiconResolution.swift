import Foundation

/// The abstract surface of §5.7.4 lexicon resolution: the protocol, its result
/// type, the documents it can resolve to, and the EXPANDED-GRANT budget that
/// bounds a request's worth of resolutions.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md
/// §5.7.4. Upstream: `packages/lex/lex-resolver/src/lex-resolver.ts`.
///
/// **Why this file is in SwanCore and not SwanOAuth or SwanInterop.** §5.7.4's
/// Swift block says "New, in SwanOAuth", and the Phase-2 plan corrected that to
/// SwanInterop because `PermissionedDataPublicRepositoryCommitVerifier` — named
/// by the fixed `SwanLexiconAuthority` interface — lives there and
/// `Package.swift` has SwanInterop → SwanOAuth, not the reverse. Both
/// placements are wrong for the *abstract* half, for the same reason and one
/// step further out: P2-F wires resolution into `SwanOAuth` and `SwanHTTP`, and
/// **neither depends on SwanInterop**. A `SwanLexiconResolving` declared in
/// SwanInterop is unreachable from the code that has to call it.
///
/// So the split is: the protocol, the result, `LexiconSpace` and the budget live
/// here in SwanCore, which every other target already depends on; the concrete
/// 15-step implementation lives in SwanInterop next to the authority resolver,
/// the CAR machinery and the cache it needs. The composition root (`swan`)
/// depends on both and injects one into the other. No `Package.swift`
/// dependency changes for any source target.

// MARK: - LexiconSpace

/// A space declaration as it appears in lexicon JSON. Ported from
/// `oauth-scopes/src/lib/lexicon.ts:23-29`, exactly as §5.7.4 cites it.
///
/// **Which tree this was read against, because reading the wrong one is how
/// this type nearly got mis-recorded.** The corpus is pinned at
/// `bddc99fb24c34b4078b9bf65837283f37b49ab66`
/// (`Swan/.interop-cache/atproto-bddc99fb…`), where `lib/lexicon.ts` is 29
/// lines and `:23-29` is this declaration. A pre-space-plane checkout of the
/// same repo has that file at 21 lines with no `LexiconSpace` in it at all, so
/// the citation reads as dangling and the type reads as invented. The control
/// that tells the two trees apart is
/// `oauth-scopes/src/scopes/space-permission.ts`: it exists only in the pinned
/// tree. Grepping for the word `space` does **not** discriminate — it hits
/// `include-scope.ts` in both.
///
/// The `space:` scope family therefore has upstream backing, and so does its
/// consumer: `expandSpaceCollections` is a real implementation at
/// `oauth-provider/src/lexicon/lexicon-manager.ts:74-95`, which materialises
/// `space.collections` into any bare `space:<type>` grant.
///
/// **What that materialisation does to the grant's VERBS is an open ruling, and
/// this type deliberately does not answer it.** The sentence above is scoped to
/// `collections` on purpose; do not read it as settling actions. The two
/// positions on the table, recorded as facts rather than as a conclusion:
/// upstream's `withDefaultCollections` (`space-permission.ts:134-146`) passes
/// `this.action` through **unchanged**, and `action`'s schema default is
/// `SPACE_DEFAULT_ACTIONS = [read, create, update, delete]` (`:25-30`), so
/// upstream a bare space grant is writable after expansion; Swan currently
/// carries a guard that drops those verbs when `action` was never stated, which
/// would leave it read-only. That is being decided elsewhere.
///
/// `LexiconSpace` is structurally the wrong place to settle it in any case — the
/// declaration carries collections and no action information at all, so nothing
/// here could express either answer even if it wanted to.
public struct LexiconSpace: Sendable, Equatable, Decodable {
    /// Must decode to exactly `"space"`. Retained rather than asserted here for
    /// the same reason `LexiconPermissionSet.type` is: the resolver classifies
    /// a document by this discriminator (`lexicon-manager.ts:153`,
    /// `lexicon.defs.main?.type !== 'space'`), so the value has to survive
    /// decoding in order to be classified.
    public let type: String
    /// `name:lang` (`lexicon.ts:26`) is **accepted and ignored**, matching the
    /// treatment `LexiconPermissionSet` already gives its siblings `title:lang`
    /// and `detail:lang`: a display-localisation map contributes no capability.
    ///
    /// It is ignored by mechanism rather than by intention-in-a-comment — a
    /// synthesized `Decodable` keyed container simply does not look at keys it
    /// has no case for. That is load-bearing rather than incidental: a real
    /// space from a localised lexicon carries `name:lang`, and rejecting the
    /// document over it would refuse a legitimate authority. Pinned by
    /// `testSpaceDocumentCarryingNameLangStillDecodes`.
    public let name: String
    /// May legitimately be empty. §5.7.5: "A space declaring an empty
    /// collection list is not an error; the bare grant passes through."
    /// Materialisation treats `[]` and "unresolvable" completely differently,
    /// so an empty array must decode as an empty array and never as `nil`.
    public let collections: [String]
    public let description: String?

    public init(
        type: String = "space",
        name: String,
        collections: [String],
        description: String? = nil
    ) {
        self.type = type
        self.name = name
        self.collections = collections
        self.description = description
    }

    private enum CodingKeys: String, CodingKey {
        case type, name, collections, description
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let collections = try container.decode([String].self, forKey: .collections)
        guard collections.allSatisfy(AtprotoSyntax.isValidNSID) else {
            throw DecodingError.dataCorruptedError(
                forKey: .collections, in: container,
                debugDescription: "space collections must be concrete NSIDs"
            )
        }
        self.init(
            type: try container.decode(String.self, forKey: .type),
            name: try container.decode(String.self, forKey: .name),
            collections: collections,
            description: try container.decodeIfPresent(String.self, forKey: .description)
        )
    }
}

// MARK: - SwanLexiconDocument

/// What a successfully proved `com.atproto.lexicon.schema` record's `defs.main`
/// turned out to be.
///
/// The classification happens in the resolver because that is where the bytes
/// are proved; `lexicon-manager.ts:126-129` keys its "Lexicon document is not a
/// permission set" rejection off `lexicon.defs.main?.type`, which is why the
/// discriminator has to survive as far as this enum.
public enum SwanLexiconDocument: Sendable, Equatable {
    case permissionSet(LexiconPermissionSet)
    case space(LexiconSpace)
    /// Proved and schema-valid, but `defs.main` is absent or names some other
    /// definition type. This is a SUCCESS, not a failure: the document was
    /// established as belonging to the authority's signed repo. The consumer
    /// decides what to do with it — `invalid_scope` at PAR for an `include:`
    /// (`lexicon-manager.ts:126-129`), `invalid_request` at mint — and the row
    /// is cached POSITIVELY, because refetching it would prove the same thing.
    case other
}

// MARK: - SwanLexiconResolution

/// A resolution ATTEMPT, including the negative outcome.
public enum SwanLexiconResolution: Sendable, Equatable {
    /// Mirrors upstream's `LexResolverResult` (`lex-resolver.ts:37-44`), which
    /// carries THREE fields: `uri`, `cid`, `lexicon`.
    ///
    /// `verifiedCID` is not decoration and must not be dropped. It is the CID
    /// the MST walk resolved to (`lex-resolver.ts:545`, returned `:555`) — the
    /// content address the proof chain actually terminated at, and the only
    /// value in the result that ties the returned bytes back to the signed
    /// commit.
    ///
    /// `sourceURI` is the `at://<did>/com.atproto.lexicon.schema/<nsid>` from
    /// step 4. The DID in it is the authority the DNS TXT step actually
    /// selected, which is not recoverable from the NSID alone once the TXT
    /// record changes.
    case resolved(SwanLexiconDocument, sourceURI: String, verifiedCID: String)

    /// Upstream's `LexResolverError` branch (`lexicon-getter.ts:19-27`): the
    /// resolver failed in an EXPECTED way. Cacheable. Distinct from a thrown
    /// error, which propagates (`:26-27`).
    ///
    /// **REACHABILITY IS CONSTRAINED** — see `SwanLexiconResolverFailure`, which
    /// enumerates the complete set of conditions that may produce it. Anything
    /// not in that enum — a programming error, a cancellation, a storage fault —
    /// THROWS and propagates. Widening this to catch-all would convert a bug
    /// into a cached "this lexicon doesn't exist" for five minutes.
    case unresolvable
}

/// The complete, closed set of resolver-class failures — precisely the set
/// upstream wraps in `LexResolverError` (`lex-resolver-error.ts:41-77`).
///
/// This exists so `.unresolvable`'s constrained reachability is a fact about the
/// type system rather than a claim in a comment: the resolver's internal steps
/// throw *this*, the outer layer converts *only this* into `.unresolvable`, and
/// every other error type flows past untouched.
///
/// **None of these is a "silent drop".** §5.7.5's silent-drop rows describe
/// entries *within a successfully proved document* that fail their own family's
/// parse or authority gate. A failure here means the document was never
/// established as belonging to the authority's signed repo, so there is nothing
/// to drop entries from. If one of these ever reached a drop path, an
/// attacker-controlled PDS would get to choose which of a user's requested
/// permissions survive by selectively corrupting proofs.
///
/// ## Never add a `.cancelled` case
///
/// **Every member of this enum is, by construction, cacheable as a negative
/// result — that is what this type IS.** A value here means "the authority's
/// document could not be established, and the next request may answer from a
/// `document IS NULL` row for five minutes without touching the network."
/// Cancellation means nothing of the kind: the work simply stopped, and the
/// authority may be perfectly healthy.
///
/// This is not hypothetical. Cancellation *was* being converted into one of
/// these — `OAuthRemoteDocumentFetcher` re-wraps a `CancellationError` as
/// `SwanError.unavailable` (`OAuthRemoteFetch.swift:674-677`), so an
/// error-identity check could not see it, and a resolver catch-all classified
/// it as `.recordFetchFailed`. Because `resolveAll` cancels every in-flight
/// sibling when the 10 s group deadline expires, **one slow authority
/// negative-cached its innocent siblings**: an attacker choosing which of a
/// user's permissions survive, arriving through the cache rather than through
/// the drop path §5.7.5 forbids. It is fixed by keying on task state
/// (`Task.checkCancellation()`) rather than on error type — see
/// `SwanLexiconResolver.classify`.
///
/// Adding `.cancelled` here would reinstate that bug through the front door,
/// with a comment explaining why it was intentional. A reader who notices
/// cancellation is unrepresentable in this enum has found the design, not an
/// omission. If cancellation ever needs to be observed, it belongs on a
/// separate channel that no cache write is derived from.
public enum SwanLexiconResolverFailure: Error, Sendable, Equatable {
    // Steps 1-4 — authority selection.

    /// Step 1: not a syntactically valid NSID, or it has no authority segment.
    case invalidNSID
    /// Step 2: the DNS TXT lookup itself failed (`lex-resolver.ts:354-359`).
    case dnsUnavailable
    /// Step 3: zero `did=` lines — upstream `No DID found in DNS TXT records`.
    case noAuthorityDIDInTXT
    /// Step 3: more than one `did=` line — upstream
    /// `Multiple DIDs found in DNS TXT records`. **Not "first wins."**
    case multipleAuthorityDIDsInTXT
    /// Step 3: the text after `did=` is not a valid DID (`assertDid`).
    case invalidAuthorityDIDInTXT

    // Steps 5-6 — DID document.

    /// Step 5: DID-document resolution failed (`:427-432`), or the method is
    /// refused by `allowedLexiconAuthorityDIDMethods` (§9-D22).
    case authorityDocumentUnavailable
    /// Step 6: no PDS endpoint, or no `atproto` signing key (`:434-439`).
    case authorityDocumentIncomplete

    // Step 7 — fetch.

    /// The `com.atproto.sync.getRecord` fetch failed (`:465-469`). Includes the
    /// per-step deadline and the 256 KiB body cap.
    case recordFetchFailed

    // Steps 8-13 — the six proofs. Each closes a distinct hole; dropping any
    // one leaves a working attack (§5.7.4, "What each proof actually stops").

    /// Step 8: the CAR does not carry exactly one root (`repo/src/car.ts:60`).
    case carRootCountInvalid
    /// Step 9: the root block does not decode as a repo-v3 `commit` (`:532`).
    case commitDecodeFailed
    /// Step 10: `commit.did` is not the resolved DID (`:533-535`,
    /// `Invalid repo did`). **Cross-repo substitution.**
    case commitDIDMismatch
    /// Step 11: the signature does not verify under the DID-document key
    /// (`:537-541`, `Invalid signature on commit`).
    case commitSignatureInvalid
    /// Step 12: the record is not reachable from `commit.data` through the MST
    /// (`:543-546`, `Record not found in proof`). Covers both provable absence
    /// and a withheld path node — a proof that cannot be completed is not a
    /// proof, and an attacker choosing which blocks to omit must not be able to
    /// steer which of those two it looks like.
    case recordNotInProof
    /// Step 13: the record's `$type` is not `com.atproto.lexicon.schema`
    /// (`:548-553`, `Invalid record type`), or the record bytes do not decode.
    case recordTypeMismatch

    // Steps 14-15 — document.

    /// Step 14: the document fails lexicon-document schema validation
    /// (`:472-477`).
    case documentSchemaInvalid
    /// Step 15: `lexicon.id != uri.rkey` (`:480-485`).
    case documentIDMismatch
}

// MARK: - SwanLexiconResolving

/// The only type in the system that performs a network fetch on behalf of a
/// scope. `resolve` owns all fifteen steps of §5.7.4 — **including the six
/// proofs.**
///
/// **A conforming implementation that performs steps 1-7 and skips 8-13 is NOT
/// a partial implementation of this protocol; it is a different and unsafe
/// protocol wearing this one's name.** It is stated here because "we'll add
/// proof verification in a follow-up" is exactly the shortcut §5.7.4 exists to
/// forbid: a resolver that fetches without proving launders an
/// attacker-controlled HTTP response into a signed-looking grant, and since
/// Phase 2 feeds `include:` expansion straight into what an OAuth grant
/// materialises to, that is privilege escalation operated by lying in a
/// response body.
///
/// The fifteen steps, and what each proof stops:
///
/// 1. `NSID.from(nsid)`; take the reverse-DNS authority.
/// 2. DNS `TXT _lexicon.<authority>`.
/// 3. Keep lines starting `did=`; require **exactly one**. Zero is an error and
///    more than one is an error — never "first wins".
/// 4. `at://<did>/com.atproto.lexicon.schema/<nsid>`. The collection is
///    **hardcoded**, never caller-suppliable.
/// 5. Resolve the DID document (`did:plc:` or `did:web:`), extracting BOTH the
///    PDS endpoint AND the `atproto` verification method from one read.
/// 6. Reject if either is missing.
/// 7. `com.atproto.sync.getRecord` against the **resolved** PDS — never a
///    caller-supplied host — returning raw CAR bytes.
/// 8. **Proof:** the CAR has exactly one root. Stops a second root smuggling an
///    alternate commit past a caller that naively reads `roots[0]`.
/// 9. **Proof:** the root block decodes as a `commit`. Refuses wrong-shape CBOR
///    *before* any trust decision.
/// 10. **Proof:** `commit.did` equals the **resolved** DID, not one the response
///     chose. Stops **cross-repo substitution** — a correctly self-signed commit
///     from the attacker's own repo presented as this DID's data.
/// 11. **Proof:** the commit signature verifies against the key from the
///     **DID document**, never from the response. Stops forged commits.
/// 12. **Proof:** MST membership from `commit.data`. Stops record-existence
///     forgery — an unlinked orphan block sitting in the CAR proves nothing.
/// 13. **Proof:** the record's `$type` is the collection. Stops type confusion.
/// 14. The document validates against the lexicon-document schema.
/// 15. `lexicon.id == uri.rkey`. Stops same-repo record substitution — a validly
///     signed lexicon describing a *different* NSID at the expected rkey.
///
/// Trust flows from the DID document through commit signature → MST membership →
/// record bytes. Never from "the server said so."
public protocol SwanLexiconResolving: Sendable {
    func resolve(_ nsid: String) async throws -> SwanLexiconResolution
}

// MARK: - Budget

/// Which of the **two separately-bounded populations** a group of resolutions
/// belongs to (§5.7.4, "Where these caps live").
///
/// They are separate because space-type NSIDs are not `include:`-derived: they
/// are resolved by `expandSpaceCollections`, which iterates *every* scope in the
/// token. An earlier budget bounded only the `include:` set and left them
/// unbounded, and a 64-token set can name up to 64 distinct types.
public enum SwanLexiconResolutionPopulation: Sendable, Equatable {
    /// Distinct `include:` NSIDs. Capped at 4.
    case includes
    /// Distinct `space:<type>` NSIDs reached by materialisation. Capped at 8.
    case spaceTypes

    public var maximumDistinctNSIDs: Int {
        switch self {
        case .includes: return SwanLexiconResolutionBudget.maximumIncludeNSIDs
        case .spaceTypes: return SwanLexiconResolutionBudget.maximumSpaceTypeNSIDs
        }
    }
}

/// **EXPANDED-GRANT budget**, not the raw-input one (§6.4, §9-Q5).
///
/// RAW-INPUT measures the bytes that arrived on the wire and is enforced by the
/// wire tokenizers. Everything here measures what Swan holds *after its own
/// transformations*, and is enforced at token mint and persistence. The
/// distinction is load-bearing rather than bookkeeping: an 80-byte `include:`
/// passes the raw budget at PAR and then inflates past it under Swan's own
/// expansion, so a single shared number would report the failure against the
/// wrong actor at the wrong stage.
///
/// The CPU half is named deliberately. CAR parse, commit-signature verification
/// and the MST walk are **CPU**, not network; a wall-clock deadline does not
/// bound them and a body cap does.
public enum SwanLexiconResolutionBudget: Sendable {
    /// §5.7.4: cap distinct `include:` NSIDs at 4 per request.
    public static let maximumIncludeNSIDs = 4
    /// §5.7.4: cap distinct space-type NSIDs at 8 per request.
    public static let maximumSpaceTypeNSIDs = 8

    /// Per-step network policy — per step, NOT per include.
    public static let dnsDeadlineSeconds: Double = 2
    public static let didDocumentDeadlineSeconds: Double = 3
    /// The existing `OAuthRemoteFetchPolicy` default.
    public static let recordFetchDeadlineSeconds: Double = 5

    /// Per-request wall clock for the ENTIRE resolution group. Not 4 × 5 s
    /// sequentially, and not one 5 s deadline across ≥ 12 network operations
    /// plus three CPU-bound proof stages.
    public static let groupDeadlineSeconds: Double = 10

    /// The explicit CAR cap for this call site.
    ///
    /// It is an **anti-DoS control on MST-walk and signature work**, not a
    /// document-size preference: a single-record proof CAR is one commit block
    /// plus an MST path, a few KiB by construction. It equals
    /// `OAuthRemoteFetchPolicy.maximumBodyBytes`'s default, where it currently
    /// bounds this work only incidentally, as a JSON-document cap that happens
    /// to also apply. Naming it here makes it deliberate.
    ///
    /// The complementary node-count bound comes from `PublicRepositoryLimits`,
    /// which the full validators already use — deliberately the same limits
    /// object, because two MST budgets that can drift apart is a worse outcome
    /// than either number.
    public static let maximumCARBytes = 256 * 1_024

    /// `LEXICON_REFRESH_FREQUENCY = 5 * MINUTE`
    /// (`oauth-provider/oauth-constants.ts:84`). Stale triggers a refetch; it
    /// does not invalidate.
    public static let refreshThresholdSeconds: Double = 5 * 60

    /// **Swan addition.** Upstream serves stale *forever*, and because the token
    /// scope is re-derived on every refresh (`token-manager.ts:260-263`), a
    /// permission set that was **narrowed** upstream would keep minting the
    /// wider grant indefinitely whenever the resolver is unreachable. Past this,
    /// a cached document is treated as unresolved. A deliberate divergence
    /// trading availability for grant-freshness — the correct direction for an
    /// authorization server. Applies to `last_succeeded_at`, not `updated_at`.
    public static let hardExpirySeconds: Double = 24 * 60 * 60
}

/// Exceeding a count cap or the group deadline. Both are `invalid_scope` at PAR
/// and `invalid_request` at token mint — §5.7.5 keeps upstream's asymmetric
/// codes for the same root cause deliberately, so this type carries the
/// condition and the call site chooses the code.
public enum SwanLexiconResolutionBudgetError: Error, Sendable, Equatable {
    case tooManyDistinctNSIDs(SwanLexiconResolutionPopulation, requested: Int)
    case groupDeadlineExceeded
}

public extension SwanLexiconResolving {
    /// Resolves a whole population under the EXPANDED-GRANT budget: the count
    /// cap for that population, one `withThrowingTaskGroup`, and the single 10 s
    /// group deadline across all of it.
    ///
    /// Duplicates are collapsed before the cap is applied, because the cap is on
    /// **distinct** NSIDs and the underlying resolutions would share a cache row
    /// anyway.
    ///
    /// Budget failures throw; they are not `.unresolvable`. An over-cap request
    /// is a property of the request, not of any authority, and caching it
    /// against an NSID would let one oversized request poison that NSID's row
    /// for five minutes.
    func resolveAll(
        _ nsids: some Sequence<String>,
        population: SwanLexiconResolutionPopulation
    ) async throws -> [String: SwanLexiconResolution] {
        let distinct = Array(Set(nsids)).sorted()
        guard distinct.count <= population.maximumDistinctNSIDs else {
            throw SwanLexiconResolutionBudgetError.tooManyDistinctNSIDs(
                population, requested: distinct.count
            )
        }
        guard !distinct.isEmpty else { return [:] }
        return try await SwanLexiconDeadline.run(
            seconds: SwanLexiconResolutionBudget.groupDeadlineSeconds,
            onExpiry: SwanLexiconResolutionBudgetError.groupDeadlineExceeded
        ) { [self] in
            try await withThrowingTaskGroup(
                of: (String, SwanLexiconResolution).self
            ) { group in
                for nsid in distinct {
                    group.addTask { (nsid, try await self.resolve(nsid)) }
                }
                var results: [String: SwanLexiconResolution] = [:]
                for try await (nsid, resolution) in group {
                    results[nsid] = resolution
                }
                return results
            }
        }
    }
}

// MARK: - Deadline

/// A per-step / per-group wall clock.
///
/// Deliberately small and local to lexicon resolution. It races the operation
/// against a sleep and **cancels the loser**, so an expired step does not leave
/// a network read running past the group deadline that was supposed to bound it.
public enum SwanLexiconDeadline: Sendable {
    public static func run<T: Sendable>(
        seconds: Double,
        onExpiry expiry: any Error,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await swanRaceWithDeadline(
            seconds: seconds,
            onExpiry: expiry,
            operation: operation
        )
    }
}
