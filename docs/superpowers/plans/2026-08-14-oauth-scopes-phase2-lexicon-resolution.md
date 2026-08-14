# OAuth permission scopes — Phase 2: lexicon resolution

> **For agentic workers:** the sealed spec
> `docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md` (commit
> `168b14a5`) is the implementation authority. This plan decomposes §5.7.3-§5.7.6
> into lanes and fixes the interfaces between them. Where the spec gives Swift,
> that Swift is the target. Where this plan and the spec disagree, the spec wins
> and the disagreement is worth reporting.

**Goal:** resolve `include:<nsid>` permission sets and bare `space:<type>`
collection declarations from their authority's *cryptographically proved* repo
record, and wire both into PAR and token mint.

**Architecture:** a `SwanLexiconResolving` orchestrator performs 15 steps, six of
which are proofs over a `com.atproto.sync.getRecord` CAR. Trust flows from the
DID document through commit signature → MST membership → record bytes. Never
from "the server said so."

## Global Constraints

- **`sync.getRecord`, never `repo.getRecord`.** The latter has no cryptographic
  linkage to repo state; a dishonest PDS can return any JSON it likes, and Phase 2
  feeds that straight into what a grant materialises to. This is the reason the
  first spec draft was rewritten rather than annotated (§5.7.4).
- **A resolver that does steps 1-7 and skips 8-13 is not a partial
  implementation — it is a different, unsafe protocol wearing this one's name.**
  Say so in the doc comment. "Proof verification in a follow-up" is the exact
  shortcut §5.7.4 exists to forbid.
- **A proof failure NEVER degrades to a silent drop.** Silent-drop rows apply to
  entries *within a successfully proved document*. If a proof failure reaches a
  drop path, an attacker-controlled PDS chooses which of a user's permissions
  survive by selectively corrupting proofs (§5.7.5).
- **All outbound I/O goes through `OAuthRemoteFetchPolicy`.** Adding a second
  fetch path that bypasses its URL policy, public-address peer check, redirect
  policy, admission control, or body cap is the one refactor §5.7.4 forbids
  outright.
- **Arity is part of the value.** Never collapse `.scalar` into a one-element
  `.list`. Stringifying a scalar `collection` expands a rejected entry into a live
  `repo:` create/update/delete grant (§5.7.3 gate 3).
- **Two separately-named budgets.** RAW-INPUT measures wire bytes; EXPANDED-GRANT
  measures what Swan holds after its own transformations. Everything in Phase 2 is
  EXPANDED-GRANT. Caps: 4 distinct `include:` NSIDs, 8 distinct space-type NSIDs,
  10 s group deadline, 256 KiB CAR.
- **Asymmetric error codes are deliberate.** Same root cause → `invalid_scope` at
  PAR, `invalid_request` at token mint. Match upstream for interop; comment the
  asymmetry rather than unifying it.
- VCS: jj-colocated, git read-only. **Seal → `jj new` immediately → then report.**
- Never bare `swift build`; use `xcrun --toolchain XcodeDefault`.

---

## Verified starting facts

Each was checked against the tree, not inferred. They set lane sizes.

| claim | status |
|---|---|
| `withDefaultCollections` has zero production callers (tests only) | **confirmed** — expansion is unwired; the L1 guard is pre-positioned |
| `RepositoryMSTValidation.validate` AND `validateProjection` are both full-tree walks | **confirmed** — `validateProjection`'s own doc says "the same strict validation as `validate`"; both route through `requiredBlock`, which throws `missingBlock`. A single-record proof CAR contains only the root→record path, so **both reject a legitimate proof**. New walker needed; `RepositoryMSTCodec` is reusable |
| `OAuthRemoteFetch` has no bytes-returning fetch | **confirmed** — only `fetchJSON` (`:564`, `:587`, `:623`) |
| `PublicRepositoryDIDResolver` is `did:plc:`-only | **confirmed** — `repositoryDID.hasPrefix("did:plc:")` guard in `resolveCommitVerifier` |
| no `sync.getRecord` client exists | **confirmed** — `LiveInterop.swift:1419` uses `repo.getRecord` for an unrelated purpose |

---

## Interfaces — fixed before dispatch

Lanes work against these. Changing one is a cross-lane event: report it, don't
absorb it silently.

```swift
// P2-C produces, P2-E consumes.
public protocol SwanLexiconAuthorityResolving: Sendable {
    /// Steps 5-6. Accepts did:plc: AND did:web:, gated by operator policy
    /// `allowedLexiconAuthorityDIDMethods` (default [.plc, .web], §9-D22).
    /// Throws if no PDS endpoint or no `atproto` verification method.
    func resolveAuthority(did: String) async throws -> SwanLexiconAuthority
}

public struct SwanLexiconAuthority: Sendable, Equatable {
    public let pdsEndpoint: URL
    public let commitVerifier: PermissionedDataPublicRepositoryCommitVerifier
}

// P2-B produces, P2-E consumes.
public enum RepositoryMSTProof {
    /// Step 12. Walks ONLY the path from `rootCID` to `key`, tolerating absent
    /// sibling subtrees — which is what distinguishes a proof walk from
    /// `validate`/`validateProjection`. Returns the record CID the key maps to,
    /// or nil if the key is provably absent. Bounded by the SAME
    /// `PublicRepositoryLimits` the full validators use — do not introduce a
    /// second MST budget.
    public static func membership(
        rootCID: CID, key: String,
        blocks: any PublicRepositoryBlockSource,
        limits: PublicRepositoryLimits = .standard
    ) async throws -> CID?
}

// P2-D produces, P2-E consumes.
extension OAuthRemoteDocumentFetcher {
    /// Sibling of fetchJSON, through the SAME OAuthRemoteFetchPolicy.
    public func fetchBytes(from url: URL) async throws -> Data
}

// P2-A produces, P2-F consumes. Spec §5.7.3 gives the full Swift.
extension IncludeScope {
    public func expand(_ set: LexiconPermissionSet) -> [IncludedPermission]
    public func isParentAuthorityOf(_ other: String) -> Bool
}

// P2-E produces, P2-F consumes. Spec §5.7.4 gives the full Swift.
public protocol SwanLexiconResolving: Sendable {
    func resolve(_ nsid: String) async throws -> SwanLexiconResolution
}
```

---

## Lanes

Dependency order: **P2-A, P2-B, P2-C, P2-D run concurrently** (no shared files).
**P2-E** joins B+C+D. **P2-F** joins A+E. **P2-G** verifies E.

### P2-A — expansion (pure, zero network) · SwanCore

§5.7.3 in full: `LexiconPermissionSet`, `LexiconValue`, `LexiconPermission`,
`LexPermissionSyntax`, a `ScopeParameterSchema.parse(_:LexPermissionSyntax)`
overload, `IncludeScope.expand`, `isParentAuthorityOf`, `isAllowed`,
`lexSyntax(for:)`.

The four behaviours that are not optional — implement any three and no upstream
vector passes, while two upstream *rejections* invert into grants:
`spaceType`→`type` remap; reserved-key filtering; the scalar-vs-array tri-state;
`ParamValue = string | number | boolean`.

Vectors: the `include-scope.test.ts` `describe` blocks named in §5.7.6, plus the
four written-out vectors — especially **scalar-where-array** (`:494-508` → `[]`)
and **one-valid-one-invalid-authority** (`:558-578` → a one-element array, the
only vector proving the authority gate is per-entry rather than per-set).

`isParentAuthorityOf` must use **UTF-8 byte units throughout** — the first draft
mixed `Character` distance with byte count. It is `public` and reachable with
unvalidated input, and upstream calls it "a security feature."

### P2-B — MST membership proof walker · SwanPublicRepository

The single-key walker above, plus the **proof-CAR test fixture builder** the
whole of P2-G depends on: build a signed commit, an MST path, and a CAR — and
the adversarial variants (two roots, cross-repo, bad signature, wrong key,
record-present-but-unlinked, `$type` mismatch).

The fixture builder is the reason this lane is not small. Without it P2-G cannot
assert anything, and P2-G contains the single most important vector in Phase 2.

### P2-C — did:web authority resolution · SwanInterop

Lift the `did:plc:` hard-requirement for lexicon-authority resolution. Extract the
`atproto` verification method **and** the `#atproto_pds` service endpoint from a
`did:web` document. Add `allowedLexiconAuthorityDIDMethods` as operator policy
(default `[.plc, .web]`, §9-D22) — PLC-only is a knob, not the protocol.

Do **not** tie the PDS host to the DID host: `extractPdsUrl` is just
`new URL(service.serviceEndpoint)` and nothing constrains its host. A `did:web`
authority whose PDS lives on another host is legitimate and is exactly the
independence the proof chain exists for.

### P2-D — `fetchBytes` · SwanOAuth

A bytes-returning sibling to `fetchJSON` through the same policy object, with an
explicit 256 KiB cap at this call site treated as an **anti-DoS control on
MST-walk and signature work**, not as a document-size preference.

### P2-E — resolver orchestrator + cache · SwanOAuth + SwanSQLite

All 15 steps including all 6 proofs. DNS TXT `_lexicon.<authority>` reusing
`ATHandleDNSResolving.txtRecords(name:)` (new call site, **not** new DNS
plumbing) with **exactly-one** `did=` selection. The `oauth_lexicon_documents`
table exactly as specified — `document` **NULLABLE**, because a negative-cache
row is the mechanism that stops the resolver being hammered for a known-broken
NSID.

`.unresolvable` has **constrained reachability**: only the enumerated
resolver-class failures. Everything else — programming error, cancellation,
storage fault — throws and propagates. Widening it to catch-all converts a bug
into a cached "this lexicon doesn't exist" for five minutes.

Two caches, not one: domain-keyed for steps 1-6, document-keyed for steps 7-15.
Cache the DID document, not the proof result — the proof must be re-verified
against whatever key the document currently names.

### P2-F — wiring · SwanOAuth + SwanHTTP

PAR: every `include:` must resolve or the request is `invalid_scope`; expand
before extracting space types for consent display.

Token mint, in order: (a) `include:`→concrete; (b) `expandSpaceCollections`;
(c) `resolveSpaceSelfAuthority`. **(b) is not include-specific** — it iterates
every scope in the token, and bulleted.app's `space:` scope contains no
`include:` and is affected.

(b) **throws** when the declaration cannot be resolved, deliberately: passing the
bare grant through would let an unreachable or hostile authority silently *widen*
what it covers. An empty declared collection list is **not** an error — the bare
grant passes through. `type=*` is skipped.

Record the **Phase-1 divergence** this closes: with no materialisation step, a
plain `space:app.bulleted.space` token can never write. §7.4 Stage 6 currently
pins that as upstream conformance; it is not — it is a divergence, and it is why
bulleted.app authorizes and then cannot create a record.

Consent must render an empty expansion with §5.7.2's canonical string naming the
NSID — a `.warn` reaches an operator, and the person authorizing never sees it.

### P2-G — resolver negative vectors · SwanOAuthTests

Every row of §5.7.6's resolver table. These are **negative** vectors by design: a
resolver that passes every happy-path test and skips proof verification is worse
than no resolver, because it launders an attacker-controlled response into a
signed-looking grant.

**`cross-repo substitution` is the single most important vector in Phase 2** — a
correctly self-signed commit from the attacker's own repo, presented as this
DID's data. It is the one a proof-free implementation passes every other test
while failing.

Plus: negative caching performs **no** network I/O and no MST walk on the second
attempt within 5 minutes; and a `did:web` authority resolves.

---

## Completion gate

Phase 2 is not done until all of these are green **and** independently measured
(three `swift test` invocations in one shell command contaminate each other —
run them separately):

- `xcrun --toolchain XcodeDefault swift build --product swan`
- `swift build --build-tests`
- the §7.6 narrow repeated scope-suite gate
- the wider SwanSpaces/SwanSQLite gate
- the bulleted.app E2E — which for the first time should be able to **write**
- golden-corpus regenerate-and-zero-diff
- every §5.7.6 resolver negative vector, cross-repo substitution named explicitly
- D23 provenance and D20 refresh-survival still green (Phase 1 regressions)
