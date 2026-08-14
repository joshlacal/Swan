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

### P2-E — resolver orchestrator + cache · **SwanInterop** (corrected)

> **Module correction.** This lane originally said "SwanOAuth + SwanSQLite".
> That was impossible: `Package.swift` has **SwanInterop → SwanOAuth**, not the
> reverse, and `PermissionedDataPublicRepositoryCommitVerifier` — named by the
> fixed `SwanLexiconAuthority` interface — is defined in
> `SwanInterop/PublicRepositoryCARReplication.swift:282`. P2-E in SwanOAuth
> could never have consumed P2-C. SwanInterop already depends on SwanOAuth,
> SwanSQLite, SwanPublicRepository and SwanCore, so P2-E moves there with **zero
> `Package.swift` change**. Found by P2-C, not by me — and it is the second time
> this plan-level mistake has been made (Phase 1 put `SwanScopePermissions` in
> SwanOAuth and hit the same cycle). Check `Package.swift` before assigning a
> module, not the module's apparent subject matter.

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

## Errata against the sealed spec

Two contradictions found by implementation, each verified against upstream source
rather than adjudicated from the spec's own prose. Recorded here; **no sealed
spec text has been edited** — that is the spec owner's call.

### E1 — §5.7.6's per-entry authority vector is wrong on both halves

§5.7.6 describes `include-scope.test.ts:558-578` as *"a two-entry repo set"*
yielding *"a **one**-element array holding only the in-namespace grant"*, and
calls it *"the only vector proving the authority gate is per-entry, not
per-set."* Read at
`.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354/…/include-scope.test.ts:557-574`,
it is a **one-entry** set whose `collection` array holds
`['com.example.calendar.event', 'app.bsky.feed.post']`, inside a
`describe('rejects')` block, expecting **`[]`**. `isAllowedPermission` applies
`.every` over the entry's own collections (`include-scope.ts:125`), so the entry
drops whole.

The consequence matters more than the miscitation: **the fixture cannot witness
the property §5.7.6 assigns it.** P2-A proved this by mutation — replacing the
per-entry gate with a per-set gate leaves the upstream-verbatim assertion
*passing*; only Swan-authored vectors fail. A per-set implementation passes every
upstream include vector.

**Resolution taken:** implement upstream-verbatim (`[]`), and add Swan-authored
vectors that genuinely witness per-entry behaviour — a two-entry set (one wholly
in-namespace, one wholly foreign) → one surviving grant, plus a five-entry mixed
set where a blob drop, a gate-2 parse failure and a wildcard-space drop coexist
with two survivors. Those are what fail under a per-set gate.

### E2 — §5.7.1's `include:` `aud` contradicts its own citation

§5.7.1 validates `IncludeScope`'s `aud` as `{ $0 == "*" || isValidAtprotoDIDRefAbsolute($0) }`
while its comment claims the *"same `@atproto/did` predicate as `rpc:`'s `aud`"*
and cites `include-scope.ts:184-188`. Upstream at `:183-187` is
`validate: isAtprotoDidRefAbsolute` — **no wildcard**; the declared type at `:30`
is `undefined | AtprotoDidRefAbsolute`. Swan's `IncludeScope.swift:46`
(`audRaw == "*" ? .any : .service(audRaw)`) accepts a scope upstream rejects at
parse.

This is a divergence in the **accepting** direction — Swan would admit and
persist a grant no conformant AS would issue. Not pinned by the golden corpus
(4 include entries, none with a wildcard `aud`).

**Currently fail-closed, so not urgent:** P2-A's `inheritAud` splice requires a
concrete service DID-ref, so `.any` does not splice and the entry drops —
upstream's reachable behaviour. **Open decision:** whether §5.7.1 should lose the
`"*"`. It is Phase-1 wire grammar.

## Accepted divergences from upstream

Both are **fail-closed** — they refuse documents upstream would accept, never the
reverse — and both are documented in-code with a pinning test. Recorded here so
they are visible rather than buried in a lane report.

| divergence | upstream | Swan | why accepted |
|---|---|---|---|
| **Multikey-only verification methods** | also accepts `EcdsaSecp256r1VerificationKey2019` / `EcdsaSecp256k1VerificationKey2019`, whose `publicKeyMultibase` carries *raw* key bytes with no multicodec prefix and takes its curve from `type` | Multikey only | supporting the legacy forms needs a bare base58 decoder plus a second raw-point grammar, and `Base58BTC` is deliberately `private` to `SwanAccounts/PLCOperation.swift` so curve/point-encoding proof stays in one place. Every atproto producer in reach emits Multikey. Pinned by `testWebAuthorityWithLegacyVerificationMethodTypeIsRejected` |
| **Exactly-one `#atproto` / `#atproto_pds`** | `Array.find` (first match wins) | refuses a document declaring either twice; also requires https, non-empty host, no embedded credentials on the PDS endpoint, where upstream requires only `URL.canParse` | matches `SwanServiceEndpointResolver`'s existing rule for services |

**Open, not blocking:** full legacy-verification-method parity is available by
making `Base58BTC` public. It is an interop-availability question (a legitimate
authority publishing a legacy key type would fail to resolve → `invalid_scope`),
not a security one. Decide before Phase 2 closes.

## Running the golden-corpus gate — and a durability warning

```bash
SWAN_UPSTREAM_ATPROTO=/Users/joshlacalamito/Developer/Catbird+Petrel/Swan/.interop-cache/atproto-bddc99fb24c34b4078b9bf65837283f37b49ab66 \
  Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh
```

**Resolved:** the `bddc99fb` tree now lives at that path — in the **main Swan
checkout's** `.interop-cache/`, not a workspace's, following the existing
`atproto-<commit>` convention beside `atproto-3f6c96d5…`. `.interop-cache/` is
gitignored (`.gitignore:6`), so this adds 37 MB of untracked cache and touches no
VCS state. Verified from that path: zero diff. It previously existed only in an
ephemeral job scratch directory.

Note `interop/fetch-reference.sh` pins `3f6c96d5…`, a *different* commit for a
different purpose. Do not repoint it at `bddc99fb`; the two trees serve different
gates and both are needed.

Without `SWAN_UPSTREAM_ATPROTO` the corpus-integrity test **silently skips** —
it does not fail — so a green suite says nothing about corpus/upstream agreement.

**Only one tree on this machine is `bddc99fb`**, and it currently sits in an
ephemeral job scratch directory that is deleted with the job. Of the four other
`atproto` checkouts present:

| tree | verdict |
|---|---|
| `.interop-cache/atproto-3f6c96d5…` | has `space-permission.ts`, but is the **wrong commit** — needs 80 type-only-import rewrites and produces six different `values` rows |
| `Catbird+Petrel/atproto` | no `space-permission.ts` — predates the space plane |
| `Catbird+Petrel/Petrel/atproto` | no `space-permission.ts`; also spells the `include:` `aud` rule as `isAtprotoAudience` rather than `isAtprotoDidRefAbsolute` |
| `Developer/atproto-oauth-debug` | unverified |

**Action needed:** move a `bddc99fb` checkout somewhere durable, or the gate
becomes unrunnable and the corpus drifts undetected. The `space-permission.ts`
presence check is the cheap positive control — a tree without it is not
`bddc99fb`, and every `space:` vector generated from it would be *wrong rather
than absent*.

Note the two predicate spellings are not a contradiction: `isAtprotoAudience` is
`` `${AtprotoDid}#${string}` `` — DID plus exactly one fragment. **Neither
predicate accepts `*`**, so E2 holds across every tree checked.

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
