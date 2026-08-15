# Swan OAuth permission scopes — implementation spec

Status: design, ready to implement. Assembled from `10-design-grammar.md`,
`11-design-families.md`, `12-design-enforcement.md`, `13-design-tests.md`
(job `2a78ce63`). Where those four disagreed, this document takes one position
and records the reasoning in §9 "Decisions taken". No file under `Sources/` or
`Tests/` was modified to produce it.

Reference trees, read-only, pinned:

| Tree | Path | Role |
|---|---|---|
| Upstream TypeScript | `bluesky-social/atproto`, branch `permissioned-data` @ `bddc99fb`, `packages/oauth/oauth-scopes/src` | **normative** scope grammar |
| Upstream provider | same checkout, `packages/oauth/oauth-provider/src` | how an AS consumes scopes |
| Upstream syntax | same checkout, `packages/syntax/src` | at-uri / nsid / did syntax |
| **Upstream DID** | same checkout, `packages/did/src` (10 entries incl. `atproto.ts`, `did-ref.ts`, `lib/`, `methods/`) | **normative** — `isAtprotoDidRefAbsolute` (`atproto.ts:230`), atproto method allow-list (`atproto.ts:19`). §4.1, §9-D13 |
| **Upstream lexicon resolver** | same checkout, `packages/lex/lex-resolver/src/lex-resolver.ts` (577 L) | **normative** — the `include:` resolution + repo-proof contract Phase 2 ports. §5.7.4, §9-D14 |
| **Upstream PDS** | same checkout, `packages/pds/src` (285 `.ts` files, 67 `authorize:` route callbacks) | **normative** — request-time enforcement model: `permissions.assertRpc`×15, `assertRepo`×5, `assertIdentity`×4, `assertAccount`×2, `assertSpace`×2 + the shared helper `api/com/atproto/space/util.ts:87-100`. §6.3, §9-D16 |
| **Upstream space plane** | same checkout, `packages/space/src` (`credential.ts`, `dpop.ts`, `error.ts`, `repo-commit.ts`, …) | **normative** — `cnf.jkt` minting (`credential.ts:105`) and the `requireCnf` parse flag (`:154-155`). §6.8, §9-D18 |
| **Upstream consent UI** | same checkout, `packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx` (1287 L) | **normative** — semantic consent rendering; the `identity:*` theft warning at `:227`. §7.4 Stage 4, §9-D19 |
| **Upstream OAuth types** | same checkout, `packages/oauth/oauth-types/src/oauth-scope.ts` (`OAUTH_SCOPE_REGEXP` `:5-6`, `oauthScopeSchema` `:17-19`), `oauth-client-metadata.ts:36` | **normative** — what client-metadata `scope` validation actually is: lexical only. §9-D21 |
| Rust reference | `ngerakines/atproto-crates`, `crates/atproto-oauth/src/scopes.rs` (3345 L) and `scopes/space_permission.rs` (1614 L) | independent implementation of the same proposal, **corroboration only** |
| Swan | `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-merge3` | the thing being changed |

The seven bolded rows were **not** visible to the first draft of this document
(§2 constraint 5). Every claim that used to read "absent from this checkout",
"reconstructed", "inferred", or "no upstream model" derived its authority from
that gap and has been re-derived against the complete tree.

Below, `oauth-scopes/…` means the upstream scope-grammar package; bare
`Sources/…` / `Tests/…` means Swan.

---

## 1. Goal, and the concrete failure it fixes

**Goal:** replace Swan's hand-rolled `space:`-only scope validator with a
complete, upstream-conformant implementation of the permissioned-data OAuth
scope grammar, so that a third-party AT Protocol client can sign in to
swan.place with the same scope strings it sends to any other implementation.

**The failure.** `bulleted.app` cannot sign in to swan.place. Its client
metadata requests exactly five scopes (recovered from its client metadata
during the live failure, `.claude/jobs/2a78ce63/timeline.jsonl`):

```
atproto
include:app.bulleted.authFull
blob:image/*
include:app.bulleted.spaceAccess
space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self
```

The client fetched the three well-known documents three times and stopped; it
never reached PAR. Four of the five scopes are unrepresentable in Swan, and the
`space:` scope — the one Swan claims to support — is rejected **four**
independent ways:

- **No `authority`, no `skey`.** `PermissionedSpaceScopeSyntax.isQualified`
  ends with `requiredKeys == ["authority", "skey"] && (hasAction != hasManage)`
  (`Sources/SwanCore/SwanCore.swift:243`). This scope names neither.
  Upstream defaults them to `self` and `*` respectively
  (`oauth-scopes/scopes/space-permission.ts:183`, `:189`).
- **Repeated `manage=`.** `keys.insert(String(pair[0])).inserted`
  (`SwanCore.swift:224`) hard-fails on the second occurrence of any key.
  `manage` appears three times. Upstream declares `manage` `multiple: true`
  (`space-permission.ts:217`; `:220` is that key's `default: []`).
- **`action` and `manage` co-present.** The same line `:243` demands
  `hasAction != hasManage`. Upstream carries both lists on every
  `SpacePermission` (`space-permission.ts:82-89`) and selects between them per
  match call (`:100-102`); the exclusivity Swan enforces at parse time does not
  exist upstream at any layer.
- **Remote clients may not register a `space:` scope at all.**
  `OAuthClientMetadata.validate()` computes
  `scopes.contains("atproto") || (isLocalhostDevelopmentClient && scopes.contains(where: PermissionedSpaceScopeSyntax.isIssuableQualified))`
  (`Sources/SwanOAuth/OAuthClientMetadata.swift:343-344`). An HTTPS client can
  carry bare `atproto` and nothing else. This is the gate `bulleted.app` hits
  *before* it ever hits the grammar; **retiring** it is part of this change, not
  a follow-up (§8, Stage C). "Retiring", not "lifting": `isIssuableQualified` is
  deleted as a semantic client-metadata gate rather than re-expressed over the
  new parser (§9-D21). Upstream validates `OAuthClientMetadata.scope` with
  `oauthScopeSchema` alone (`oauth-client-metadata.ts:36` →
  `oauth-scope.ts:17-19`) — a purely lexical RFC scope-token check with no
  dictionary of permission families. Registration grants nothing; the semantic
  work moves to PAR/authorize.

Two of the five are `include:` scopes, which Swan has no concept of at all —
grepping `Sources/` for `include:` scope handling and `permission-set` returns
nothing (positive control: the same grep for `"space:"` returns
`SwanCore.swift:199`, `:334`, and `SwanSpaces.swift:398`).

Swan's own doc comment already names the divergence as deliberate:
"the proposal's shorthand `space:<type>` is not accepted at this boundary. Swan
has no trusted generic issuer-side context from which to normalize it"
(`SwanCore.swift:161-165`). This spec supplies that context (§6.4, `self`
resolution at token mint) and removes the divergence.

**Done means:** `bulleted.app` completes discovery → registration → PAR →
consent → token mint → an authorized request against swan.place, and the **six**
enforcement outcomes in §7.4 Stage 6 hold. (The first draft said "four"; Stage 6
enumerates six checks, and the arithmetic is fixed here rather than in the test
section alone.)

"Consent" in that chain carries a **content** requirement, not merely a
completion one: a minimum semantic consent renderer is a precondition of an
unrestricted Stage C (§9-D19, §7.4 Stage 4). A flow that reaches token mint
through a page that renders raw scope strings only does not satisfy "done".

---

## 2. Global constraints

1. **Swift 6 strict concurrency.** Every new type is a `Sendable` value type.
   No `@unchecked`, anywhere. The decisive constraint is that
   `SpaceAuthorizationPolicy.require` / `.requireManagement`
   (`Sources/SwanSpaces/SwanSpaces.swift:237`, `:281` — `:280` is the closing
   doc-comment line) are **synchronous,
   non-isolated `throws`** functions called from inside the
   `SQLiteControlDatabase` actor's region (`Sources/SwanSQLite/SwanSQLite.swift:9272`,
   `:11628`, `:11647`, reached from the non-`async` helpers at `:11624-11652`).
   Anything the matcher needs must be synchronously available with no isolation
   hop. See §6.6 for the two things this rules out.
2. **4-space indent**, matching `Sources/`. One exception:
   `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift` is written with
   **2-space** indent (see `:255-270`). Match each file's local style.
   **Never run plain `swiftformat` on Swan** — it strips `: Sendable`, emits
   non-compiling code, and swallows `XCTUnwrap` failures. `swiftlint` where it
   applies.
3. **Module boundaries.** `Package.swift:76-82` declares `SwanCore` with
   dependencies `Crypto` + `Logging` only — no Swan-target dependencies.
   `SwanSpaces` (`Package.swift:107-114`) depends on `SwanCore`; `SwanSQLite`
   (`:124-131`) depends on `SwanStorage` → `SwanSpaces` → `SwanCore`;
   `SwanOAuth` (`:148-151`) depends on `SwanCore`, `SwanSpaces`, `SwanStorage`,
   `SwanAccounts`; `SwanHTTP` (`:170-176`) on all of them. The eleven existing
   call sites of the current grammar (`grep -rn "PermissionedSpaceScopeSyntax\." Sources/`)
   span **five** targets:

   | target | call site |
   |---|---|
   | SwanOAuth | `DurableOAuthTokenService.swift:1248`, `OAuthValidatedSession.swift:93`, `OAuthClientMetadata.swift:292,344,460` |
   | SwanHTTP | `SwanSpaceListXRPC.swift:81`, `SwanSpaceDelegationXRPC.swift:79`, `SwanOAuthResourceAuthorization.swift:208` |
   | SwanSQLite | `OAuthControlStore.swift:2354` |
   | SwanSpaces | `SwanSpaces.swift:315,360` |

   `SwanCore` is the only module all five share. **The grammar and the
   permission facade go in `SwanCore`** (§3, §9-D1).

   **Three further scope-string sites that the `PermissionedSpaceScopeSyntax.`
   grep does not find, and that this spec must still cover.** Each was missed by
   the first draft of this document; each is now assigned an owner below.

   | site | what it does | owner section |
   |---|---|---|
   | `Sources/swan/SwanCommand.swift:7206` | **Builds** a scope by raw interpolation: `"space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=\(action)"`, plus a conditional `&collection=\(collection)`. Four uncontrolled interpolations — exactly the hazard §4.2 exists to close. | §6.5.9 |
   | `Sources/SwanOAuth/OAuthClientMetadata.swift:453-465` (`localhostRequestedScopes`) | A **second wire tokenizer and a second issuance gate** on the localhost bridge: ≤ 64 tokens, ≤ 4096 bytes each, `$0 > 0x20 && $0 < 0x7F`, and `value == "atproto" \|\| isIssuableQualified(value)`. Called from `Sources/SwanHTTP/SwanOAuthPARHTTP.swift:307` and `Sources/SwanHTTP/SwanLocalhostOAuthHTTP.swift:598`. **The second issuance gate is deleted, not re-expressed** (§9-D21): A′ becomes tokenizer + raw-input budget only, matching stage A. | §6.3 stage A′, §6.4, §9-D21 |
   | `Sources/SwanHTTP/SwanLocalhostOAuthHTTP.swift:817-826` (`consentPage`) | A **second consent renderer**, independent of the authorization-server one, emitting its own `scopes.sorted()` `<li>` list (verified: `:819-821`, mirroring `SwanOAuthAuthorizationServerHTTP.swift:1170-1172`). It is the page the §7.1 acceptance harness actually drives, so the semantic-renderer obligation binds **both**. | §7.4 Stage 4, §9-D19 |
4. **No new dependencies.** No package added to `Package.swift`. No
   `URLComponents.queryItems` (it decodes `+` as `+`, not space, drops the
   positional/query duality, and offers no tri-state for repeated keys), no
   `addingPercentEncoding` (it emits `%20` where `URLSearchParams` emits `+`,
   breaking byte-equality with the reference).
5. **Upstream branch pin, and the complete tree.** All upstream citations are
   against `bluesky-social/atproto` branch `permissioned-data` @ `bddc99fb`.
   **Every package this grammar depends on is present at that pin**, and the
   full 3,383-file tree is what this document is now written against. Nothing in
   this spec is reconstructed from test vectors for want of a source.

   Concretely present, and each opened for this revision: `packages/did/src`
   (10 entries; `atproto.ts:230` defines `isAtprotoDidRefAbsolute`,
   `atproto.ts:19` fixes the method allow-list to `'plc' | 'web'`);
   `packages/lex/lex-resolver/src/lex-resolver.ts` (577 L, the real resolver);
   `packages/lexicon-resolver` (a second resolver package); `packages/pds/src`
   (285 `.ts` files — 346 is the whole package including tests and tooling; 67 `authorize:` route callbacks; `permissions.assertRpc`×15,
   `assertRepo`×5, `assertIdentity`×4, `assertAccount`×2, `assertSpace`×2 plus
   the shared helper at `api/com/atproto/space/util.ts:87-100`);
   `packages/space/src` (`credential.ts`, `dpop.ts`, `error.ts`, `repo-commit.ts`,
   `lthash.ts`, `sync/`, `types.ts`, `util.ts`);
   `packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx`
   (1287 L, the consent renderer); `packages/oauth/oauth-types/src/oauth-scope.ts`
   (`OAUTH_SCOPE_REGEXP` at `:5-6`, `oauthScopeSchema` at `:17-19`).

   **Why the first draft said otherwise — recorded so a reader of the old
   version can follow.** That draft was written against a *reference export*
   containing three subtrees only (`oauth-scopes`, `syntax/src`,
   `oauth-provider/src`); its "positive controls" (`ls .../packages/did/src`
   errors; `find .../packages -iname '*lex-resolver*'` → zero;
   `grep -rn 'ScopePermissions\b'` outside `oauth-scopes` → zero) were run
   *inside that constructed directory* and so confirmed the absence of files
   that had never been copied into it — an absence proof with no positive
   control over the search domain itself. The rule that follows: **a positive
   control must prove the search domain contains the thing it would find, not
   merely that the query is well-formed.** Every downstream "absent",
   "reconstructed", "inferred", "no upstream model", and "no reference
   implementation to port" clause inherited its authority from this constraint
   and has been re-derived; the corrections land in §4.1 and §5.7.4 (grammar and
   resolver), §6.3 and the §6 route-mapping table (enforcement), §6.8
   (credential binding), §7.4 Stage 4 (consent), and §9.1 D13-D21.
6. **No plain `swift build`.** A custom default toolchain wedges SwiftPM. Use
   `xcrun --toolchain XcodeDefault swift build --product swan` (§7.6).

---

## 3. Architecture: modules, types, ownership

```
Sources/SwanCore/OAuthScopes/
    AtprotoSyntax.swift             // TWO DID validators, deliberately separate (§9-D13):
                                    //   isValidDID                     — permissive @atproto/syntax DID (syntax/src/did.ts:51),
                                    //                                    used by SpaceURI and by space?authority=
                                    //   isValidAtprotoDIDRefAbsolute   — strict port of @atproto/did (atproto.ts:230-234):
                                    //                                    method ∈ {plc, web}, did:web path refused, exactly one
                                    //                                    '#', RFC3986 fragment. Used by rpc/include aud=.
                                    // plus shared NSID / record-key validators
    ScopeToken.swift                // RFC 6749 §3.3 scope-token wrapper
    ScopeParseError.swift           // the closed error enum
    ScopeStringSyntax.swift         // lexical layer: prefix / positional / bag
    ScopeParameterBag.swift         // ordered multimap + tri-state lookup
    ScopeParameterSchema.swift      // upstream Parser<P,S> analogue: parse + format
    ScopePermission.swift           // protocol + AtprotoScope enum
    Families/AccountPermission.swift
    Families/BlobPermission.swift
    Families/IdentityPermission.swift
    Families/IncludeScope.swift
    Families/RepoPermission.swift
    Families/RpcPermission.swift
    Families/SpacePermission.swift
    ScopePermissions.swift          // SwanScopePermissions facade + the six targets
Sources/SwanSpaces/
    SpaceScopeTargets.swift         // SpaceURI/SpaceRecordURI ergonomic overloads (new)
Sources/SwanOAuth/
    OAuthScopeAdmissionPolicy.swift // PAR/authorize ADMISSION, over PARSED values. NOT a
                                    // registration-time shape policy: registration is lexical +
                                    // budget only and grants nothing (§9-D21)
    OAuthScopeErrorMapping.swift    // ScopeParseError -> RFC 6749 error code
    OAuthProofValidation.swift      // + OAuthIssuanceDPoPProofValidator (§6.5)
```

Ownership, stated once:

| Layer | Owns | Does not own |
|---|---|---|
| `ScopeStringSyntax` | bytes → prefix / positional / ordered pairs; percent-decoding | which keys exist, what they mean |
| `ScopeParameterSchema` | declared keys, arity, required, defaults, validation, canonical order | family semantics |
| the seven family types | matching, normalization, `scopeNeededFor` | I/O, policy, storage |
| `SwanScopePermissions` | "may this token do X", once per request, synchronously | parsing policy, error codes |
| `SwanOAuth` policy types | which shapes Swan will *issue*, which errors reach the wire, `self` resolution, DPoP | matching |
| `SwanSpaces` / `SwanSQLite` call sites | constructing targets from domain values | scope grammar |

**Match targets are plain value structs of `String`s** (`SpaceScopeTarget`,
`RepoScopeTarget`, …), declared in `SwanCore` — **not** `SpaceURI`, which lives
in `SwanSpaces` (`SwanSpaces.swift:39-103`) and would invert the dependency. A
thin `SwanSpaces` extension supplies the ergonomic `SpaceURI` /
`SpaceRecordURI` overloads (§6.2).

**The request-time path cannot name a network fetcher — and this is now more
load-bearing, not less.** `SwanCore` does not import `SwanOAuth`, so
`SwanLexiconResolving` and `OAuthRemoteDocumentFetcher` are unreachable from the
matcher. An accidental request-time fetch fails to compile rather than silently
adding a network hop to every authorized request (§9-D8).

Under §9-D14 the Phase-2 resolver is a port of
`packages/lex/lex-resolver/src/lex-resolver.ts`, whose trust path is not a JSON
fetch but a CAR read plus commit-signature verification plus an MST membership
walk (`lex-resolver.ts:529-546`). So the module fence now excludes not one
network hop but a network hop **and** CBOR/CAR parsing **and** signature
verification from every authorized request. A future reader tempted to relax the
fence "just to cache one document" is relaxing it on a path that would also drag
in crypto (§6.9).

---

## 4. The grammar layer

### 4.1 Shared validators (kills the third copy)

> **Pointer for readers of an earlier version:** §9.2's open question **Q1**
> ("`isAtprotoDidRefAbsolute` is reconstructed, not sourced") is **closed**. The
> package is present at the pin (`packages/did/`), the reconstruction is
> rejected, and the ported grammar, Swift, and upstream vectors live in this
> section. §9.1 carries the decision.

Swan has three near-duplicate DID/NSID/record-key validators today:
`SwanCore.swift:399-424`, `SwanSpaces.swift:77-102`, and
`SwanSpaces.swift:397+` (`scopeType` / `strictQueryParameters`). One home:

```swift
/// AT Protocol identifier syntax shared by the scope grammar and the space
/// resource domain. Three near-identical private copies existed before this
/// (SwanCore.swift:399-424, SwanSpaces.swift:77-102, SwanSpaces.swift:397+);
/// a scope grammar that disagrees with the resource matcher about what a DID
/// is turns a parse into an authorization difference.
public enum AtprotoSyntax {
    /// syntax/src/did.ts:51, :67-70 — length <= 2048 and
    /// `^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$`.
    /// STRICTER than Swan's current SpaceURI.isValidDID (SwanSpaces.swift:77-82),
    /// which accepts a trailing `:` and a method containing digits/uppercase.
    /// `space:*?authority=did:` must be nil (space-permission.test.ts:91).
    ///
    /// THIS FUNCTION IS NOT MUTATED BY THE Q1 RULING. It is the permissive,
    /// method-AGNOSTIC `@atproto/syntax` DID, and it is the correct validator
    /// for `space:?authority=` (§5.6.2) and for `SpaceURI`. The strict,
    /// atproto-constrained DID reference is a SEPARATE function
    /// (`isValidAtprotoDIDRefAbsolute`, below) — never fold the two together.
    ///
    /// The two are different sides of the matcher, and conflating them is the
    /// specific error Josh's Q1 ruling names. A did-ref that appears as a
    /// REQUEST TARGET (the `aud` of the call being authorized, supplied by the
    /// resource plane) is validated by the generic grammar; a did-ref that
    /// appears as an `aud=` value INSIDE A GRANT is validated by the atproto
    /// grammar, because a grant is minted once and replayed forever. Upstream
    /// keeps the same split: `isDidRefAbsolute` (`packages/did/src/did-ref.ts:11-18`)
    /// is method-agnostic and `isAtprotoDidRefAbsolute`
    /// (`packages/did/src/atproto.ts:230-235`) re-checks the did-part against
    /// `isAtprotoDid` as an independent second pass (`atproto.ts:233`).
    ///
    /// One correction to the comment this doc replaced: it claimed Swan's
    /// current validator wrongly "accepts … a method containing digits/uppercase".
    /// Upstream's real method grammar (`packages/did/src/did.ts:86-116`,
    /// charcodes 0x61-0x7A and 0x30-0x39 only) is lowercase-alnum — digits ARE
    /// legal in a method name, uppercase is not. Swan is too loose on uppercase
    /// only.
    public static func isValidDID(_ value: String) -> Bool

    /// Re-derived from syntax/src/nsid.ts:86-118, NOT copied from SpaceURI.
    /// Total <= 317 bytes (nsid.ts:87), each segment <= 63, >= 3 segments.
    /// Three divergences from Swan's current SpaceURI.isValidNSID
    /// (SwanSpaces.swift:83-93), all resolved in upstream's favour (§9-D3):
    ///   com.example.foo-bar  upstream REJECT (last segment is a "name" and may
    ///                        not contain "-", nsid.ts:112-117) / Swan accepts
    ///   com.example-.foo     upstream REJECT (no segment ends in "-", :104-106)
    ///                        / Swan accepts
    ///   com.9example.foo     upstream ACCEPT (only segment 0 may not start with
    ///                        a digit, :109-111) / Swan rejects
    public static func isValidNSID(_ value: String) -> Bool

    /// 1...512 bytes, not "." or "..", charset alnum + `-._:~`.
    /// SwanCore.swift:418-424 and SpaceURI.isValidRecordKey (SwanSpaces.swift:95-102)
    /// BOTH already agree with upstream here: they accept exactly
    /// space-permission.test.ts:114-126 (`self`, `3jui7kd54zh2y`, `a.b-c_d~e:f`,
    /// 512x`x`) and reject exactly :128-143 (`hello world`, `.`, `..`, `a/b`,
    /// `a#b`, 513x`x`). Keep the behaviour, delete the duplicates.
    public static func isValidRecordKey(_ value: String) -> Bool

    /// Generic, method-AGNOSTIC absolute DID reference. Ported byte-for-byte
    /// from `packages/did/src/did-ref.ts:11-18`:
    ///   1. exactly one `#` — `:14` rejects "no `#`", `:16` rejects a second
    ///      `#` anywhere after the first (`value.includes('#', hashIndex + 1)`);
    ///   2. the fragment is NON-EMPTY — `:15`, `hashIndex === value.length - 1`;
    ///   3. the fragment satisfies RFC 3986 §3.5 `fragment = *( pchar / "/" / "?" )`
    ///      — `isFragment`, `packages/did/src/lib/uri.ts:5-59`;
    ///   4. the did-part satisfies the generic `isDid` (`did.ts:233-245`).
    /// Use this wherever a did-ref is a REQUEST TARGET.
    public static func isValidDIDRefAbsolute(_ value: String) -> Bool

    /// The ATPROTO-CONSTRAINED absolute DID reference — a DID whose method is
    /// `plc` or `web`, plus a MANDATORY non-empty RFC 3986 fragment. This is the
    /// validator `rpc:`'s and `include:`'s `aud=` use (`rpc-permission.ts:25-27`,
    /// `include-scope.ts:16`).
    ///
    /// PORTED, NOT RECONSTRUCTED. The definition is
    /// `packages/did/src/atproto.ts:230-235`:
    ///   `isDidRefAbsolute(value) && isAtprotoDid(value.slice(0, value.indexOf('#')))`
    /// — two independent passes, not one fused predicate. The atproto layer is a
    /// second tightening pass over an already-validated generic did-ref, and the
    /// Swift port must keep that shape so the two functions stay separately
    /// testable.
    ///
    /// `isAtprotoDid` (`atproto.ts:27-29`) is `isDidPlc(input) || isAtprotoDidWeb(input)`:
    ///
    ///   * **The method allow-list is MANDATORY**, contradicting the first
    ///     draft's "Do NOT hard-code a method allow-list". Upstream hard-codes it
    ///     as a TypeScript union — `AtprotoIdentityDidMethods = 'plc' | 'web'`
    ///     (`atproto.ts:19`) — not as a config parameter, and rejects everything
    ///     else with `Atproto only allows "plc" and "web" DID methods`
    ///     (`atproto.ts:25`). `did:foo:bar#baz` is a VALID generic did-ref and an
    ///     INVALID atproto did-ref (`packages/did/tests/did-ref.test.ts:37`).
    ///     The first draft's `isValidDID(didPart) && …` accepts it. That is the
    ///     security-relevant direction of the divergence: strictly wider than
    ///     upstream on DID method, in an `aud=` grant value.
    ///   * `did:plc:` is FIXED LENGTH — exactly 32 characters total, of which the
    ///     24 after the 8-char `did:plc:` prefix are base32 `[a-z2-7]`
    ///     (`packages/did/src/methods/plc.ts:6`, `:10-19`, `isBase32Char` at `:53-54`).
    ///     There is no variable MSID grammar at all. `did:plc:111` fails on BOTH
    ///     counts — length and charset.
    ///   * `did:web:` is generic `isDidWeb` (`methods/web.ts:10-23`) PLUS two
    ///     atproto-only exclusions (`atproto.ts:74-88`):
    ///       - **no path component** — any `:` after the `did:web:` prefix
    ///         (`isDidWebWithPath`, `atproto.ts:90-92`). `did:web:example.com:admin`
    ///         is a valid GENERIC did:web (`tests/methods/web.test.ts:16-18`) and
    ///         an invalid ATPROTO did:web. A reconstruction built from
    ///         `isValidDID` alone accepts it;
    ///       - **no https port**, except localhost — `isDidWebWithHttpsPort` /
    ///         `isLocalhostDid`, `atproto.ts:94-116`. `%3A` (encoded `:`) before
    ///         any path separator is a port. `did:web:localhost%3A8080` stays
    ///         legal, which is what keeps a local dev PDS usable.
    ///
    /// PURE AND SYNCHRONOUS, like every other member of `AtprotoSyntax` — it is
    /// a byte scan with no allocation beyond the input and no I/O, so it is
    /// reachable from the value types §6.9 lists as needing no actor.
    public static func isValidAtprotoDIDRefAbsolute(_ value: String) -> Bool

    /// `atproto.ts:27-29`. Exposed separately because the atproto DID constraint
    /// is meaningful without a fragment (it is what `isValidAtprotoDIDRefAbsolute`
    /// applies to the did-part).
    public static func isValidAtprotoDID(_ value: String) -> Bool
}
```

**The fragment grammar, written out**, because "a non-empty valid service id"
was the first draft's placeholder and it never pinned a charset. Upstream's
`isFragment` (`packages/did/src/lib/uri.ts:5-59`) is an explicit charcode scan,
not a regex, admitting:

| class | bytes | uri.ts |
|---|---|---|
| unreserved | `A-Z` `a-z` `0-9` `-` `.` `_` `~` | `:20-27` |
| sub-delims | `!` `$` `&` `'` `(` `)` `*` `+` `,` `;` `=` | `:28-41` |
| pchar extra | `:` `@` | `:42-43` |
| fragment extra | `/` `?` | `:44-45` |
| pct-encoded | `%` + exactly two hex digits; truncated or non-hex → **false** | `:46-51` (`isHexDigit`, `:61-67`) |
| anything else | → **false** | `:52-54` |

**Emptiness is the CALLER's job, and getting this wrong silently accepts
`did:plc:…#`.** `isFragment(v, n, n)` over an empty range loops zero times and
returns `true` (`uri.ts:11`, `:57`). The empty-fragment rejection lives one level
up, in `isDidRefAbsolute` (`did-ref.ts:15`). Any Swift port that inlines the
scan without re-adding the caller-side check admits an empty fragment.

```swift
extension AtprotoSyntax {
    /// Ported from `packages/did/src/lib/uri.ts:5-59`. Operates on a UTF-8 byte
    /// slice so the charcode comparisons are literal transcriptions of upstream's
    /// `charCodeAt` switch rather than Character-level approximations.
    /// The caller MUST separately reject an empty range — see `did-ref.ts:15`.
    static func isFragment(_ value: [UInt8], from start: Int, to end: Int) -> Bool {
        var i = start
        while i < end {
            switch value[i] {
            case 0x41...0x5A, 0x61...0x7A, 0x30...0x39,
                 0x2D, 0x2E, 0x5F, 0x7E:                       // unreserved, uri.ts:20-27
                break
            case 0x21, 0x24, 0x26, 0x27, 0x28, 0x29,
                 0x2A, 0x2B, 0x2C, 0x3B, 0x3D:                 // sub-delims, uri.ts:28-41
                break
            case 0x3A, 0x40:                                   // ":" "@", uri.ts:42-43
                break
            case 0x2F, 0x3F:                                   // "/" "?", uri.ts:44-45
                break
            case 0x25:                                         // "%", uri.ts:46-51
                guard i + 2 < end,
                      isHexDigit(value[i + 1]),
                      isHexDigit(value[i + 2]) else { return false }
                i += 2
            default:
                return false                                   // uri.ts:52-54
            }
            i += 1
        }
        return true
    }

    /// uri.ts:61-67.
    private static func isHexDigit(_ c: UInt8) -> Bool {
        (0x30...0x39).contains(c) || (0x41...0x46).contains(c) || (0x61...0x66).contains(c)
    }

    /// did-ref.ts:11-18.
    public static func isValidDIDRefAbsolute(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard let hash = bytes.firstIndex(of: 0x23) else { return false }   // :14 no '#'
        guard hash != bytes.count - 1 else { return false }                 // :15 empty fragment
        guard !bytes[(hash + 1)...].contains(0x23) else { return false }    // :16 second '#'
        guard isFragment(bytes, from: hash + 1, to: bytes.count) else { return false } // :17
        return isValidDID(String(decoding: bytes[..<hash], as: UTF8.self))  // :17 isDid
    }

    /// atproto.ts:230-235. A SEPARATE function; `isValidDID` is untouched.
    public static func isValidAtprotoDIDRefAbsolute(_ value: String) -> Bool {
        guard isValidDIDRefAbsolute(value) else { return false }
        let bytes = Array(value.utf8)
        guard let hash = bytes.firstIndex(of: 0x23) else { return false }
        return isValidAtprotoDID(String(decoding: bytes[..<hash], as: UTF8.self))
    }

    /// atproto.ts:27-29.
    public static func isValidAtprotoDID(_ value: String) -> Bool {
        if value.hasPrefix("did:plc:") { return isValidDIDPlc(value) }
        if value.hasPrefix("did:web:") { return isValidAtprotoDIDWeb(value) }
        return false                                   // atproto.ts:19 — plc | web, closed set
    }

    /// plc.ts:10-19. Length-and-charset only; no MSID grammar.
    private static func isValidDIDPlc(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 32 else { return false }              // plc.ts:6, :13
        guard value.hasPrefix("did:plc:") else { return false }     // plc.ts:14
        for i in 8..<32 {                                           // plc.ts:15-17
            let c = bytes[i]
            guard (0x61...0x7A).contains(c) || (0x32...0x37).contains(c) else { return false }
        }                                                           // isBase32Char, plc.ts:53-54: a-z 2-7
        return true
    }

    /// atproto.ts:74-88 layered on web.ts:10-23.
    private static func isValidAtprotoDIDWeb(_ value: String) -> Bool {
        guard isValidDIDWeb(value) else { return false }            // atproto.ts:75-77
        guard !didWebHasPath(value) else { return false }           // atproto.ts:79-81 / :90-92
        guard !didWebHasHTTPSPort(value) else { return false }      // atproto.ts:83-85 / :102-116
        return true
    }

    /// atproto.ts:90-92 — ANY `:` after the 8-byte `did:web:` prefix is a path.
    private static func didWebHasPath(_ did: String) -> Bool {
        did.dropFirst(8).contains(":")
    }

    /// atproto.ts:94-116. Localhost is exempt (`:95-100`), so a dev PDS at
    /// `did:web:localhost%3A8080` stays valid.
    private static func didWebHasHTTPSPort(_ did: String) -> Bool {
        if did == "did:web:localhost"
            || did.hasPrefix("did:web:localhost:")
            || did.hasPrefix("did:web:localhost%3A") { return false }   // :95-100
        let tail = did.dropFirst(8)
        guard let pathIdx = tail.firstIndex(of: ":") else {
            // No path component: an encoded colon anywhere after the prefix is
            // a port. atproto.ts:105, :107-111.
            return tail.contains("%3A")
        }
        // There is a path component: an encoded colon BEFORE it is a port.
        // atproto.ts:112-114 (`did.lastIndexOf('%3A', pathIdx) !== -1`).
        return tail[..<pathIdx].range(of: "%3A", options: .backwards) != nil
    }
}
```

`isValidDIDWeb` ports `methods/web.ts:10-23` (prefix, no leading `:` at
`web.ts:13`, `assertDidMsid` over the remainder, URL-parseability of the rebuilt
`https://` URL) and is omitted here only for length — same byte-scan style, no
regex.

**Upstream vectors — `packages/did/tests/did-ref.test.ts:4-41`, ported whole.**
These are the vectors the first draft could not see and therefore guessed at.

| input | `isValidAtprotoDIDRefAbsolute` | cite |
|---|---|---|
| `did:plc:l3rouwludahu3ui3bt66mfvj#atproto` | **true** | `:6-8` |
| `did:web:example.com#service_id` | **true** | `:9` |
| `did:web:example.com#atproto_label` | **true** | `:10-12` |
| `did:plc:l3rouwludahu3ui3bt66mfvj` (bare DID, no `#`) | false | `:16-18` |
| `did:web:example.com` (bare DID, no `#`) | false | `:19` |
| `#atproto` (relative ref, no DID part) | false | `:23` |
| `""` | false | `:27` |
| `did:plc:l3rouwludahu3ui3bt66mfvj#` (empty fragment) | false | `:28-30` |
| `did:plc:l3rouwludahu3ui3bt66mfvj##foo` (second `#`) | false | `:31-33` |
| `did:plc:l3rouwludahu3ui3bt66mfvj#a#b` (second `#`) | false | `:34-36` |
| `did:foo:bar#baz` (method not `plc`/`web`) | false | `:37` |
| non-string (`null`, `123`) | false — Swift's type system already excludes these; keep the row so the count matches upstream | `:38-39` |

Three vectors upstream proves elsewhere and this port must also carry, because
they are the ones the reconstruction gets wrong and `did-ref.test.ts` does not
cover:

| input | expected | why |
|---|---|---|
| `did:web:example.com:admin#atproto` | **false** | `did:web:example.com:path:to:resource` is an explicitly VALID generic did:web (`tests/methods/web.test.ts:15-18`); atproto rejects it via `isDidWebWithPath` (`atproto.ts:90-92`) |
| `did:web:localhost%3A8080#atproto` | **true** | localhost port exemption, `isLocalhostDid`, `atproto.ts:94-100` |
| `did:web:example.com%3A8443#atproto` | **false** | `did:web:example.com%3A8080` is an explicitly VALID generic did:web (`tests/methods/web.test.ts:14`); atproto rejects the non-localhost https port via `isDidWebWithHttpsPort` (`atproto.ts:102-117`) |

These three are the whole reason the ruling says "port exactly": every one of
them is a case where the generic grammar and the atproto grammar disagree, and
the first draft's `isValidDID(didPart)` reconstruction lands on the generic —
i.e. the permissive — side of all three.

`SpaceURI`'s private validators (`SwanSpaces.swift:77-102`) are re-pointed at
`AtprotoSyntax`. **This makes `SpaceURI` stricter about NSIDs and DIDs than it
is today**, so a persisted space URI with a hyphenated final NSID segment or a
trailing-colon DID would newly fail to parse. Audit before cutover (§8, step 1).

### 4.2 `ScopeToken` — the RFC 6749 §3.3 gate

The Rust reference calls this load-bearing, not cosmetic
(`atproto-oauth/src/scopes.rs:1040-1061`): anything that builds a scope by
interpolating a value it did not choose must check the token charset, or "a
field that reads as a name is free to append a second grant to it."

```swift
/// A single RFC 6749 §3.3 `scope-token`:
///   scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// SP terminates a token, and `"` / `\` are excluded so a grant survives being
/// carried inside a quoted string. Every serialiser output and every value
/// interpolated into a scope passes through here — mirrors scopes.rs:1055-1061.
public struct ScopeToken: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String

    public init?(_ rawValue: String) {
        guard Self.isScopeToken(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    public static func isScopeToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { byte in
            byte == 0x21 || (0x23...0x5b).contains(byte) || (0x5d...0x7e).contains(byte)
        }
    }

    public var description: String { rawValue }
}
```

Swan's existing wire parser (`SwanOAuthAuthorizationServerHTTP.swift:1059-1069`)
uses `$0 > 0x20 && $0 < 0x7F`, which **admits `"` (0x22) and `\` (0x5C)** that
RFC 6749 excludes. Tightening it to `ScopeToken.isScopeToken` is a strict
narrowing of an existing accept set and lands in the same change.

### 4.3 Parameter bag — the tri-state lookup

Upstream distinguishes `undefined` (key absent) from `null` (key present but
structurally invalid): `lib/syntax-string.ts:18-23` returns `null` when
`getSingle` finds more than one value; `lib/parser.ts:121-122` rejects on
`null` while `:142-156` treats `undefined` as "fall through to positional, then
default". Collapsing both into Swift's `String?` silently turns
`space:x?skey=a&skey=b` from *reject* into *use the default*.

```swift
/// Insertion-ordered multimap over a scope's query string.
///
/// Order is load-bearing: canonical serialisation is *schema-declaration*
/// order, never alphabetical (parser.ts:54 iterates `schemaKeys`, a `Set`
/// built from `Object.keys(schema)`; nothing in `format`/`toString` sorts).
/// A Swift `Dictionary` would randomise that, so the storage is an array.
public struct ScopeParameterBag: Sendable, Hashable {
    public struct Entry: Sendable, Hashable {
        public let key: String
        public let value: String
        public init(key: String, value: String) { self.key = key; self.value = value }
    }

    /// The three states mirror upstream's `undefined | value | null` convention
    /// exactly (syntax-string.ts:18-23): `.repeated` means "present but
    /// malformed", never "absent".
    public enum SingleLookup: Sendable, Hashable {
        case absent
        case present(String)
        case repeated([String])
    }

    public private(set) var entries: [Entry]

    public init(_ entries: [Entry] = []) { self.entries = entries }

    public var isEmpty: Bool { entries.isEmpty }

    /// Distinct keys in first-appearance order (syntax-string.ts:14-16).
    public func orderedKeys() -> [String] {
        var seen = Set<String>()
        return entries.compactMap { seen.insert($0.key).inserted ? $0.key : nil }
    }

    public func values(for key: String) -> [String] {
        entries.lazy.filter { $0.key == key }.map(\.value)
    }

    public func single(_ key: String) -> SingleLookup {
        let found = values(for: key)
        switch found.count {
        case 0: return .absent
        case 1: return .present(found[0])
        default: return .repeated(found)
        }
    }

    /// `nil` when absent; `[]` is never produced by the parser but is a legal
    /// programmatic value that the schema rejects (parser.ts:131).
    public func multiple(_ key: String) -> [String]? {
        let found = values(for: key)
        return found.isEmpty ? nil : found
    }

    public mutating func append(key: String, value: String) {
        entries.append(Entry(key: key, value: value))
    }

    public mutating func set(key: String, value: String) {
        entries.removeAll { $0.key == key }
        entries.append(Entry(key: key, value: value))
    }
}
```

### 4.4 Scope string syntax

Direct port of `syntax-string.ts:44-75` with `minIdx` (`util.ts:5-9`) inlined.

**Percent-decoding is NOT symmetric upstream, and the first draft of this spec
got it wrong in a way that rejects scopes upstream accepts.** Verified at
`syntax-string.ts:62-64` and `:71`:

| position | upstream decoder | behaviour on a malformed `%` |
|---|---|---|
| positional | `decodeURIComponent(...)` | **throws `URIError`**, uncaught |
| query string | `new URLSearchParams(...)` | **never throws** — the `application/x-www-form-urlencoded` parser leaves an invalid `%` sequence as literal bytes and maps invalid UTF-8 to U+FFFD |

Swan must reproduce both halves:

- **Positional:** `%zz` is a typed `.malformedPercentEncoding` throw (upstream's
  `URIError`, made typed).
- **Query:** a malformed `%` sequence is **passed through as literal bytes** and
  invalid UTF-8 becomes U+FFFD. It does **not** throw. The value then either
  fails its family's `validate` (and the scope is rejected for *that* reason) or
  is legal, exactly as upstream.

This matters because `%` is in the DID charset (`syntax/src/did.ts:51`,
`[a-zA-Z0-9._:%-]`). `space:*?authority=did:web:ex%ample.com` parses upstream and
would throw under a symmetric-strict decoder — and under §9-D5 a throw at PAR is
a hard `invalid_scope` rejection of the whole request, i.e. precisely the interop
failure this change exists to remove. `decodeFormComponent` below therefore takes
a lossy path and `decodeURIComponent` a throwing one; **do not unify them.**

```swift
/// Lexical decomposition of a scope string:
///   scope = prefix [ ":" positional ] [ "?" query ]
/// Positional runs to the first `?`; everything after the *first* `?` is one
/// query string, so a literal `?` inside a value belongs to the preceding
/// value rather than starting a new pair (syntax-string.test.ts:36-42). A later
/// `#` is likewise a literal — this is a query string, not a URL, so there is
/// no fragment (include-scope.test.ts:32-39).
public struct ScopeStringSyntax: Sendable, Hashable {
    public let prefix: String
    /// `nil` = no `:` segment. `""` is legal and distinct: `"my-res:"` parses
    /// to an empty positional (syntax-string.test.ts:16-18). Load-bearing —
    /// it is why `"rpc:?aud=…"` is rejected for an INVALID (empty) `lxm`
    /// rather than for a missing one (rpc-permission.test.ts:53-55).
    public let positional: String?
    public let parameters: ScopeParameterBag

    public init(prefix: String, positional: String? = nil, parameters: ScopeParameterBag = .init()) {
        self.prefix = prefix
        self.positional = positional
        self.parameters = parameters
    }

    // MARK: parse

    public static func parse(_ scope: String) throws(ScopeParseError) -> ScopeStringSyntax {
        guard ScopeToken.isScopeToken(scope) else { throw .notAScopeToken(scope) }

        let bytes = Array(scope.utf8)
        let questionIdx = bytes.firstIndex(of: 0x3f)   // "?"
        let colonIdx = bytes.firstIndex(of: 0x3a)      // ":"

        // util.ts:5-9 minIdx — min of the two, ignoring "absent".
        let prefixEnd: Int? = switch (colonIdx, questionIdx) {
        case (nil, nil): nil
        case let (value?, nil): value
        case let (nil, value?): value
        case let (a?, b?): Swift.min(a, b)
        }

        guard let prefixEnd else {
            return ScopeStringSyntax(prefix: scope)
        }

        let prefix = String(decoding: bytes[..<prefixEnd], as: UTF8.self)

        // syntax-string.ts:58-66: a positional exists only when `:` precedes `?`.
        var positional: String?
        if let colonIdx {
            if let questionIdx {
                if colonIdx < questionIdx {
                    positional = try decodeURIComponent(bytes[(colonIdx + 1) ..< questionIdx], in: scope)
                }
            } else {
                positional = try decodeURIComponent(bytes[(colonIdx + 1)...], in: scope)
            }
        }

        // syntax-string.ts:68-72: an empty query (`"x?"`) yields no params at all.
        var parameters = ScopeParameterBag()
        if let questionIdx, questionIdx < bytes.count - 1 {
            parameters = parseQueryString(bytes[(questionIdx + 1)...])
        }

        return ScopeStringSyntax(prefix: prefix, positional: positional, parameters: parameters)
    }

    /// `application/x-www-form-urlencoded` decoding, matching `URLSearchParams`:
    /// split on `&`, split each pair on the FIRST `=`, `+` decodes to SPACE,
    /// `%XX` decodes bytewise. A pair with no `=` yields an empty value; an
    /// empty pair (from `a=1&&b=2`) is SKIPPED, matching URLSearchParams and
    /// NOT SwanCore.swift:218-227, which rejects it (vector D10, §7.3).
    /// NON-THROWING by design — see the decoder table above.
    private static func parseQueryString(_ bytes: ArraySlice<UInt8>) -> ScopeParameterBag {
        var bag = ScopeParameterBag()
        for pair in bytes.split(separator: 0x26, omittingEmptySubsequences: true) {   // "&"
            let split = pair.split(separator: 0x3d, maxSplits: 1, omittingEmptySubsequences: false) // "="
            let key = decodeFormComponent(split[0])
            let value = split.count > 1 ? decodeFormComponent(split[1]) : ""
            bag.append(key: key, value: value)
        }
        return bag
    }

    /// `URLSearchParams` semantics: LOSSY, never throws (syntax-string.ts:71).
    /// A malformed `%` sequence survives as literal bytes; invalid UTF-8 becomes
    /// U+FFFD. See the table above for why this must NOT be the strict decoder.
    private static func decodeFormComponent(_ bytes: ArraySlice<UInt8>) -> String {
        let folded = bytes.map { $0 == 0x2b ? 0x20 : $0 }[...]   // "+" -> SP
        return lossyPercentDecode(folded)
    }

    /// `decodeURIComponent` semantics: STRICT, throws (syntax-string.ts:62-64).
    /// Used for the positional segment only. No `+` folding outside a query.
    private static func decodeURIComponent(
        _ bytes: ArraySlice<UInt8>, in scope: String
    ) throws(ScopeParseError) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let byte = bytes[index]
            if byte == 0x25 {   // "%"
                let high = bytes.index(index, offsetBy: 1, limitedBy: bytes.endIndex - 1)
                let low = bytes.index(index, offsetBy: 2, limitedBy: bytes.endIndex - 1)
                guard let high, let low,
                      let hi = hexValue(bytes[high]), let lo = hexValue(bytes[low])
                else { throw .malformedPercentEncoding(scope) }
                out.append(hi << 4 | lo)
                index = bytes.index(index, offsetBy: 3)
            } else {
                out.append(byte)
                index = bytes.index(after: index)
            }
        }
        guard let decoded = String(bytes: out, encoding: .utf8) else {
            throw .malformedPercentEncoding(scope)
        }
        return decoded
    }

    private static func lossyPercentDecode(_ bytes: ArraySlice<UInt8>) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let byte = bytes[index]
            if byte == 0x25,
               let high = bytes.index(index, offsetBy: 1, limitedBy: bytes.endIndex - 1),
               let low = bytes.index(index, offsetBy: 2, limitedBy: bytes.endIndex - 1),
               let hi = hexValue(bytes[high]), let lo = hexValue(bytes[low]) {
                out.append(hi << 4 | lo)
                index = bytes.index(index, offsetBy: 3)
            } else {
                // Literal `%` (or a truncated / non-hex escape) passes through
                // verbatim — URLSearchParams does not reject it.
                out.append(byte)
                index = bytes.index(after: index)
            }
        }
        // `String(decoding:as:)` substitutes U+FFFD, matching the WHATWG URL
        // spec's UTF-8 decode-without-BOM-or-fail behaviour. Never nil.
        return String(decoding: out, as: UTF8.self)
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    // MARK: prefix matching — syntax.ts:16-33

    /// True iff `value` names this prefix: exact match, or prefix followed by
    /// `:` or `?`. Rejects superstring false positives such as
    /// `isScopeString("prefixes", for: "prefix")` (syntax.test.ts:32-42).
    /// This is what makes the seven prefixes disjoint and the dispatcher in
    /// §4.7 safe.
    public static func isScopeString(_ value: String, for prefix: String) -> Bool {
        let value = Array(value.utf8), prefix = Array(prefix.utf8)
        guard value.count > prefix.count else { return value == prefix }
        let next = value[prefix.count]
        guard next == 0x3a || next == 0x3f else { return false }
        return value.starts(with: prefix)
    }
}
```

### 4.5 Canonical serialiser — two encoders that must not be unified

`syntax-string.ts:30-42` uses `encodeURIComponent` for the positional and
`URLSearchParams.toString()` for the query, then folds **both** through
`normalizeURIComponent` (`:82-132`), which un-escapes exactly `: / + , @ %`
(`ALLOWED_SCOPE_CHARS`, `:85`) and nothing else — never `?` or `&`, by explicit
comment (`:83-84`).

| position | kept raw | space | everything else |
|---|---|---|---|
| positional | `A-Za-z0-9` `!'()*-._~` plus `:` `/` `+` `,` `@` `%` | `%20` | uppercase `%XX` |
| query value | `A-Za-z0-9` `*-._` plus `:` `/` `+` `,` `@` `%` | `+` | uppercase `%XX` |

```swift
extension ScopeStringSyntax {
    /// Canonical wire form. syntax-string.ts:30-42.
    public func canonicalString() throws(ScopeParseError) -> String {
        var scope = prefix
        if let positional {
            scope += ":" + Self.normalizeAllowedChars(Self.encodeURIComponent(positional))
        }
        if !parameters.isEmpty {
            let query = parameters.entries
                .map { Self.encodeFormComponent($0.key) + "=" + Self.encodeFormComponent($0.value) }
                .joined(separator: "&")
            scope += "?" + Self.normalizeAllowedChars(query)
        }
        guard ScopeToken.isScopeToken(scope) else { throw .notAScopeToken(scope) }
        return scope
    }

    /// JavaScript `encodeURIComponent`: leaves A-Za-z0-9 and `-_.!~*'()` raw.
    static func encodeURIComponent(_ value: String) -> String {
        percentEncode(value, unreserved: Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()".utf8))
    }

    /// `application/x-www-form-urlencoded` serialiser, as `URLSearchParams`
    /// does it: unreserved set is A-Za-z0-9 plus `*-._`, and SPACE becomes `+`
    /// (NOT `%20` — Foundation's `addingPercentEncoding` would emit `%20` and
    /// break byte-equality with the reference implementation).
    static func encodeFormComponent(_ value: String) -> String {
        var out = ""
        for byte in value.utf8 {
            if byte == 0x20 { out += "+" }
            else if Self.formUnreserved.contains(byte) { out.unicodeScalars.append(Unicode.Scalar(byte)) }
            else { out += String(format: "%%%02X", byte) }
        }
        return out
    }

    private static let formUnreserved: Set<UInt8> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._".utf8
    )

    private static func percentEncode(_ value: String, unreserved: Set<UInt8>) -> String {
        var out = ""
        for byte in value.utf8 {
            if unreserved.contains(byte) { out.unicodeScalars.append(Unicode.Scalar(byte)) }
            else { out += String(format: "%%%02X", byte) }
        }
        return out
    }

    /// `normalizeURIComponent`, syntax-string.ts:82-132. Un-escapes exactly
    /// `: / + , @ %` and nothing else — never `?` or `&`, which would break
    /// query parsing (the @NOTE at syntax-string.ts:83-84).
    static func normalizeAllowedChars(_ value: String) -> String {
        var out = value
        for (encoded, raw) in [("%3A", ":"), ("%2F", "/"), ("%2B", "+"), ("%2C", ","), ("%40", "@"), ("%25", "%")] {
            out = out.replacingOccurrences(of: encoded, with: raw)
        }
        return out
    }
}
```

**Pinned upstream lossiness, deliberately reproduced.** `+` is in
`ALLOWED_SCOPE_CHARS` (`syntax-string.ts:85`), so a param value containing a
literal `+` is encoded to `%2B` by `URLSearchParams.toString()` and then
un-escaped back to a raw `+` by `normalizeURIComponent` — which re-parses as a
SPACE. Round-trip of `+` inside a query value is **not** stable upstream. Swan
reproduces this rather than diverging.

**The first draft claimed "no value admitted by any of the seven validators can
contain `+`". That is false, and the test it prescribed asserted a falsehood.**
The NSID charset (`[a-zA-Z0-9.-]`, `syntax/src/nsid.ts:121`), DID charset
(`[a-zA-Z0-9._:%-]`, `syntax/src/did.ts:51`) and record-key charset do exclude
`+` — but `blob`'s `accept` does not. `lib/mime.ts:3-13, 23-28` requires only:
exactly one `/`, non-empty on both sides, no SPACE, and `*` confined to the whole
value or the trailing subtype. Nothing restricts `+`, and `+` in MIME subtypes is
ubiquitous (`image/svg+xml`, `application/atom+xml`, `application/vnd.api+json`).

Traced through the serialiser above, `blob?accept=image/png&accept=image/svg+xml`
canonicalises to a string that **does not re-parse**:

| step | value |
|---|---|
| `encodeFormComponent` | `image%2Fsvg%2Bxml` |
| `normalizeAllowedChars` un-escapes `%2F`→`/` **and `%2B`→`+`** (`+` is in `ALLOWED_SCOPE_CHARS`, `syntax-string.ts:85`) | `image/svg+xml` |
| re-parse: `decodeFormComponent` folds `+`→SP | `image/svg xml` |
| `isStringSlashString` rejects a value containing SPACE (`mime.ts:10`) | whole scope → `null` |

This is upstream's own defect, reproduced verbatim rather than diverged from.
The pinned test is therefore **not** "no family validator admits `+`" — it is:

> `blob?accept=image/png&accept=image/svg+xml` parses; its canonical form
> re-materialises the raw `+`; and that canonical string then **fails to
> re-parse**. Pinned as a known upstream lossiness so a future reader does not
> "fix" the encoder and silently diverge from the reference.

It also constrains §9-D7: a client that registers `blob:image/svg+xml` in its
metadata and requests the same grant produces a *different* canonical form on
each side as soon as a second `accept` value is present. D7's
canonicalise-both-sides subset check must therefore fall back to raw-string
comparison for any scope whose canonical form fails to re-parse — never treat it
as "the registered scope does not exist" (§9-D7).

Consequences pinned by upstream tests: `did:plc:abc` stays literal in a query
value (`space-permission.test.ts:159-161`); `#` becomes `%23` because it is not
in the allow-set (`rpc-permission.test.ts:33-37`); `~` stays raw in a positional
but becomes `%7E` in a query value.

**That last asymmetry is confirmed, and it is pinned by a GENERATED golden
vector rather than by a hand-transcribed one.** (Pointer for readers of an
earlier version: §9.2's open question **Q3** is **closed** — no human ruling was
needed, only a mechanism. §9.1 carries the decision; §7.1 carries the
generator.) The first draft labelled it
"inferred from the two encoder sets, not pinned by any upstream test" and
raised it as an open question. It is no longer open: the inference matches the
reference implementation, and the mechanism that keeps it matching is a corpus
generator, not a human reading a `.ts` file and typing a row into this
document. Run the pinned `packages/oauth/oauth-scopes/src` parse/format pair
over an input list, emit `(input, canonical | null)` pairs as a checked-in
fixture, and have the Swift tests assert against the fixture. §7.1 defines the
generator and §7.6 adds the regenerate-and-diff gate step that catches a corpus
which silently drifts from the pin.

The consequence for THIS section: the "pinned by upstream test" vs "inferred"
labels scattered through §4.5 were being used to grade confidence, and those
grades are now stale. Every encoder-boundary row here — the `~` asymmetry
above, and §7.2.1's S12a/S12b/S12c/S15 — is **generated**. Do not re-transcribe
them by hand; a transcription error in a canonicalisation vector is invisible
until a client's registered scope stops matching its requested scope.

### 4.6 The schema layer (upstream `Parser<P, S>`)

```swift
/// One declared parameter. Declaration ORDER in `ScopeParameterSchema.parameters`
/// is the canonical serialisation order (parser.ts:54, :95). An Array, never a
/// Dictionary — a Dictionary would randomise canonical order.
public struct ScopeParameter: Sendable {
    public enum Arity: Sendable, Hashable { case single, multiple }

    public let key: String
    public let arity: Arity
    public let isRequired: Bool
    /// Absent = no default at all (`include`'s `aud`); `[]` is a real, distinct
    /// default meaning "empty set" (`space`'s `collection`).
    public let defaultValue: [String]?
    public let validate: @Sendable (String) -> Bool
    /// Applied BEFORE default comparison and before serialisation
    /// (parser.ts:61-65), not as a separate post-parse pass.
    public let normalize: @Sendable ([String]) -> [String]

    public init(
        key: String,
        arity: Arity,
        isRequired: Bool = false,
        defaultValue: [String]? = nil,
        normalize: @escaping @Sendable ([String]) -> [String] = { $0 },
        validate: @escaping @Sendable (String) -> Bool
    ) {
        self.key = key
        self.arity = arity
        self.isRequired = isRequired
        self.defaultValue = defaultValue
        self.normalize = normalize
        self.validate = validate
    }
}

/// Parsed, validated, defaulted parameter values for one scope.
///
/// **Provenance is stored alongside the value and is load-bearing.** Two of
/// Swan's three existing space predicates are written against the *literal*
/// text of the scope, not its parsed meaning:
///
///  * `permitsAggregateSpaceList` (`SwanCore.swift:299-303`) requires a
///    **literal** `skey=*` and a **literal** `action=read`, reading
///    `strictQualifiedParameters` (`:352-375`), which only ever reports keys
///    physically present in the string.
///  * `permitsWholeSpaceRead` (`:270-277`) requires `parameters.count == 3` and
///    `Set(parameters.keys) == ["authority","skey","action"]` — i.e. the grant
///    named `action` and named nothing else.
///
/// `space`'s schema defaults `skey` to `["*"]` (spec §5.6.2) and `action` to the
/// full record list, so without provenance "the client wrote `skey=*`" and "the
/// client wrote nothing" become indistinguishable and both predicates silently
/// widen. Collapsing this into a plain `[String: [String]]` is the same class of
/// mistake as collapsing `ScopeParameterBag`'s tri-state into `String?`.
///
/// Provenance is **never** consulted by upstream-conformant matching — only by
/// the two Swan-specific narrowings in §6.1/§6.2 and by the §7.3 fence.
///
/// **These bits must be DURABLE — see §9-D23, which is a blocker.** They have to
/// survive parse → admission → mint (where `self` is resolved) → persistence →
/// reload → match, and they must be persisted beside the effective grant rather
/// than re-derived. A serialised scope string cannot carry them in either
/// direction: resolving `self` makes a defaulted `authority` *look* stated (which
/// would flip the delegation fence open), and canonical serialisation deletes
/// values equal to their defaults, which destroys a stated `skey=*` (which would
/// silently disable the listing fence). Both directions are demonstrated against
/// upstream's own serialiser in the golden corpus,
/// `Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json`.
/// Consequently `withResolvedAuthority` takes provenance explicitly and preserves
/// it: resolution changes the value, never the statedness.
public struct ScopeParameterValues: Sendable, Hashable {
    public enum Provenance: Sendable, Hashable {
        /// The key appeared in the scope string (named or positional form).
        case stated
        /// The key was absent and `ScopeParameter.defaultValue` supplied it.
        case defaulted
    }

    private struct Slot: Sendable, Hashable {
        let values: [String]
        let provenance: Provenance
    }

    private var storage: [String: Slot]

    public init() { self.storage = [:] }

    public func single(_ key: String) -> String? { storage[key]?.values.first }
    public func multiple(_ key: String) -> [String] { storage[key]?.values ?? [] }
    public func has(_ key: String) -> Bool { storage[key] != nil }

    /// True iff the key was physically present in the scope string. This is the
    /// witness `permitsAggregateSpaceList` and `permitsWholeSpaceRead` need.
    public func wasStated(_ key: String) -> Bool { storage[key]?.provenance == .stated }

    public mutating func set(_ key: String, _ values: [String], _ provenance: Provenance = .stated) {
        storage[key] = Slot(values: values, provenance: provenance)
    }
}

public struct ScopeParameterSchema: Sendable {
    public let prefix: String
    /// The schema key that may ALSO be spelled as the `:positional` segment.
    public let positionalKey: String?
    public let parameters: [ScopeParameter]

    public init(prefix: String, positionalKey: String? = nil, parameters: [ScopeParameter]) {
        self.prefix = prefix
        self.positionalKey = positionalKey
        self.parameters = parameters
    }

    private var keys: Set<String> { Set(parameters.map(\.key)) }

    // MARK: parse — parser.ts:101-160, every `return null` becomes a typed throw

    public func parse(_ syntax: ScopeStringSyntax) throws(ScopeParseError) -> ScopeParameterValues {
        guard syntax.prefix == prefix else {
            throw .prefixMismatch(expected: prefix, actual: syntax.prefix)
        }

        // parser.ts:105-107 — any key not in the schema kills the whole scope.
        // This is why `identity:*?action=manage` is rejected: `identity` has no
        // `action` key at all (identity-permission.test.ts:24-36).
        let declared = keys
        for key in syntax.parameters.orderedKeys() where !declared.contains(key) {
            throw .unknownParameter(prefix: prefix, key: key)
        }

        var result = ScopeParameterValues()
        for parameter in parameters {
            let named: [String]?
            switch parameter.arity {
            case .single:
                switch syntax.parameters.single(parameter.key) {
                case .absent:
                    named = nil
                case let .present(value):
                    named = [value]
                case .repeated:
                    // parser.ts:121-122 via syntax-string.ts:21-22
                    throw .repeatedSingleValuedParameter(prefix: prefix, key: parameter.key)
                }
            case .multiple:
                named = syntax.parameters.multiple(parameter.key)
            }

            if let named {
                // parser.ts:124-127 — positional and named form of the same key
                // are mutually exclusive. Enforced HERE, not in the lexer: the
                // lexer is deliberately permissive (syntax-string.test.ts:107-113).
                if parameter.key == positionalKey, syntax.positional != nil {
                    throw .positionalAndNamedConflict(prefix: prefix, key: parameter.key)
                }
                // parser.ts:131 — an empty multi-value array is invalid.
                guard !named.isEmpty else {
                    throw .emptyMultiValuedParameter(prefix: prefix, key: parameter.key)
                }
                // parser.ts:132-138
                for value in named where !parameter.validate(value) {
                    throw .invalidParameterValue(prefix: prefix, key: parameter.key, value: value)
                }
                result.set(parameter.key, named, .stated)
            } else if parameter.key == positionalKey, let positional = syntax.positional {
                // parser.ts:146-151
                guard parameter.validate(positional) else {
                    throw .invalidPositionalValue(prefix: prefix, key: parameter.key, value: positional)
                }
                result.set(parameter.key, [positional], .stated)
            } else if parameter.isRequired {
                // parser.ts:152-153
                throw .missingRequiredParameter(prefix: prefix, key: parameter.key)
            } else if let defaultValue = parameter.defaultValue {
                // parser.ts:155 — omit the key entirely when defaultValue == nil.
                // `.defaulted` is the provenance witness; see the type's docs.
                result.set(parameter.key, defaultValue, .defaulted)
            }
        }
        return result
    }

    // MARK: format — parser.ts:50-96, the canonicalisation direction

    public func format(_ values: ScopeParameterValues) throws(ScopeParseError) -> String {
        var bag = ScopeParameterBag()
        var positional: String?

        for parameter in parameters {   // declaration order == canonical order
            guard values.has(parameter.key) else { continue }   // parser.ts:57
            let normalized = parameter.normalize(values.multiple(parameter.key))

            // parser.ts:67-76 — a non-required value equal to its default is
            // omitted entirely. `arrayParamEquals` (:169-176) is order- and
            // duplicate-INSENSITIVE, so the Swift equivalent is Set==Set,
            // NOT array ==.
            if !parameter.isRequired, let defaultValue = parameter.defaultValue,
               Set(defaultValue) == Set(normalized) {
                continue
            }

            switch parameter.arity {
            case .single:
                guard let value = normalized.first else { continue }
                if parameter.key == positionalKey { positional = value }
                else { bag.set(key: parameter.key, value: value) }
            case .multiple:
                if parameter.key == positionalKey, normalized.count == 1 {
                    positional = normalized[0]           // parser.ts:79-80, :87-88
                } else {
                    var seen = Set<String>()             // parser.ts:82-85: dedupe,
                    for value in normalized where seen.insert(value).inserted {
                        bag.append(key: parameter.key, value: value)   // insertion order, NOT sorted
                    }
                }
            }
        }

        return try ScopeStringSyntax(prefix: prefix, positional: positional, parameters: bag)
            .canonicalString()
    }
}
```

Sorting, where it happens, lives **inside a family's `normalize`**, never in
`format`.

### 4.7 The family protocol and the dispatcher

**The protocol is split in two, and it must be.** `IncludeScope` is a scope
family — it has a prefix, a schema, a parse and a canonical form — but it is
**not** a permission: it implements no `Matchable` upstream
(`include-scope.ts:22-26`) and has no `matches`. A single protocol carrying
`associatedtype Target`, `matches` and `scopeNeeded` cannot be conformed to by
`IncludeScope`, yet §4.7's dispatcher below calls `prefix`, `parse(_:)` and
`canonicalScopeString()` on it. Without the split those are **three compile
errors in the type the whole PAR path routes through**. Upstream has the same
split cleanly: `ResourcePermission<R,T> extends Matchable<T>`
(`lib/resource-permission.ts:8`); `IncludeScope` extends neither.

```swift
/// Anything with a prefix, a schema, a parse and a canonical form. `IncludeScope`
/// stops here — it names a permission SET and matches nothing itself.
public protocol ScopeFamily: Sendable, Hashable {
    static var schema: ScopeParameterSchema { get }

    init(parameters: ScopeParameterValues) throws(ScopeParseError)
    var scopeParameters: ScopeParameterValues { get }
}

extension ScopeFamily {
    public static var prefix: String { schema.prefix }

    public static func parse(_ scope: String) throws(ScopeParseError) -> Self {
        guard ScopeStringSyntax.isScopeString(scope, for: schema.prefix) else {
            throw .prefixMismatch(expected: schema.prefix, actual: scope)
        }
        return try Self(parameters: schema.parse(ScopeStringSyntax.parse(scope)))
    }

    public func canonicalScopeString() throws(ScopeParseError) -> String {
        try Self.schema.format(scopeParameters)
    }
}

/// One permission family (`space:`, `repo:`, `rpc:`, ...) — a `ScopeFamily` that
/// additionally answers "does this grant cover that request". The subset
/// ("grants") relation is deliberately NOT part of `Equatable` — the Rust
/// reference keeps it a separate exhaustive function with per-family exceptions
/// (scopes.rs:896-991), and `space:` opts out of subset reduction entirely
/// (scopes.rs:985-988).
public protocol ScopePermission: ScopeFamily {
    associatedtype Target: Sendable

    func matches(_ target: Target) -> Bool
    /// The minimal scope string that WOULD satisfy `target` — the message
    /// content of a denial (scopes-set.ts:57-65, :90-112).
    ///
    /// **Must be total over `Target`.** Every case of every `Target` enum needs
    /// an arm, including Swan-shaped ones such as
    /// `SpaceScopeTarget.Operation.delegationExchange`, which the first draft
    /// left undefined (§5.6.6). The *target case* is Swan-shaped — upstream
    /// spells the same capability as an ordinary `action: 'read'` assert at a
    /// route rather than as a distinct match target — but the *rule* has an
    /// upstream analogue; see §6.2 and the corrected comment in §5.6.3.
    static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String
}
```

The six matchable families conform to `ScopePermission`; `IncludeScope` conforms
to `ScopeFamily` only. Each of the seven must supply
`init(parameters:) throws(ScopeParseError)` and `var scopeParameters` explicitly
— the §5 declarations show the fields and the schema, not those two members, so
implement them per family (the `init` is where family-level forbidden
combinations such as `rpc` `aud=*` + `lxm=*` are enforced, §5.5).

The dispatcher is unchanged from the first draft **except** that it now compiles:
`IncludeScope.prefix`, `IncludeScope.parse(_:)` and `s.canonicalScopeString()`
all resolve through the `ScopeFamily` extension above.

```swift
/// Every scope Swan can interpret. Dispatch is a fixed prefix table (as in
/// scopes.rs:347), not upstream's try-each-family-in-order
/// (atproto-oauth-scope.ts:64-83): O(1), and it yields a real error instead of
/// a `null` that cannot say which family rejected the string. Safe because
/// `isScopeString` makes the prefixes disjoint (§4.4) — `identity` never eats
/// `identityfoo`.
public enum AtprotoScope: Sendable, Hashable {
    case atproto
    case transitionEmail
    case transitionGeneric
    case transitionChatBsky
    case account(AccountPermission)
    case blob(BlobPermission)
    case identity(IdentityPermission)
    case include(IncludeScope)
    case repo(RepoPermission)
    case rpc(RpcPermission)
    case space(SpacePermission)

    public static func parse(_ scope: String) throws(ScopeParseError) -> AtprotoScope {
        switch scope {
        case "atproto": return .atproto
        case "transition:email": return .transitionEmail
        case "transition:generic": return .transitionGeneric
        case "transition:chat.bsky": return .transitionChatBsky
        default: break
        }
        if ScopeStringSyntax.isScopeString(scope, for: AccountPermission.prefix) {
            return .account(try AccountPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: BlobPermission.prefix) {
            return .blob(try BlobPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: IdentityPermission.prefix) {
            return .identity(try IdentityPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: IncludeScope.prefix) {
            return .include(try IncludeScope.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: RepoPermission.prefix) {
            return .repo(try RepoPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: RpcPermission.prefix) {
            return .rpc(try RpcPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: SpacePermission.prefix) {
            return .space(try SpacePermission.parse(scope))
        }
        throw .unknownPrefix(scope)
    }

    public func canonicalScopeString() throws(ScopeParseError) -> String {
        switch self {
        case .atproto: "atproto"
        case .transitionEmail: "transition:email"
        case .transitionGeneric: "transition:generic"
        case .transitionChatBsky: "transition:chat.bsky"
        case let .account(p): try p.canonicalScopeString()
        case let .blob(p): try p.canonicalScopeString()
        case let .identity(p): try p.canonicalScopeString()
        case let .include(s): try s.canonicalScopeString()
        case let .repo(p): try p.canonicalScopeString()
        case let .rpc(p): try p.canonicalScopeString()
        case let .space(p): try p.canonicalScopeString()
        }
    }
}
```

The three `transition:*` values **parse** so that a client sending them is not
rejected at PAR, but grant nothing: Swan implements no transition semantics
(positive control: `grep -rn 'transition:' Sources/` returns nothing, while
`grep -rn '"atproto"' Sources/` returns 44 hits including
`OAuthPublicationMetadata.swift:161` and `OAuthValidatedSession.swift:92`).
`transition:generic` must specifically **not** reach `space:` — upstream keeps
that as an explicit override-to-super "to keep that a decision rather than an
oversight" (`scope-permissions-transition.ts:55-61`, pinned by
`scope-permissions-transition.test.ts:55-68`). Replicate as an explicit test,
§7.2 vector T4.

**"Parse but grant nothing" is a Swan divergence, not conformance — record it as
such.** The first draft cited only the `allowsSpace` override, which is the one
arm that *does* grant nothing. Read in full,
`scope-permissions-transition.ts:27-80` is the opposite for every other family:

| transition scope | upstream grants | Swan grants |
|---|---|---|
| `transition:email` | `account:email?action=read` (`:27-37`) | nothing |
| `transition:generic` | **all** blob (`:39-45`), **all** repo (`:47-53`), and all rpc whose `lxm` is `*` or does not start with `chat.bsky.` (`:64-80`) | nothing |
| `transition:chat.bsky` | rpc with `lxm` starting `chat.bsky.` (`:76-78`) | nothing |
| any of the three | **nothing** for `space:` (`:55-61`) | nothing — the one arm where Swan and upstream agree |

This is a defensible Swan choice, but the control that was cited for it has to
be restated with its real scope. `oauth-provider` recognises scopes through
`isAtprotoOauthScope`, not through the transition subclass — and the grep
`grep -rn ScopePermissionsTransition oauth-provider/src` → **0** is **correct
for that one directory and wrong as a statement about upstream**.
`ScopePermissionsTransition` is live in the consent UI:
`packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx:160`
constructs one (`new ScopePermissionsTransition(includeScope.toScopes(permissionSet))`)
to render what a permission set actually grants. So the subclass is not inert
upstream; it is simply not the *recognition* mechanism in the authorization
path. Say that, and stop citing a directory-scoped grep as a tree-wide absence —
that is the exact failure mode this whole revision exists to correct. (The
identical sentence appears in §9.1 D11 and must be fixed there too; the two
halves land together or the document contradicts itself.)

Swan additionally wires no `repo:`/`rpc:`/`blob:` *permission family* into any
route (§9-D12). The routes themselves exist — §9-D12 names Swan's repo mutation
and XRPC proxy routes — they simply consult no scope of those families. Saying
"no routes" would repeat the exact confusion the §9-Q4 correction removed:
route absent is not the same as scope enforcement absent. But
the consequence must be stated rather than discovered: **a token Swan mints
carrying `transition:generic` is inert where a reference PDS honours it for
repo, rpc and blob.** §7.2.5's T3 therefore pins a *divergence*, not
conformance, and its row says so.

One further caution on this table, for whoever ships it: the rows above are
derived from `scope-permissions-transition.ts` and assert what "a reference PDS
honours". That is now directly checkable against `packages/pds` (67 `authorize:`
route callbacks; see §6's route→scope mapping table), not merely inferable from
the transition class. Re-verify each row against the actual route set before
shipping the table as fact.

### 4.8 Error table

Upstream has **no error type**: every failure is `return null` (`parser.ts`'s
own `@NOTE` at `:98-100` says a `ValidationResult<T>` "could easily" be added
and never was), and the provider then either silently drops the token
(`request-manager.ts:177-185`) or raises `invalid_scope` for a different reason
entirely. Swan's typed enum is the missing half.

```swift
public enum ScopeParseError: Error, Sendable, Hashable, CustomStringConvertible {
    case notAScopeToken(String)
    case malformedPercentEncoding(String)
    case unknownPrefix(String)
    case prefixMismatch(expected: String, actual: String)
    case unknownParameter(prefix: String, key: String)
    case repeatedSingleValuedParameter(prefix: String, key: String)
    case positionalAndNamedConflict(prefix: String, key: String)
    case emptyMultiValuedParameter(prefix: String, key: String)
    case invalidParameterValue(prefix: String, key: String, value: String)
    case invalidPositionalValue(prefix: String, key: String, value: String)
    case missingRequiredParameter(prefix: String, key: String)
    case forbiddenParameterCombination(prefix: String, detail: String)
    case scopeTooLong(bytes: Int, limit: Int)
    // `description` renders each WITHOUT echoing a full attacker-chosen string
    // into a log line; the value fields are for structured logging only.
}
```

`ScopeDenied` (the *authorization* denial, distinct from a *parse* failure) is
a separate type (§6.1), mirroring `scope-missing-error.ts` — but unlike
upstream it never reaches the wire (§6.1, §9-D6).

| # | upstream failure (source) | Swift case | disposition at PAR / `/oauth/authorize` | client-visible OAuth error |
|---|---|---|---|---|
| 1 | *(none — Rust `is_scope_token`, scopes.rs:1055-1061)* | `.notAScopeToken` | reject the whole request | `invalid_request` (400) — the `scope` form field itself is malformed |
| 2 | `decodeURIComponent` **throws `URIError`**, uncaught (syntax-string.ts:62-64) | `.malformedPercentEncoding` | reject the request | `invalid_scope` (400) |
| 3 | no family's `fromString` returned non-null (atproto-oauth-scope.ts:42-53, 64-83); Rust `ParseError::UnknownPrefix` (scopes.rs:1128) | `.unknownPrefix` | **reject** (upstream: silent drop, request-manager.ts:184) — §9-D5 | `invalid_scope` (400) |
| 4 | `isScopeStringFor` false (syntax.ts:16-33) | `.prefixMismatch` | internal only — reached only by a mis-dispatched family call | n/a (programmer error; assert in debug) |
| 5 | key not in schema (parser.ts:105-107) | `.unknownParameter` | reject | `invalid_scope` (400) |
| 6 | `getSingle` with >1 value → `null` (syntax-string.ts:21-22 → parser.ts:121-122) | `.repeatedSingleValuedParameter` | reject | `invalid_scope` (400) |
| 7 | positional + named form of the same key (parser.ts:124-127) | `.positionalAndNamedConflict` | reject | `invalid_scope` (400) |
| 8 | empty multi-value array (parser.ts:131) | `.emptyMultiValuedParameter` | reject | `invalid_scope` (400) |
| 9 | `validate` false on a named value (parser.ts:132-138) | `.invalidParameterValue` | reject | `invalid_scope` (400) |ᵃ
| 10 | `validate` false on the positional (parser.ts:146-150) | `.invalidPositionalValue` | reject | `invalid_scope` (400) |
| 11 | required key absent (parser.ts:152-153) | `.missingRequiredParameter` | reject | `invalid_scope` (400) |
| 12 | family-level forbidden combo, e.g. `rpc` `aud=*` + `lxm=*` (rpc-permission.ts:86-88) | `.forbiddenParameterCombination` | reject | `invalid_scope` (400) |
| 13 | *(none upstream)* — Swan per-token byte cap (§6.4) | `.scopeTooLong` | reject the whole request | `invalid_request` (400), at the wire parser, before persistence |
| — | `atproto` absent after parsing (request-manager.ts:241-248) | *(not a parse error)* `ScopeAdmissionError.missingBaseScope` | reject — §6.3 **stage E**, see the note below | `invalid_scope` (400) |
| — | `openid` present (request-manager.ts:241-248) | `ScopeAdmissionError.forbiddenScope` | reject — §6.3 **stage A**, at the wire tokenizer | `invalid_scope` (400) |
| — | granted scope not a subset of registered (`DurableOAuthTokenService.swift:1112-1113`) | `ScopeAdmissionError.notRegistered` | reject | `invalid_request` (400) — **stays opaque**, §6.3 |
| — | request-time denial | `ScopeDenied(needed:)` | n/a | per-route opaque code; `needed` logged server-side only (§6.1) |

ᵃ **Row 9 keeps ONE case, but the reason is no longer unknowable.** With
`@atproto/did` in hand (§4.1), an `aud=` rejection now has a derivable taxonomy —
method not in `{plc, web}` (`atproto.ts:19`), `did:plc` wrong length or wrong
alphabet (`methods/plc.ts:6`, `:15-17`), `did:web` carrying a path
(`atproto.ts:90-92`) or a non-localhost port (`atproto.ts:102-117`), missing or
empty fragment (`did-ref.ts:14-15`), second `#` (`did-ref.ts:16`), bad
percent-escape in the fragment (`lib/uri.ts:46-51`). Do **not** subdivide the
enum case: the wire error stays `invalid_scope` either way, and a finer wire
taxonomy would tell a caller more about Swan's parser than it needs. Do carry
the reason in the STRUCTURED LOG payload (§4.8's `description` contract already
forbids echoing the attacker-chosen string into the line), so an operator
debugging a client's rejected `aud=` is not reduced to guessing. The point of
this footnote is that "why did this `aud` fail" is now a question with an
answer, where the first draft's reconstruction could not have produced one.

**`invalid_scope` is new to Swan.** `grep -rn 'invalid_scope' Sources/` → **0
hits**; `invalid_request` → **21 hits**; `unauthorized_client` → **0**. Every
scope failure today collapses into the deliberately opaque `invalid_request` at
`SwanOAuthAuthorizationServerHTTP.swift:212-217`, `:257-271`. This is a
wire-visible behaviour change: `invalid_scope` reveals *which* scope was
refused, which is exactly what upstream intends (a client can fix its request)
but is more than Swan discloses today. It is safe **only** because it describes
the request's own text and leaks no server-side fact — which is precisely why
the subset failure (row "notRegistered") keeps `invalid_request`: that one
*would* leak the client's registration (`:256-259` records the reasoning).

**`ScopeAdmissionError` has a home, an owner and a divergence to record.** The
first draft introduced the last two rows and then never mentioned them again — no
stage, no file, no vector. Fixed here:

- **`.forbiddenScope` (`openid`)** is enforced at **stage A**, in the wire
  tokenizer, as an explicit reject of the literal token `openid`. It cannot be
  left to stage B: `AtprotoScope.parse` throws `.unknownPrefix` on `openid` first
  (§4.7), so a stage-C-or-later `forbiddenScope` row would be unreachable by
  construction and the wire would report the wrong reason. A literal check is one
  line and preserves upstream's error text.
- **`.missingBaseScope` (`atproto` required)** is enforced at **stage E**, in
  `OAuthScopeAdmissionPolicy` (§3), over the parsed set.
- **Swan's floor is NOT upstream's, and this spec adopts Swan's.** Upstream
  requires the literal `atproto` scope unconditionally
  (`request-manager.ts:241-243`). Swan's floor today is
  `atproto` **OR** a qualified `space:` grant
  (`OAuthValidatedSession.swift:91-95`, `SwanOAuthResourceAuthorization.swift:206-210`,
  `OAuthControlStore.swift:2352-2356`). §6.5.2 keeps that shape, so **a Swan PAR
  carrying only `space:…` and no `atproto` is accepted where a reference AS
  rejects it.** That is a real interop divergence in the *lenient* direction. It
  is kept because tightening it to upstream's rule would break every existing
  space-only session in production, and it is recorded here rather than left as
  a contradiction between this table and §6.5.2. Vector: §7.2.6.

**Every stage assignment above re-checked against the four-layer boundary
(§9-Q9).** The Q9 ruling retires `isIssuableQualified` as a *semantic*
client-metadata gate and moves the boundaries; this table assigned stages before
that ruling, and one of its assumptions is now wrong. The four layers, and where
each row of this table lands:

| layer | what it may reject | this table's rows |
|---|---|---|
| **1. Client metadata** (registration) | **LEXICAL ONLY** — a valid RFC 6749 §3.3 scope-token list, plus Swan's documented byte/count budgets (§6.4, §9-Q5). Registration grants nothing, so an unknown or future-dated scope name may be declared safely. Upstream's whole client-metadata scope validator is `oauthScopeSchema` = `OAUTH_SCOPE_REGEXP` and **nothing else** (`packages/oauth/oauth-types/src/oauth-scope.ts:5-9`, `:17-19`) — a regexp over the scope-token charset with no family lookup and no length bound | rows 1 and 13 only |
| **2. PAR / authorize** | requested ⊆ declared; each requested token must pass Swan's atproto parser; the base-scope floor; the Phase-1 `include:` policy | rows 2-12, and the `.forbiddenScope` / `.missingBaseScope` / `.notRegistered` rows |
| **3. Token mint** | expansion/materialisation failures, `self` resolution, expanded-grant budget | not represented here — see §5.7.5 and §6.4 |
| **4. Resource plane** | the exact semantic matcher plus Swan's provenance fences | the `ScopeDenied` row |

Two corrections follow, and they must be read together with §6.3's stage table:

1. **Stage D no longer does semantic work.** §6.3 describes stage D as "which
   scope *shapes* a client may **register** at all". Under Q9 that is layer 1,
   and layer 1 is lexical. A client may register `space:app.bulleted.space` —
   or `some.future.family:whatever` — and registration alone grants it nothing.
   The refusal a semantic gate used to produce at registration now happens at
   layer 2 instead, where the client is actually asking for something, and it
   produces `invalid_scope` (this table's rows 3-12) rather than a
   client-metadata load failure. This is not a loosening: **nothing reachable
   became reachable**, because registration was never an authorization. It is a
   relocation of the same refusal to the layer that has the request in front of
   it. Note where Swan deliberately diverges from upstream at layer 2: upstream
   silently DROPS a scope it cannot parse (`request-manager.ts:177-185`); Swan
   rejects with `invalid_scope` (§9-D5, row 3 above).
2. **Stage A′ is layer 1 AND layer 2 in one function, which is why it was
   missed.** `localhostRequestedScopes` (`OAuthClientMetadata.swift:453-465`)
   tokenizes *and* applies `value == "atproto" || isIssuableQualified(value)`.
   The tokenizing half is layer 1 and survives; the `isIssuableQualified` half
   is the retired semantic gate and must be deleted rather than re-expressed
   over the new parser. The dangers that gate was reaching for — a default
   `self` authority, `skey=*`, or a defaulted action set amplifying into
   something broader than intended — are now handled at layer 4 by the
   delegation and listing provenance fences (§5.6.3, §6.1), which is the layer
   that can actually see what is being asked for.

Rows that do **not** move: `.forbiddenScope` stays at stage A. Its home is
lexical (a literal-token check against `openid`) even though its *motive* is
semantic, and §4.7 already records why — `AtprotoScope.parse` throws
`.unknownPrefix` on `openid` first, so a later `forbiddenScope` row would be
unreachable by construction and the wire would report the wrong reason.
`.missingBaseScope` stays at stage E, which is layer 2. `.notRegistered` stays
at stage C, which is layer 2, and keeps `invalid_request` rather than
`invalid_scope` for the leak reason given above.

---

## 5. The seven permission families

All seven are `prefix` + table-driven schema. The Rust reference flags
copy-pasting the positional/query split per family as a known bug class:
*"Reading only the positional form left every query-form scope granting
nothing."* Every family below uses the one `ScopeParameterSchema` from §4.6.

Parse failure at the **set** layer is not an error: an unparseable *held* scope
grants nothing and is skipped silently (`scopes-set.ts:47-55`;
`scopes-set.test.ts:42-47` "should not match invalid scopes"). That is a
different layer from PAR admission, which rejects (§4.8 row 3, §9-D5).

### 5.1 `account`

Source: `oauth-scopes/scopes/account-permission.ts:11-83`.

```swift
public enum AccountAttribute: String, Sendable, Hashable, CaseIterable {
    case email, repo, status                      // account-permission.ts:11-15
}

public enum AccountAction: String, Sendable, Hashable, CaseIterable {
    case read, manage                             // account-permission.ts:18-19
}

public struct AccountPermission: ScopePermission {
    /// Positional key. single, required, no default.
    public let attr: AccountAttribute
    /// multiple, not required, default ["read"] (account-permission.ts:54-58).
    /// Never empty.
    public let action: [AccountAction]

    public static let schema = ScopeParameterSchema(
        prefix: "account",
        positionalKey: "attr",
        parameters: [
            .init(key: "attr", arity: .single, isRequired: true,
                  validate: { AccountAttribute(rawValue: $0) != nil }),
            // NO `normalize`. `account-permission.ts:54-59` declares exactly
            // `multiple` / `required` / `validate` / `default` — verified by
            // reading the whole declaration. It is the ONLY multi-valued
            // parameter in the seven families without a normalizer, and the
            // omission is upstream's, not an oversight in the port.
            //
            // The first draft invented one (`AccountAction.allCases.filter(given.contains)`),
            // which diverges the canonical BYTES: `account:email?action=manage&action=read`
            // canonicalises to `account:email?action=read&action=manage` with a
            // normalizer and to `account:email?action=manage&action=read` without
            // one, because `format` appends the deduped set in INSERTION order
            // (parser.ts:82-85). Since §9-D7 makes canonical form load-bearing
            // for the registration subset check, that is not cosmetic.
            .init(key: "action", arity: .multiple,
                  defaultValue: [AccountAction.read.rawValue],
                  validate: { AccountAction(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let attr: AccountAttribute
        public let action: AccountAction
    }

    /// account-permission.ts:35-40. `manage` subsumes `read`; the implication is
    /// one-directional — a `read` grant never satisfies a `manage` request.
    public func matches(_ target: Target) -> Bool {
        guard attr == target.attr else { return false }
        return action.contains(.manage) || action.contains(target.action)
    }
}
```

Vectors — `scopes/account-permission.test.ts`:

| scope string | expectation | cite |
|---|---|---|
| `account:email?action=read` | `attr == .email`, `action == [.read]` | `:8-11` |
| `account:repo?action=manage` | `attr == .repo`, `action == [.manage]` | `:13-18` |
| `account:status` | `action == [.read]` (default) | `:21-26` |
| `account:invalid` | nil | `:29-30` |
| `account:email?action=invalid` | nil | `:34-37` |
| `invalid:email`, `account`, `""`, `account:` | all nil | `:41-44` |
| `account:email?action=manage` vs `{email, read}` | true | `:137-143` |
| `account:email?action=read` vs `{email, manage}` | false | `:92-96` |
| `account:email` vs `{email, manage}` | false | `:104-109` |
| `AccountPermission(.email, [.manage])` → format | `account:email?action=manage` | `:147-150` |
| `AccountPermission(.repo, [.read])` → format | `account:repo` (default elided) | `:152-155` |
| round-trip set: `account:email`, `account:email?action=manage`, `account:repo`, `account:repo?action=manage`, `account:status`, `account:status?action=manage` | each → itself | `:174-187` |
| `scopeNeeded({email, read})` | `account:email` | `:49-59` |
| `scopeNeeded({email, manage})` | `account:email?action=manage` | `:61-74` |
| **Swan-added**: `account:email?action=manage&action=read` → format | `account:email?action=manage&action=read` — **insertion order preserved**, NOT declaration order. The row exists because there is no upstream multi-action `account:` format vector, so nothing else in the suite would catch a re-introduced normalizer. | *(no upstream vector; pins `account-permission.ts:54-59`'s absent `normalize`)* |

`account` is **not includable** in a permission set (`include-scope.ts:110`;
`include-scope.test.ts` "account permissions" → `[]`).

### 5.2 `blob`

Source: `oauth-scopes/scopes/blob-permission.ts:21-106`, matcher in
`oauth-scopes/lib/mime.ts`.

```swift
/// `*/*` | `type/*` | `type/subtype`. Never `*/subtype`, never `**`. mime.ts:21-28.
public enum AcceptPattern: Sendable, Equatable, Hashable, Comparable {
    case any                      // "*/*"
    case type(String)             // "image/*" — stores "image"
    case exact(String, String)    // "image/png"

    public var stringValue: String {
        switch self {
        case .any: return "*/*"
        case let .type(t): return "\(t)/*"
        case let .exact(t, s): return "\(t)/\(s)"
        }
    }

    /// mime.ts:3-13 + :23-28. Exactly one "/", non-empty both sides, no spaces,
    /// and "*" only as the whole value or as the trailing subtype.
    public init?(_ raw: String) { /* … */ }
}

/// mime.ts:17-19 — `isStringSlashString` AND contains no "*".
public struct ConcreteMime: Sendable, Hashable {
    public let type: String
    public let subtype: String
    public init?(_ raw: String) { /* one "/", both sides non-empty, no " ", no "*" */ }
}

public struct BlobPermission: ScopePermission {
    /// Positional key. multiple, required, NO default — bare `blob` is rejected
    /// (blob-permission.ts:38-40, test :21-24). Never empty.
    public let accept: [AcceptPattern]

    public static let schema = ScopeParameterSchema(
        prefix: "blob",
        positionalKey: "accept",
        parameters: [
            .init(key: "accept", arity: .multiple, isRequired: true,
                  normalize: Self.normalizeAccept,   // blob-permission.ts:42-50, :84-106
                  validate: { AcceptPattern($0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        /// The declared Content-Type of the blob being uploaded.
        public let mime: String
    }

    /// mime.ts:45-47, :66-71. The REQUEST mime is gated FIRST: it must itself be
    /// a concrete `type/subtype` with no `*` anywhere, or nothing matches — not
    /// even `*/*` (mime.test.ts:73-74).
    public func matches(_ target: Target) -> Bool {
        guard let concrete = ConcreteMime(target.mime) else { return false }
        return accept.contains { Self.covers($0, concrete) }
    }

    /// mime.ts:35-43. First-match-wins OR. Upstream's `type/*` arm is
    /// `mime.startsWith(accept.slice(0, -1))`, i.e. a prefix test on "type/";
    /// comparing the parsed type is equivalent because ConcreteMime already
    /// required exactly one "/".
    private static func covers(_ pattern: AcceptPattern, _ mime: ConcreteMime) -> Bool {
        switch pattern {
        case .any: return true
        case let .type(t): return mime.type == t
        case let .exact(t, s): return mime.type == t && mime.subtype == s
        }
    }

    /// blob-permission.ts:42-50, :84-106:
    ///  1. if the list contains `*/*` → collapse to exactly ["*/*"];
    ///  2. else lowercase every value, drop each `type/subtype` already covered
    ///     by a `type/*` in the same list, then sort lexicographically.
    static let normalizeAccept: @Sendable ([String]) -> [String] = { /* … */ }
}
```

Vectors — `scopes/blob-permission.test.ts` + `lib/mime.test.ts`:

| scope string / construction | expectation | cite |
|---|---|---|
| `blob:image/png` | `accept == [.exact("image","png")]` | `:8-10` |
| `blob?accept=image/png&accept=image/jpeg` | `["image/png","image/jpeg"]`, parse order preserved | `:14-18` |
| `blob` | nil — `accept` is required | `:21-24` |
| `blob:invalid`, `blob?accept=invalid-mime`, `blob?accept=invalid`, `blob:*/**`, `blob:*/png`, `invalid`, `scope` | all nil | `:26-38` |
| `blob:*/*` vs `image/jpeg`, `application/json` | true | `:64-69` |
| `blob:image/*` vs `image/gif` | true | `:71-75` |
| `blob:image/png` vs `image/jpeg` | false | `:77-81` |
| `blob?accept=image/png&accept=image/jpeg` vs `image/gif` | false | `:83-91` |
| `["image/png","image/jpeg"]` → format | `blob?accept=image/jpeg&accept=image/png` (sorted, query form) | `:96-98` |
| `["*/*","image/*"]` → `blob:*/*`; `["*/*","image/png"]` → `blob:*/*`; `["image/*","image/png"]` → `blob:image/*` | redundancy stripped | `:100-110` |
| single value serialises positionally: `blob:image/png`, `blob:image/*`, `blob:*/*` | | `:112-118` |
| `matchesAccept("*/*", "image/")`, `("*/*", "/mime")` | **false** — malformed request mime fails the `isMime` gate before any pattern is consulted | `mime.test.ts:73-74` |
| `matchesAnyAccept([], "image/png")` | false — empty accept set matches nothing | `mime.test.ts:90-91` |
| `scopeNeeded({mime: "image/png"})` | `blob:image/png` | `:42-45` |

`blob` is **not includable** (`include-scope.test.ts` "valid permissions" /
"invalid permissions" both → `[]`).

### 5.3 `identity`

Source: `oauth-scopes/scopes/identity-permission.ts:7-55`. The smallest family:
one parameter, no `action`, and the wildcard lives **inside the enum**.

```swift
public enum IdentityAttribute: String, Sendable, Hashable, CaseIterable {
    case handle
    case any = "*"                                 // identity-permission.ts:7-8
}

public struct IdentityPermission: ScopePermission {
    /// Positional key. single, required, no default. There is no second
    /// parameter — any `?action=…` makes the whole scope invalid via the
    /// unknown-key rejection at parser.ts:105-107.
    public let attr: IdentityAttribute

    public static let schema = ScopeParameterSchema(
        prefix: "identity",
        positionalKey: "attr",
        parameters: [
            .init(key: "attr", arity: .single, isRequired: true,
                  validate: { IdentityAttribute(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable { public let attr: IdentityAttribute }

    /// identity-permission.ts:20-22. Asymmetric: a `*` GRANT satisfies any
    /// request, but a `handle` grant does NOT satisfy a `*` request.
    public func matches(_ target: Target) -> Bool {
        attr == .any || attr == target.attr
    }
}
```

| scope string | expectation | cite |
|---|---|---|
| `identity:handle` | `attr == .handle` | `:8-10` |
| `identity:*` | `attr == .any` | `:14-16` |
| `identity:invalid`, `invalid` | nil | `:20-21` |
| `identity:*?action=*`, `identity:*?action=manage`, `identity:*?action=submit`, `identity:handle?action=invalid`, `identity?attribute=invalid&action=invalid` | all nil — proves `action` is not a recognised key for this family | `:24-36` |
| `identity:handle` vs `{.handle}` | true | `:57` |
| `identity:handle` vs `{.any}` | **false** | `:58` |
| `identity:*` vs `{.any}` and `{.handle}` | both true | `:64-65` |
| `IdentityPermission(.handle)` → format | `identity:handle` | `:70-73` |
| `IdentityPermission(.any)` → format | `identity:*` | `:75-78` |
| `scopeNeeded({.handle})` / `({.any})` | `identity:handle` / `identity:*` | `:40-48` |

`identity` is **not includable** (`include-scope.test.ts` "identity
permissions" → rejected, same shape as `account`).

### 5.4 `repo`

Source: `oauth-scopes/scopes/repo-permission.ts:15-102`.

```swift
public enum RepoAction: String, Sendable, Hashable, CaseIterable {
    case create, update, delete                    // repo-permission.ts:15-19
}
/// Canonical order for normalization. `*` is NOT a valid action
/// (`repo:*?action=*` → nil, repo-permission.test.ts:78).
public let REPO_ACTIONS: [RepoAction] = [.create, .update, .delete]

public enum CollectionParam: Sendable, Hashable, Comparable {
    case any                                       // "*"
    case nsid(String)                              // repo-permission.ts:23-25
}

public struct RepoPermission: ScopePermission {
    /// Positional key. multiple, required, NO default. Never empty.
    public let collection: [CollectionParam]
    /// multiple, not required, default [create, update, delete]
    /// (repo-permission.ts:69-72).
    public let action: [RepoAction]

    public static let schema = ScopeParameterSchema(
        prefix: "repo",
        positionalKey: "collection",
        parameters: [
            // Declaration order IS canonical order: `collection` precedes
            // `action`, which is NOT alphabetical (parser.ts:54).
            .init(key: "collection", arity: .multiple, isRequired: true,
                  // repo-permission.ts:60-66: >1 value → if any is `*` collapse
                  // to ["*"]; else dedupe and SORT.
                  normalize: { $0.contains("*") && $0.count > 1 ? ["*"] : Array(Set($0)).sorted() },
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            .init(key: "action", arity: .multiple,
                  defaultValue: REPO_ACTIONS.map(\.rawValue),
                  // :73-77 — filter REPO_ACTIONS by membership, preserving
                  // REPO_ACTIONS order, so `action=delete&action=create`
                  // canonicalises to create,delete.
                  normalize: { given in RepoAction.allCases.map(\.rawValue).filter(given.contains) },
                  validate: { RepoAction(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let collection: String
        public let action: RepoAction
    }

    /// repo-permission.ts:41-47. The collection wildcard is exact membership of
    /// `.any` in the set — never a prefix or glob match.
    public func matches(_ target: Target) -> Bool {
        guard action.contains(target.action) else { return false }
        if collection.contains(.any) { return true }
        return collection.contains(.nsid(target.collection))
    }
}
```

Parse vectors — `scopes/repo-permission.test.ts`:

| scope string | expectation | cite |
|---|---|---|
| `repo:com.example.foo` | `collection == ["com.example.foo"]`, `action == [create,update,delete]` | `:7-12` |
| `repo:com.example.foo?action=create&action=update` | `action == [create, update]` | `:15-21` |
| `repo:*` | `collection == [*]`, all three actions | `:43-57` |
| `repo:*?action=create` | matches `{create, any collection}`; not `{update, …}` | `:31-41` |
| `repo:foo bar`, `repo:.foo`, `repo:bar.` | all nil | `:59-63` |
| `repo:com.example.foo?action=invalid` | nil | `:65-70` |
| `invalid`, `scope` | nil | `:72-75` |
| `repo:*?action=*`, `repo:invalid`, `repo?collection=invalid&action=invalid` | all nil | `:77-87` |

Canonicalisation, verbatim `:205-260` — every row is `parse → format`:

| input | canonical out |
|---|---|
| `repo:com.example.foo` | `repo:com.example.foo` |
| `repo:com.example.foo?action=create` | `repo:com.example.foo?action=create` |
| `repo:com.example.foo?action=create&action=update` | `repo:com.example.foo?action=create&action=update` |
| `repo:*?action=create&action=update&action=delete` | `repo:*` |
| `repo:com.example.foo?action=create&action=update&action=delete` | `repo:com.example.foo` |
| `repo:*?action=create` | `repo:*?action=create` |
| `repo:*?action=update` | `repo:*?action=update` |
| `repo?collection=*&action=update` | `repo:*?action=update` |
| `repo?collection=*&collection=com.example.foo&action=update` | `repo:*?action=update` |
| `repo?collection=*` | `repo:*` |
| `repo?collection=*&action=create&action=update&action=delete` | `repo:*` |
| `repo?collection=*&collection=com.example.foo` | `repo:*` |
| `repo?action=create&collection=com.example.foo` | `repo:com.example.foo?action=create` |
| `repo?collection=com.example.foo&action=create&action=update&action=delete` | `repo:com.example.foo` |
| `repo?action=create&collection=com.example.foo&collection=com.example.bar` | `repo?collection=com.example.bar&collection=com.example.foo&action=create` |

The last row pins three rules at once: two collections means **no positional
collapse**; the collection list is **sorted**; and `collection` still precedes
`action` because that is schema-declaration order, not alphabetical.

Matching (`:121-188`): `repo:com.example.foo?action=create` matches
`{create, com.example.foo}`, not `{update, com.example.foo}`;
`repo:*?action=create` matches `{create, com.example.bar}`, not `{delete, …}`;
a multi-action grant matches create+update but not delete.

`scopeNeeded({collection:"com.example.foo", action:.create})` →
`repo:com.example.foo?action=create` (`:87-93`). `scopeNeeded` does **not**
validate its input — `{collection:"invalid", action:.create}` →
`repo:invalid?action=create` (`:104-116`).

### 5.5 `rpc`

Source: `oauth-scopes/scopes/rpc-permission.ts:22-98`.

```swift
public enum LxmParam: Sendable, Hashable, Comparable {
    case any                                       // "*"
    case nsid(String)                              // rpc-permission.ts:22-24
}

public enum AudParam: Sendable, Hashable {
    case any                                       // "*"
    /// An atproto DID (`plc` or `web` only) plus a MANDATORY non-empty RFC 3986
    /// fragment — `isAtprotoDidRefAbsolute`, `packages/did/src/atproto.ts:230-235`,
    /// reached from `rpc-permission.ts:25-27`. Grammar and vectors: §4.1.
    case service(String)
}

public struct RpcPermission: ScopePermission {
    /// single, REQUIRED, NO DEFAULT. Omitting `aud` always fails the parse
    /// (rpc-permission.ts:67-70; test :58-62).
    public let aud: AudParam
    /// Positional key. multiple, required, no default.
    public let lxm: [LxmParam]

    public static let schema = ScopeParameterSchema(
        prefix: "rpc",
        positionalKey: "lxm",
        parameters: [
            .init(key: "lxm", arity: .multiple, isRequired: true,
                  normalize: { $0.contains("*") && $0.count > 1 ? ["*"] : Array(Set($0)).sorted() },
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            // rpc-permission.ts:25-27 — `value === '*' || isAtprotoDidRefAbsolute(value)`,
            // imported from `@atproto/did` (`packages/did/src/atproto.ts:230-235`).
            // NOT the generic DID validator: `aud=did:foo:bar#baz` must be nil.
            .init(key: "aud", arity: .single, isRequired: true,
                  validate: { $0 == "*" || AtprotoSyntax.isValidAtprotoDIDRefAbsolute($0) }),
        ]
    )

    /// `rpc:*?aud=*` is forbidden even though the memberwise init would accept
    /// it — the check lives in the parse path, not the initializer
    /// (rpc-permission.ts:86-88 → ScopeParseError.forbiddenParameterCombination).
    /// Keep that split: a caller constructing `RpcPermission(.any, [.any])`
    /// directly exercises a path upstream also leaves open (no test calls it).
    public init(aud: AudParam, lxm: [LxmParam]) { self.aud = aud; self.lxm = lxm }

    public struct Target: Sendable, Hashable {
        public let lxm: String
        public let aud: String
    }

    /// rpc-permission.ts:43-49. Both dimensions are exact-string; there is no
    /// prefix matching on `lxm`.
    public func matches(_ target: Target) -> Bool {
        switch aud {
        case .any: break
        case let .service(s): guard s == target.aud else { return false }
        }
        if lxm.contains(.any) { return true }
        return lxm.contains(.nsid(target.lxm))
    }
}
```

Vectors — `scopes/rpc-permission.test.ts`:

| scope string | expectation | cite |
|---|---|---|
| `rpc:com.example.service?aud=did:web:example.com%23service_id` | `aud == "did:web:example.com#service_id"`, `lxm == ["com.example.service"]` | `:7-13` |
| `rpc?lxm=com.example.method1&aud=*` | `{aud: *, lxm: [com.example.method1]}` | `:16-19` |
| `rpc?aud=*&lxm=com.example.method1&lxm=com.example.method2` | both lxm kept in order | `:71-81` |
| `rpc?aud=did:web:example.com%23service_id` | nil (no lxm) | `:49-52` |
| `rpc:?aud=did:web:example.com%23service_id` | nil — **empty positional is present-but-invalid, not absent** | `:53-55` |
| `rpc:com.example.method1` | nil (no aud) | `:61` |
| `rpc:com.example.method1?aud=did:web:example.com&lxm=com.example.method2` | nil — positional + named form of the same key | `:65-71` |
| `rpc?aud=*&lxm=*`, `rpc:*?aud=*` | both nil — "any audience + any method" is never a valid grant | `:96-99` |
| `rpc?aud=did:web:example.com` | nil (no lxm) | `:86-89` |
| `rpc?lxm=com.example.method1` | nil (no aud) | `:91-94` |
| `rpc:com.example.service` | nil | `:101-103` |
| `rpc:com.example.service?aud=invalid` | nil | `:105-109` |
| `rpc:invalid`, `rpc?lxm=invalid` | nil | `:111-114` |
| 21-case sweep incl. `rpc:*`, `rpc:foo.bar` (2-label NSID), `rpc:foo.bar.baz?aud=did:web`, `…?aud=did:plc:111%23service_id`, `…?aud=did:foo:bar`, `rpc:com.example.service?aud=…&invalid=param`, `notrpc:…`, and lxm in both positional and named form | all nil — **port element-for-element** | `:114-142` |

Three rows of that sweep now have **derivable reasons** rather than
"port it and don't ask", because `@atproto/did` is present (§4.1):

| sweep row | why it is nil |
|---|---|
| `…?aud=did:plc:111%23service_id` | fails `isDidPlc` twice over — length is not 32 (`methods/plc.ts:6`, `:13`) and `1` is not in the base32 alphabet `[a-z2-7]` (`plc.ts:15-17`, `:53-54`). **Not** "method-specific validation of an unknown shape" |
| `…?aud=did:foo:bar` | fails on TWO independent grounds: no `#` at all, so `isDidRefAbsolute` rejects at `did-ref.ts:14`; and `foo` is not in the closed method set `'plc' \| 'web'` (`atproto.ts:19`, `:27-29`). The fragment-bearing form `did:foo:bar#baz` is pinned false on the method ground alone at `tests/did-ref.test.ts:37` |
| `rpc:foo.bar.baz?aud=did:web` | bare `did:web` has no `#`, so `isDidRefAbsolute` rejects at `did-ref.ts:14` before the method check ever runs |
| `rpc:*?aud=did:web:example.com%23service_id` vs `{lxm:"com.example.anyMethod", aud:"did:web:example.com#service_id"}` | true | `:225-238` |
| `rpc:com.example.service?aud=…%23service_id` vs `aud:"did:example:456#service_id"` | false | `:192-203` |
| `RpcPermission("did:web:example.com#service_id", ["*","com.example.method1"])` → format | `rpc:*?aud=did:web:example.com%23service_id` | `:264-272` |

Canonicalisation `:279-316`:

| input | canonical out |
|---|---|
| `rpc:com.example.service?aud=did:web:example.com%23service_id` | unchanged |
| `rpc:com.example.service?aud=did:web:example.com#service_id` (bare `#`) | `…%23service_id` |
| `rpc?lxm=com.example.method1&lxm=com.example.method2&aud=*` | unchanged (2 lxm → query form, `lxm` before `aud`) |
| `rpc?lxm=…method1&lxm=…method2&lxm=*&aud=did:web:example.com%23service_id` | `rpc:*?aud=did:web:example.com%23service_id` |
| `rpc?aud=did:web:example.com%23foo&lxm=com.example.service` | `rpc:com.example.service?aud=did:web:example.com%23foo` (input key order discarded) |
| `rpc?lxm=com.example.method1&aud=did:web:example.com#foo` | `rpc:com.example.method1?aud=did:web:example.com%23foo` |
| `rpc?lxm=com.example.method1&aud=did:web:example.com%23bar` | `rpc:com.example.method1?aud=did:web:example.com%23bar` |
| `rpc:com.example.method1?&aud=*` | `rpc:com.example.method1?aud=*` (empty pair skipped) |

That last row is a **direct contradiction of Swan today**: `SwanCore.swift:218-226`
splits the query with `omittingEmptySubsequences: false` and rejects any
component lacking exactly one `=`, so `?&aud=*` is refused. It is fence vector
D10 (§7.3).

### 5.6 `space` — Swan's core surface

Source: `oauth-scopes/scopes/space-permission.ts:14-286`. This is the family
`bulleted.app` uses and the one Swan already has a divergent implementation of.

#### 5.6.1 The scope string that must parse

```
space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self
```

Traced through `parser.ts`: positional → `type = "app.bulleted.space"` (valid
NSID: 3 segments, name segment `space` is letters-only); `manage` →
`[create, update, delete]`; `action` → `[read_self]`; `authority` → default
`self` (`space-permission.ts:183`); `skey` → default `*` (`:189`);
`collection` → default `[]` (`:198`) — **no write targets**.

Canonical re-serialisation, in schema-declaration order
(type, authority, skey, collection, action, manage — `space-permission.ts:175-227`),
with `authority` / `skey` / `collection` elided as equal to their defaults:

```
space:app.bulleted.space?action=read_self&manage=create&manage=update&manage=delete
```

Note the **reordering**: the client sent `manage` before `action`; canonical
form emits `action` first. Any Swan-side string comparison against a stored
scope must compare canonical forms, not wire forms — except the refresh
equality check, §9-D7.

#### 5.6.2 Types — grant side (wildcard-capable) vs request side

The grant side cannot be a `SpaceURI`: `type`, `authority`, and `skey` all
admit `*`, and `authority` admits the unresolved sentinel `self`, none of which
`SpaceURI.init` will construct (`SwanSpaces.swift:44-51`). The **request** side
is exactly a space tuple plus an operation.

```swift
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
    case any                                       // "*"
    case nsid(String)                              // space-permission.ts:40-42
}

public enum SpaceAuthorityParam: Sendable, Hashable {
    case any                                       // "*"
    /// Wire value "self". NOT spelled `case self` — `.self` is a metatype
    /// expression in Swift and `x == .self` will not compile. The name also
    /// carries the fail-closed property: an UNRESOLVED self matches nothing.
    case unresolvedSelf
    case did(String)                               // space-permission.ts:47-51
}

public enum SpaceSkeyParam: Sendable, Hashable {
    case any                                       // "*"
    case key(String)                               // record-key syntax, :53-56
}

public enum SpaceCollectionParam: Sendable, Hashable, Comparable {
    case any                                       // "*"
    case nsid(String)                              // space-permission.ts:58-61
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
    }

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
```

`SpaceAction.allCases` **must** stay in declaration order
`read_self, read, create, update, delete` (`SPACE_ACTIONS`,
`space-permission.ts:14-20`) — that order is the serialisation order, which is
why `collection` sorts but `action` does not.

The request side. Upstream encodes four match arms as a TypeScript
discriminated union (`space-permission.ts:63-76`); a Swift enum makes the
switch exhaustive rather than a chain of `undefined` checks. Target types live
in `SwanCore` and carry `String`s only (§3):

```swift
public struct SpaceScopeTarget: Sendable, Hashable {
    public enum Operation: Sendable, Hashable {
        /// Whole-space read. Collection-independent (space-permission.ts:104-107).
        case read
        /// Own-repo read. Collection-independent (:108-110).
        case readSelf
        /// Record write. `collection` is REQUIRED here by construction —
        /// upstream makes it non-optional only in the write arm (:70-74).
        case write(RecordWrite, collection: String)
        /// Space-lifecycle op. Never checked against `action` or `collection` (:100-102).
        case manage(SpaceManageOp)
        /// The whole-space-read delegation exchange. See §6.2.
        ///
        /// CORRECTED: this was labelled "SWAN-SPECIFIC, no upstream analogue".
        /// That is FALSE, and the label came from searching `oauth-scopes`
        /// (which has no request-time layer at all) rather than `packages/pds`.
        /// Upstream states the exchange in prose and implements the split it
        /// rests on:
        ///   * `packages/pds/src/api/com/atproto/space/util.ts:104-107` —
        ///     "Reaching another member's repo takes a space credential, which
        ///     only the authority issues and only after deciding the holder may
        ///     read the space … A whole-space `read` grant is what an app
        ///     exchanges for such a credential (see getDelegationToken); it is
        ///     not itself one."
        ///   * `space/util.ts:109-126` (`assertSpaceRead`) implements the
        ///     own-repo-vs-whole-space split, and at `:118-124` returns the SAME
        ///     `RepoNotFound` error a genuinely absent repo gets — a deliberate
        ///     non-oracle, commented as such: "whether a given account holds a
        ///     repo in a space the caller cannot read is not the caller's
        ///     business."
        /// So Swan's operation is a HARDENING of an upstream concept, not an
        /// invention. That matters for §6.2: a fence justified as "we invented
        /// this, so we may shape it freely" invites deletion by a later reader,
        /// where a fence justified as "upstream says a whole-space read grant is
        /// exchangeable but is not itself a credential" does not. Re-derive
        /// §6.2's rules clause-by-clause against `assertSpaceRead` before
        /// keeping any clause on "upstream has nothing here" grounds.
        case delegationExchange

        public enum RecordWrite: Sendable, Hashable {
            case create, update, delete
            var asAction: SpaceAction {
                switch self {
                case .create: return .create
                case .update: return .update
                case .delete: return .delete
                }
            }
        }
    }

    public let type: String        // concrete NSID
    public let authority: String   // concrete DID
    public let skey: String        // concrete record key
    public let operation: Operation
}
```

#### 5.6.3 Matching — full Swift

```swift
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

        case .read:
            // Reads are collection-independent (:104-107).
            return action.contains(.read)

        case .readSelf:
            // `read` implies `read_self`, but not the reverse (:108-110).
            return action.contains(.read) || action.contains(.readSelf)

        case let .write(verb, collection):
            // Writes need BOTH the verb AND a collection target (:112-115).
            guard action.contains(verb.asAction) else { return false }
            return collectionAllows(collection)

        case .delegationExchange:
            // The SINGLE most dangerous arm in this file.
            //
            // CORRECTED: an earlier draft said "upstream has no such rule at
            // all". That is false, and §6.2 withdraws it. Upstream's rule is
            // LOOSER, not absent: its read arm is collection-independent
            // (oauth-scopes/src/scopes/space-permission.ts:104-107) and `read`
            // is in the default action set (:207-211), so upstream exchanges a
            // credential for both a bare `space:<type>` and a
            // collection-qualified read — see
            // pds/src/api/com/atproto/space/getDelegationToken.ts:22 and the
            // prose at pds/src/api/com/atproto/space/util.ts:106-107.
            // Swan's arm is a HARDENING of a real upstream rule.
            //
            // It must reproduce, exactly, what SwanCore.swift:270-277 enforces
            // today — NOT a relaxed paraphrase of it:
            //
            //   parameters.count == 3
            //   Set(parameters.keys) == ["authority", "skey", "action"]
            //   parameters["action"] == "read"        // literal, single-valued
            //
            // The first draft wrote `action.contains(.read) && collection.isEmpty`,
            // which under the new defaults (`action` defaults to
            // [read,create,update,delete], `collection` to [], `skey` to `*`)
            // newly ADMITS all three of these, every one of which is rejected
            // today — i.e. a bare `space:<type>` string with no query at all
            // becomes a whole-space read delegation over every space of that
            // type owned by the subject:
            //
            //   space:com.x.y?authority=did:plc:abc
            //       -> bare; defaulted action contains .read      -> WAS false
            //   space:com.x.y?authority=did:plc:abc&skey=*&action=read&action=create
            //       -> duplicate key; rejected at SwanCore.swift:224 -> WAS false
            //   space:com.x.y?authority=…&action=read&manage=delete
            //       -> hasAction != hasManage rejects at :243        -> WAS false
            //
            // The `wasStated` provenance witness (§4.6) is what makes the
            // literal-vs-defaulted distinction expressible at all.
            return isExactReadOnlyDelegationGrant
        }
    }

    /// The delegation fence, stated once. Every clause maps to a clause of
    /// `permitsWholeSpaceRead` (`SwanCore.swift:270-277`); none may be dropped.
    ///
    /// `manage` is checked even though a manage grant cannot satisfy a read:
    /// today's `hasAction != hasManage` (`SwanCore.swift:243`) makes an
    /// action+manage grant unparseable, so admitting one here would be a
    /// widening even if the manage list is never consulted.
    /// **This fence is where the retired `isIssuableQualified` gate's job now
    /// lives, and it must not be re-litigated once that gate is deleted.**
    /// §9-Q9 removes `isIssuableQualified` as a semantic client-metadata gate
    /// (§4.8's layer table). The dangers it was reaching for were real —
    /// a `space:` grant whose `authority` defaulted to `self`, whose `skey` was
    /// `*`, or whose `action` list was defaulted rather than stated, amplifying
    /// into something far broader than the user believed they consented to. Q9
    /// moves those refusals from layer 1 (registration, which grants nothing and
    /// therefore cannot see what is being asked) to layer 4 (the resource plane,
    /// which has the concrete operation in front of it). This predicate and
    /// `allowsSpaceListing` (§6.1) ARE that layer-4 handling. Each of the four
    /// clauses below rejects one of the exact amplification shapes the old gate
    /// was blocking, which is why every one of them tests `wasStated` — a
    /// PROVENANCE test, not a value test. A defaulted `[read]` and a stated
    /// `[read]` carry the same value and must not carry the same authority.
    /// Deleting a clause here re-opens a hole that nothing else closes.
    private var isExactReadOnlyDelegationGrant: Bool {
        // 1. `action` was named explicitly, and names exactly [read].
        //    Not "contains read"; not a defaulted list.
        //    <- SwanCore.swift:277 `parameters["action"] == "read"`
        guard scopeParameters.wasStated("action"), action == [.read] else { return false }
        // 2. The grant names no collection at all — a collection-qualified
        //    grant (INCLUDING `collection=*`) must never be amplifiable into a
        //    credential that reads every member repository.
        //    <- SwanCore.swift:246-257 (doc comment) and :279 (key-set equality)
        guard collection.isEmpty, !scopeParameters.wasStated("collection") else { return false }
        // 3. No `manage` list. Today `hasAction != hasManage` (:243) makes an
        //    action+manage grant unparseable, so admitting one here would widen
        //    even though the manage list is never consulted for a read.
        guard manage.isEmpty, !scopeParameters.wasStated("manage") else { return false }
        // 4. `authority` and `skey` were both named.
        //    <- SwanCore.swift:279 `Set(keys) == ["authority","skey","action"]`
        //       and :243 `requiredKeys == ["authority","skey"]`
        return scopeParameters.wasStated("authority") && scopeParameters.wasStated("skey")
    }

    /// space-permission.ts:118-123. `.any` is exact membership in the set, not
    /// a glob. An EMPTY collection list allows nothing.
    private func collectionAllows(_ collection: String) -> Bool {
        if self.collection.contains(.any) { return true }
        return self.collection.contains(.nsid(collection))
    }

    public var hasCollections: Bool { !collection.isEmpty }          // :125-127
    public var isSelfAuthority: Bool { authority == .unresolvedSelf } // :148-150
}
```

#### 5.6.4 Issuance-time rewrites (both pure; neither does I/O)

```swift
extension SpacePermission {
    /// space-permission.ts:134-146. No-op when the grant already names
    /// collections (including `collection=*`) or the declaration list is empty.
    public func withDefaultCollections(_ collections: [SpaceCollectionParam]) -> SpacePermission {
        guard !hasCollections, !collections.isEmpty else { return self }
        return SpacePermission(type: type, authority: authority, skey: skey,
                               collection: collections, action: action, manage: manage)
    }

    /// space-permission.ts:156-166. The matcher is context-free and cannot do
    /// this itself; the caller supplies the granting user's DID at token mint
    /// (§6.4).
    public func withResolvedAuthority(_ userDID: String) -> SpacePermission {
        guard authority == .unresolvedSelf else { return self }
        return SpacePermission(type: type, authority: .did(userDID), skey: skey,
                               collection: collection, action: action, manage: manage)
    }
}
```

#### 5.6.5 The five independent elision rules

`format` applies five *separately specified* rules. The Rust reference calls
this the single easiest thing to get wrong (`space_permission.rs:596-646`):

| param | elided when | never elided when |
|---|---|---|
| `type` | never (required, always positional) | — |
| `authority` | `== .unresolvedSelf` | `== .any` — eliding `authority=*` would silently **narrow** an any-authority grant to the user's own |
| `skey` | `== .any` | a concrete key |
| `collection` | `== []` | any non-empty list (sorted; `*` collapses the list) |
| `action` | set-equals `SPACE_DEFAULT_ACTIONS` | anything else, filtered into `SPACE_ACTIONS` order (`:212-214`) |
| `manage` | `== []` | anything else, filtered into `SPACE_MANAGE_OPS` order (`:221-226`) |

A naive "omit anything equal to the type's default value" formatter violates
row 2 and is a grant-narrowing bug, not a cosmetic one.

#### 5.6.6 `scopeNeeded`

```swift
extension SpacePermission {
    /// space-permission.ts:252-281. For a manage request, `action` is pinned to
    /// [.readSelf] — the narrowest expressible action — rather than omitted,
    /// because omitting it would default to the full record action list and
    /// suggest read/write over every record (:258-260).
    ///
    /// FOUR arms, not upstream's three. `SpaceScopeTarget.Operation` carries a
    /// Swan-specific fifth case, `.delegationExchange`, and `requireSpace`
    /// (§6.1) calls `scopeNeeded` for EVERY target including that one. The first
    /// draft specified only upstream's `space-permission.ts:252-281` and left
    /// `scopeNeeded(.delegationExchange)` undefined — an unhandled switch case
    /// in a `throws` function reached on every delegation denial.
    ///
    /// `.delegationExchange` must emit the string that
    /// `isExactReadOnlyDelegationGrant` (§5.6.3) actually accepts — all four of
    /// `authority`, `skey`, `action=read` stated, and no `collection`:
    ///
    ///     space:<type>?authority=<did>&skey=<skey>&action=read
    ///
    /// Note this is byte-identical to the `.read` arm's output for the same
    /// tuple, and that is correct: the two differ in what a GRANT must look
    /// like, not in what the caller should have asked for.
    public static func scopeNeeded(for target: SpaceScopeTarget) throws(ScopeParseError) -> String
}
```

**`scopeNeeded` must never leak a `ScopeParseError` out of a denial.** It does
not validate its input (§5.4, ported from `repo-permission.test.ts:104-116`), so
its final `canonicalString()` throws `.notAScopeToken` (§4.5) whenever
`target.skey` or `target.collection` carries a byte the encoders leave raw. See
§6.1's `requireSpace` for the mandatory degradation.

#### 5.6.7 Vectors — `scopes/space-permission.test.ts`

Parse. Defaults when omitted: `authority = self`, `skey = *`, `collection = []`,
`action = [read, create, update, delete]`, `manage = []` (`:4-5`, `:10-20`).

| # | input | expectation | cite |
|---|---|---|---|
| SP1 | `space:com.atmoboards.forum` | type set; authority `self`; skey `*`; collection `[]`; action `[read,create,update,delete]`; manage `[]` | `:10-20` |
| SP2 | `space:*?authority=did:plc:abc123xyz` | type `*`, authority `did:plc:abc123xyz` | `:22-29` |
| SP3 | `space:com.atmoboards.forum?authority=*` | authority `*` | `:31-36` |
| SP4 | `space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create&action=update` | all five fields as written; action `[create,update]` | `:38-48` |
| SP5 | `space:com.atmoboards.forum?collection=*` | action still the full default list | `:50-55` |
| SP6 | `space:com.atmoboards.forum?action=read_self&collection=*` | action `[read_self]` | `:57-62` |
| SP7 | `space:com.atmoboards.forum?manage=update&manage=delete` | manage `[update, delete]` | `:64-69` |
| SP8 | `space:com.example.x?manage=bogus` | **nil** | `:71-75` |
| SP9 | `space:com.atmoboards.forum` | collection `[]` | `:77-80` |
| SP10 | `space:foo bar` | **nil** | `:82-85` |
| SP11 | `space:short` | **nil** — NSID needs ≥3 labels | `:84` |
| SP12 | `space:*?authority=not-a-did` | **nil** | `:87-92` |
| SP13 | `space:*?authority=did:` | **nil** | `:91` |
| SP14 | `space:com.example.x?action=bogus` | **nil** | `:94-98` |
| SP15 | `space:com.example.x?collection=not_an_nsid` | **nil** | `:100-106` |
| SP16 | `space:com.example.x?skey=` | **nil** — empty skey | `:108-112` |
| SP17 | `space:com.example.x?skey=self` | skey `self` | `:114-126` |
| SP18 | `space:com.example.x?skey=3jui7kd54zh2y` | accepted | `:117` |
| SP19 | `space:com.example.x?skey=a.b-c_d~e:f` | accepted | `:118` |
| SP20 | `space:com.example.x?skey=` + `"x"×512` | accepted | `:119` |
| SP21 | `space:com.example.x?skey=hello%20world` | **nil** | `:128-143` |
| SP22 | `space:com.example.x?skey=.` | **nil** | `:131` |
| SP23 | `space:com.example.x?skey=..` | **nil** | `:132` |
| SP24 | `space:com.example.x?skey=a%2Fb` | **nil** | `:133` |
| SP25 | `space:com.example.x?skey=a%23b` | **nil** | `:134` |
| SP26 | `space:com.example.x?skey=` + `"x"×513` | **nil** | `:135` |
| SP27 | `repo:com.example.x` | **nil** for the space parser | `:145-148` |
| SP28 | `whatever` | **nil** | `:147` |

Matching. Base target `{type: com.atmoboards.forum, authority: did:plc:abc,
skey: default}`; `anyAuthority(rest)` = `space:com.atmoboards.forum?authority=*`
+ `rest`.

| # | grant | request | expected | cite |
|---|---|---|---|---|
| M1 | `?authority=*` | `.read` | true | `:241-244` |
| M2 | `?authority=*&action=create` | `.read` | false | `:246-249` |
| M3 | `?authority=*&action=read` | `.read` | true | `:251-253` |
| M4 | `?authority=*&action=read` | `.write(.create, com.atmoboards.thread)` | false | `:254-260` |
| M5 | `?authority=*` (default actions, no collection) | `.write(.create, com.atmoboards.thread)` | **false** — omitted collection blocks all writes even though `create` is in the action list | `:263-272` |
| M6 | `?authority=*&collection=*` | `.write(.create, any.collection.name)` | true | `:274-283` |
| M7 | `?authority=*&collection=*` | `.write(.update, another.one.here)` | true | `:283-289` |
| M8 | `?authority=*&action=read&manage=update` | `.manage(.update)` | true | `:292-295` |
| M9 | same grant | `.manage(.delete)` | false | `:296` |
| M10 | `?authority=*&action=read` | `.manage(.update)` | false | `:299-302` |
| M11 | `?authority=*` (defaults) | `.manage(.update)` | false | `:304-307` |
| M12 | `?authority=*&action=read` | `.readSelf` | **true** — read implies read_self | `:309-312` |
| M13 | `?authority=*&action=read_self` | `.readSelf` | true | `:314-316` |
| M14 | `?authority=*&action=read_self` | `.read` | **false** — not symmetric | `:317` |
| M15 | `?authority=*&action=read_self&collection=com.atmoboards.thread` | `.readSelf` | true — reads are not constrained by collection | `:320-327` |
| M16 | `?authority=*&collection=com.atmoboards.thread&action=create` | `.write(.create, com.atmoboards.thread)` | true | `:329-339` |
| M17 | same grant | `.write(.create, com.atmoboards.reply)` | false | `:340-346` |
| M18 | `space:*?authority=did:plc:abc` | `.read` on base target | true | `:349-351` |
| M19 | same | `.read` on type `com.example.different` | true | `:352-358` |
| M20 | `space:com.atmoboards.forum?authority=did:plc:abc&skey=default` | `.read`, authority `did:plc:other` | false | `:361-373` |
| M21 | same | `.read`, skey `other` | false | `:375-377` |
| M22 | `space:com.atmoboards.forum` (unresolved `self`) | `.read` | **false — fail closed** | `:380-384` |
| M23 | `space:com.atmoboards.forum?action=read` after `.withResolvedAuthority("did:plc:abc")` | `.read` | true | `:386-390` |
| M24 | same resolved grant | `.read`, authority `did:plc:other` | false | `:391-397` |

`scopeNeeded` (`:151-223`) — the string a denial names:

| target | expected scope string | cite |
|---|---|---|
| `{com.atmoboards.forum, did:plc:abc, default, action:read}` | `space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read` | `:152-162` |
| `… + collection:com.atmoboards.thread, action:create` | `space:com.atmoboards.forum?authority=did:plc:abc&skey=default&collection=com.atmoboards.thread&action=create` | `:164-175` |
| `…, manage:update` (no action given) | `space:com.atmoboards.forum?authority=did:plc:abc&skey=default&action=read_self&manage=update` — note `read_self`, deliberately *not* the default action list | `:177-187` |

Round-trip (`:401-414`): `space:com.atmoboards.forum` → itself; and
`space:com.atmoboards.forum?authority=did:plc:abc123xyz&skey=default&collection=com.atmoboards.thread&action=create`
→ itself byte-for-byte (colons in the DID stay un-escaped, `:411-412`).

`withResolvedAuthority` (`:416-438`): `self` → given DID (`:417-422`); a
concrete authority returned *identical* (`:424-430`); `authority=*` returned
identical (`:432-437`).

`withDefaultCollections` (`:440-490`): a bare grant +
`[com.atmoboards.thread, com.atmoboards.reply]` → both, in that order, and
writes to `com.atmoboards.thread` then match (`:441-464`); a grant already
naming a collection is unchanged (`:466-474`); `collection=*` unchanged
(`:476-484`); an empty default list is a no-op (`:486-489`).

**The two highest-value properties, ported as properties not cases:**

1. **Anti-widening** (`:189-222`). For each of `{action:read}`,
   `{action:read_self}`, `{action:create, collection:com.atmoboards.thread}`,
   `{manage:delete}` — `scopeNeeded` → parse → `matches(target) == true`,
   **and** when the op named no collection the reparsed scope must **not** match
   `.write(.create, "com.atmoboards.thread")`.
2. **Second-format idempotence + `authority=*` survival** — from the Rust
   reference, which upstream does not state:
   `format(parse(s)) == format(parse(format(parse(s))))`, and specifically that
   **`authority=*` survives the round trip while `skey=*` is dropped**
   (`space_permission.rs:1058-1126`, esp. `:1064-1073`). This is the single
   highest-value non-upstream vector in the whole suite.

**Swan-specific vector, from §5.6.1:**

```
space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self
  → parses; type .nsid("app.bulleted.space"), authority .unresolvedSelf,
    skey .any, collection [], action [.readSelf], manage [.create,.update,.delete]
  → canonicalScopeString() ==
    "space:app.bulleted.space?action=read_self&manage=create&manage=update&manage=delete"
  → matches(.manage(.update)) on ANY concrete space   == false  (unresolved self)
  → after .withResolvedAuthority(userDID),
    matches(SpaceScopeTarget(type: "app.bulleted.space", authority: userDID,
                             skey: <any>, operation: .manage(.update)))  == true
  → matches(.write(.create, "app.bulleted.item"))     == false  (collection == [])
  → matches(.read)                                    == false  (action == [.readSelf])
  → matches(.readSelf)                                == true
```

### 5.7 `include` — the family Swan has no equivalent of

Source: `oauth-scopes/scopes/include-scope.ts:27-226`, consumed by
`oauth-provider/lexicon/lexicon-manager.ts` and `lexicon-getter.ts`.

`IncludeScope` is **not** a permission. It does not implement `Matchable`
(`include-scope.ts:22-26`) and has no `matches`. It names a *lexicon-defined
permission set* that must be fetched and expanded into concrete
`repo:` / `rpc:` / `space:` scopes before anything can be matched against it.

**Phase 1 ships the type, not the resolver** (§9-D4): `include:` parses, is
persisted verbatim, and grants nothing at request time. Phase 2 is
§5.7.3-§5.7.6.

**Phase 2 is a PORT, not speculative engineering.** This sentence is where a
reader lands first, so it has to be here rather than buried in §5.7.4. The
earlier draft of this document recorded `@atproto/lex-resolver` as absent from
the reference checkout and treated Phase 2 as a design Swan would have to
invent. That was an artifact of a truncated export, not a fact about upstream.
The package is present at the pin: `packages/lex/lex-resolver/src/lex-resolver.ts`,
**577 lines**, actively consumed by `oauth-provider` (six source files import
it), with a published four-stage contract documented in its own header
(`lex-resolver.ts:184-191`) and a **second, independent implementation**
corroborating every step (`packages/lexicon-resolver/src/{lexicon,record}.ts`).
Phase 2's cost is the cost of porting a specified protocol with a verification
contract and a test corpus — not the cost of designing a trust model from
scratch. Note that this cuts the other way too: a port has a **correctness
standard** a design does not, and §5.7.4's proof-verification steps are not
optional garnish on the fetch.

#### 5.7.1 Type and vectors (Phase 1)

```swift
public struct IncludeScope: Sendable, Hashable {
    /// Positional key. single, required, no default.
    public let nsid: String
    /// single, not required, NO DEFAULT (absent stays absent — this is why
    /// `ScopeParameterSchema.parse` must omit the key rather than store an
    /// empty array). include-scope.ts:184-188.
    public let aud: AudParam?

    public static let schema = ScopeParameterSchema(
        prefix: "include",
        positionalKey: "nsid",
        parameters: [
            .init(key: "nsid", arity: .single, isRequired: true,
                  validate: AtprotoSyntax.isValidNSID),
            // include-scope.ts:16, :184-188 — same `@atproto/did` predicate as
            // `rpc:`'s `aud` (§5.5): `isAtprotoDidRefAbsolute`,
            // `packages/did/src/atproto.ts:230-235`. Methods are restricted to
            // `plc` and `web` (`atproto.ts:19`); the fragment is mandatory and
            // non-empty (`did-ref.ts:14-15`).
            .init(key: "aud", arity: .single, defaultValue: nil,
                  validate: { $0 == "*" || AtprotoSyntax.isValidAtprotoDIDRefAbsolute($0) }),
        ]
    )
}
```

| scope string | expectation | cite |
|---|---|---|
| `include:com.example.bar` | `{nsid: com.example.bar, aud: nil}` | `:12-19` |
| `include:com.example.baz?aud=did:web:example.com%23my_service` | `aud == .service("did:web:example.com#my_service")` | `:22-30` |
| `include:com.example.baz?aud=did:web:example.com#my_service` | same — a bare `#` in a query string is a literal | `:32-39` |
| `include?nsid=com.example.baz` | named form of the positional key | `:41-48` |
| `include?aud=did:web:example.com%23my_service&nsid=com.example.baz` | both named, any order | `:50-59` |
| rejects (**port all 17**): `""`, `repo:com.example.baz`, `include`, `include#`, `include:`, `include:#`, `include:&`, `include:com..example`, `include:com`, `include:com.example`, `include:9com.example.foo`, `include:com.example.-bar`, `include:invalid^nsid`, `include:nsid`, `include:com.example.baz?aud=`, `include:com.example.baz?aud=did:web:example.com`, `include:com.example.baz?aud=invalid^did` | all nil | `:66-87` (18 array entries, `:86`/`:87` duplicated → **17 distinct**) |
| `IncludeScope("com.example.foo")` → format | `include:com.example.foo` | `:96-100` |
| `IncludeScope("com.example.foo", "did:web:example.com#my_service")` → format | `include:com.example.foo?aud=did:web:example.com%23my_service` | `:101-110` |

Row 16 of the rejects — **`include:com.example.baz?aud=did:web:example.com` is
rejected**, at `include-scope.test.ts:85` — **corroborates** the mandatory
`#fragment` in `AtprotoSyntax.isValidAtprotoDIDRefAbsolute`. Its status has
changed: in the earlier draft this was evidence of last resort, the single
consumer-side vector from which the whole validator was being reverse-engineered.
It is now a conformance check against a rule stated directly in the source —
`did-ref.ts:14` (`hashIndex === -1` → reject). Keep the vector; it is cheap and
it fails loudly if the port drops the check. Do not keep the framing that made
it load-bearing.

#### 5.7.2 Phase-1 behaviour, asserted explicitly

An `include:` scope in a granted set contributes **zero** capability. Every
`allows*` returns false for it; `SwanScopePermissions` logs at `.warn` once per
construction that an `include:` was held but not resolved. The acceptance test
asserts this directly (§7.4 Stage 6) — a silently-dropped `include:` is
indistinguishable from a bug at 3am.

**The user must be told the same thing the log is told (§9-Q7).** A `.warn` line
reaches an operator; it does not reach the person deciding whether to authorize.
An unresolved Phase-1 `include:` therefore carries a mandatory consent string,
and this is the ONE canonical wording — the grammar side and the UI side must
not drift into two:

> **Requested permission set `<nsid>`.** Swan does not currently grant
> capabilities derived from this set.

Two constraints on it, both deliberate:

1. **It is shown, not suppressed.** The tempting alternative — omit an
   `include:` from the consent screen because it grants nothing — produces a
   consent screen that disagrees with the token: the scope IS stored verbatim,
   IS returned in the token response, and WILL begin granting capabilities the
   day Phase 2 ships, without a fresh consent. Showing "requested but not
   granted" is the only rendering that stays true across that transition.
2. **It is a semantic string, not the raw scope text.** Upstream's consent
   renderer is semantic throughout — `oauth-provider-ui/src/components/utils/scope-description.tsx`
   resolves an `include:` to its permission set and describes what the set
   actually contains (`:158-161`). Swan is not required to port the React UI,
   but it is required to have a semantic description for every permission it
   can actually grant, plus this explicit treatment of the one it can parse and
   cannot yet grant. Raw scope text stays available as advanced detail beneath
   the semantic line, never as a substitute for it.

The same wording governs the empty-expansion case in §5.7.5's failure matrix,
where a Phase-2 `include:` resolves successfully but every entry is dropped.

#### 5.7.3 Phase 2 — expansion (pure, given a permission-set document)

**The whole lexicon→scope-syntax translation layer is a named upstream class,
and it is not optional.** Upstream does **not** build a `ScopeStringSyntax` here.
It builds a second, different `ScopeSyntax` implementation,
`LexPermissionSyntax` (`oauth-scopes/lib/syntax-lexicon.ts:9-66`), which exists
for four behaviours the first draft of this spec elided into a `{ /* … */ }`
stub. Implement §5.7.3 without them and **not one upstream `buildPermissions`
vector passes**, while two upstream *rejections* invert into grants:

1. **`spaceType` → `type` remap** (`syntax-lexicon.ts:24-31`). The doc comment is
   explicit: "JSON spells the space type as `spaceType`, since `type` is taken by
   the permission discriminator. The scope string calls it `type`." Every space
   fixture in the upstream suite uses `spaceType:` —
   `include-scope.test.ts:639-654` expects
   `{resource:'space', spaceType:'com.example.calendar.group', action:[…]}` →
   `['space:com.example.calendar.group']`. Without the remap, `type` is required
   (§5.6.2) and absent, so `parse` throws `.missingRequiredParameter` and **no
   space permission is ever expanded**.
2. **Reserved-key filtering** (`:24, :33, :34`, and `keys()` at `:42-48`, which
   yields only keys whose `get()` is defined). Every upstream fixture carries
   `type: 'permission'` and `resource: 'repo'|'space'|'rpc'`
   (`include-scope.test.ts:450-456`). Under §4.6's unknown-key rule
   (porting `parser.ts:105-107`) either key kills the whole entry, so **every**
   entry is dropped.
3. **The scalar-vs-array tri-state — a security widening, not a drop.**
   `syntax-lexicon.ts:50-61`: `getSingle` returns **`null`** when the value is an
   array; `getMulti` returns **`null`** when it is not; `parser.ts:121-122` turns
   either `null` into a whole-entry rejection. Upstream has a test for it:
   `include-scope.test.ts:494-508` rejects a repo entry whose `collection` is the
   *scalar* `'com.example.calendar.event'` where an array is required → `[]`.
   Stringify scalars into a one-element array and that entry expands into a
   **live `repo:` create/update/delete grant**.
   (The companion fixture at `:510-524`, `action: 'all'`, is *not* a widening —
   `'all'` fails `RepoAction`'s `validate` either way — but the mechanism it
   tests is the same one, and only one of the two needs to be exploitable.)
4. **`ParamValue = string | number | boolean`** (`lib/syntax.ts:1`) — scalars are
   genuinely non-String (`inheritAud: true` is a boolean), which is why the
   adapter needs an explicit typed value rather than a stringify.

```swift
/// Mirrors LexiconPermissionSet (oauth-scopes/lib/lexicon.ts:14-21) INCLUDING
/// the `type` discriminator, which `lexicon-manager.ts:126-129` keys its
/// "not a permission set" rejection off. Dropping it (as the first draft did)
/// makes that rejection unimplementable.
public struct LexiconPermissionSet: Sendable, Equatable, Decodable {
    /// Must decode to exactly "permission-set" (lexicon.ts:15).
    public let type: String
    public let permissions: [LexiconPermission]
    public let title: String?
    public let detail: String?
}

/// `ParamValue = string | number | boolean` (lib/syntax.ts:1), plus the array
/// form. The ARITY IS PART OF THE VALUE and must not be erased — see gate 3
/// above. Do NOT collapse `.scalar` and a one-element `.list`.
public enum LexiconValue: Sendable, Equatable, Decodable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case list([LexiconValue])

    /// The stringification `ScopeParameterSchema` consumes, applied only AFTER
    /// arity has been checked.
    var scalarText: String? {
        switch self {
        case let .string(s): return s
        case let .number(n): return n == n.rounded() ? String(Int(n)) : String(n)
        case let .bool(b): return b ? "true" : "false"
        case .list: return nil
        }
    }
}

/// A permission entry as it appears in lexicon JSON (lib/lexicon.ts:6-10).
/// `type` and `resource` are the two reserved discriminators; `fields` holds
/// EVERYTHING ELSE, `spaceType` included, and must NOT contain `type` or
/// `resource` — see `LexPermissionSyntax` below, which is what enforces it.
public struct LexiconPermission: Sendable, Equatable, Decodable {
    /// Must decode to exactly "permission" (lexicon.ts:7).
    public let type: String
    public let resource: String
    public let fields: [String: LexiconValue]
}

/// Port of `oauth-scopes/lib/syntax-lexicon.ts:9-66`. The ONLY adapter from
/// lexicon JSON into the schema layer. It is a second `ScopeSyntax`
/// implementation, not a `ScopeStringSyntax` — there is no scope string here to
/// lex, and manufacturing one would re-introduce the encoding round-trip.
public struct LexPermissionSyntax: Sendable {
    public let permission: LexiconPermission

    public var prefix: String { permission.resource }        // :14-16
    public var positional: String? { nil }                   // :18-20

    /// :22-40. Reserved-key filtering plus the `spaceType` remap.
    private func get(_ key: String) -> LexiconValue? {
        if key == "type" {
            // :24-31 — only `space` surfaces a `type`, sourced from `spaceType`.
            guard permission.resource == "space" else { return nil }
            return permission.fields["spaceType"]
        }
        if key == "resource" { return nil }                  // :33
        if key == "spaceType" { return nil }                 // :34
        return permission.fields[key]                        // :37-39
    }

    /// :42-48. Surface keys only — `spaceType` is yielded as `type` for a space,
    /// and any key whose `get()` is nil is omitted entirely. This is what makes
    /// §4.6's unknown-key rejection safe against `type` / `resource`.
    public func keys() -> [String] {
        let isSpace = permission.resource == "space"
        return permission.fields.keys.compactMap { key in
            let surfaceKey = (isSpace && key == "spaceType") ? "type" : key
            return get(surfaceKey) != nil ? surfaceKey : nil
        }
    }

    /// :50-54. `.rejected` <-> upstream `null`: present, but an ARRAY where a
    /// single value is required. `.absent` <-> `undefined`.
    public func getSingle(_ key: String) -> ScopeParameterBag.SingleLookup {
        switch get(key) {
        case .none: return .absent
        case .some(.list): return .repeated([])     // parser.ts:121-122 -> reject
        case let .some(value): return value.scalarText.map { .present($0) } ?? .absent
        }
    }

    /// :56-61. `nil` == absent; `.some(nil)` (modelled as `.rejected` below)
    /// == present but NOT an array, which parser.ts:121-122 rejects.
    public enum MultiLookup: Sendable, Equatable { case absent, rejected, values([String]) }

    public func getMulti(_ key: String) -> MultiLookup {
        switch get(key) {
        case .none: return .absent
        case let .some(.list(items)):
            let texts = items.compactMap(\.scalarText)
            return texts.count == items.count ? .values(texts) : .rejected
        case .some: return .rejected            // scalar where an array is required
        }
    }
}

/// The concrete, matchable result of expanding an include.
public enum IncludedPermission: Sendable, Equatable {
    case repo(RepoPermission)
    case rpc(RpcPermission)
    case space(SpacePermission)
    /// There is deliberately NO `.include` case: a permission set cannot
    /// contain another include (include-scope.ts:73-111 has no such branch), so
    /// expansion is structurally depth-1 and needs no cycle detection. Positive
    /// control: grepped include-scope.ts and lexicon-manager.ts for
    /// "recursion"/"depth" — zero hits.
}

extension IncludeScope {
    /// include-scope.ts:53-71. Three gates per entry, all silent-skip on
    /// failure — an unusable entry never fails the whole set.
    public func expand(_ set: LexiconPermissionSet) -> [IncludedPermission] {
        set.permissions.compactMap { entry in
            // Gate 1: only repo / space / rpc survive. blob, account, identity
            // and anything unknown are dropped (include-scope.ts:80-110).
            guard let syntax = lexSyntax(for: entry) else { return nil }
            // Gate 2: the entry must parse as its family. A malformed
            // collection/action drops the entry, it does not throw (:64-65).
            guard let permission = IncludedPermission(syntax) else { return nil }
            // Gate 3: namespace authority (below).
            guard isAllowed(permission) else { return nil }
            return permission
        }
    }

    /// include-scope.ts:88-108, the `rpc` special cases:
    ///  - an entry naming a concrete `aud` (anything but `*`/absent) is
    ///    rejected outright (:91-93);
    ///  - an entry with `inheritAud: true`, no `aud`, and a non-nil `self.aud`
    ///    has this include's own `?aud=` spliced in (:98-105).
    ///
    /// Returns the ADAPTER, not a scope string. `ScopeParameterSchema` gains a
    /// `parse(_ syntax: LexPermissionSyntax)` overload whose only difference
    /// from the `ScopeStringSyntax` overload is that it consults
    /// `getSingle`/`getMulti`/`keys()` on the adapter — every rejection rule
    /// (unknown key, repeated single, empty multi, validate, required) is the
    /// same code path, per `parser.ts:101-160` being generic over `ScopeSyntax`.
    private func lexSyntax(for entry: LexiconPermission) -> LexPermissionSyntax? { /* … */ }

    /// include-scope.ts:144-174. Strips this include's NSID after the LAST dot
    /// and requires the candidate to share that exact prefix including the dot.
    public func isParentAuthorityOf(_ other: String) -> Bool {
        // A bare wildcard is ALWAYS rejected — a permission set may not grant
        // "everything" (:145-147). Pinned for rpc (test :428-442) and for space
        // type (test :691-704, "too broad for a permission-set").
        guard other != "*" else { return false }
        guard let lastDot = nsid.lastIndex(of: ".") else {
            // Upstream THROWS here — "this is a security feature, let's be
            // strict about it" (:155-157). In Swift, return false and surface
            // the malformed NSID at parse time instead; `nsid` was already
            // validated as an NSID, so this branch is unreachable.
            return false
        }
        // UTF-8 byte units THROUGHOUT. The first draft mixed
        // `nsid.distance(from:to:)` (Character distance) with `other.utf8.count`
        // (byte count). Safe for ASCII NSIDs, but `other` is an arbitrary string
        // from a lexicon document at this point — gate 3 runs BEFORE family
        // validation is guaranteed for every field — and this function is
        // `public`, so it can be called on unvalidated input. Upstream calls it
        // "a security feature" (:155-157); a unit mismatch inside one is worth
        // removing on sight rather than arguing is unreachable.
        let groupPrefixEnd = nsid.utf8.distance(from: nsid.utf8.startIndex,
                                                to: lastDot.samePosition(in: nsid.utf8)!)
        guard groupPrefixEnd < other.utf8.count - 1 else { return false }    // :160-162
        return other.utf8.starts(with: nsid.utf8.prefix(groupPrefixEnd + 1)) // :167-171
    }

    /// include-scope.ts:119-137. Which NSIDs get checked differs per family:
    ///  - rpc:   EVERY `lxm`
    ///  - repo:  EVERY `collection`
    ///  - space: ONLY `type`. `collection` is deliberately EXEMPT, because
    ///           "collections may live under a different authority" (:131-133;
    ///           tests "allows cross-namespace collections", :707-743, which
    ///           explicitly include `collection=*`).
    private func isAllowed(_ permission: IncludedPermission) -> Bool { /* … */ }
}
```

#### 5.7.4 Phase 2 — resolution: this is a port of `@atproto/lex-resolver`

> **Pointer for readers of an earlier version:** §9.2's open question **Q2**
> ("`@atproto/lex-resolver` is absent; Phase 2 has no reference implementation
> to port from") is **closed**, and the `com.atproto.repo.getRecord` design it
> licensed is **withdrawn as the wrong security model**. This section is the
> replacement. §9.1 carries the decision.

**Everything in this section is ported from a present, normative reference.**
The earlier draft opened by recording `@atproto/lex-resolver` as absent from the
checkout and proceeded by consumer-side inference from how `LexiconGetter` and
`LexiconManager` call `.get()`. That absence claim was false — an artifact of a
reference export containing three subtrees. The resolver is at
`packages/lex/lex-resolver/src/lex-resolver.ts`, 577 lines, and it is the
machinery that resolves `include:<nsid>` permission sets for real OAuth grants,
i.e. exactly the thing Swan must interoperate with.

**Which of the two upstream resolver packages is normative.** There are two, and
picking the wrong one silently ports the wrong contract:

| package | version | wired into | verdict |
|---|---|---|---|
| `@atproto/lex-resolver` (`packages/lex/lex-resolver/`) | 0.2.7 (`package.json:2-3`) | `packages/oauth/oauth-provider/package.json:74`; six oauth-provider sources import it — `oauth-provider.ts`, `token/token-manager.ts`, `request/request-manager.ts`, `lexicon/lexicon-manager.ts`, `lexicon/lexicon-getter.ts`, `lexicon/lexicon-manager.test.ts` | **NORMATIVE** — this is the OAuth path |
| `@atproto/lexicon-resolver` (`packages/lexicon-resolver/`) | 0.4.15 (`package.json:2-3`) | **zero** dependents | corroboration only |

The "zero dependents" claim carries a named positive control, because an
unverified absence claim is what produced the design this section replaces:
`grep -rln '"@atproto/lexicon-resolver"' --include=package.json packages/`,
minus the package's own manifest, returns nothing — while the identical grep for
`"@atproto/lex-resolver"` returns `packages/oauth/oauth-provider/package.json`
and `packages/lex/lex-installer/package.json`. The control is the *contrast*:
the same query over the same tree finds one package and not the other.

Both implement the same protocol over different plumbing (`lex-resolver` on
`@atproto/lex-client` + `@atproto-labs/did-resolver`, `lexicon-resolver` on
`@atproto/lex` + `@atproto/identity`'s `IdResolver`). Cite `lex-resolver.ts` for
the design; use `packages/lexicon-resolver/src/{lexicon,record}.ts` only as an
independent second implementation that corroborates each step. That two
independent implementations agree on every verification below is itself the
strongest available evidence that none of them is incidental.

##### The security model, and why the earlier design was the wrong one

The earlier §5.7.4 fetched the lexicon with **`com.atproto.repo.getRecord`**.
That endpoint is an application-layer XRPC call: the PDS looks the record up in
whatever backs that endpoint and returns JSON. **There is no cryptographic
linkage between that response and the DID's repo state.** The client is trusting
the HTTP server's word, and nothing else.

The concrete attack this admits, stated plainly because it is the reason this
section was rewritten rather than annotated: a compromised, misconfigured,
MITM'd, or simply dishonest PDS can return **any JSON it likes** for
`com.atproto.lexicon.schema/<nsid>` — including a permission set that expands to
a **broader** set of scopes than the DID's real signed repo declares. Since
Phase 2 feeds `include:` expansion directly into what an OAuth grant materialises
to, that is a privilege-escalation channel operated by lying in an HTTP
response. The earlier design had no way to detect it, because it never checked a
signature or a proof at all.

Upstream fetches **`com.atproto.sync.getRecord`** (`lex-resolver.ts:449-452`),
which returns a CAR containing the signed commit **plus the MST path from the
commit's `data` root down to the record**, and then independently re-derives:
commit → signature over a key resolved **from the DID document, not from the
response** → MST walk → record CID → record bytes → `$type`. Trust flows from
the DID document through a cryptographic chain to the bytes. Never from "the
server said so."

##### The complete resolution sequence

Driven by `LexResolver.get()` → `resolve()` + `fetch()` (`lex-resolver.ts:292-298`).
Upstream documents it as four stages in its own header (`:184-191`); the table
below is those four stages expanded into the individual checks, because the
verification stage is where the earlier draft's single row hid six separate
proofs.

| # | step | upstream | Swan component |
|---|---|---|---|
| 1 | `NSID.from(nsidStr)`; take `nsid.authority` — the reverse-DNS domain segment | `:327-328` | pure string, `AtprotoSyntax` |
| 2 | DNS `TXT _lexicon.<authority>` | `:350-352` → `getDomainTxtDid`, `:506-520` | **reuse** `Sources/SwanAccounts/ATHandleVerification.swift` — `ATHandleDNSResolving.txtRecords(name:)` (`:98` protocol, `:103` `SystemATHandleDNSResolver`), which today queries `_atproto.<handle>` (`:452`), over the bounded C wire-parser in `Sources/CATHandleDNS/include/CATHandleDNS.h`. §2 constraint 3 already establishes `SwanOAuth` → `SwanAccounts` (`Package.swift:150`). New call site, **not** new DNS plumbing |
| 3 | Join each record's chunks, keep lines starting `did=`, require **EXACTLY ONE** — zero is `No DID found in DNS TXT records`, more than one is `Multiple DIDs found in DNS TXT records`; then `assertDid` on the remainder | `:507-519` | new selection logic on the existing resolver |
| 4 | `AtUri.make(did, 'com.atproto.lexicon.schema', nsid)` — the collection is **hardcoded**, never caller-suppliable | `:343` | pure |
| 5 | Resolve the DID document, restricted to methods `'plc' \| 'web'`, and extract **BOTH** the PDS service endpoint **AND** the `atproto` verification method | `:423-425` (`extractAtprotoData`); resolver built by `createDidResolver`, `:260`, `packages/internal/did-resolver/src/create-did-resolver.ts:21-35` | **gap**: `PLCPublicRepositoryCommitKeyResolver.resolveCommitVerifier(for:)` (`Sources/SwanInterop/PublicRepositoryDIDResolver.swift:43-79`) already extracts the `atproto` verification method and returns a bound P-256 / secp256k1 verifier — but hard-requires `did:plc:` at `:46`. **did:web authorities need adding**; a lexicon authority may legitimately be `did:web` |
| 6 | Reject if `!key \|\| !pds \|\| !URL.canParse(pds.serviceEndpoint)` | `:434-439` | — |
| 7 | `com.atproto.sync.getRecord` against the **resolved** PDS (never a caller-supplied host) with `{ did, collection, rkey }`. Returns **raw CAR bytes**, not JSON | `:441-452` | see "network boundary" below |
| 8 | **Proof: CAR has exactly one root** | `readCarWithRoot`, `packages/repo/src/car.ts:55`, check at `:60` (`roots.length !== 1`) | `Sources/SwanPublicRepository/PublicRepositoryCAR.swift` — `parseIncrementally`, already used under a `maximumCARBytes` bound from `Sources/SwanPublicRelayVerifier/RelayRepositoryVerifier.swift` |
| 9 | **Proof: root block decodes as a `commit`** (`did`, `version: 3`, `data: Cid`, `rev`, `prev`, `sig`) | `:532` | `Sources/SwanPublicRepository/PublicRepositoryCommit.swift` |
| 10 | **Proof: `commit.did === did`** — the resolved DID, not one the response chose | `:533-535` | new equality check |
| 11 | **Proof: commit signature verifies against the DID-DOCUMENT-resolved key** | `:537-541` (`getDidKeyFromMultibase` at `:558-577`, then `verifyCommitSig`) | `PublicRepositoryCommitVerifier` (`Sources/SwanPublicRepository/PublicRepositoryCommitSigner.swift:20-31`) — architecturally identical: a verifier object bound to an already-resolved key, independent of CAR parsing |
| 12 | **Proof: MST membership** — `MST.load(blockstore, commit.data)` then `.get("com.atproto.lexicon.schema/<nsid>")` must yield a CID | `:543-546` | `Sources/SwanPublicRepository/RepositoryMSTCodec.swift` + `RepositoryMSTValidation.swift` |
| 13 | **Proof: record `$type === collection`** | `:548-553` | new |
| 14 | Validate the document against the lexicon-document schema | `:472-477` | **new business logic** — Swan has no `lexiconDocumentSchema` equivalent |
| 15 | **`lexicon.id === uri.rkey`** | `:480-485` | new |

##### What each proof actually stops

Steps 8-13 are not defence in depth around one real check; each closes a
distinct hole, and dropping any one of them leaves a working attack. This table
exists so nobody ships "the fetch plus a signature check" and calls it the port.

| check | what it stops |
|---|---|
| exactly one CAR root | an attacker-added second root smuggling an alternate commit past a caller that naively reads `roots[0]` |
| root decodes as a `commit` | malformed/wrong-shape root; CBOR that does not parse to the exact commit schema is refused **before** any trust decision |
| `commit.did === did` | **cross-repo substitution** — a correctly self-signed commit belonging to the *attacker's own* repo presented as this DID's data |
| signature over the DID-doc key | **forged or unsigned commits.** The key comes only from the independently-resolved DID document. An attacker controlling the PDS response cannot supply their own key alongside a self-consistent signature — **for `did:plc:`. See the caveat below; this row does not hold for `did:web:`.** |
| MST membership | **record-existence forgery** — proves the record is reachable from the signed commit's `data` root, not merely present as an unlinked orphan block in the CAR |
| record `$type` | type confusion — right MST key, wrong lexicon type |
| `lexicon.id === rkey` | same-repo record substitution — a validly signed lexicon that describes a *different* NSID sitting at the expected rkey |

**Note on failure domains — and a WITHDRAWN restriction.** An earlier revision of
this section claimed that for `did:web:` "the DID document is fetched from the
same origin that serves the record", and used that to restrict lexicon
authorities to `did:plc:`. **That claim is false as stated, the restriction is
withdrawn, and Phase 2 accepts both atproto-blessed DID methods, as upstream
does.**

Same-origin is a deployment topology, not a property of the method. Resolution
fetches the document from `https://{host}/.well-known/did.json`
(`packages/internal/did-resolver/src/methods/web.ts:78`), but the PDS comes from
the document's own `#atproto_pds` service, and `extractPdsUrl` is simply
`new URL(service.serviceEndpoint)` (`packages/did/src/atproto.ts:145-160`) —
`isAtprotoPersonalDataServerService` (`:174-186`) constrains the *service id* to
`<did>#atproto_pds` and the endpoint to being a parseable URL, and **nothing ties
its host to the DID's host**. So

```
_lexicon.example.com  TXT  did=did:web:identity.example.com
did:web document      →  verificationMethod: key K
                      →  #atproto_pds: https://pds.some-other-host.net
```

is legitimate, and compromising `pds.some-other-host.net` yields exactly the
independence the proof chain is for: that PDS can return arbitrary CAR bytes but
cannot produce a valid commit under K.

The weaker topology — `did:web:example.com` whose PDS *is* `example.com` — does
collapse both into one origin. That is worth naming, but it is a property of that
deployment, not a reason to reject the method.

There is also a deeper limit that a PLC-only rule would not have fixed. **The
first trust decision in this sequence is DNS**: `_lexicon.<authority>` →
`did=<DID>` (step 2). An attacker who controls the lexicon authority's DNS simply
repoints `_lexicon` at a `did:plc:` they control. PLC-only buys separation against
one narrower threat — *the `did:web` HTTPS origin is compromised while its DNS
stays trustworthy* — and nothing against authority compromise generally.

**Decision for Phase 2:** the default resolver accepts both `did:plc:` and
`did:web:`, matching upstream (`createDidResolver`,
`packages/internal/did-resolver/src/create-did-resolver.ts:21-35`, typed over
`AtprotoIdentityDidMethods` = `plc | web`). Interoperability with the upstream
permission model is the point of this work, and a method restriction Swan applies
unilaterally is an interop divergence.

PLC-only remains available as **operator policy, not protocol**:
`allowedLexiconAuthorityDIDMethods: Set<DIDMethod> = [.plc, .web]` by default, and
a deployment that wants the stronger failure-domain separation may set `[.plc]`.
Recorded as an operator knob in §9-D22, not as a silent divergence.

Consequence for step 5: `Sources/SwanInterop/PublicRepositoryDIDResolver.swift:46`
today hard-requires `repositoryDID.hasPrefix("did:plc:")`, and Phase 2 must lift
that for lexicon-authority resolution — which is what the Phase-2 vector table
already assumed when it recorded a `did:web` lexicon authority as resolving. The
withdrawn restriction had contradicted that table; they now agree.

##### Network boundary — the hardening stays, UNDERNEATH upstream semantics

Every word of Swan's outbound-fetch hardening is kept. It governs the
**transport**; `sync.getRecord` plus proof verification governs **trust**. The
two are stacked, not alternatives, and the earlier draft's error was treating
the transport hardening as if it were the trust model.

Swan already owns a hardened outbound GET: `OAuthRemoteDocumentFetcher.fetchJSON(from:)`
(`Sources/SwanOAuth/OAuthRemoteFetch.swift:572-591`) behind
`OAuthRemoteFetchPolicy` (`:92-110`), whose defaults are a **256 KiB body cap
and a 5 s timeout** (`:101-102`, hard-bounded to ≤ 30 s at `:104`). It enforces
URL policy, DNS resolution raced against the same deadline (`:228-320`), a
public-address-only peer check (`OAuthIPAddress.isPublicInternetAddress`,
`:66-79`), redirect policy, and admission control (`:596-600`). The lexicon
resolver **must** go through this and must not construct its own `HTTPClient`.

**A new implementation requirement the earlier text hid:** `fetchJSON(from:)` is
insufficient by itself. Step 7 returns a **CAR**, not JSON. A bytes-returning
sibling — `fetchBytes(from:)` — must be added **through the same
`OAuthRemoteFetchPolicy`**, inheriting the same URL policy, the same
public-address peer check, the same redirect policy, the same admission control,
and the same body cap. Adding a second fetch path that bypasses any of those is
the one refactor this section forbids outright.

##### Budget — re-derived, and the CPU half named

The earlier budget assumed one GET per include and was corrected to ≥ 3
sequential network operations. Both numbers were network-only. The real
per-include cost is **DNS TXT + DID document + `sync.getRecord`**, and then
**CAR parse + commit-signature verification + MST walk**, and the last three are
**CPU**, not network. A wall-clock deadline does not bound them; a body cap
does.

- **Per-step network policy**, not per-include: DNS ≤ 2 s, DID document ≤ 3 s,
  `sync.getRecord` ≤ 5 s (the existing `OAuthRemoteFetchPolicy` default).
- **Per-request wall clock** for the entire resolution group: **10 s**, enforced
  by the existing deadline-race helper (`OAuthRemoteFetch.swift:280-320`).
- **CPU bound, stated deliberately rather than inherited.** The proof work is
  bounded in the *response-size* dimension, and the only thing bounding it today
  is the 256 KiB body cap (`OAuthRemoteFetch.swift:101`) — which currently bounds
  it **incidentally**, as a JSON-document cap that happens to also apply. Make it
  deliberate: a single-record proof CAR is small by construction (one commit
  block plus an MST path, on the order of a few KiB), so cap the CAR at **256 KiB
  explicitly for this call site** and treat the cap as an anti-DoS control on
  MST-walk and signature work, not as a document-size preference. Additionally
  bound the MST walk by **node count**, since a CAR under the byte cap can still
  encode a pathological node graph. **This bound already exists and needs
  wiring, not writing**: `RepositoryMSTValidation.validate`
  (`Sources/SwanPublicRepository/RepositoryMSTValidation.swift:112`) takes a
  `PublicRepositoryLimits` and enforces `limits.maximumMSTNodes` and
  `limits.maximumMSTEntriesPerNode` (`:147-148`, checked at `:184` and
  `:407`/`:420`); `RelayRepositoryVerifier` already relies on it (`:53`) behind
  `PublicRepositoryLimits.standard.maximumCARBytes` (`:25`). Pass the same
  limits object from the lexicon path rather than introducing a second policy —
  two MST budgets that can drift apart is a worse outcome than either number.
- Steps 1-6 are cached separately from steps 7-15 and keyed by **domain**, not
  by NSID — four includes under one authority share one DNS + DID resolution.
- Exceeding any count cap, any per-step policy, the group deadline, or a size
  bound is `invalid_scope` at PAR (`invalid_request` at token mint — see the
  §5.7.5 matrix for why the codes differ).

##### The Swift surface

```swift
/// New, in SwanOAuth. The only type in the system that performs a network fetch
/// on behalf of a scope. `resolve` owns all fifteen steps above — including the
/// six proofs. A conforming implementation that performs steps 1-7 and skips
/// 8-13 is NOT a partial implementation of this protocol; it is a different and
/// unsafe protocol wearing this one's name. State that in the doc comment
/// because "we'll add proof verification in a follow-up" is exactly the shortcut
/// this section exists to forbid.
public protocol SwanLexiconResolving: Sendable {
    func resolve(_ nsid: String) async throws -> SwanLexiconResolution
}

/// A resolution ATTEMPT, including the negative outcome. See the cache schema
/// below for why "resolved to nothing" must be representable.
public enum SwanLexiconResolution: Sendable, Equatable {
    /// Mirrors upstream's `LexResolverResult` (`lex-resolver.ts:37-44`), which
    /// carries THREE fields: `uri`, `cid`, `lexicon`.
    ///
    /// `verifiedCID` is not decoration and must not be dropped. Upstream returns
    /// it from `verifyRecordProof` (`lex-resolver.ts:545`, `:555`) — it is the CID
    /// the MST walk resolved to, i.e. the content address the proof chain
    /// actually terminated at, and it is the only value in the result that ties
    /// the returned bytes back to the signed commit. Persist it (see the cache
    /// schema) so a cached document can be shown to be the same document that
    /// was proved, and so a later audit can answer "which record did this grant
    /// expand from" with a content address rather than a URI that may since have
    /// been rewritten.
    ///
    /// `sourceURI` is the `at://<did>/com.atproto.lexicon.schema/<nsid>` from
    /// step 4, retained because upstream's `LexiconData` persists it
    /// (`lexicon-getter.ts:38`) and because the DID in it is the authority the
    /// DNS TXT step actually selected — which is not recoverable from the NSID
    /// alone once the TXT record changes.
    case resolved(SwanLexiconDocument, sourceURI: String, verifiedCID: String)

    /// Upstream's `LexResolverError` branch (`lexicon-getter.ts:19-27`): the
    /// resolver failed in an EXPECTED way. Cacheable. Distinct from a thrown
    /// error, which propagates (`:26-27`).
    ///
    /// **REACHABILITY IS CONSTRAINED.** `.unresolvable` may be produced ONLY by
    /// a resolver-class failure — precisely the set upstream wraps in
    /// `LexResolverError` (`lex-resolver-error.ts:41-77`), which is: authority
    /// resolution failed (`lex-resolver.ts:354-359`), DID document resolution
    /// failed (`:427-432`), no PDS endpoint or signing key in the document
    /// (`:434-439`), the record fetch failed (`:465-469`), **proof verification
    /// failed** (`:455-463`), the document failed schema validation (`:472-477`),
    /// or `lexicon.id != rkey` (`:480-485`). Everything else — a programming
    /// error, a cancellation, a storage fault — THROWS and propagates, matching
    /// `lexicon-getter.ts:26-27`. Widening `.unresolvable` to catch-all would
    /// convert a bug into a cached "this lexicon doesn't exist" for five minutes.
    case unresolvable
}

public enum SwanLexiconDocument: Sendable, Equatable {
    case permissionSet(LexiconPermissionSet)   // lexicon.ts:14-21
    case space(LexiconSpace)                   // lexicon.ts:23-29
    case other                                 // resolved, but wrong `main.type`
}

/// lexicon.ts:23-29 — referenced once by the first draft and never defined.
/// `expandSpaceCollections` (§5.7.5) needs THIS, not a permission set.
public struct LexiconSpace: Sendable, Equatable, Decodable {
    /// Must decode to exactly "space".
    public let type: String
    public let name: String
    public let collections: [String]
    public let description: String?
}
```

##### Cache

Mirror `LexiconStore` — the three-method interface at
`packages/oauth/oauth-provider/src/lexicon/lexicon-store.ts:8-12`
(`findLexicon` / `storeLexicon` / `deleteLexicon`) — and `LexiconData`, whose
**declaration** is `lexicon/lexicon-data.ts:5-11` (`createdAt`, `updatedAt`,
`lastSucceededAt`, and the two nullable fields `uri` and `lexicon`) and whose
**construction**, including the negative-result branch, is
`lexicon-getter.ts:30-40`. Both citations are needed: the declaration is what
makes `uri`/`lexicon` nullable in the type system, and the construction is what
proves the null branch is deliberately taken rather than an unreached case.
Realise them as a SwanSQLite table alongside
the existing `oauth_control_*` tables (`Sources/SwanSQLite/SwanSQLite.swift:91-126`):

```sql
CREATE TABLE oauth_lexicon_documents (
    nsid              TEXT    PRIMARY KEY NOT NULL,
    -- NULLABLE, deliberately. `lexicon-getter.ts:19-40` writes a row with
    -- `lexicon: null` on a LexResolverError, explicitly "to avoid hammering the
    -- resolver with requests for the same lexicon that is known to be
    -- unavailable" (:20-23); `getPermissionSet` then throws on `!lexicon`
    -- (lexicon-manager.ts:122-124). The first draft declared this NOT NULL,
    -- which makes that row unrepresentable and turns the spec's own
    -- serve-stale-on-failure rule into a refetch on EVERY request for an
    -- unresolvable NSID — the exact failure upstream's design exists to prevent.
    document          BLOB,               -- validated JSON, post-shape-check; NULL == resolved to nothing
    source_uri        TEXT,               -- at://<did>/com.atproto.lexicon.schema/<nsid>, lexicon-getter.ts:38
    -- The CID the MST walk terminated at (lex-resolver.ts:545, returned :555).
    -- NULLABLE for the same reason `document` is: a negative-cache row proved
    -- nothing. On a positive row it is NOT optional — it is the only stored
    -- value that ties `document` back to a signed commit, and it is what lets an
    -- audit answer "which record did this grant expand from" with a content
    -- address rather than a URI whose TXT record may since have been repointed.
    verified_cid      TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,   -- always bumped, success or failure
    last_succeeded_at INTEGER             -- preserved across failures
) STRICT;
```

A `document IS NULL` row is a **negative cache entry**, not a missing row:
`updated_at` still advances (so `isStale()` governs the next attempt at the
5-minute threshold), `last_succeeded_at` is preserved
(`lexicon-getter.ts:36-38`), and any read of it yields `invalid_scope` /
`invalid_request` per the matrix in §5.7.5 **without** a network round trip. The
24 h hard expiry below applies to `last_succeeded_at`, not `updated_at`.

- **Refresh threshold**: stale when `now - updated_at >= 5 minutes`
  (`LEXICON_REFRESH_FREQUENCY = 5 * MINUTE`, `oauth-provider/oauth-constants.ts:84`).
  Stale triggers a refetch; it does not invalidate.
- **Serve-stale on failure**: a resolver failure returns the cached document and
  bumps `updated_at` while preserving `last_succeeded_at`
  (`lexicon-getter.ts:19-40`), explicitly "to avoid hammering the resolver".
  Non-resolver (unexpected) errors propagate (`:26-27`).
- **Swan addition — a hard expiry.** Upstream serves stale *forever*, and
  because the token scope is re-derived on every refresh
  (`token-manager.ts:260-263`), a permission set that was **narrowed** upstream
  would keep minting the wider grant indefinitely whenever the resolver is
  unreachable. Swan adds `HARD_EXPIRY = 24 h`: past it, a cached document is
  treated as unresolved. A deliberate divergence trading availability for
  grant-freshness — the correct direction for an authorization server.
- **CORRECTION — the earlier bullet here was wrong twice.** It read: "No
  in-package default `LexiconStore` exists upstream to copy — positive control:
  read `lexicon-store.ts` in full (29 lines); interface plus three type-guards
  only, no concrete class." Both halves fail:
    1. `packages/oauth/oauth-provider/src/lexicon/lexicon-store.ts` is **37
       lines**, not 29. A positive control that misreports the length of the file
       it claims to have read in full did not read it.
    2. **A concrete implementation exists.**
       `packages/pds/src/account-manager/oauth-store.ts:85` declares
       `implements AccountStore, RequestStore, DeviceStore, LexiconStore, TokenStore`,
       with `findLexicon` / `storeLexicon` / `deleteLexicon` at `:524`, `:528`,
       `:532` (section marker at `:522`). It was invisible only because
       `packages/pds` was not in the truncated export.
  Re-derive the schema above against that implementation and against the
  resolver's own **hook-based** cache contract (`lex-resolver.ts:106-159`), which
  is the layer upstream actually intends callers to cache at:
  `onResolveAuthority` (`:116`) / `onResolveAuthorityResult` (`:123`) /
  `onResolveAuthorityError` (`:130`) sit at the DNS-authority step, and
  `onFetch` (`:140`) / `onFetchResult` (`:147`) / `onFetchError` (`:158`) sit at
  the record-fetch step. A returned value from `onResolveAuthority` or `onFetch`
  **replaces** the default operation and suppresses the matching result/error
  hooks (`:108-112`, `:133-135`). That is
  the seam Swan's domain-keyed cache (steps 1-6) and document cache (steps 7-15)
  should map onto, and it is why they are two caches rather than one.
- `LexResolver` itself holds **no** cache for the fetch result; caching is
  entirely delegated to those hooks (`:401-412`). The one cache built in sits
  underneath, in DID-document resolution: `createDidResolver` wraps the resolver
  in `DidResolverCached` (`packages/internal/did-resolver/src/create-did-resolver.ts:21-35`).
  Swan's equivalent belongs at the same layer — cache the DID document, not the
  proof result, because the proof must be re-verified against whatever key the
  document currently names.

##### Where these caps live: the EXPANDED-GRANT budget, not the raw-input one

**These are expansion-side caps and must be filed as such**, because §6.4 now
defines **two separately named budgets** (§9-Q5) and describing half of one of
them here under the unqualified word "budget" is how they get merged back
together by a later reader:

| budget | measures | enforced at |
|---|---|---|
| **RAW-INPUT** | the bytes that arrived on the wire | wire tokenizers (stages A and A′) |
| **EXPANDED-GRANT** | what Swan holds *after its own transformations* — `self` resolution, Phase-2 `include:` expansion, `expandSpaceCollections` | token mint and persistence |

Everything below is **EXPANDED-GRANT**. The distinction is load-bearing rather
than bookkeeping: an 80-byte `include:` or a bare `space:<type>` passes the raw
budget at PAR and then **inflates past it** under Swan's own expansion. The
resulting failure is caused by Swan's transformation, not by the client's
request, and it surfaces at token mint rather than at PAR — so a single shared
number would report it against the wrong actor at the wrong stage.

- **`include:` population.** Cap **distinct `include:` NSIDs at 4** per request,
  resolve them concurrently in one `withThrowingTaskGroup`, and apply the
  per-step / 10 s-group / size policy stated above — **not** 4 × 5 s
  sequentially, and **not** one 5 s deadline across ≥ 12 network operations
  plus three CPU-bound proof stages.
- **Space-type NSIDs are a SECOND, separately-bounded population.** They are
  resolved from the same resolver by `expandSpaceCollections` (§5.7.5), they are
  **not** `include:`-derived, and the earlier cap bounded only the `include:`
  set — leaving them unbounded. Cap **distinct space-type NSIDs at 8** per
  request (a 64-token set can name up to 64 distinct types), resolve them in the
  same task group under the same 10 s group deadline, and share the
  domain-keyed cache from steps 1-6.
- Both counts, both size bounds and the group deadline are expanded-grant
  limits. Exceeding one is `invalid_scope` at PAR and `invalid_request` at token
  mint — see the §5.7.5 matrix, which keeps upstream's asymmetric codes for the
  same root cause deliberately.

#### 5.7.5 Phase 2 — resolution timing, and the failure matrix

Three call sites, in this order:

1. **PAR / `/oauth/authorize`.** After `oauthServerScopes` parses the raw set
   (`SwanOAuthAuthorizationServerHTTP.swift:1059`) and before/alongside
   `OAuthValidatedSession.init` (`Sources/SwanOAuth/OAuthValidatedSession.swift:26-32`).
   Two jobs: every `include:` must resolve, or the request is rejected; and the
   consent payload is built. Upstream does both here
   (`oauth-provider/oauth-provider.ts:744-762`) and additionally expands
   `include:` → `space:` *before* extracting space types for display
   (`lexicon-manager.ts:21-36`). Failure → `invalid_scope`
   (`request-manager.ts:293-312`).
2. **Token mint / refresh**, after the subset check (§6.3 stage C), because that
   check compares *raw requested* against *registered*, so both sides must still
   be in `include:` form. Three transformations, in order:
   (a) `include:` → concrete `repo:` / `rpc:` / `space:`;
   (b) `expandSpaceCollections` — a bare `space:<type>` (no `collection`) is
   rewritten to carry the type's declared collections (`lexicon-manager.ts:74-95`),
   which **throws** if the declaration cannot be resolved, deliberately, because
   passing it through would mint a token with no write targets at all — a
   *narrower* grant than the user consented to (`:68-73`). **"Cannot be
   resolved" now has an enumerated membership**, and every one of these throws
   rather than passing the bare grant through: the DNS TXT step returning zero or
   more than one `did=` (`lex-resolver.ts:507-519`); DID-document resolution
   failing or yielding no PDS endpoint / no `atproto` signing key (`:427-439`);
   the `sync.getRecord` fetch failing (`:465-469`); **any of the six proof
   checks** — CAR root count, commit decode, `commit.did` equality, commit
   signature, MST membership, record `$type` (`:455-463` wrapping
   `verifyRecordProof`, `:522-556`); schema validation (`:472-477`); and
   `lexicon.id != rkey` (`:480-485`). The list matters because the tempting
   shortcut — "if we can't prove it, just leave the bare grant alone" — inverts
   the deliberate direction of `:68-73`: it would let an unreachable or hostile
   authority silently *widen* what a bare `space:<type>` grant covers by leaving
   it unmaterialised. A space declaring an
   empty collection list is not an error; the bare grant passes through
   (`lexicon-manager.test.ts:178-187`). A `type=*` grant is skipped (`:80`, `:90`);
   (c) `resolveSpaceSelfAuthority` (§6.4).

   **(b) is NOT include-specific, and filing it under "Phase 2" leaves Phase 1
   with a silent grant-narrowing.** Verified: `lexicon-manager.ts:74-95` iterates
   **every** scope in the token — include-derived or not — collects each non-`*`
   `space:` type whose grant `!hasCollections`, and materialises
   `space.collections`. bulleted.app's `space:` scope contains no `include:` and
   is affected. Three consequences the first draft did not state:

   1. **Phase 1 narrows every bare `space:` grant to zero write targets.** With
      `collection` defaulting to `[]` (§5.6.2) and no materialisation step, a
      plain `space:app.bulleted.space` token **can never write**. M5 and §7.4
      Stage 6 check 3 pin the behaviour, but as *upstream conformance* — it is
      not. It is a **Phase-1 divergence from a conformant AS**, and it is the
      reason bulleted.app will authorize and then be unable to create a record
      even after Stage C. Record it beside D4's stated cost, and assert it in
      §7.4 Stage 6 as a divergence rather than as expected behaviour.
   2. Its budget is the **space-type** NSID population, capped separately in
      §5.7.4 — not the `include:` cap.
   3. `expand(_ set: LexiconPermissionSet) -> [IncludedPermission]` cannot
      express it: materialisation needs a `LexiconSpace` (`lib/lexicon.ts:23-29`,
      now defined in §5.7.4), not a permission set. It is a **separate**
      `SwanLexiconResolving` consumer with its own entry point, sequenced after
      (a) and before (c).
   Failure → upstream raises `InvalidRequestError` here
   (`token-manager.ts:135-138`), **not** `invalid_scope` — a different code than
   the PAR-time failure for the same root cause. Match upstream for interop, and
   comment the asymmetry rather than silently unifying it.
3. **Request time (resource plane): never.** By the time a bearer token reaches
   `SwanOAuthResourceAuthorization` the stored scopes are fully expanded,
   self-resolved and collection-materialised. A resource request performs
   **zero** outbound I/O for authorization. This is structural, not a
   convention — §3.

| condition | PAR / authorize | token mint / refresh |
|---|---|---|
| fetch fails, cache fresh (< 24 h) | serve cached, no error (`lexicon-getter.ts:19-28`) | same |
| fetch fails, no cache | `invalid_scope` (`request-manager.ts:300-307`) | `invalid_request` (`token-manager.ts:135-138`) |
| fetch fails, cache older than 24 h | `invalid_scope` (Swan addition) | `invalid_request` |
| resolves, but `main.type != "permission-set"` | `invalid_scope` (`lexicon-manager.ts:126-129`) | `invalid_request` |
| bare `space:<type>` whose space declaration won't resolve | n/a | `invalid_request` (`lexicon-manager.ts:68-73`) |
| entry is `blob`/`account`/`identity`/unknown | dropped silently | dropped silently |
| entry fails its family's parse | dropped silently (`include-scope.ts:64-65`) | same |
| entry fails the authority gate | dropped silently (`:67-68`) | same |
| every entry dropped → empty expansion | **not** an error; the `include:` contributes nothing — log at `.warn`, since a silent zero-grant is indistinguishable from success at the wire, **and render it in consent** with §5.7.2's canonical string, which names the NSID: "Requested permission set `<nsid>`. Swan does not currently grant capabilities derived from this set", because a `.warn` reaches an operator and the person authorizing never sees it (§9-Q7) | same |

**Proof failures are HARD, and none of them belongs in a "dropped silently"
row.** The rows above were written against a `repo.getRecord` design that had no
proof stage, so the matrix had nowhere to put these. Each is a distinct
`LexResolverError` upstream (`lex-resolver-error.ts:41-77`, wrapped at
`lex-resolver.ts:455-463` with the description `Failed to verify Lexicon record
proof at <uri>`), and each terminates resolution:

| proof failure | upstream | PAR / authorize | token mint / refresh |
|---|---|---|---|
| CAR has ≠ 1 root | `packages/repo/src/car.ts:60` | `invalid_scope` | `invalid_request` |
| root block does not decode as a `commit` | `lex-resolver.ts:532` | `invalid_scope` | `invalid_request` |
| `commit.did` ≠ the resolved DID (cross-repo substitution) | `:533-535`, `Invalid repo did` | `invalid_scope` | `invalid_request` |
| commit signature does not verify against the DID-document key | `:537-541`, `Invalid signature on commit` | `invalid_scope` | `invalid_request` |
| record not reachable from `commit.data` via the MST | `:543-546`, `Record not found in proof` | `invalid_scope` | `invalid_request` |
| record `$type` ≠ `com.atproto.lexicon.schema` | `:548-553`, `Invalid record type` | `invalid_scope` | `invalid_request` |
| document fails lexicon-schema validation | `:472-477` | `invalid_scope` | `invalid_request` |
| `lexicon.id` ≠ `uri.rkey` | `:480-485` | `invalid_scope` | `invalid_request` |
| DNS TXT yields zero or **more than one** `did=` line | `:507-519` | `invalid_scope` | `invalid_request` |
| DID document has no PDS endpoint or no `atproto` signing key | `:434-439` | `invalid_scope` | `invalid_request` |

Two properties of that table are the whole point of it:

1. **A proof failure never degrades to a drop.** The silent-drop rows above
   describe *entries within a successfully proved document* that fail their own
   family's parse or authority gate — upstream drops those, and Swan matches.
   A proof failure means the document was never established as belonging to the
   authority's signed repo, so there is nothing to drop entries *from*. If a
   proof failure ever reaches a drop path, an attacker-controlled PDS gets to
   choose which of a user's requested permissions survive by selectively
   corrupting proofs. Assert this in the Phase-2 vectors (§5.7.6).
2. **They ARE cacheable as negative results**, exactly like any other
   `LexResolverError` (`lexicon-getter.ts:19-27` swallows the whole class). A
   `document IS NULL` row is written, `updated_at` advances, and the 5-minute
   `isStale` threshold governs the retry. Cacheable and hard are not in tension:
   the request fails now, and the *next* request fails from cache instead of
   re-walking an MST for an authority that is currently broken or hostile.
| `atproto` absent from the request | `invalid_scope` (`request-manager.ts:241-248`) | n/a |
| `openid` present | rejected outright (`request-manager.ts:241-248`) | n/a |

#### 5.7.6 Phase 2 vectors

**Resolver-level vectors come first, and they did not exist in the earlier
draft.** It listed only `include-scope.test.ts` and `lexicon-manager.test.ts` —
both *consumer* suites, which exercise expansion given a document and say
nothing about how the document was obtained. Under the corrected design the
resolver is the security boundary, so it needs its own vectors, and they must be
**negative** vectors: a resolver that passes every happy-path test and skips
proof verification is worse than no resolver, because it launders an
attacker-controlled response into a signed-looking grant. Each row below
constructs the artifact locally and asserts the resolution fails:

| vector | construct | expect | pins |
|---|---|---|---|
| two `did=` TXT lines | a stub DNS resolver returning two records both starting `did=` | resolution fails | `lex-resolver.ts:507-519` — **exactly one**, not "first wins" |
| zero `did=` TXT lines | records present but none prefixed `did=` | resolution fails | `:507-519` |
| DID doc with PDS but no `atproto` key | strip the verification method | resolution fails | `:434-439` |
| DID doc with key but no PDS service | strip `#atproto_pds` | resolution fails | `:434-439` |
| CAR with two roots | append a second root to a valid CAR | resolution fails | `packages/repo/src/car.ts:60` |
| **cross-repo substitution** | a CAR from a *different* DID's repo, correctly self-signed, containing a lexicon at the same rkey | resolution fails | `:533-535`. **The single most important vector in this table** — it is the one a proof-free implementation passes every other test while failing |
| bad commit signature | flip one byte of `commit.sig` | resolution fails | `:537-541` |
| signature valid, wrong key | sign with a key the DID document does not name | resolution fails | `:537-541` — pins that the key comes from the document, not the response |
| record present in CAR but not in the MST | include the record block, omit it from the tree under `commit.data` | resolution fails | `:543-546` — pins membership, not mere presence |
| record `$type` mismatch | a record tagged as a different lexicon at the right MST key | resolution fails | `:548-553` |
| `lexicon.id` ≠ rkey | a validly signed lexicon whose `id` names a different NSID | resolution fails | `:480-485` |
| happy path | a well-formed single-record proof CAR | resolves; `verifiedCID` equals the CID the MST walk returned | `:545`, `:555` |
| negative caching | any of the above, then a second resolve within 5 min | second attempt performs **no** network I/O and no MST walk | `lexicon-getter.ts:19-40`, `oauth-constants.ts:84` |
| `did:web` authority | a `did:web` lexicon authority | resolves | closes the `did:plc:`-only gap at `Sources/SwanInterop/PublicRepositoryDIDResolver.swift:46` |

`isParentAuthorityOf` on `IncludeScope("com.example.foo.auth")` (`:113+`):
`com.example.foo.identifier` → true; `com.example.foo.bar.baz` → true;
`com.example.foo.bar.baz.quz` → true; `com` and `com.example` → **false**;
siblings of the root domain → false; other domains → false; `"*"` → **always**
false.

Expansion (`include-scope.test.ts` `describe` blocks):

- blob "valid permissions" / "invalid permissions" → both `[]`.
- account "account permissions", identity "identity permissions" → rejected even
  with valid syntax.
- rpc: "allows `*` aud"; "inherits aud" (`:237-263`); "forbids use of specific
  `aud`"; "invalid `lxm` syntax"; "extra properties"; "missing `lxm`"; "missing
  `aud`"; "both `inheritAud` and `aud` specified"; "invalid authority";
  "un-specified inherited-aud"; "wildcard-aud"; "wildcard-aud for invalid
  authority" (`:428-442`).
- repo: "valid permission"; "valid permission with partial actions"; "invalid
  `collection` syntax"; "invalid `action` syntax" (`:510-540`); "invalid
  `action` values"; "invalid authority"; "permissions with one valid and one
  invalid authority" — the valid one survives, the invalid one is dropped.
- space: "space permission with type only"; "space permission with type and
  collection"; "space type outside the include namespace" (dropped); "wildcard
  space type (too broad for a permission-set)" (`:691-704`, dropped);
  "collection outside the include namespace" (**kept** — collections are
  authority-exempt); "wildcard collection" (kept) (`:707-743`).

`LexiconManager` behaviour to port (`oauth-provider/lexicon/lexicon-manager.test.ts`):
"resolves a space type named directly"; "resolves a space type reached through a
permission set"; "does not resolve a wildcard space type"; "materializes the
declared collections into a bare grant"; "leaves a grant that already names
collections alone"; "leaves a `collection=*` grant alone"; "throws when a space
type cannot be resolved" (`:153-164`); "throws when the resolved document is not
a space" (`:165-176`); "leaves a bare grant alone when the space declares no
collections" (`:178-187`); "resolves a bare grant authority to the granting
user"; "passes non-space scopes through untouched"; "expands a space grant
alongside unrelated scopes"; "expands several space grants independently".

**Four vectors written out rather than named**, because their semantics are not
recoverable from the `it()` title and would otherwise be guessed:

| vector | input | expected |
|---|---|---|
| `'inherits aud'` (`include-scope.test.ts:237-263`) | `include:com.example.foo.auth?aud=did:web:example.com%23svc` + an rpc entry with `inheritAud: true`, no `aud`, `lxm: ['com.example.foo.get']` | `['rpc:com.example.foo.get?aud=did:web:example.com%23svc']` — the splice at `include-scope.ts:98-105` requires **all three** of `inheritAud === true`, `aud === undefined`, and `this.aud !== undefined`; drop any one and the entry is dropped |
| `'permissions with one valid and one invalid authority'` (`:558-578`) | a two-entry repo set, one collection inside the include's namespace and one outside | a **one**-element array holding only the in-namespace grant. This is the only vector proving the authority gate is **per-entry**, not per-set — a per-set gate would yield `[]` and pass every other include test |
| space fixture shape (`:639-654`) | `{type:'permission', resource:'space', spaceType:'com.example.calendar.group', action:[…]}` | `['space:com.example.calendar.group']` — pins the `spaceType`→`type` remap (§5.7.3 gate 1) |
| scalar-where-array (`:494-508`) | a repo entry whose `collection` is the scalar `'com.example.calendar.event'` | `[]` — pins `getMulti`'s `null` (§5.7.3 gate 3). **Assert this one explicitly**; it is the vector that fails if arity is erased by stringification |

---

## 6. Enforcement and server integration

### 6.1 `SwanScopePermissions` — the one facade

Upstream's object is `oauth-scopes/src/scope-permissions.ts:37-109`: a wrapper
around a `ScopesSet` with six paired `allowsX` / `assertX` methods, each
delegating to `scopes.matches(resource, options)` (`scopes-set.ts:47-55`). The
Rust reference's equivalent (`atproto-oauth/src/scopes.rs:1163-1503`) crucially
also carries `subject: Option<String>` — the DID that `space:`'s
`authority=self` resolves against, "bound once per token rather than threaded
through every check" (`scopes.rs:1166-1174`).

**Swan takes the Rust shape** (subject bound into the value), not the TS shape
(subject threaded per call), for one concrete reason: Swan's matcher is reached
from *inside* an actor (`SwanSQLite.swift:9272`, `:11628`, `:11647`) where
re-deriving a subject would mean another `await` (§2 constraint 1).

```swift
// Sources/SwanCore/OAuthScopes/ScopePermissions.swift

/// A frozen, request-scoped answer to "may this token do X".
///
/// Constructed once per authenticated request from durable token state and
/// never mutated. Parsing is EAGER: a stored scope string that does not parse
/// is recorded in `rejected` and grants nothing (mirroring scopes.rs:1160-1162
/// and scopes-set.test.ts:42-47) rather than silently re-failing to parse on
/// every match. The raw strings are retained verbatim so persistence and audit
/// surfaces never see a re-serialized value.
///
/// DO NOT add a memoizing cache. A cache needs an actor or a lock, which would
/// make `allowsSpace` async, which would make `SpaceAuthorizationPolicy.require`
/// async, which would ripple into `requireRead`/`requireWrite`
/// (SwanSQLite.swift:11624-11652) and every repository operation in SwanSQLite.
/// The work being cached is parsing <= 64 tokens of <= 1024 bytes, once per
/// request, in the same request that just did an ES256 verification
/// (OAuthProofValidation.swift:75-87) and at least two SQLite round trips.
public struct SwanScopePermissions: Sendable, Equatable, Hashable {
    /// Exactly the strings the durable token family carries, unmodified.
    public let rawScopes: Set<String>
    /// The account DID this grant was issued to. `space:` grants naming
    /// `authority=self` resolve against this and ONLY this; a permissions value
    /// with no subject fails closed on every `self` grant, matching
    /// `self_matches_nothing_without_a_subject`
    /// (atproto-oauth/src/scopes/space_permission.rs:1579-1584).
    public let subject: String?
    private let parsed: [AtprotoScope]
    /// Retained for logging only — never consulted by a match. Upstream throws
    /// this information away (`filter(isAtprotoOauthScope)`,
    /// request-manager.ts:184); Swan keeps it so a narrowed grant is greppable.
    public let rejected: [String: ScopeParseError]

    public init(rawScopes: Set<String>, subject: String?) {
        self.rawScopes = rawScopes
        self.subject = subject
        // Sort so `parsed` is a deterministic function of the inputs and
        // `Equatable` is stable across Set iteration order.
        var parsed: [AtprotoScope] = []
        var rejected: [String: ScopeParseError] = [:]
        for value in rawScopes.sorted() {
            do { parsed.append(try AtprotoScope.parse(value)) }
            catch { rejected[value] = error }
        }
        self.parsed = parsed
        self.rejected = rejected
    }

    /// The base AT Protocol session scope. An explicit predicate rather than a
    /// `rawScopes.contains` at each call site: three files spell this today
    /// (OAuthValidatedSession.swift:91-95, DurableOAuthTokenService.swift:1246-1250,
    /// SwanOAuthResourceAuthorization.swift:206-210) and they must not drift
    /// apart again.
    public var hasBaseATProtocolScope: Bool { rawScopes.contains("atproto") }

    /// True when this grant carries something the AT Protocol resource plane
    /// **enforces**. Replaces the three copies of `hasATProtocolResourceScope`
    /// — and must replace them with *the same accept set*, not a wider one.
    ///
    /// ## Why this is `.space` only, and not "any recognised family"
    ///
    /// The predicate this replaces is
    /// `SwanOAuthResourceAuthorization.swift:206-210` (and its two twins at
    /// `OAuthValidatedSession.swift:91-95` and
    /// `DurableOAuthTokenService.swift:1246-1250`):
    ///
    ///     scopes.contains("atproto") || scopes.contains { isQualified($0) }
    ///
    /// i.e. `atproto` **OR a qualified `space:` grant** — nothing else. That
    /// floor is the ONLY scope check several routes perform. Verified, each
    /// discarding the scope set entirely:
    ///
    ///   * SwanHTTP/SwanSpaceXRPC.swift:77 — `guard case let .accountOAuth(subject, _)`
    ///   * SwanHTTP/SwanSpaceBlobXRPC.swift:340 — `case let .accountOAuth(subject, _) where subject == author: return`
    ///   * SwanHTTP/SwanSpaceRepositorySyncXRPC.swift:288 — identical shape
    ///   * SwanHTTP/SwanSimpleSpaceXRPC.swift:426-427; SwanSpaceXRPC.swift:403, 492, 879
    ///   * SwanSQLite/SQLitePreMigratedAccountDirectory.swift:2519-2520, 2584, 2634
    ///
    /// The first draft returned `true` for account / blob / identity / repo /
    /// rpc as well. After §8 Stage C a remote client may register
    /// `identity:handle` or `blob:image/*`; such a token would then pass the
    /// floor and reach blob upload and repository sync on its own repo, which
    /// perform **no further scope check**. Today no such token can exist.
    /// §6.1's own "stated, deliberate dead surface" argument does not cover
    /// this: a dead surface that nonetheless satisfies the authorization floor
    /// is not dead — it is an unenforced grant that opens routes.
    ///
    /// **The `default: return true` arm returns when — and only when — the
    /// corresponding route actually consults `allowsRepo` / `allowsRPC` /
    /// `allowsBlob`.** Widening this predicate and wiring those routes are one
    /// change, not two. That condition is now *actionable* rather than
    /// aspirational: §6.5.10 names, per route, which upstream `assert*` call
    /// each Swan endpoint must grow before the corresponding family may join
    /// this accept set. Today the answer for `repo:` / `blob:` is visible in
    /// one line — `SwanPublicRepositoryMutationXRPC.swift:449-450` guards every
    /// repo write and every blob upload with `scopes.contains("atproto")` and
    /// nothing else, which is precisely the route a widened predicate would
    /// open.
    ///
    /// **§9-Q9's ruling confirms this shape and does not license widening it.**
    /// Retiring `isIssuableQualified` as a client-metadata gate (§6.3 stages A′
    /// and D) removes a *registration-layer* semantic check; it says nothing
    /// about the resource plane. `hasResourceScope` stays atproto-or-space.
    /// Read the retirement as permission to widen here and the exact hazard the
    /// retired gate was accidentally covering — a registered `blob:image/*`
    /// reaching an unguarded upload route — reappears one layer down.
    public var hasResourceScope: Bool {
        hasBaseATProtocolScope || parsed.contains { scope in
            if case .space = scope { return true }
            return false
        }
    }
}

public extension SwanScopePermissions {
    func allowsSpace(_ target: SpaceScopeTarget) -> Bool {
        parsed.contains { scope in
            guard case let .space(grant) = scope else { return false }
            return grant.resolvingSelf(as: subject).matches(target)
        }
    }

    /// **Never propagates a `ScopeParseError`.** `scopeNeeded` does not validate
    /// its input (§5.6.6) and its final `canonicalString()` throws
    /// `.notAScopeToken` whenever `target.skey` / `target.collection` carries a
    /// byte the encoders leave raw. If that throw escaped, `requireSpace` would
    /// surface a **denial** as an `unavailable` — `SpaceAuthorizationPolicy.require`
    /// (`SwanSpaces.swift:237-243`) is plain `throws` and propagates, and the
    /// handlers map non-`SwanError` throws to `unavailable`
    /// (`SwanSpaceXRPC.swift:73-75`, `SwanSpaceDelegationXRPC.swift:74-76`).
    /// An attacker could then distinguish "denied, well-formed target" from
    /// "denied, odd target" — exactly the oracle
    /// `SwanOAuthResourceAuthorization.swift:9-16` forbids and §9-D6 claims to
    /// preserve. Degrade the formatting failure into the same opaque denial.
    func requireSpace(_ target: SpaceScopeTarget) throws {
        guard allowsSpace(target) else {
            let needed = (try? SpacePermission.scopeNeeded(for: target))
                ?? "space:<unrenderable target>"
            throw ScopeDenied(needed: needed)
        }
    }

    /// SpacePermission's `self` resolver, at the FACADE layer. Defined here
    /// because the first draft used it at this call site and defined only
    /// `withResolvedAuthority(_ userDID: String)` (§5.6.4) — a different name
    /// with a non-optional parameter, so the code as written did not compile
    /// and the `nil`-subject fail-closed behaviour the type's doc comment
    /// promises had no implementation. §6.5.2 deliberately constructs
    /// `SwanScopePermissions(rawScopes:, subject: nil)` at two floor checks, so
    /// this path is live.
    ///
    /// `nil` subject == FAIL CLOSED: the grant is returned unchanged with its
    /// authority still `.unresolvedSelf`, and `matches` returns false on that
    /// (§5.6.3 step 2), per `space_permission.rs:1574-1584`.
    ///
    /// Lives on `SpacePermission` (SwanCore), NOT on the facade:
    ///
    ///     extension SpacePermission {
    ///         func resolvingSelf(as subject: String?) -> SpacePermission {
    ///             guard let subject else { return self }   // fail closed
    ///             return withResolvedAuthority(subject)    // §5.6.4
    ///         }
    ///     }
    ///
    /// Note the double resolution this creates and why it is accepted: §6.4
    /// rewrites `self` → subject DID at **token mint** (upstream's choice,
    /// `lexicon-manager.ts:163-169`) and this resolves again at **match time**
    /// (the Rust crate's choice, `space_permission.rs:199-206`). Belt and
    /// braces: a row written by an older binary, or a `SwanScopePermissions`
    /// built directly from a raw set in a test, still fails closed rather than
    /// matching nothing silently. It is idempotent — `withResolvedAuthority`
    /// is a no-op on an already-concrete authority (`space-permission.test.ts:424-430`).

    func allowsRepo(_ target: RepoPermission.Target) -> Bool { … }
    func requireRepo(_ target: RepoPermission.Target) throws { … }

    func allowsRPC(_ target: RpcPermission.Target) -> Bool { … }
    func requireRPC(_ target: RpcPermission.Target) throws { … }

    func allowsBlob(_ target: BlobPermission.Target) -> Bool { … }
    func requireBlob(_ target: BlobPermission.Target) throws { … }

    func allowsAccount(_ target: AccountPermission.Target) -> Bool { … }
    func requireAccount(_ target: AccountPermission.Target) throws { … }

    func allowsIdentity(_ target: IdentityPermission.Target) -> Bool { … }
    func requireIdentity(_ target: IdentityPermission.Target) throws { … }

    /// **Upstream HAS an analogue — the earlier "Swan-specific, no upstream
    /// analogue" label was written against the truncated reference tree and is
    /// withdrawn.** `packages/pds/src/api/com/atproto/space/listSpaces.ts:20-25`
    /// asserts `assertSpace({ type: type ?? '*', authority: authority ?? '*',
    /// skey: '*', action: 'read_self' })` — i.e. it makes the *request filters*
    /// the match target and defaults each absent filter to `'*'`. Its comment at
    /// `:16-18` states Swan's own rationale in upstream's words: "No one space to
    /// check against, so the filters are the target: an unfiltered listing needs
    /// a wildcard grant." The inverse-matching itself is not a special rule
    /// upstream — it falls out of `SpacePermission.matches`
    /// (`oauth-scopes/src/scopes/space-permission.ts:94-98`), where a *concrete*
    /// grant dimension fails against a literal `'*'` target
    /// (`this.type !== '*' && this.type !== target.type`).
    ///
    /// So the function stays, and `aggregateDimension` (SwanCore.swift:324-327)
    /// is the correct semantics — but the correct *citation* is the two lines
    /// above, and the honest description is **a hardening of upstream's rule,
    /// not an invention**. Two clauses are Swan's own and must be justified as
    /// hardenings, not inherited:
    ///
    ///  * **The literal-`skey=*` / literal-single-`action=read` requirement.**
    ///    Upstream's defaults are `skey` → `'*'` and `action` →
    ///    `SPACE_DEFAULT_ACTIONS = ['read','create','update','delete']`
    ///    (`space-permission.ts:186-191`, `:207-211`, `:25-30`), so a *bare*
    ///    `space:<type>` grant satisfies upstream's `listSpaces` assert with no
    ///    query string at all. Swan refuses that. This is exactly the
    ///    "default `self` / `skey=*` / default action sets amplifying" hazard
    ///    §9-Q9 names as the reason retiring `isIssuableQualified` is safe: the
    ///    danger did not disappear, it moved here. Deleting this fence and
    ///    deleting that gate in the same release removes both halves.
    ///  * **`action == [.read]` exactly, where upstream accepts `read_self` too**
    ///    (`space-permission.ts:108-110`).
    ///
    /// Must NOT be folded into `allowsSpace`; it exists because the
    /// list route refuses to fetch broadly and then censor rows
    /// (the `aggregateDimension` doc comment, SwanCore.swift:320-323).
    ///
    /// **Written out, because the first draft left it `{ … }` and thereby never
    /// confronted the one thing it promised to preserve.** Today's rule
    /// (`SwanCore.swift:299-303`) is:
    ///
    ///     Set(parameters.keys) == ["authority", "skey", "action"]
    ///     parameters["skey"]   == "*"        // LITERAL
    ///     parameters["action"] == "read"     // LITERAL
    ///
    /// `parameters` comes from `strictQualifiedParameters` (`:352-375`), which
    /// reads only keys physically present in the string, so "literal" is
    /// observable today. Under the new grammar `skey` *defaults* to `["*"]` and
    /// `action` defaults to a list *containing* `read`, so without the
    /// `wasStated` provenance witness added in §4.6 a bare `space:<t>` grant
    /// would silently start satisfying `listSpaces?type=<t>&authority=<self>`.
    /// (The all-authorities case would still fail, because `aggregateDimension`
    /// requires a literal `*` grant and `self` resolves to a concrete DID — so
    /// only half of it narrows correctly, which is worse than either extreme.)
    func allowsSpaceListing(type: String?, authority: String?) -> Bool {
        let requestedType = type ?? "*"
        let requestedAuthority = authority ?? "*"
        return parsed.contains { scope in
            guard case let .space(grant) = scope else { return false }
            let resolved = grant.resolvingSelf(as: subject)
            let p = resolved.scopeParameters
            // 1. Exactly the three keys, all STATED — today's key-set equality.
            guard p.wasStated("authority"), p.wasStated("skey"), p.wasStated("action"),
                  !p.wasStated("collection"), !p.wasStated("manage") else { return false }
            // 2. LITERAL `skey=*` and LITERAL single `action=read`.
            guard resolved.skey == .any, resolved.action == [.read] else { return false }
            // 3. aggregateDimension on type and authority (SwanCore.swift:324-327):
            //    a wildcard REQUEST is satisfied only by a wildcard GRANT.
            return Self.aggregateDimension(resolved.type.stringValue, covers: requestedType)
                && Self.aggregateDimension(resolved.authority.stringValue, covers: requestedAuthority)
        }
    }

    /// Verbatim `SwanCore.swift:324-327`.
    private static func aggregateDimension(_ grant: String?, covers requested: String) -> Bool {
        if requested == "*" { return grant == "*" }
        return grant == requested || grant == "*"
    }
}

/// Carries the minimal satisfying scope for LOGS AND TESTS ONLY.
///
/// SwanOAuthResourceAuthorization.swift:9-16 states Swan's rule for this
/// boundary: "every invalid, expired, replayed, token-binding, and
/// account-lifecycle predicate becomes the same denial. This avoids turning the
/// protected-resource boundary into a DPoP or account-status oracle."
/// Upstream's ScopeMissingError is `expose = true` with `status = 403`
/// (scope-missing-error.ts) and echoes the needed scope to the caller; Swan
/// deliberately does not (§9-D6). Every HTTP adapter maps this to its own
/// opaque per-route code and logs `needed` server-side.
public struct ScopeDenied: Error, Sendable, Equatable {
    public let needed: String
}
```

Six families exist even though Swan today enforces only `space:`. **The surface
is dead in Swan; it is not dead upstream — every one of the six is wired to
concrete routes in `packages/pds`, and the port targets are named, not guessed
(§6.5.10).** Concretely, from the pinned tree:

* `assertRepo` → the record-write routes: `packages/pds/src/api/com/atproto/repo/createRecord.ts:64`,
  `putRecord.ts:82` **and** `:86` (both create and update, unconditionally),
  `deleteRecord.ts:60`, `applyWrites.ts:118` (once per unique `(action, collection)` pair).
* `assertBlob` → `packages/pds/src/api/com/atproto/repo/uploadBlob.ts:16`
  (`assertBlob({ mime: encoding })`, mime read from the `Content-Type` header, not the body).
* `assertRpc` → the proxy plane: the generic catch-all at
  `packages/pds/src/pipethrough.ts:66-68` plus 14 per-route call sites
  (`api/app/bsky/actor/getPreferences.ts:22`, `putPreferences.ts:22`,
  `getProfile.ts:18`, `getProfiles.ts:18`, `api/app/bsky/feed/getFeed.ts:17` **and** `:18`,
  `getTimeline.ts:18`, `getAuthorFeed.ts:18`, `getActorLikes.ts:18`, `getPostThread.ts:28`,
  `api/app/bsky/notification/registerPush.ts:28`, `unregisterPush.ts:22`,
  `api/com/atproto/moderation/createReport.ts:15`, `api/com/atproto/server/getServiceAuth.ts:29`).
* `assertIdentity` → `api/com/atproto/identity/updateHandle.ts:13` (`{attr:'handle'}`),
  `signPlcOperation.ts:16`, `submitPlcOperation.ts:12`,
  `requestPlcOperationSignature.ts:14` (all `{attr:'*'}`).
* `assertAccount` → `api/com/atproto/server/requestEmailConfirmation.ts:18`
  (`{attr:'email', action:'manage'}`) and `api/com/atproto/repo/importRepo.ts:25`
  (`{attr:'repo', action:'manage'}`).
* `assertSpace` (via the shared `assertSpaceScope` helper,
  `api/com/atproto/space/util.ts:87-100`) → 17 space/simplespace call sites, plus the
  direct `permissions.assertSpace(...)` at `api/com/atproto/space/listSpaces.ts:20-25`.

The four non-space families let the XRPC pipethrough
(`Sources/SwanHTTP/SwanXRPCPipethrough.swift`) and the public repo mutation
route (`Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:441`) adopt
`rpc:` / `repo:` / `blob:` without a second facade being invented later. Until
those routes are wired, their `allowsX` is reached only by tests — **not yet
ported**, with a named upstream mapping (§6.5.10) rather than a design gap.
The earlier framing ("a stated, deliberate dead surface, not an oversight")
rested on §9-Q4's premise that no upstream request-time verifier existed; that
premise was false, and the correction is §6.3's closing paragraph and §6.5.10.

### 6.2 What replaces the three existing predicate helpers

| today | replacement |
|---|---|
| `PermissionedSpaceScopeSyntax.permitsWholeSpaceRead(_:spaceType:authority:skey:)` (`SwanCore.swift:258-283`) | `allowsSpace(.delegationExchange(space))`, whose matcher arm is spelled out clause-by-clause in §5.6.3 (`isExactReadOnlyDelegationGrant`). **Three enforced conditions, not one.** The doc comment at `SwanCore.swift:246-257` explains why a collection-qualified grant (including `collection=*`) must never be amplifiable into a credential that reads every member repository — but the code enforces two more: `Set(parameters.keys) == ["authority","skey","action"]` (`:279`) and a **literal single** `action=read` (`:277`). Paraphrasing it as "contains read and names no collection" admits a bare `space:<type>` with no query at all. **The earlier claim "upstream has no such rule" is FALSE and is withdrawn** — it was written against the truncated tree. Upstream has the delegation-exchange rule in both prose and code: `packages/pds/src/api/com/atproto/space/util.ts:102-108` documents it ("A whole-space `read` grant is what an app exchanges for such a credential (see getDelegationToken); it is not itself one"), and `api/com/atproto/space/getDelegationToken.ts:22` implements it as `assertSpaceScope(auth, space, { action: 'read' })`. What is genuinely Swan's is the **hardening**, and it must be justified clause by clause against that code, not against an absence: (i) upstream's read arm is collection-independent (`oauth-scopes/src/scopes/space-permission.ts:104-107` — `if (target.action === 'read') return this.action.includes('read')`, no `collectionAllows` call), so upstream **does** let `space:<t>?action=read&collection=x` be exchanged for a whole-space credential; Swan refuses, and that refusal is the substance of `SwanCore.swift:246-257`; (ii) upstream's default action set contains `read` (`space-permission.ts:25-30`, `:207-211`), so a bare `space:<t>` is exchangeable upstream and is not in Swan; (iii) Swan additionally requires a literal single `action=read` and exactly the three stated keys (`SwanCore.swift:277`, `:279`). Keep the full clause set, never a general read — and keep it labelled a hardening of a real upstream rule. |
| `permitsAggregateSpaceList(_:spaceType:authority:)` (`SwanCore.swift:290-309`) | `allowsSpaceListing(type:authority:)` — body given in full in §6.1, keeping `aggregateDimension` semantics (`SwanCore.swift:324-327`; the "does not fetch broadly and then hide rows" rationale lives in that function's doc comment at `:320-323`, **not** at `:285-289`, which is the tail of `permitsAggregateSpaceList`'s own comment). Not upstream behaviour; must not be folded into `allowsSpace`. Requires the `wasStated` provenance witness (§4.6) to preserve its literal-`skey=*` / literal-`action=read` requirements. |
| `SwanSpaces.scopeAllows(_:space:permission:collection:)` (`SwanSpaces.swift:298-351`) and `managementScopeAllows` (`:353-373`) | `allowsSpace(_:)` with `.record(...)` / `.manage(...)`. Both private functions **delete**, along with their local `scopeType` (`:397-406`), `scopeTypePrefixLength` (`:408-413`), `strictQueryParameters` (`:379-395`), and `tupleElement` (`:415-417`) — the third copy of the tuple/validator logic. |
| `PermissionedSpaceScopeSyntax.isQualified(_ scope: String)` (`SwanCore.swift:198-243`) | superseded by `SpacePermission.parse` + `AtprotoScope.parse`. During Stages A–B it survives as a **one-line deprecated shim** — `(try? SpacePermission.parse(scope)).map(SpaceScopeAdmissionPolicy.isQualified) ?? false` — so the eleven call sites migrate one at a time. The `@available(*, deprecated, message:)` attribute is what makes "run alongside" a finite, greppable state rather than a permanent second grammar. Its 7…4096-byte cap and printable-ASCII gate disappear with it (§6.4). |
| `isIssuableQualified` (`SwanCore.swift:175-196`) | **DELETED, not relocated** (§9-Q9 ruling). It is not re-expressed over the new parser, and it does not become "an issuance policy over a parsed `SpacePermission`" — that earlier plan kept a semantic permission-family check at the client-metadata layer, which is the layer upstream deliberately leaves purely lexical (`oauth-types/src/oauth-client-metadata.ts:36` → `oauth-types/src/oauth-scope.ts:5-19`: `OAUTH_SCOPE_REGEXP` and nothing else, no length cap, no dictionary of known families). Its two live call sites — `OAuthClientMetadata.swift:290-295` (`localhostDevelopmentMetadata`'s `$0 == "atproto" \|\| isIssuableQualified($0)` guard) and `:343-344` (`validate()`'s `hasResourceScope` disjunct) — lose the call, and `:453-465`'s copy goes with stage A′. Its **zero** test coverage today — positive control: `grep -rn isIssuableQualified Tests/` returns zero, while `grep -rn isQualified Tests/` hits `Tests/SwanSpacesTests/SwanSpacesTests.swift:103, 108, 739` — is now an argument **for deletion**: nothing pins its behaviour, so nothing is lost, and re-expressing it would mean writing first-time tests for a gate the ruling retires. The invariants it was silently carrying are re-homed in the row below and in §6.2's tail. |

The ergonomic layer, in `SwanSpaces` (so `SwanCore` never imports it):

```swift
// Sources/SwanSpaces/SpaceScopeTargets.swift

/// The RECORD-ONLY subset of `SwanSpaces.SpacePermission`. Introduced because
/// the domain enum (`SwanSpaces.swift:175-182`) carries `case manage`, and a
/// total, non-throwing `record(_:action:collection:)` over it would have to map
/// `.manage` to *something*. Today that path is closed by construction —
/// `scopeAllows` requires `parameters["action"] == action` (`SwanSpaces.swift:325`)
/// and `"manage"` is never a legal `action=` value, so
/// `SpaceAuthorizationPolicy.require(..., permission: .manage)` is unsatisfiable
/// for every scope. The first draft noticed the hazard and left it as advice
/// ("rename the domain type or qualify at use"); that leaves the illegal state
/// REPRESENTABLE, and if it is ever routed to `.manage(SpaceManageOp)` a
/// `manage=`-bearing grant newly authorizes a *record* operation.
/// Remove the state instead of documenting it.
public enum SpaceRecordAction: Sendable, Hashable {
    case readSelf, read, create, update, delete

    /// Fails for `.manage` — the ONE case that must not become a record target.
    public init?(_ permission: SwanSpaces.SpacePermission) {
        switch permission {
        case .readSelf: self = .readSelf
        case .read: self = .read
        case .create: self = .create
        case .update: self = .update
        case .delete: self = .delete
        case .manage: return nil
        }
    }
}

public extension SpaceScopeTarget {
    static func record(_ space: SpaceURI, action: SpaceRecordAction, collection: String?) -> SpaceScopeTarget
    static func manage(_ space: SpaceURI, operation: SimpleSpaceManagementOperation) -> SpaceScopeTarget
    static func delegationExchange(_ space: SpaceURI) -> SpaceScopeTarget
}
```

Call sites converting a domain `SpacePermission` therefore `guard let action =
SpaceRecordAction(permission) else { throw SwanError.unauthorized(...) }` — a
`.manage` domain permission reaching the record path is a **denial**, preserving
today's unsatisfiable-by-construction behaviour explicitly rather than by
accident.

`SwanSpaces.SpacePermission` (`SwanSpaces.swift:175-182`) already spells
`read_self/read/create/update/delete/manage`, and
`SimpleSpaceManagementOperation` (`:188+`) is the disjoint manage vocabulary.
**Note the name collision** with the new `SwanCore.SpacePermission`: the
`SwanSpaces` one is a *domain* permission used by `SpaceGrant.allows`
(`:209-214`), not an OAuth `action` value. Rename the domain type or qualify at
use; the mapping into `SpaceScopeTarget` must keep `.manage` routing to the
`manage=` parameter and never to `action=`. The current `scopeAllows` achieves
that by rejecting `parameters["manage"] != nil` (`SwanSpaces.swift:322`) plus
requiring `parameters["action"] == action` (`:325`), which for
`permission == .manage` can never match a legal scope.

**Audit before deleting `isIssuableQualified` — what was it actually holding
up?** The function is `SwanCore.swift:175-196`; read as a list of assertions it
carried **five**, and each needs a new home or an explicit release.

**The fifth row was missing from an earlier draft of this table, and it is the
one that matters most.** Both call sites spell the predicate
`$0 == "atproto" || isIssuableQualified($0)`, and `isIssuableQualified` opens
with `guard isQualified(scope)` (`SwanCore.swift:176`), which opens with
`let prefix = "space:"` / `guard scope.hasPrefix(prefix)` (`:199-200`). So the
disjunction is a **closed permission-family allow-list of exactly two members**:
`atproto` and `space:`. Deleting it is not only a relaxation *within* `space:` —
it admits `account:`, `blob:`, `identity:`, `repo:`, `rpc:` and `include:` on a
bridge where none of them has ever been representable.

| invariant it enforced | line | where it lives after deletion |
|---|---|---|
| `action` ∈ `{read, read_self, create, update, delete}` — i.e. `manage` is **not** an `action=` value | `SwanCore.swift:184-185` | `SpaceRecordAction` (above) plus the grammar's own `action` schema (§5.6.2). The illegal state is removed by construction, not by a predicate; that is strictly stronger than the gate was. |
| a write action must name a concrete `collection`; only `read` may be collection-free | `SwanCore.swift:192-195` | `OAuthScopeAdmissionPolicy` at **PAR/authorize** (§6.3 stage B/E), never at registration. Upstream expresses the same intent as a *default*, not a gate: `collection` defaults to `[]` with the comment "Empty means no write targets, not 'all collections'" (`space-permission.ts:193-198`), so upstream mints a grant that authorizes no writes rather than refusing the request. Swan rejects instead (§9-D5). |
| the tuple's `authority` must be a DID and `skey` a valid record key — i.e. **no `self`, no `*`** | `SwanCore.swift:182-183` | Nothing, deliberately. This clause is *why* `isIssuableQualified` admits zero of bulleted.app's five scopes (§6.3 stage A′), and it contradicts the grammar this spec adopts, where `authority` defaults to `self` (`space-permission.ts:180-184`) and `skey` defaults to `'*'` (`:186-191`). It is released, and released is the point of the ruling. |
| **a closed two-member family allow-list: only `atproto` and `space:` are representable at all** | `SwanCore.swift:176` → `:199-200`, via the disjunction at `OAuthClientMetadata.swift:292` (registration) and `:460` (request) | **`OAuthScopeAdmissionPolicy` at PAR/authorize (§6.3 stage B/E), and nowhere earlier.** This is the row that makes retirement a genuine widening rather than a relaxation: after deletion the localhost bridge accepts **six** families it has never accepted — `account:`, `blob:`, `identity:`, `include:`, `repo:`, `rpc:` — **plus the three `transition:*` static scopes** D11 admits as inert (`transition:email`, `transition:generic`, `transition:chat.bsky`), which were equally unrepresentable under the old two-member allow-list. Nine newly admissible values, not five. `hasResourceScope` (§6.1) is `atproto`-or-`space:` only, so none of the nine unlocks a resource route by itself. **Two consequences that must ship with the deletion, not after it:** (a) §7.4's acceptance test asserts, per newly-admitted family, that a token carrying *only* that family reaches no protected route; (b) the Q7 consent renderer must describe all seven families before Stage C, because a bridge that could previously only ever show `atproto` and `space:` can now show `identity:*`. If (b) slips, narrow the feature flag (§9-Q7) rather than shipping raw-only consent over a widened family set. |
| exact key set `{authority, skey, action}` (±`collection`) | `SwanCore.swift:180-181` | Nothing at the issuance layer. The *resource-plane* fences keep their own, stricter, key-set requirements — `isExactReadOnlyDelegationGrant` (§5.6.3) and `allowsSpaceListing` (§6.1) — and those are what stop a permissive default set amplifying. That is the concrete reason the retirement is safe: the dangerous shapes were never actually stopped at registration for a *remote* client (`OAuthClientMetadata.swift:343-344` gates the disjunct on `isLocalhostDevelopmentClient`), so the fences were already the only real defence. |

Deleting the gate without first confirming those four rows is how a "cleanup"
silently becomes a widening.

### 6.3 Stage table: who validates what, and where it fails

| stage | module / file | owns | failure |
|---|---|---|---|
| A. Wire tokenization (remote AS path) | `SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:1059-1069` (`oauthServerScopes`), called at `:828` as `oauthServerScopes(fields["scope"] ?? "")` | split on `' '`, dedupe, ≤ 64 tokens, per-token byte/charset cap (tightened to `ScopeToken.isScopeToken`, §4.2), **plus the literal `openid` rejection** (§4.8) | `OAuthServerRequestError.malformed` → `invalid_request` |
| A′. Wire tokenization (**localhost bridge**) | `SwanOAuth/OAuthClientMetadata.swift:453-465` (`localhostRequestedScopes`), called at `SwanHTTP/SwanOAuthPARHTTP.swift:307` and `SwanHTTP/SwanLocalhostOAuthHTTP.swift:598` | **A second tokenizer AND a second issuance gate that the first draft never mentioned — the tokenizer stays and is unified, the gate is removed.** Same tightening as A (`ScopeToken.isScopeToken` in place of `$0 > 0x20 && $0 < 0x7F` — the exact predicate §4.2 condemns for admitting `"` and `\`) and the unified 1024-byte raw-input cap in place of its own 4096 (§6.4). **The `value == "atproto" \|\| isIssuableQualified(value)` disjunct at `:460` is DELETED, not re-expressed** (§9-Q9): A′ becomes tokenizer + budget only, exactly matching A, and every semantic question moves to stage B/E. The row's original diagnosis survives as the *reason* for the deletion: **`isIssuableQualified` (`SwanCore.swift:175-196`) admits ZERO of bulleted.app's five scopes, so leaving A′ untouched leaves the localhost flow rejecting four of five even after the rest of this spec ships** — and `Tests/SwanHTTPTests/LocalhostOAuthBrowserHTTPTests.swift`, which §7.1 tells the acceptance test to reuse, is the harness that drives exactly this path. Upstream's counterpart at this layer is purely lexical (`oauth-types/src/oauth-scope.ts:5-9`, `:17-19`); it holds no permission-family dictionary at all. Note §8 Stage C removes only the `isLocalhostDevelopmentClient &&` gate at `OAuthClientMetadata.swift:344`; `:460` is untouched by every stage as originally written and must be included. | `SwanError.malformed` → `invalid_request` |
| B. Grammar parse | `SwanCore` `AtprotoScope.parse` — **new call at PAR** | every token must parse into a known family or be a static value | `invalid_scope` (§4.8, §9-D5) |
| C. Client registration subset | `SwanOAuth/OAuthValidatedSession.swift:29` + `SwanOAuthAuthorizationServerHTTP.swift:255` + `DurableOAuthTokenService.swift:1112-1113` | requested ⊆ registered, **both sides canonicalised** (§9-D7) | `invalid_request` — stays opaque, `:256-259` |
| D. Client metadata — **lexical + budget only** | `SwanOAuth/OAuthClientMetadata.swift:290-295, 343-344, 438-447` (`parseScopes`) | That the `scope` field is a well-formed RFC OAuth scope-token list, plus Swan's documented raw-input budget (§6.4). **No permission-family knowledge. Registration grants nothing** (§9-Q9). This is exactly upstream's boundary: `OAuthClientMetadata.scope` is validated by `oauthScopeSchema` and nothing else (`oauth-types/src/oauth-client-metadata.ts:36` → `oauth-types/src/oauth-scope.ts:17-19`), which is `OAUTH_SCOPE_REGEXP` (`:5-6`) — space-delimited printable ASCII minus `"` and `\`, no length cap, no dictionary. An unknown or future scope name **registers fine**; it is rejected later, at PAR, if requested. Two concrete edits: the `isIssuableQualified` calls at `:292` and `:344` are deleted (§6.2), and `parseScopes` (`:441`) is *tightened* from `$0 > 0x20 && $0 < 0x7F` to the RFC charset, since today it still admits `"` (0x22) and `\` (0x5C) that upstream's regexp excludes | client-metadata rejection at load |
| E. Base-scope floor | `OAuthValidatedSession.swift:91-95` + `OAuthScopeAdmissionPolicy` (`ScopeAdmissionError.missingBaseScope`) | a session must carry `atproto` or a `space:` grant. **This is Swan's floor, which is looser than upstream's unconditional `atproto` requirement — the divergence is recorded in §4.8, not silently inherited.** | `SwanError.unauthorized` → PAR `invalid_scope` (matching the error table and B2; an earlier draft said `invalid_request` here) |
| F. Token mint: `self` resolution (+ Phase-2 expansion) | `DurableOAuthTokenService.swift:333-373` (`_issueAuthorizationCode`) — **new** — **and the refresh path `:700-718`**, whose binding comparison at **`:770`** reads the result (§6.4) | rewrite `authority=self` → the subject DID, preserving the requested bytes separately (§6.7). **Resolution runs on BOTH paths**, which is why the refresh binding check cannot compare against `family.binding.scopes` — see §6.4's refresh corollary and §9-D7 | `invalid_request` at the token endpoint |
| G. Persistence re-validation | `SwanSQLite/OAuthControlStore.swift:2218-2226`, `:2233-2240`, `:2345-2356` | byte caps, no whitespace, resource-scope floor, **and now a full re-parse** | `OAuthControlStoreError.invalidInput` |
| H. Request-time enforcement | `SwanHTTP/SwanOAuthResourceAuthorization.swift:160` mints the context; `SwanSpaces/SwanSpaces.swift:237-274, 280-296` decides. **Upstream counterpart:** `packages/pds/src/auth-verifier.ts:658` builds the permissions object and `:668` invokes the route's `authorize` callback before the handler runs; the per-route mapping is `pipethrough.ts:66-68` for the generic case and 67 `authorize:` callbacks across `packages/pds/src`. Swan's per-route correspondences are enumerated in §6.5.10 | the tuple/action/collection comparison for *this* operation | `SwanError.unauthorized` → per-route opaque code |

Upstream's split is the same shape, and it now matches at **every** stage
including H:

* **PAR/authorize** — `oauth-provider/src/request/request-manager.ts`
  `RequestManager.validate()`: the atproto-scope narrowing at `:184`
  (`Array.from(scopes).filter(isAtprotoOauthScope)`), the mandatory `atproto`
  token at `:241`, the `openid` rejection at `:243-248`, and permission-set
  resolution at `:297` whose `LexResolverError` becomes `invalid_scope` at
  `:304`. The requested-⊆-declared check is a separate, purely lexical step in
  `oauth-provider/src/client/client.ts:336-356`.
* **Token mint** — `token/token-manager.ts:133` and `:260-261`, both calling
  `lexicon/lexicon-manager.ts:43` `buildTokenScope`, which expands `include:`
  (`:52`), expands bare `space:<type>` into declared collections (`:60`,
  `expandSpaceCollections` at `:74`) and resolves `authority=self` against the
  granting DID (`:62`, `resolveSpaceSelfAuthority` at `:163-169`).
* **Request time** — **the earlier statement that "a request-time verifier is
  not present in the reference checkout at all" is FALSE and is withdrawn.** It
  was produced by a positive control run inside a reference export that
  contained only three subtrees and never included `packages/pds`. The verifier
  is `packages/pds/src/auth-verifier.ts`: `oauth()` builds the permissions
  object at `:658`, asserts the base `atproto` scope at `:661-666`, and invokes
  the route's own `authorize(permissions, ctx)` callback at `:668` — **before**
  returning credentials at `:670-675`, so a thrown assert aborts the request
  with no handler code running. There are **67** `authorize:` callbacks under
  `packages/pds/src` (positive control: `grep -rn "authorize:" packages/pds/src
  --include "*.ts" | wc -l` → 67, run against the complete tree at the pin).

Stage H therefore stays in `SwanSpaces` (reached from the durable adapter) for
**Swan's own architectural reasons** — the matcher is called synchronously from
inside actor-isolated code (`SwanSQLite.swift:9272`, `:11628`, `:11647`; §2
constraint 1), so it must stay a non-`async` value-type call — and **not**
because no model exists. The model exists and is enumerated route by route in
§6.5.10. Two shapes from it are worth naming here because they change how
Swan's own handlers must be written:

1. **Auth-phase vs handler-phase asserts.** Upstream asserts in the auth phase
   when the arguments come from params, headers, or static config
   (`pipethrough.ts:68`, `api/com/atproto/identity/updateHandle.ts:13`), and
   defers to a handler-phase assert when they come from the request **body** —
   `authorize: () => {}` with a comment, then the assert inside the handler
   (`api/com/atproto/space/listSpaces.ts:9-11` then `:20-25`;
   `api/com/atproto/space/getDelegationToken.ts:14-16` then `:22`). Every repo
   and space *write* route does the latter, because `collection` is a body
   field. Swan's own body-parse timing forces the same split.
2. **`assertRepoAvailability` is not a scope check.** It is an account-status
   check (`api/com/atproto/sync/util.ts:6`) run *in addition to* any scope assert.
   Do not count it as one when classifying a route as enforced.

Stage G gains a real parse check: today's `hasATProtocolResourceScope`
(`OAuthControlStore.swift:2352-2356`) only asks "is *at least one* scope
qualified", which lets an unparseable companion scope ride along beside a good
one.

**But that check must be additive-only, and the first draft's version could
permanently lock out live sessions.** Verified: the only per-element INSERT gate
today is `validScope` (`OAuthControlStore.swift:2345-2350`) — non-empty, ≤ 256
UTF-8 bytes, no whitespace, no control characters, **and nothing else**;
`hasATProtocolResourceScope` (`:2352-2356`) is an **OR over the set**, so
`{atproto, <arbitrary junk>}` was always accepted. Consequently:

- A live token family may legitimately hold an unparseable companion scope.
- Refresh rotation **rewrites** the family row, so a full-re-parse gate on that
  write would fail rotation and **permanently lock out that session** — §8.1's
  "old tokens are not re-minted, they keep their stored scope string" does not
  save it, because rotation is a write.
- It also contradicts §9-D5 in the same document: D5 rules that a *held*
  unparseable scope silently grants nothing; a hard write failure is the
  opposite.

**Resolution — the stage-G rule, stated precisely:**

1. On **INSERT of a newly-minted grant**: every element must parse. New tokens
   are fully under the new grammar's control, so this is a real tightening with
   no back-compat surface.
2. On **UPDATE / rotation of an existing family**: parse each element, **log**
   every rejection with the family id, and **do not fail the write** unless the
   *post-rotation* set would have zero parseable scopes. A rotation must never
   be the thing that ends a session.
3. `hasATProtocolResourceScope` at `:2352-2356` is replaced by
   `SwanScopePermissions(rawScopes:, subject: nil).hasResourceScope` — the same
   `atproto`-or-`space:` accept set (§6.1), not a wider one.

§7.5's replay test is re-stated accordingly: it asserts a **count and a list**,
not "zero rejected" (see §7.5).

### 6.4 Stage F: `self` resolution, and the byte caps

Swan has no `self` resolution anywhere today — `SwanCore.swift:311-315`
documents the deliberate omission. Upstream resolves it in
`lexicon-manager.ts:163-169` (`resolveSpaceSelfAuthority`) called from
`buildTokenScope`, **at token mint**.

**The Rust crate does NOT make the same choice, and the first draft
misattributed it.** `atproto-oauth/src/scopes/space_permission.rs:199-206`
documents `SpaceDid::SelfDid` as "Resolved against the subject of the token
carrying the grant, **at match time**. A `ScopesSet` built without a subject
cannot resolve it and so matches nothing." The two references differ; what the
Rust crate *does* corroborate is the correction that the `space:` **default**
authority is `self`, not `*`.

Swan takes **both**, deliberately, and §6.1's `resolvingSelf(as:)` documents why:
mint-time rewrite makes the persisted grant usable (§9-D8's fail-closed
argument), and match-time re-resolution keeps a row written by an older binary —
or a `SwanScopePermissions` built directly from a raw set — failing closed rather
than matching nothing silently. The rewrite is idempotent
(`space-permission.test.ts:424-430`), so running it twice is free. What it does
mean, and what must be stated rather than discovered: **there is no layer left at
which an unresolved `self` fails closed for a minted token** — the fence for
`.delegationExchange` and `allowsSpaceListing` cannot rest on unresolved-`self`,
which is precisely the error §7.3 made and now corrects.

In Swan the subject DID first meets the client binding at
`DurableOAuthTokenService._issueAuthorizationCode(subject:binding:…)`
(`DurableOAuthTokenService.swift:333-373`) — `createPushedAuthorizationRequest`
(`:141`) has no subject, so a PAR row genuinely cannot hold a resolved scope.
Resolution goes immediately before `requireOAuthDPoPBinding(binding)` (`:347`):

```swift
let resolved = try binding.resolvingSelfAuthority(to: subject)
try requireOAuthDPoPBinding(resolved)
let record = OAuthAuthorizationCode(… binding: resolved …)
```

and identically in `redeemRefresh`'s family-reuse path (`:700-718`), because
upstream re-derives scope on every refresh (`token-manager.ts:260-261`, calling
`lexicon-manager.ts:43` again) and a stored family could have been written by an
older binary. Swan's resolution is a pure string rewrite with no lexicon fetch,
so re-running it is idempotent and cheap.

**Refresh corollary — this paragraph is where the D7/D8 contradiction is
generated, so it must not be silent here.** Because resolution runs on the
refresh path, `family.binding.scopes` at refresh time holds the **resolved**
grant. The live binding check is
`DurableOAuthTokenService.swift:770` —

```swift
requestedScopes.map({ $0 == family.binding.scopes }) ?? true
```

— inside the guard at `:768-772`, which throws
`OAuthControlStoreError.bindingMismatch` on inequality. A client re-presenting
the scope string it originally *requested* would therefore be compared against a
string Swan itself rewrote. For `authority=self` — the **default**
(`space-permission.ts:180-184`) and after §6.4 the common case — requested and
resolved deliberately differ, so that comparison fails for every `self`-bearing
grant. **The comparison stays raw-string equality; the baseline operand
changes** to the requested set, `family.scopes_requested ?? family.scopes`
(§6.7, and §9-D7/D8 which C owns). Re-canonicalisation is *not* the failure mode
that fires here — resolution is.

**Fail-closed corollary:** an unresolved `self` matches nothing —
`SpacePermission.matches` returns `false` on `.unresolvedSelf`
(§5.6.3 step 2), per `space-permission.test.ts:380-384` and
`space_permission.rs:1574-1584`.

**Byte caps must be unified in the same change.** **Five** different caps govern
one value today — the first draft counted four and missed the localhost bridge:

| cap | where | value |
|---|---|---|
| per-token, remote PAR tokenizer | `SwanOAuthAuthorizationServerHTTP.swift:1061-1064` | 256 bytes, ≤ 64 tokens |
| per-token, **localhost bridge** | `OAuthClientMetadata.swift:456-461` (`localhostRequestedScopes`) | **4096 bytes**, ≤ 64 tokens |
| per-token, persistence | `OAuthControlStore.swift:2345-2350` (`validScope`) | 256 bytes |
| per-token, syntax | `SwanCore.swift:200` (`isQualified`) | 7…4096 bytes |
| per-token, metadata | `OAuthPublicationMetadata.swift:164` | 256 bytes |

The localhost row is the one that would survive an incomplete unification:
§9-D9's "the split disappears entirely" is only true if `:456-461` moves to 1024
with the rest. Left alone, the localhost request path keeps admitting 4096-byte
tokens while every other layer caps at 1024.

All five of those rows measure **raw input**. Note what is missing from the
table: **no cap today measures the expanded grant**, because Swan performs no
expansion today. That row is added below, as a second budget, before the
expansion that would need it exists.

A `space:` grant with a multi-valued `collection` list (upstream allows
`multiple: true`, `space-permission.ts:193-205`) blows past 256 bytes with three
or four NSIDs. Upstream has **no** length limit at all. The strongest evidence
is the client-metadata validator itself: `oauth-types/src/oauth-scope.ts:5-6`
is `OAUTH_SCOPE_REGEXP`, a pure charset/separator grammar with no quantifier
bound, and `:17-19` wraps it in `oauthScopeSchema` with nothing added; that
schema is the *only* validator applied to `OAuthClientMetadata.scope`
(`oauth-types/src/oauth-client-metadata.ts:36`). The caps below are Swan's, and
because they are Swan's they must be **published** (§6.6), not left as an
undocumented operational limit (§9-Q5 ruling).

**Decision (§9-D9): one cap, 1024 bytes per token, at all FOUR surviving
layers** — remote PAR tokenizer, localhost tokenizer (`localhostRequestedScopes`),
`validScope`, and `validateScopes` — **plus a whole-set budget of 8192 bytes.**
`isQualified`'s 7…4096 disappears with the shim. Raising a cap is
read-compatible — every existing row is ≤ 256 bytes and re-validates under the
larger bound, so there is no data rewrite.

**Two budgets, not one budget enforced twice.** The ruling splits them, and they
must be named separately even where the initial numbers coincide, because they
measure different strings and fail at different places with different blame:

| budget | measures | enforced at | who is at fault when it trips |
|---|---|---|---|
| **RAW-INPUT** | exactly the bytes the client sent — the `scope` parameter as received, before any Swan transformation | the WIRE: `SwanOAuthAuthorizationServerHTTP.swift:1059-1069` (`oauthServerScopes`) and `OAuthClientMetadata.swift:453-465` (`localhostRequestedScopes`); also `parseScopes` (`:438-447`) for the metadata document | the client. It sent too much. `invalid_request` at PAR. |
| **EXPANDED-GRANT** | what Swan holds **after its own transformations**: `self` → subject DID (§6.4), Phase-2 `include:` expansion and `expandSpaceCollections` (§5.7.4-§5.7.5) | TOKEN MINT (`DurableOAuthTokenService.swift:333-373` and the refresh path `:700-718`) and PERSISTENCE (`OAuthControlStore.swift:2345-2350`) | **Swan.** The client's request was inside budget; Swan's expansion pushed it out. |

Initial numbers: both start at 1024 B/token, 64 tokens, 8192 B/set. They are
still two budgets. Do not collapse them into one constant with one error case —
§4.8's `.scopeTooLong` row cannot serve both without losing the distinction
(that table is A's; flagged there).

**Why the split is not bookkeeping.** The failure it exists to name is real and
asymmetric: an 80-byte `include:com.example.permission-set` or a bare
`space:com.example.type` passes PAR comfortably under the raw-input budget, and
then **inflates** — `buildTokenScope` turns one `include:` into the whole
permission set (`lexicon-manager.ts:52`, `nsidToPermissionScopes` at `:211`) and
turns a bare `space:<type>` into one carrying every declared collection
(`expandSpaceCollections`, `:74-95`). The resulting set can exceed 8192 bytes
when the request never came close. Under a single shared budget that surfaces as
an `OAuthControlStoreError.invalidInput` at persistence — a 500-shaped internal
failure — for a request the server had already accepted at PAR. Under the split
it surfaces **at token mint, as its own error**, attributed to Swan's expansion
rather than to the client's request, and it is a Phase-2 gating condition
(§5.7.4's per-request expansion caps are the same budget family, and A re-files
them there). Phase 1 expands only `self`, which is length-bounded by a DID and
cannot inflate materially — so the split costs nothing today and is exactly the
thing that will be missing on the day `include:` lands.

**The raw-input budget belongs at the wire, not at persistence.** The first draft
placed the aggregate "in `validScope`'s caller", i.e. at
`OAuthControlStore.swift:2345`. But the hazard it names — "64 tokens × 1024 bytes
would be 64 KB" — is a *wire* hazard: at persistence, the request has already
been fully tokenized, fully parsed, and (Phase 2) already triggered lexicon
resolution. Enforce it where the bytes arrive. **Persistence is no longer "a
defence-in-depth copy of the same 8192 budget"** — that framing is withdrawn,
because persistence never sees the raw request. Persistence measures the
expanded grant, and is therefore the *primary* enforcement point of the second
budget, not a redundant copy of the first.

### 6.5 Exact call-site changes

#### 6.5.1 `AuthorizationContext.accountOAuth` carries permissions, not strings

`Sources/SwanSpaces/SwanSpaces.swift:221` (inside the `AuthorizationContext`
enum declared at `:219-230`):

```swift
case accountOAuth(subject: String, scopes: Set<String>)
```

becomes

```swift
case accountOAuth(subject: String, permissions: SwanScopePermissions)
```

`SwanScopePermissions` is `Sendable, Equatable, Hashable` (§6.1), so
`AuthorizationContext`'s existing `Sendable, Equatable` conformance (`:219`) is
preserved with **no `@unchecked` anywhere**.

This is the single highest-leverage change: it moves parsing from "every
predicate, every call" to "once, at the boundary that already validated the
token". `grep -rn accountOAuth Sources/` returns **24 occurrences across 16
files** (`SwanOAuth/SpaceCredentialAuthority.swift`,
`SwanInterop/LocalSemanticInterop.swift`, nine `SwanHTTP/*XRPC.swift` files,
`SwanSQLite/SQLitePreMigratedAccountDirectory.swift`,
`SwanSQLite/SwanSQLite.swift`, `SwanSpaces/SwanSpaces.swift`); with `Tests/`
included the count is 133. Most are `case let .accountOAuth(subject, _)`
destructures needing no edit beyond the label.

The one site to read carefully is
`SwanSQLite/SQLitePreMigratedAccountDirectory.swift:272-274`, which checks
literal `scopes.contains("atproto")` — narrower than
`hasATProtocolResourceScope`, so a space-only grant is refused there. It becomes
`permissions.hasBaseATProtocolScope`, which is *the same predicate*, **not** the
broader `hasResourceScope`. Do not "fix" it while migrating.

#### 6.5.2 Construction point

`SwanHTTP/SwanOAuthResourceAuthorization.swift:137-160`:

```swift
        // was: guard Self.hasATProtocolResourceScope(grant.scopes) else { … }
        let permissions = SwanScopePermissions(
            rawScopes: grant.scopes,
            subject: grant.subject
        )
        guard permissions.hasResourceScope else {
            throw SwanResourceAuthorizationFailure.denied
        }
        …
        return .accountOAuth(subject: grant.subject, permissions: permissions)
```

`Self.hasATProtocolResourceScope` (`:206-210`) is deleted.
`DurableOAuthTokenService.AccessGrant` (`DurableOAuthTokenService.swift:78-92`)
already carries both `subject` and `scopes`, so no new plumbing is needed.

`OAuthValidatedSession.swift:91-95` and
`DurableOAuthTokenService.swift:1246-1250` keep their own floor checks but
re-expressed as
`SwanScopePermissions(rawScopes: scopes, subject: nil).hasResourceScope` —
`nil` subject is correct at both: neither has resolved `self` yet (§6.4), and a
`self` grant must not be *counted* as satisfying the floor before it is
resolvable.

#### 6.5.3 `SwanSpaceListXRPC.swift:79-86`

```swift
        guard case let .accountOAuth(subject, permissions) = authorization,
              permissions.allowsSpaceListing(
                  type: spaceType,
                  authority: authority
              ) else {
            throw AuthenticatedSpaceListFailure.denied
        }
```

`spaceType` / `authority` are already `String?` here and the `?? "*"` defaulting
lives in the matcher (`SwanCore.swift:292-293`) — keep it there.

#### 6.5.4 `SwanSpaceDelegationXRPC.swift:78-86`

```swift
        guard case let .accountOAuth(subject, permissions) = authorization,
              permissions.allowsSpace(.delegationExchange(space)) else {
            throw SpaceDelegationMintingFailure.denied
        }
```

`space` is already a validated `SpaceURI` at `:56`, so the three-string argument
list collapses to one value — removing the possibility of an argument-order bug
that the current `spaceType:authority:skey:` signature (`SwanCore.swift:258-263`)
admits, all three being `String`.

#### 6.5.5 `SwanSpaces/SwanSpaces.swift:261-266` (record ops)

```swift
        case let .accountOAuth(subject, permissions):
            guard subject == author,
                  permissions.allowsSpace(
                      .record(space, action: permission, collection: uri?.collection)
                  )
            else {
                throw SwanError.unauthorized("OAuth scope does not cover this space operation")
            }
```

The `collection == nil` branch semantics at `SwanSpaces.swift:329-341` — an
aggregate read requires an *unqualified or wildcard* collection grant, because
"aggregate surfaces must not silently censor their response" — move into
`SpaceScopeTarget.record` as an explicit `aggregate` flag, **not** into the
generic matcher. **A Swan hardening of an upstream rule, not a Swan invention** —
the "no upstream analogue" label here was written against the truncated tree and
is withdrawn; what upstream has is the *opposite* rule, which is precisely what
makes the hardening necessary. Upstream reads are
unconditionally collection-independent — `space-permission.ts:104-110` takes the
`read` / `read_self` arms **before** `collectionAllows` is ever consulted
(`:112-115`), test
"read_self is not constrained by collection" `:320-327`); it must stay visible.

#### 6.5.6 `SwanSpaces/SwanSpaces.swift:281-296` (`requireManagement`)

```swift
        guard case let .accountOAuth(subject, permissions) = authorization,
              subject == space.authority else {
            throw SwanError.unauthorized("authority account OAuth is required")
        }
        if permissions.hasBaseATProtocolScope { return }
        guard permissions.allowsSpace(.manage(space, operation: operation)) else {
            throw SwanError.unauthorized("OAuth scope does not cover this space management operation")
        }
```

The ambient `atproto` bypass at `:290` is preserved verbatim and stays gated on
`subject == space.authority` (`:287`). Worth stating: this bypass is *stricter*
than upstream's transition scopes, which never reach a space at all
(`scope-permissions-transition.ts:55-61`) — Swan's bypass applies only to an
account acting on its own authority, so it is not the same hazard.

#### 6.5.7 Untouched-but-affected

`SwanSQLite/SwanSQLite.swift:9272, 11628, 11647` call
`SpaceAuthorizationPolicy.requireManagement` / `.require` and change **only** by
virtue of the enum payload rename — they pass `authorization` through whole.
This is exactly why `SwanScopePermissions` must stay a synchronous value type
(§6.7): those three sites are inside actor-isolated code and their callers are
non-`async` (`SwanSQLite.swift:11624-11652`).

`SwanHTTP/SwanSpaceBlobXRPC.swift:319`, `SwanSpaceXRPC.swift:62, 627, 697`,
`SwanSpaceRepositorySyncXRPC.swift:331`, `SwanSimpleSpaceXRPC.swift:406`,
`SwanPublicRepositoryMutationXRPC.swift:441` all obtain an
`AuthorizationContext` from `authorizer.authorize(…)` and forward it; no edit
beyond the destructure label.

#### 6.5.8 Request-time error, exactly

`SwanResourceAuthorizationFailure` (`SwanOAuthResourceAuthorization.swift:17-21`)
gains **no new case**. A scope shortfall is `.denied`, identical to a bad token
or an inactive account, per that file's oracle rule (`:9-16`). Each route
renders its own already-defined opaque code:

- `com.atproto.space.listSpaces` → `AuthenticatedSpaceListFailure.denied`
  (`SwanSpaceListXRPC.swift:79-86`)
- `com.atproto.space.getDelegationToken` → `SpaceDelegationMintingFailure.denied`
  (`SwanSpaceDelegationXRPC.swift:78-86`)
- record/blob/sync routes → `SwanError.unauthorized` from
  `SpaceAuthorizationPolicy.require` (`SwanSpaces.swift:261-266`)

`ScopeDenied.needed` goes to `context.logger` at `.info` with the route path and
the needed scope string, mirroring the "record the distinguishing detail
server-side" pattern already used at
`SwanOAuthAuthorizationServerHTTP.swift:260-269`.

#### 6.5.9 Three sites the first draft's inventory missed

**(a) `Sources/swan/SwanCommand.swift:7206` — the one scope *producer* in
`Sources/`.** §4.2's entire justification for `ScopeToken` is that "every
serialiser output and every value interpolated into a scope passes through here";
this is the site that proves it is needed, and it appeared in neither §2's
five-target table nor §6.5's call-site list nor §8's migration steps:

```swift
var scope = "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=\(action)"
if let collection {
    scope += "&collection=\(collection)"
}
```

Four uncontrolled interpolations. Replace with construction through
`SpacePermission` + `canonicalScopeString()`, which routes every value through
the encoders (§4.5) and the `ScopeToken` gate (§4.2). Nothing else in `Sources/`
builds a scope by interpolation — positive control: `grep -rn '"space:\\('
Sources/` returns this line only.

**(b) `Sources/SwanHTTP/SwanOAuthPARHTTP.swift:155` — `scopes: form.scopes ?? metadata.scopes`.**
`form.scopes` is `Set<String>?` (`:26`) and `localhostRequestedScopes` returns
`nil` for an absent `scope` parameter (`OAuthClientMetadata.swift:454`), so a
PAR with no `scope` at all is silently granted the client's **entire registered
scope set**. Upstream does the opposite: `new Set(parameters.scope?.split(' '))`
→ empty (`request-manager.ts:177`) → hard `InvalidScopeError` at `:241`.

Scope of the hazard, stated precisely: **this is the localhost bridge**
(`SwanLocalhostPARHTTP`, the file's own `enum` at `:12`, reached via
`registerLocalhostPAREndpoint` at `:52`), and its metadata comes from
`OAuthClientMetadata.localhostDevelopmentMetadata` (`:149`). The remote AS PAR
path is a different route (`SwanOAuthAuthorizationServerHTTP.swift:173`) and
tokenizes with `oauthServerScopes(fields["scope"] ?? "")` (`:828`), whose
`guard !values.isEmpty` rejects an absent `scope` as `.malformed`. A remote HTTPS
client therefore **cannot** reach the substitution.

It is still wrong, and it is still a silent widening on a live route: change
`:155` to require an explicit `scope` and reject its absence, matching both the
remote path and upstream. Add a vector.

**§9-Q9 makes this strictly worse, not better.** Under the ruling, client
metadata is validated **lexically only** — registration grants nothing and a
client may safely declare scope names Swan does not implement, exactly as
upstream permits (`oauth-types/src/oauth-client-metadata.ts:36` →
`oauth-scope.ts:17-19`). The registered set therefore stops being "a set of
things the client was vetted for" and becomes "a set of strings the client
typed". Substituting it for an absent request is then not merely a widening to
the maximum the client asked for at registration — it is a grant of an
**unvetted** set, since the semantic admission checks that would have caught a
malformed or unknown scope now live one layer later, at PAR, on the path this
substitution bypasses. Requiring an explicit `scope` is a precondition of the
Q9 layering, not an independent cleanup.

**(c) `Sources/SwanHTTP/SwanLocalhostOAuthHTTP.swift:817-826` — the second
consent renderer.** See §7.4 Stage 4, which now carries a *content* requirement
(semantic descriptions for every permission Swan can grant), not only a
completeness one — the question formerly filed as §9-Q7 is ruled, and both
renderers are in scope.

#### 6.5.10 Route → permission mapping: ported, and (separately) local policy

This section exists because §9-Q4's premise was false. There **is** an upstream
model for request-time enforcement (§6.3's closing paragraph), so Swan does not
author a mapping — it **ports** one, and only routes with no upstream
counterpart are local policy. The rule for this section: a row may be labelled
*local policy* only if a positive control run against `packages/pds` (not
against `oauth-scopes`, and not against the truncated export) found no
counterpart, and that control is named in the row.

**Ported mappings.** Every row's upstream side was opened at the pin; every
row's Swan side was grepped in this repository.

| Swan endpoint | Swan enforcement point today | upstream route | upstream assert | port |
|---|---|---|---|---|
| `com.atproto.space.createRecord` | `SwanSpaces.swift:261-266` via `SpaceAuthorizationPolicy.require` | `api/com/atproto/space/createRecord.ts:40` | `assertSpaceScope(auth, space, {action:'create', collection})` | **direct.** Already the shape §6.5.5 adopts (`allowsSpace(.record(space, action:, collection:))`). |
| `com.atproto.space.putRecord` | same | `space/putRecord.ts:49` | `assertSpaceScope(…, {action: exists ? 'update' : 'create', collection})` | **direct**, with one hazard: upstream resolves `create` vs `update` by an existence check *inside the transaction*, which is **not** the same as `com.atproto.repo.putRecord`'s rule (`repo/putRecord.ts:82` **and** `:86` assert *both* create and update unconditionally). Do not port one shape onto the other route. |
| `com.atproto.space.deleteRecord` | same | `space/deleteRecord.ts:35` | `assertSpaceScope(…, {action:'delete', collection})` | **direct.** |
| `com.atproto.space.applyWrites` | same | `space/applyWrites.ts:104` | `assertSpaceScope(…, {action, collection})` per write, in the handler loop | **direct.** Per-write, not per-request. |
| `com.atproto.space.getRecord`, `getBlob`, `getRepo`, `getLatestCommit`, `listRecords`, `listBlobs`, `listRepoOps` | `SwanSpaceRepositorySyncXRPC.swift:288`, `SwanSpaceBlobXRPC.swift:340`, `SwanSpaceListXRPC.swift` | `space/getRecord.ts:18`, `getBlob.ts:19`, `getRepo.ts:21`, `getLatestCommit.ts:17`, `listRecords.ts:19`, `listBlobs.ts:18`, `listRepoOps.ts:18` | `assertSpaceRead(auth, space, repo)` → `space/util.ts:109-127` | **direct, and the highest-value row in this table.** `assertSpaceRead` branches on credential type: a space credential is checked by `assertCredentialSpace` (`:114-116`); an account credential that is not the named repo gets a *deliberate non-oracle* — the same `RepoNotFound` an absent repo gets, with the comment at `:119-120` ("whether a given account holds a repo in a space the caller cannot read is not the caller's business"); only the own-repo case reaches `assertSpaceScope(…, {action:'read_self'})` at `:126`. Swan's sites currently check `subject == author` and stop. Porting means porting the *error shape* too, which is the same oracle rule Swan states independently at `SwanOAuthResourceAuthorization.swift:9-16`. |
| `com.atproto.space.getDelegationToken` | `SwanSpaceDelegationXRPC.swift:78-86` (§6.5.4) | `space/getDelegationToken.ts:22` | `assertSpaceScope(auth, space, {action:'read'})` | **ported with a documented Swan hardening.** Upstream's read arm is collection-independent and its default action set contains `read`, so upstream accepts both a bare `space:<t>` and a collection-qualified read here. Swan's `isExactReadOnlyDelegationGrant` refuses both. See §6.2's first row for the clause-by-clause justification. |
| `com.atproto.space.listSpaces` | `SwanSpaceListXRPC.swift:79-86` (§6.5.3) | `space/listSpaces.ts:20-25` | `assertSpace({type: type ?? '*', authority: authority ?? '*', skey:'*', action:'read_self'})`, handler-phase (auth-phase `authorize` is a no-op at `:9-11` with the reason stated) | **ported with a documented Swan hardening**, per §6.1's `allowsSpaceListing`. The filters-are-the-target rule is upstream's (`:16-18`); the literal-`skey=*` / literal-`action=read` / stated-keys requirements are Swan's. |
| `com.atproto.simplespace.createSpace` / `updateSpace` / `deleteSpace` / `addMember` / `removeMember` | `SwanSpaces.swift:281-296` (`requireManagement`, §6.5.6) | `simplespace/createSpace.ts:22`, `updateSpace.ts:16`, `deleteSpace.ts:17`, `addMember.ts:18`, `removeMember.ts:17` | `assertSpaceScope(…, {manage:'create'\|'update'\|'delete'})` **plus** `assertSpaceOwner` on all but create | **direct.** Note upstream requires **both** the scope assert and an ownership assert; Swan's `requireManagement` already gates on `subject == space.authority` (`:287`), which is the ownership half. Keep both halves when porting; dropping either is a widening. |
| `com.atproto.simplespace.getSpace` / `listMembers` | `SwanSimpleSpaceCheckUserAccessXRPC.swift`, `SwanSimpleSpaceXRPC.swift:426-427` | `simplespace/getSpace.ts:25`, `listMembers.ts:20` | `assertSpaceScope(…, {action:'read_self'})` (getSpace additionally branches to a space-credential check) | **direct.** |
| `com.atproto.repo.createRecord`, `putRecord`, `deleteRecord`, `applyWrites` | **NONE beyond the base scope** — `SwanPublicRepositoryMutationXRPC.swift:449-450` is `guard case let .accountOAuth(subject, scopes) = authorization, scopes.contains("atproto")` | `repo/createRecord.ts:64`, `putRecord.ts:82` **and** `:86`, `deleteRecord.ts:60`, `applyWrites.ts:118` | `assertRepo({action, collection})` — `applyWrites` once per unique `(action, collection)` pair | **NOT YET PORTED.** Swan declares all four NSIDs in its public profile (`Sources/SwanPublicWire/SwanPublicWire.swift:35`, `:36`, and siblings) and serves them at `SwanPublicRepositoryMutationXRPC.swift:538-556`. This is the concrete route §6.1's `hasResourceScope` doc refers to: widening that predicate to admit `repo:` **before** this row is ported hands a `repo:`-only grant an unchecked write. |
| `com.atproto.repo.uploadBlob` | same single `scopes.contains("atproto")` guard | `repo/uploadBlob.ts:16` | `assertBlob({mime: encoding})`, mime derived from the `Content-Type` **header** | **NOT YET PORTED.** Swan's handler is `SwanPublicRepositoryMutationXRPC.swift:48`, registered at `:557`. The header-derived `mime` is the porting detail most easily lost — a body-derived mime would let a client name a type it is not uploading. |
| generic XRPC proxy | `SwanXRPCPipethrough.swift` / `SwanXRPCProxyRouting.swift` | `pipethrough.ts:66-68`, params built at `:96-112` | `assertRpc({lxm, aud})` where `lxm = parseReqNsid(req)` and `aud = ${did}#${serviceId}` | **NOT YET PORTED**, and the single most important shape in the table: the `scopeAud` / `tokenAud` split at `pipethrough.ts:101-106` (comment at `:101-104`) is what lets an OAuth grant's `rpc:?aud=did#service` match a proxied call **while the outbound service-auth JWT keeps a bare-DID `aud`**. Porting `assertRpc` without that split either breaks outbound auth or makes every `rpc:` scope unmatched. |
| `com.atproto.moderation.createReport` | `SwanXRPCProxyRouting.swift:105` | `moderation/createReport.ts:15` | `assertRpc({aud, lxm})`, aud from `computeProxyTo` | **NOT YET PORTED**; Swan already routes the literal NSID, so this is the cheapest single `assertRpc` to land first. |
| `app.bsky.actor.getPreferences` / `putPreferences` | `SwanXRPCProxyRouting.swift:44-45` | `api/app/bsky/actor/getPreferences.ts:22`, `putPreferences.ts:22` | `assertRpc({aud, lxm})` | **NOT YET PORTED**; literal NSIDs confirmed present in Swan's routing table. |

**Local policy — Swan-specific routes with no upstream counterpart.** Each row
names the control that found no counterpart, and the control was run against
`packages/pds`, which is where a counterpart would be if one existed.

This table is **short on purpose, and it got shorter while being written.** A
first draft of it listed `getSpaceCredential`, `notifyWrite`, `registerNotify`
and `listRepos` as Swan-only. Running the control that this section's own rule
demands — `ls packages/pds/src/api/com/atproto/space/` — falsified all four in
one command: every one of them exists upstream. That is the same mistake §9-Q4
made, reproduced inside the correction to §9-Q4, and it is recorded here rather
than quietly deleted, because it is the evidence that the rule ("name the
control, then run it") is what does the work.

| Swan endpoint | why it is local policy | positive control |
|---|---|---|
| `com.atproto.space.notifySpaceDeleted` | Swan-only deletion fan-out. Upstream's nearest relative is the tombstone read inside `getSpaceCredential.ts:32-39`, which surfaces deletion on the *next credential renewal* instead of pushing a notice. | `ls packages/pds/src/api/com/atproto/space/` → `applyWrites, createRecord, deleteRecord, getBlob, getDelegationToken, getLatestCommit, getRecord, getRepo, getSpaceCredential, index, listBlobs, listRecords, listRepoOps, listRepos, listSpaces, notifyWrite, putRecord, registerNotify, unregisterNotify, util` — 20 entries, no `notifySpaceDeleted`. |
| `com.atproto.simplespace.checkUserAccess` | Swan-only membership probe. | `ls packages/pds/src/api/com/atproto/simplespace/` → `addMember, createSpace, deleteSpace, getSpace, index, listMembers, removeMember, updateSpace` — no `checkUserAccess`. |

**Routes that exist upstream but carry no `ScopePermissions` assert**, and so owe
Swan a mapping of a *different* kind — a credential-plane check, not a scope
check. Classifying these as "unenforced" would be a reading error:

| route | upstream auth | check |
|---|---|---|
| `com.atproto.space.getSpaceCredential` | `auth: ctx.authVerifier.delegationTokenAuth` (`space/getSpaceCredential.ts:9`) | Not a scope assert at all. The delegation token's own `sub` must equal the requested space (`:14-19`), `assertSpaceHost` (`:21`), an optional client attestation (`:23-28`), a tombstone check (`:32-39`), and `authorizeCredential` (`:43-47`). The *scope* gate for this capability was already spent one hop earlier, at the user's own PDS, in `getDelegationToken.ts:22`. Swan's equivalent split is the same and is spelled out in §6.8. |
| `com.atproto.space.registerNotify`, `unregisterNotify`, `listRepos` | `auth: ctx.authVerifier.spaceCredentialAuth` (`registerNotify.ts:17`, `unregisterNotify.ts:8`, `listRepos.ts:9`) | `assertCredentialSpace(auth.credentials, space)` — the credential must name *this* space. No OAuth scope is involved, because the caller is a syncer holding a space credential, not an account. |
| `com.atproto.space.notifyWrite` | `auth: ctx.authVerifier.serviceAuth` (`notifyWrite.ts:10`) | Inter-service auth plus `simpleSpaceManager.authorizeUser` (`:54-59`); the comment at `:24` explains why authority is not checked during auth ("a PDS answers for many authorities"). |

**Routes Swan deliberately does not serve, so no mapping is owed.** Upstream
enforces `assertIdentity` on `identity/updateHandle.ts:13`,
`signPlcOperation.ts:16`, `submitPlcOperation.ts:12`,
`requestPlcOperationSignature.ts:14`, and `assertAccount` on
`repo/importRepo.ts:25`. Swan answers 404 for the whole
`com.atproto.identity.*` and `com.atproto.repo.*` namespaces except the exact
routes it registers — the refusal and its reasoning are written into
`Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift:37-47`, which names
`updateHandle` and `signPlcOperation` explicitly. `identity:` is therefore
unreachable in Swan today, which is *why* it must still get a consent string
(§7.4 Stage 4, C's section) rather than be skipped: the day a route appears, the
grant must already be describable.

`assertAccount({attr:'email', action:'manage'})` on
`server/requestEmailConfirmation.ts:18` is the one non-space family with a
**live** Swan counterpart — `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:213`,
`:249` implement `requestEmailConfirmation` end to end. It is the cheapest
`account:` port and the natural first one.

### 6.6 Authorization-server metadata

**Advertise exactly what Swan advertises today — `scopes_supported: ["atproto"]`
— and add nothing** (§9-D10).

Upstream's `metadata/build-metadata.ts:28-38` lists only
`['atproto', 'transition:email', 'transition:generic', 'transition:chat.bsky']`,
with an explicit comment at `:31-32` that this is "not a specced behavior" and
serves only as a hint that transition scopes are supported. Granular
`repo:` / `rpc:` / `space:` / `account:` / `blob:` scopes are **never**
enumerated, by design, because they are dynamic — a `space:` scope's value space
is the cross product of every space type, authority DID, skey, collection and
action in existence. There is no finite list to publish.

Swan matches that **minus the transition entries**, because Swan implements none
of them (§4.7). Concretely: `OAuthAuthorizationServerMetadata.init`
(`Sources/SwanOAuth/OAuthPublicationMetadata.swift:53`) and
`OAuthProtectedResourceMetadata.init` (`:16`) keep their `["atproto"]` defaults,
and `SwanOAuthAuthorizationServerConfiguration.init`
(`Sources/SwanHTTP/SwanHTTP.swift:191-196`) keeps its pass-through. No override
is added; there are zero overrides in the tree today (positive control:
`grep -rn "scopesSupported:" Sources/` hits only the two definition files).

Three consequences to accept explicitly rather than discover later — the third
is new, and is what §9-Q5's ruling adds:

1. `OAuthPublishedURL.validateScopes` (`OAuthPublicationMetadata.swift:159-170`)
   hard-requires `scopes.contains("atproto")` at `:161`. Correct, and it stays:
   a metadata document omitting the base scope would advertise an AS that cannot
   mint an AT Protocol session at all. It also means an operator *cannot*
   accidentally publish a space-only `scopes_supported`. Its 256-byte cap at
   `:164` moves to 1024 with the others (§6.4) — and it belongs to the
   **RAW-INPUT** budget, not the expanded-grant one: this validator measures a
   published metadata document, which is bytes as authored, and nothing Swan
   expands ever passes through it. Say which budget explicitly at the call site;
   the two share a number today and will not always.
2. `scopes_supported` is **not** the recognition mechanism — upstream's
   `isAtprotoOauthScope` (`atproto-oauth-scope.ts:42-53`) is a full
   parse-and-validate, not a metadata lookup. A client discovers Swan's grammar
   from the proposal, not from Swan. bulleted.app's failure was **not** caused
   by a missing advertisement; it read all three documents successfully and
   rejected their content. Do not add a fake advertisement to paper over a
   grammar gap. The one Swan-specific divergence a client *would* want to
   discover — that Swan rejects rather than drops unknown scopes (§9-D5) — has
   no standard metadata field; document it in `docs/`, do not invent a
   nonstandard key.

   That divergence is real and worth naming precisely, because it is a
   *deliberate* departure: upstream **silently narrows**. `request-manager.ts:184`
   is `Array.from(scopes).filter(isAtprotoOauthScope).join(' ')` — an
   unrecognised token is dropped and the request proceeds — and the comment at
   `:178-182` explains why (the AS cannot render an unknown scope for consent, so
   the client must re-authenticate once support lands). Swan returns
   `invalid_scope` instead. A naive "match upstream" reading of this section
   would implement the drop; do not.

3. **Swan's byte and count budgets are published, in `docs/`, and nowhere else**
   (§9-Q5 ruling). Upstream imposes none — its client-metadata validator is
   `oauthScopeSchema` alone (`oauth-types/src/oauth-client-metadata.ts:36` →
   `oauth-scope.ts:5-19`), a charset grammar with no quantifier bound — so every
   one of Swan's limits is a Swan-only interoperability fact that a client can
   hit and cannot discover. Publish, in a new
   `docs/oauth-scope-interoperability.md` alongside the reject-vs-drop
   divergence above:

   | published limit | budget (§6.4) | value |
   |---|---|---|
   | bytes per scope token | RAW-INPUT | 1024 |
   | tokens per request | RAW-INPUT | 64 |
   | bytes per whole `scope` parameter | RAW-INPUT | 8192 |
   | bytes per stored grant token / whole grant | EXPANDED-GRANT | 1024 / 8192 |
   | `include:` scopes resolved per request (Phase 2) | EXPANDED-GRANT | §5.7.4 |
   | space types expanded per request (Phase 2) | EXPANDED-GRANT | §5.7.4 |

   **The "no invented OAuth metadata field" rule stands verbatim** and the ruling
   agrees with it: none of these becomes a key in
   `/.well-known/oauth-authorization-server`. Publishing prose is not
   advertising a capability. The reason to publish at all is the second budget:
   a client that stays inside every documented raw-input limit can still be
   refused at token mint by Swan's own expansion (§6.4), and a client cannot
   debug that against a spec it has never been shown.

### 6.7 Persistence and the SQLite migration

**What is persisted today.** `Sources/SwanSQLite/SwanSQLite.swift:91-105`
(`oauth_control_token_families`) and `:107-126` (`oauth_control_par_requests`)
each have `scopes BLOB NOT NULL`, encoded as `JSONEncoder().encode(scopes.sorted())`
— a JSON array of strings, **not** the space-delimited OAuth wire form
(`OAuthControlStore.swift:2233-2240`). Decode round-trips through `Set<String>`
and re-asserts no post-decode duplicates plus `validScope` per element
(`:2242-2254`). The format is already opaque to scope shape, so nothing
schema-level changes for the grammar itself.

**What must change.** Upstream's store contract is that new tokens persist the
fully-expanded scope, post-`buildTokenScope` (`token/token-data.ts:22-40`;
`CreateTokenData` tightens `scope` to non-null at `token-store.ts:28-30`), with
the field nullable only for tokens minted before scope persistence existed
(`token-data.ts:37-38`). Rotation re-derives and re-persists it
(`token-store.ts:49-54`, `token-manager.ts:260-263`). Swan's analogue is
narrower because Swan (Phase 1) expands nothing except `self`:

- `oauth_control_par_requests.scopes` keeps the **as-requested** strings. A PAR
  row has no subject (`DurableOAuthTokenService.swift:141`), so it physically
  cannot hold a resolved value. **Unchanged.**
- `oauth_control_token_families.scopes` holds the **resolved** strings, and a new
  nullable column `scopes_requested BLOB` holds the pre-resolution set when the
  two differ. Storing resolved-in-place (rather than adding `scopes_resolved`)
  means every existing reader — `AccessGrant.scopes`
  (`DurableOAuthTokenService.swift:88`), `validateAccess`, the refresh path at
  `:716` — keeps working unchanged and automatically enforces against the
  resolved value. A stale binary reading a new row sees a concrete DID where it
  expected `self`, which fails closed, not open.

`scopes_requested` was introduced for one reason — consent/audit: without it,
"what did the user actually approve" is unanswerable once `self` is rewritten.
**It has a second reader, and the earlier claim that it is "never read by an
enforcement path" is FALSE as written and must change.** The refresh binding
comparison reads it.

The precise statement, replacing the blanket one:

* `scopes_requested` is **never read by the matcher** — no resource-plane
  decision, no `allowsX`, no stage-H comparison ever sees it. `SwanScopePermissions`
  is built from the **resolved** `scopes` column and only from it. That is the
  property §9-D8 actually needs, and it is preserved.
* `scopes_requested` **is** the baseline for the **refresh binding check** at
  `DurableOAuthTokenService.swift:770`. That comparison must be
  `family.scopes_requested ?? family.scopes`, not `family.binding.scopes`,
  because §6.4 resolves `self` on the refresh path too — see §6.4's refresh
  corollary, and §9-D7/D8, which C owns. Without this the two decisions
  contradict: D7 says compare raw requested bytes against `family.binding.scopes`,
  D8 changes `binding.scopes` to hold the resolved grant, and for
  `authority=self` — the grammar's **default** (`space-permission.ts:180-184`) —
  those deliberately differ, so **every `self`-bearing grant would fail to
  refresh**. That is nearly all of them after §6.4.

So this is an **authorization-path column**, not an audit-only one. Anyone
reviewing the migration below on the assumption that a NULL or a wrong value is
merely a lost audit trail is reviewing it against the wrong risk: a wrong value
here denies refresh to a live session.

**The migration.** `OAuthControlStore.migrateWithoutGate()`
(`OAuthControlStore.swift:1447-1541`) runs `SQLiteLayout.controlMigrations` (all
`CREATE TABLE IF NOT EXISTS`) and then a series of `addColumnIfMissing` calls
(`:1468-1508`), all inside one `BEGIN IMMEDIATE` transaction so two cold-starting
processes cannot race (`:1449-1453`). `addColumnIfMissing` (`:1543-1547`)
inspects `PRAGMA table_info` and emits `ALTER TABLE … ADD COLUMN` only when
absent. Add one call, following the existing `client_assertion_jkt` pattern at
`:1474-1478`:

```swift
            try await addColumnIfMissing(
                table: "oauth_control_token_families",
                column: "scopes_requested",
                definition: "BLOB"
            )
```

and add the same column to the `CREATE TABLE` text at `SwanSQLite.swift:91-105`
so fresh databases match. Nullable, no `CHECK`, no default — matching how
`dpop_jkt` / `client_assertion_*` are declared (`SwanSQLite.swift:98-101`).

Decode rule for the nullable column, mirroring upstream's back-compat note
(`token-data.ts:37-38`): **`NULL` means "requested == stored", not "unknown"**.
Rows written before this migration were written before `self` resolution
existed, so their `scopes` genuinely *is* what was requested.

**This rule is now load-bearing for authorization, not only for audit.** It is
what makes `family.scopes_requested ?? family.scopes` a *total* function: the
`??` fallback is not a defensive shrug at an unknown value, it is the correct
answer for every pre-migration row, and it is why §8.1's "old tokens are not
re-minted, they keep their stored scope string" continues to hold — a
pre-migration family refreshes by comparing against its own unchanged `scopes`,
exactly as it does today. Two corollaries that must not be discovered later:

* Never write `scopes_requested` as an empty blob to mean "same". Empty and NULL
  would then be indistinguishable from "requested nothing", and the fallback
  would silently compare against the wrong operand. Write NULL or write the set.
* The "when the two differ" storage rule and the `??` decode rule are one rule
  seen from two sides. State them together or a later reader will implement
  "always write it" on one side and "NULL is unknown" on the other.

**Migration review note.** `scopes_requested` is added below by
`addColumnIfMissing`, which is mechanically identical to the four additive OAuth
columns that preceded it — but do not let that similarity set the review bar.
The four predecessors (`dpop_jkt`, `client_assertion_*`) are inert to
authorization until a binding is presented; this one sits on the refresh path
from the moment the first resolved grant is written. Review it as an
authorization change with an additive schema, not as a schema change.

**No `permissioned_repository_migrations`-style version row.** That versioned
mechanism (`SwanSQLite.swift:948`, `:2139-2172`) exists for destructive/renaming
migrations; this one is purely additive and `addColumnIfMissing` is already
idempotent. Adding a version row here would be inconsistent with the four
additive OAuth columns that preceded it. Rollback is a redeploy: an unused extra
nullable column is inert to the previous binary.

### 6.8 `getSpaceCredential`: binding the credential to a proved key

**This section ships as its own PR, separate from the scope-grammar change, and
mint and consume land TOGETHER inside it** (§9-Q6 ruling). Both halves of that
sentence are load-bearing:

* *Separate from the grammar change* — nothing here touches `AtprotoScope`,
  `SwanScopePermissions`, the tokenizers, or the stage table. Stages A/B/C in §8.2
  are a different track; this is not a fourth stage of them (C owns that
  sequencing note).
* *Mint and consume together* — a mint-only half-landing produces credentials
  carrying a `cnf` nobody checks, which is the status quo dressed as progress; a
  consume-only half-landing rejects every credential Swan has already issued.
  Upstream keeps them one hop apart in the same system (`space/credential.ts:105`
  mints, `pds/src/auth-verifier.ts:392-400` consumes) and there is no window in
  which one exists without the other.

#### 6.8.0 What this change is and is NOT

State this before the mechanics, because the rest is easy to over-read. Two of
the three senses in which the first draft called the credential "bindable in
name only" survive as **deliberate divergences shared with upstream**; the third
does not survive and is corrected. Points 1 and 2 have been re-verified against
`packages/space/src/dpop.ts`, which the first draft never read (it reasoned only
from the Rust module).

1. **No `ath` — and upstream actively REJECTS one.** `space/src/dpop.ts:117-125`
   is a two-armed check, not an omission: when a credential is supplied
   (presentation) `ath` must equal `base64url(sha256(credential))` (`:117-120`);
   when it is absent (issuance) `ath` **must be absent too**, or the proof is
   refused with "DPoP proof `ath` must be omitted when obtaining a credential"
   (`:121-125`). This corroborates `dpop.rs:216-230`, and it is a *tightening*
   Swan should adopt rather than merely matching the omission: an issuance proof
   carrying an `ath` is malformed, not permissible. The hazard the first draft
   named is still real and still accepted — the proof is not tied to the
   delegation token, so any proof over
   `(POST, /xrpc/com.atproto.space.getSpaceCredential)` from any key validates
   against any delegation, and a stolen delegation is exchangeable for a
   credential bound to the thief's key. Upstream accepts the same exposure and
   bounds it elsewhere: the delegation is **single-use** and **audience-bound**
   (`auth-verifier.ts:468-473`, `:485-496`), so a stolen delegation is worth one
   credential at one authority, once.
2. **No nonce — upstream has no nonce machinery on this path either.**
   `space/src/dpop.ts` contains no nonce concept at all; freshness is
   `maxTokenAge: MAX_PROOF_AGE_SEC` with `clockTolerance: CLOCK_SKEW_SEC`
   (`:89-105`) plus a caller-side replay check. `verifyDpopProof`'s own doc
   comment states the split explicitly: "Checks everything but replay; the caller
   records the returned `jti` itself" (`:79`). Swan's design (§6.8.2) matches:
   proof validation stays pure and testable, the `jti` reservation is a separate
   durable step.
3. **~~Nothing verifies `cnf`~~ — WITHDRAWN. Nothing verifies it *in Swan*.**
   The claim that no model exists was §9-Q6's premise and it was false; it came
   from a reference export that did not contain `packages/pds` or
   `packages/space`. Upstream verifies `cnf` **twice**, by construction:
   structurally at parse (`space/credential.ts:154-156`, driven by the
   `requireCnf: true` flag on the `credential` token class at `:35`) and again,
   independently, at authorization (`pds/src/auth-verifier.ts:392-398`). The
   second check carries the exact rationale this spec needs, in upstream's own
   words at `:390-391`: *"Unreachable unless parseSpaceToken's own check is
   relaxed, but an unbound credential must never fall through as a bearer token
   for the whole space."* This is therefore a **Swan gap with a named upstream
   fix**, not an open design question, and the fix ships in this PR (§6.8.3).

The honest description of the change, updated for the corrected point 3: **the
thumbprint is taken from a verified proof instead of from an attacker-assertable
body field, AND a credential presenting no binding is refused rather than
honoured.** The first draft's summary — "the thumbprint is now taken from a
verified proof instead of an attacker-assertable body field" — *understates* it
now that consumption is in scope: with mint alone the change is
forward-compatible plumbing; with mint and consume together the credential
actually becomes sender-constrained, which is the property a release note may
finally name. `SwanSpaceCredentialXRPC.swift:243` already blocks the body field,
and this removes that hazard permanently.

#### 6.8.1 The change, and where it comes from

**Two references, not one.** The first draft sourced this section entirely from
the Rust reference because the TypeScript packages were missing from its
checkout. They are present at the pin, they are the authoritative shape, and
they should be the primary cross-check — the Rust module is where the
doc-drift warning at the end of this section comes from, so it is the *less*
reliable of the two on exactly this question.

| fact | TypeScript (authoritative) | Rust (corroborating) |
|---|---|---|
| `cnf` shape on the wire | `packages/space/src/credential.ts:58` — `cnf?: { jkt: string }` in the shared `SpaceTokenPayload` | `atproto-space/src/credential.rs:159-181` |
| `cnf` required for the **credential** class only | `credential.ts:30-37` (`requireCnf: true`); `delegation` and `clientAttestation` are `false` (`:24`, `:43`) | — |
| minting embeds it, and refuses to sign without it | `credential.ts:92-94` (throw before signing), `:105` (`...(opts.dpopJkt ? { cnf: { jkt: opts.dpopJkt } } : undefined)`) | `create_space_credential` |
| the thumbprint is RFC 7638 over the holder's public JWK | `space/src/dpop.ts:147-153` (`dpopJktForKey`) | — |
| **where the thumbprint comes from at issuance** | `pds/src/auth-verifier.ts:482` — `const dpopJkt = await this.verifySpaceDpopProof(ctx.req, {})`, carried on the delegation credentials and spent at `space/getSpaceCredential.ts:12`, `:50-53` (`createSpaceToken('credential', { iss, sub, dpopJkt }, keypair)`) | `space_handlers.rs:2049-2090` |
| structural rejection of a `cnf`-less credential | `credential.ts:154-156` | — |
| authorization-time rejection of a `cnf`-less credential | `auth-verifier.ts:390-398` | — |
| proof verification against the credential's `jkt` | `auth-verifier.ts:400`; `dpop.ts:127-141` (`DpopKeyMismatch`) | `dpop.rs` |
| the access-token path forbids `cnf` outright | `auth-verifier.ts:760-763` | — |

**Upstream's issuance route exists and its ordering matches the one §6.8.3 step 1
argues for, independently.** `space/getSpaceCredential.ts:9` uses
`delegationTokenAuth`, and that verifier (`auth-verifier.ts:455-497`) runs, in
order: read the bearer delegation (`:459-462`) → verify the token
(`:463`) → parse `sub` (`:464`) → **audience check** against the space authority
(`:468-473`) → issuer is a DID (`:475-480`) → **DPoP proof verification**
(`:482`) → **and only then** the single-use replay claim (`:485-496`), whose
comment at `:484` states the reason in one line: *"A fresh DPoP proof must not
make the delegation token reusable."* Swan's §6.8.3 step 1 reaches the same
ordering from the opposite direction (avoiding an unauthenticated durable
write); two independent derivations landing on the same order is the strongest
evidence available that the order is right.

The Rust reference's `get_space_credential`
(`atproto-pds/src/http/space_handlers.rs:2049-2090`) verifies an RFC 9449 DPoP
proof from the `DPoP` header and computes the minted credential's `cnf.jkt` from
*that proof's own `jwk`*. Its doc comment at `:2059-2064`: "The thumbprint is
computed from the verified proof's own `jwk`, never taken from the request body:
a body field would be an assertion anyone holding a delegation token could make
about a key someone else controls, where a proof demonstrates possession." The
body field `GetSpaceCredentialInput.dpop_jkt` was deleted outright in the same
commit (`7c6b0ae`). Two further constraints at
`atproto-pds/src/oauth/dpop.rs:216-230` (`verify_issuance_dpop_proof`): **no
`ath`**, "because the delegation token is an authorization grant rather than an
access token", and **no nonce machinery**, "space issuance does not challenge
with nonces". The proof is checked *before* the delegation token is consumed
(`space_handlers.rs:2076-2078`) "so a caller with a bad proof does not burn its
single-use grant".

Swan's generated input already has **no** `dpopJkt` field:
`Sources/SwanSpacesWire/Generated/Lexicons/Com/Atproto/ComAtprotoSpaceGetSpaceCredential.swift:14-16`
declares exactly `space: ATProtocolURI` and `clientAttestation: String?`. Better
still, the hand-written decoder gate at
`Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift:243` requires
`Set(root.keys).isSubset(of: ["space", "clientAttestation"])` — so a body
carrying `dpopJkt` is **already** a hard `InvalidRequest`, and Swan structurally
cannot regress into body-named binding. That gate is load-bearing and must be
called out in a comment so nobody widens it.

Swan has **no `cnf` claim today**: `PermissionedDataJWT.SpaceCredentialClaims`
(`Sources/SwanOAuth/SwanOAuth.swift:370-376`) is exactly `iss, sub, iat, exp,
jti`, and `grep -rn cnf Sources/` returns nothing (positive control:
`grep -rn jkt Sources/` returns `DurableOAuthTokenService.swift:1234`,
`SwanSQLite.swift:98,101,114,117`).

#### 6.8.2 A separate validator, not a flag on the existing one

`OAuthDPoPProofValidator.validate`
(`Sources/SwanOAuth/OAuthProofValidation.swift:67-125`) **requires a server
nonce unconditionally**: `:90` checks `nonceService.isValid(request.serverNonce,
now:)`, `:94` checks `constantTimeTextEqual(claims.nonce, request.serverNonce)`
(`:93` is the *target* comparison), and `OAuthDPoPRequest.init` rejects an empty
`serverNonce` (`:21-22`). The Rust
reference deliberately has no nonce here. Loosening the shared validator would
weaken the resource plane, which correctly demands nonces
(`SwanOAuthResourceAuthorization.swift:88-90` challenges when a nonce is absent).

```swift
// Sources/SwanOAuth/OAuthProofValidation.swift

/// Verifies the DPoP proof presented at space-credential issuance and returns
/// the thumbprint that will seal the minted credential's `cnf.jkt`.
///
/// Deliberately different from ``OAuthDPoPProofValidator`` in exactly two ways,
/// both matching atproto-pds/src/oauth/dpop.rs:216-260
/// (`verify_issuance_dpop_proof`):
///
///  * **No `ath`.** The delegation token in the `Authorization` header is an
///    authorization grant, not an access token, so there is nothing to hash.
///  * **No server nonce.** Space-credential issuance does not challenge, so a
///    proposal-conformant client that never asked Swan for a nonce can still be
///    served. Replay is bounded by the `jti` reservation below plus the proof
///    lifetime, exactly as it is on the nonce-bearing path.
///
/// Everything else is unchanged and non-negotiable: ES256 over the embedded
/// JWK, `typ=dpop+jwt`, `htm`/`htu` compared against the route's *fixed* method
/// and path (never a request-derived Host or target — the rule stated at
/// SwanHTTP/SwanOAuthResourceAuthorization.swift:22-27), bounded `iat`, and a
/// durable single-use `jti` claim.
public struct OAuthIssuanceDPoPProofValidator: Sendable {
    public static let proofType = "dpop+jwt"

    private let tokenService: DurableOAuthTokenService
    private let proofLifetime: TimeInterval
    private let clockSkew: TimeInterval

    public init(
        runtime: SwanOAuthRuntime,
        proofLifetime: TimeInterval = 300,
        clockSkew: TimeInterval = 60
    ) throws { … }

    public func validate(
        _ proof: String,
        method: String,
        target: URL,
        now: Date = Date()
    ) async throws -> OAuthValidatedDPoPProof { … }
}
```

It returns the existing `OAuthValidatedDPoPProof`
(`OAuthProofValidation.swift:34-38`, already `Sendable, Equatable`, carrying
`keyThumbprint`) and reserves the `jti` through the same
`tokenService.claimDPoP(jti:expiresAt:now:)`
(`DurableOAuthTokenService.swift:922`) and therefore the same
`oauth_control_dpop_replays` table (`SwanSQLite.swift:160-165`). Sharing that
table is correct: a proof consumed at issuance must not be reusable at the
resource plane.

#### 6.8.3 Handler changes, in order

`Sources/SwanHTTP/SwanSpaceCredentialXRPC.swift`, inside
`AuthenticatedGetSpaceCredentialHandler.handle` (`:61-166`):

1. **After** `space` is parsed (`:68-73`), after the bearer delegation is read
   (`:75-85`), **and after `verifiedDelegation` (`:86-105`)** — but **before the
   delegation replay claim (`:107-131`)**:

   **This ordering is a correction to the first draft, which put the proof check
   *before* `verifiedDelegation` and thereby added an unauthenticated durable
   write.** The issuance validator reserves its own `jti` through
   `tokenService.claimDPoP` (§6.8.2), a durable INSERT into
   `oauth_control_dpop_replays`. Today the first durable write on this endpoint
   happens at `:107-131`, i.e. **after** the delegation has been
   cryptographically verified at `:86-105`. Moving a durable insert ahead of
   that check lets any unauthenticated caller with a self-signed proof insert
   rows into the replay table at will.

   The stated benefit of the earlier position — sharing the replay table so
   "a proof consumed at issuance must not be reusable at the resource plane" —
   is illusory: the resource-plane validator requires a nonce and `ath`
   (`OAuthProofValidation.swift:90`, `:94`, `:97-100`), which an issuance proof
   by construction does not carry, so it could never validate there anyway.

   The change's **actual** stated goal — "so a caller with a bad proof does not
   burn its single-use grant" (`space_handlers.rs:2076-2078`) — is fully
   satisfied at this position: the proof is validated after the delegation is
   verified and before the delegation's single-use `jti` is claimed. Both
   properties hold; no unauthenticated write is introduced.

```swift
        let proofBinding: OAuthValidatedDPoPProof
        do {
            guard let proof = Self.issuanceProof(from: request.headers) else {
                throw SpaceCredentialExchangeFailure.invalidDPoPProof
            }
            proofBinding = try await capability.issuanceProofValidator.validate(
                proof,
                method: "POST",
                target: capability.credentialEndpointTarget,
                now: Date()
            )
        } catch {
            throw SpaceCredentialExchangeFailure.invalidDPoPProof
        }
```

   Ordering matters and is the reference's stated reason
   (`space_handlers.rs:2076-2078`): today Swan claims the delegation `jti` at
   `:107-131` before anything else can fail, so a client with a clock-skewed
   proof would permanently burn a single-use delegation. Moving the proof check
   ahead of *the claim* — and not ahead of *the verification* — is a
   **behavioural fix**, not just a reordering.
2. `capability.credentialEndpointTarget` is a **fixed** `URL` assembled once by
   `SwanHTTPServer` from the configured public URL plus
   `/xrpc/com.atproto.space.getSpaceCredential`, stored on
   `SwanSpaceCredentialExchangeCapability` (`:17-35`). It is never derived from
   the request — same rule and reason as
   `SwanOAuthResourceAuthorizer.target(publicURL:fixedPath:)` (defined
   `SwanOAuthResourceAuthorization.swift:268`, called `:96`).
3. `issuanceProof(from:)` is a header reader modelled exactly on
   `SwanOAuthResourceAuthorization.swift:212-221`: exactly one `DPoP` field,
   non-empty, ≤ `maximumDPoPProofBytes`, all bytes `0x21…0x7e`. Two or more
   `DPoP` fields is a rejection, not a "take the first".
4. Thread the thumbprint into issuance —
   `SpaceCredentialAuthoritySigner.issueSpaceCredential`
   (`Sources/SwanOAuth/SpaceCredentialAuthority.swift:75-84`) gains
   `boundKeyThumbprint: String`, and `DurableSpaceCredentialAuthority`
   (`:735-786`) passes it to `PermissionedDataJWT.createSpaceCredential`
   (`Sources/SwanOAuth/SwanOAuth.swift:539-561`).
5. `SpaceCredentialClaims` (`SwanOAuth.swift:370-376`) gains
   `let cnf: Confirmation?` where
   `Confirmation: Codable, Sendable, Equatable { let jkt: String }`.

   **The first draft's rule — "Optional on decode, always populated on issue …
   because a credential minted by another implementation that predates the
   binding must still verify" — is CORRECTED. Decoding compatibility must never
   become authorization compatibility.** The Swift type stays `Optional`, but
   for a different and much narrower reason than back-compat, and the optionality
   must be discharged before any authorization decision:

   * **Why the field is optional at all.** Not back-compat. Upstream's `cnf` is
     optional in the *shared* payload shape because three token classes share one
     wire type (`credential.ts:51-59`), and only the `credential` class requires
     it: `requireCnf` is `true` for `credential` (`:35`) and `false` for
     `delegation` (`:24`) and `clientAttestation` (`:43`). A decoder that does not
     yet know which class it is holding cannot demand the field. Swan's
     `Confirmation?` models exactly that and nothing more. The
     `TokenData.scope` (`token-data.ts:37-38`) analogy is withdrawn — that is a
     genuine pre-existence nullability and it is not this.
   * **Why optionality must not survive into authorization.** For the credential
     class, absence is a hard reject at **two** independent points upstream, and
     Swan reproduces both rather than collapsing them:
     1. **Structural**, at parse: `credential.ts:154-156` —
        `if (spec.requireCnf && !payload.cnf?.jkt) throw SpaceTokenError('missing token "cnf.jkt"', 'BadJwtCnf')`.
        In Swan: a `SpaceTokenSpec`-driven guard in the parse function, so the
        requirement is data (a per-class flag) rather than a hand-written
        condition at one call site.
     2. **Independently, at the call site**, before any DPoP verification is
        attempted: `auth-verifier.ts:392-398`. Port the comment at `:390-391`
        verbatim into the Swift — *"Unreachable unless parseSpaceToken's own
        check is relaxed, but an unbound credential must never fall through as a
        bearer token for the whole space"* — because the comment is the entire
        justification for code that a future reader will otherwise delete as
        unreachable. **Do not collapse these two into one check.** Upstream keeps
        them apart deliberately; the redundancy is what makes a later relaxation
        of (1) non-fatal.
   * **There is no bearer fallthrough, at any version.** A `cnf`-less space
     credential from *any* implementation, of any age, is **refused**. Swan does
     not have, and must never add, a code path that treats it as a valid bearer
     credential. Cross-check the shape from the other side: upstream's
     access-token verifier *forbids* `cnf` outright (`auth-verifier.ts:760-763`,
     "Proof-of-Possession (PoP) tokens are not allowed here"). The two planes
     have opposite requirements and neither has a permissive middle.
   * Always populated on issue, as before — Swan controls its own minting, and
     `createSpaceToken` refuses to sign a `credential` without a `dpopJkt`
     (`credential.ts:92-94`), which is the mint-side twin of the reject above.
6. `createSpaceCredential`'s guard (`SwanOAuth.swift:544-550`) gains
   `validDPoPJKT(thumbprint)` — reuse the 43-byte base64url check already
   spelled at `DurableOAuthTokenService.swift:1239-1244` and again at
   `OAuthValidatedSession.swift:78-83`; this is a third copy and should be
   hoisted to one `SwanCore` helper in the same change.
7. New failure case + response mapping. `SpaceCredentialExchangeFailure`
   (`:45-53`) gains `case invalidDPoPProof`, and
   `getSpaceCredentialResponse(for:)` (`:305-324`) maps it to
   `getSpaceCredentialError(.unauthorized, code: "InvalidDpopProof")` — the exact
   status and name the Rust reference emits (`dpop.rs:232-234`, `:238-240`). Per
   Swan's oracle rule, missing, malformed, expired, wrong-`htu`, and replayed
   proofs are all this one code; no `DPoP-Nonce` header is emitted, because this
   endpoint issues no nonce challenge.

#### 6.8.4 Consumption — designed here, and shipped in the same PR

**The first draft's "consumption is flagged, not designed here" is withdrawn**
(§9-Q6 ruling). It rested on there being no upstream consumption model; there
is one, it is 30 lines long, and mint-without-consume is the one outcome the
ruling forecloses. The two Swan sites the first draft correctly identified are
where it lands: `DurableSpaceCredentialVerifier`
(`SpaceCredentialAuthority.swift:872+`) and
`AuthorizationContext.spaceCredential(SpaceGrant)` (`SwanSpaces.swift:228`).

**The order of operations is not negotiable, and it is not the obvious one.**
Port `auth-verifier.ts:372-409` step for step:

| # | check | upstream | why the position matters |
|---|---|---|---|
| 1 | pull the credential from the request | `:376` | — |
| 2 | verify the token: signature over the issuer's resolved DID key, `exp` with 5 s skew (`credential.ts:72`), **and the structural `requireCnf` guard inside the parse** | `:377` | The structural `cnf` check (`credential.ts:154-156`) is reached *here*, before anything else looks at the payload. |
| 3 | parse `sub` into a space id | `:378` | — |
| 4 | **issuer == space authority** | `:380-388` (`BadJwtIss`) | An audience-substitution guard: without it, any DID could sign a credential naming someone else's space and have it verified against its own key. It runs **before** the `cnf` check. |
| 5 | **`cnf` presence, independently** | `:390-398` (`BadJwtCnf`) | The second of the two rejections in §6.8.3 step 5. |
| 6 | DPoP proof verification against that `jkt` | `:400` → `dpop.ts:80-144` | Only now. |
| 7 | replay: `jti` uniqueness | `dpop.ts:79` states the split; the caller records the `jti` | Kept out of the verification function so it stays pure and testable without a store — the same boundary Swan draws in §6.8.2. |

Getting steps 4–6 out of order is not merely inelegant: checking the DPoP proof
before the issuer-authority check lets a caller probe proof-validation failures
on a credential that should already have been rejected, which changes the shape
of the error oracle at the one boundary
`SwanOAuthResourceAuthorization.swift:9-16` exists to keep opaque.

Step 6's proof checks, from `space/src/dpop.ts:80-144`, in order: signature over
the proof's own embedded JWK with `typ=dpop+jwt`, ES256 only, `maxTokenAge`
`MAX_PROOF_AGE_SEC`, `clockTolerance` `CLOCK_SKEW_SEC` (`:89-105`) → non-empty
`jti` (`:108-110`) → `htm` equals the request method (`:111-113`) → `htu`
normalized to origin+pathname, query and fragment stripped per RFC 9449 §4.2
(`:114-116`, `normalizeHtu` at `:155-158`) → `ath` equals
`base64url(sha256(credential))`, **required** on this path because a credential
*is* supplied (`:117-120`) → the proof key's RFC 7638 thumbprint equals the
credential's `cnf.jkt`, else `DpopKeyMismatch` (`:127-141`).

Note the asymmetry with §6.8.2's issuance validator, which is a **third**
position, not a re-use of either existing one: issuance verifies a proof with
**no** `ath` and **no** `jkt` to compare against (`dpop.ts:121-125`, `:136`);
the resource plane verifies with a nonce and an `ath` over the access token;
consumption verifies with an `ath` over the *credential* and a `jkt` from the
credential's own `cnf`, and no nonce. §6.8.2 argues two validators; three
positions exist. Whether that is three types or one type with an explicit
`(credential:, jkt:)` parameterisation — upstream chose the latter, a single
`verifyDpopProof` whose options type makes `credential` and `jkt` present-or-both-absent
(`dpop.ts:67-77`) — is a Swift-side call, but it must be made deliberately and
the two-validator framing in §6.8.2 must not be read as settling it.

Reuse Swan's existing DPoP replay store for step 7, as upstream reuses the OAuth
one, and for the same stated reason: its retention window exceeds
`MAX_PROOF_AGE_SEC + CLOCK_SKEW_SEC`.

With consumption in the PR, the sentence "a credential whose `cnf` nobody checks
is not yet sender-constrained" stops being a caveat about Swan and becomes the
test that Swan now passes.

**Doc-drift warning.** The Rust reference's own `atproto-space/src/credential.rs`
module doc still describes the deleted body-`dpopJkt` shape at lines 14-15/22/446
— live drift in the reference. **Cross-check against the TypeScript instead:**
`packages/space/src/credential.ts:58` and `:105` are the authoritative shape, and
they do not drift, because the mint site and the type are in the same 60 lines.
When Swan makes this change, grep every doc
comment mentioning where the thumbprint comes from, not only the call sites:
`SwanSpaceCredentialXRPC.swift:36-41`, `:270-273`,
`SpaceCredentialAuthority.swift:71-74`, and `SwanOAuth.swift` around `:534-538`
all describe the current credential shape.

### 6.9 Concurrency: what is a value type, what needs an actor

Sendable value types, no actor:

| type | why |
|---|---|
| `AtprotoScope`, the seven family payloads, `ScopeStringSyntax`, `ScopeParameterBag`, `ScopeParameterValues` | Pure functions of a `String`. Immutable `let` stored properties over `String`/`Set`/`Array` of `Sendable` elements. Frozen at parse. `Sendable, Hashable`. |
| `SwanScopePermissions` | Immutable `Set<String>` + `String?` + a `[AtprotoScope]` computed once in `init`. Constructed on the request task at `SwanOAuthResourceAuthorization.swift:160`, then crosses into the SQLite actor as part of `AuthorizationContext`. It **must** be `Sendable` for that crossing to compile, and it is, with no `@unchecked`. |
| the six `*ScopeTarget` structs | Small immutable structs of `String`s and enum cases, constructed at the call site and consumed immediately. |
| `ScopeParseError` | Closed `enum … : Error, Sendable` with associated values, mirroring the Rust `ParseError` (`scopes.rs:1127-1138`) — callers pattern-match "this scope contributes nothing" vs "hard error", which a stringly-typed decoding error cannot support. |
| `ScopeDenied` | `Error, Sendable, Equatable`, one `String`. |
| `OAuthValidatedDPoPProof` | Already `Sendable, Equatable` (`OAuthProofValidation.swift:34-38`); unchanged. |
| `OAuthIssuanceDPoPProofValidator` | `Sendable` struct holding a `DurableOAuthTokenService` (itself `Sendable`) and two `TimeInterval`s — same shape as the existing `OAuthDPoPProofValidator` (`:45-65`). Its `validate` is `async` only because the `jti` reservation is, not because the type holds state. |
| the **consumption-side** space-credential proof validator (§6.8.4, new) | Same analysis, same shape, third position: it takes `(credential:, jkt:)` where the issuance validator takes neither. `Sendable` struct, no stored mutable state; `async` only for the replay reservation, exactly as above. Upstream keeps the pure part pure for the same reason — `verifyDpopProof`'s doc comment at `space/src/dpop.ts:79` ("Checks everything but replay; the caller records the returned `jti` itself") is a testability boundary, not an oversight. If the three positions collapse into one parameterised type (`dpop.ts:67-77`'s options union), it stays a value type and this row still holds. |
| the space-credential value type (`SpaceToken` / `SpaceTokenPayload` mirror, §6.8) | Immutable `let`s over `String`/`Int`, plus `Confirmation?`. The per-class requirement table (`requireCnf` etc., mirroring `credential.ts:18-46`) is **static data**, not behaviour: a `SpaceTokenType` enum with a computed `var spec` switch. Making it data rather than a hand-written condition is what keeps the two `cnf` rejections of §6.8.3 step 5 from drifting apart. |
| `AuthorizationContext` | Stays `Sendable, Equatable` (`SwanSpaces.swift:219`) — preserved precisely because its new payload is a `Sendable` value type. |

Needs an actor (and already is one):

| concern | where | why |
|---|---|---|
| DPoP `jti` replay reservation | `SQLiteControlDatabase` (`OAuthControlStore.swift:188`), via `DurableOAuthTokenService.claimDPoP` (`:922`) and `oauth_control_dpop_replays` (`SwanSQLite.swift:160-165`) | Mutable durable state with a uniqueness invariant across concurrent requests. |
| Delegation single-use claim | `DurableSpaceDelegationReplayStore` (`SwanSpaceCredentialXRPC.swift:19-23`) | Same. |
| Connection serialization | `ControlSQLiteConnectionGate` actor (`OAuthControlStore.swift:6`) | Pre-existing. |
| Phase-2 lexicon resolution | new, in `SwanOAuth` (§5.7.4) | Network I/O + cache **+ CPU**. Consulted **only** at PAR and token-mint (stages B and F), never at stage H — otherwise the request-time matcher becomes async and the whole value-type argument collapses. **That rule carries more weight than the first draft knew.** Resolution is a port of `@atproto/lex-resolver`, whose trust model is a repo-proof verification, not a JSON fetch: CAR parsing, commit-DID equality, **commit signature verification**, and an **MST membership walk** (`packages/lex/lex-resolver/src/lex-resolver.ts:529-553`; §5.7.4, A's section). Those are CPU-bound and unbounded in the response-size dimension, so they are not merely "a fetch you must not do on the request path" — they are work that would make the request path *compute-bound* on attacker-supplied input. An accidental request-time resolution is a denial-of-service vector, not just an `async` compile error. The §2/§3 rule that the request-time path cannot even name a network fetcher is the structural defence, and it now also keeps CAR parsing and signature verification out of stage H. |

**Explicitly rejected: a scope-parse cache.** See the doc comment in §6.1. Write
the rejection into the type's documentation so a later "optimization" does not
quietly reintroduce it.

---

## 7. Test strategy

### 7.1 Where the tests live

| suite | path (new file) | existing target | why there |
|---|---|---|---|
| Grammar conformance (syntax layer) | `Tests/SwanCoreTests/ScopeSyntaxConformanceTests.swift` | `SwanCoreTests` | Today's grammar is `PermissionedSpaceScopeSyntax` in `Sources/SwanCore/SwanCore.swift:166-438`; the replacement belongs in the same module. `Package.swift:206` declares `.testTarget(name: "SwanCoreTests", dependencies: ["SwanCore", "SwanSpacesWire"])` — **no new dependency required**. |
| Per-family parse/format/match vectors | `Tests/SwanCoreTests/ScopeFamilyVectorTests.swift` | `SwanCoreTests` | Same module. Split from the syntax file so a hang in one can be bisected from the other by `--filter`. |
| `space:` matching + `self` resolution | `Tests/SwanCoreTests/SpacePermissionMatchTests.swift` | `SwanCoreTests` | Pure value semantics; no DB, no HTTP. |
| Resource-domain integration | extend `Tests/SwanSpacesTests/SwanSpacesTests.swift` (1570 L; existing scope assertions at `:103`, `:108`, `:739`) | `SwanSpacesTests` | `scopeAllows` / `permitsWholeSpaceRead` / `permitsAggregateSpaceList` live in `Sources/SwanSpaces/SwanSpaces.swift:280-373`; their tests already live here. Do not fork a new file — the seam is one matcher. |
| Persistence round-trip under the new grammar | `Tests/SwanSQLiteTests/OAuthScopePersistenceTests.swift` | `SwanSQLiteTests` | `encodeScopes`/`decodeScopes`/`validScope` are `Sources/SwanSQLite/OAuthControlStore.swift:2233-2254, 2344-2350`. |
| **Credential sender-constraint** (separate PR, §6.8, §9-D18) | `Tests/SwanSpacesTests/SpaceCredentialBindingTests.swift` | `SwanSpacesTests` | Mint and consume land together (§9-D18), so their tests do too. Three obligatory assertions: (a) mint sets `cnf.jkt` from the **verified proof**, never from a body field; (b) presentation with a key whose thumbprint ≠ `cnf.jkt` is **denied**; (c) presentation of a `cnf`-less credential is **DENIED, not accepted as a bearer credential** — the exact case upstream guards at `packages/pds/src/auth-verifier.ts:392-398` (`if (!jkt) throw new AuthRequiredError('space credential is not bound to a key', 'BadJwtCnf')`), with the rationale in the comment at `:390-391`. Assertion (c) is the one that fails if "optional on decode" is allowed to leak into "optional to authorize". |
| **The bulleted.app acceptance test** | `Tests/SwanHTTPTests/RemoteClientPermissionedScopeE2ETests.swift` | `SwanHTTPTests` | Needs the full fixture: `Tests/SwanHTTPTests/OAuthPARHTTPTests.swift:15-51` already builds `makeFixture()` + the DPoP-nonce challenge; `Tests/SwanHTTPTests/LocalhostOAuthBrowserHTTPTests.swift` (783 L) already drives authorize → consent → code. Reuse both patterns rather than inventing a third harness. |

Style: **XCTest**, matching the repo (155 files `import XCTest` vs 1
`import Testing`, that one being `Tests/SwanPublicWireTests/SwanPublicWireTests.swift`).
Classes are `final class X: XCTestCase, @unchecked Sendable` (the shape at
`OAuthPARHTTPTests.swift:15`). 4-space indent, no config file — **never run
plain `swiftformat` on Swan**.

Every table in §5 and §7.2-7.3 is a `[Vector]` array driven by one loop, with
`line: UInt = #line` per element so a red vector points at its own row, not at
the loop:

```swift
private struct Vector: Sendable {
    let input: String
    /// Canonical re-serialization, or nil == must not parse.
    let expected: String?
    let line: UInt
}
```

#### 7.1a The upstream-golden corpus — generated, not transcribed

Encoder-level rows are **not** hand-transcribed. Hand-transcription is what
produced the three wrong line numbers recorded in §9.1a R3, and it is the wrong
mechanism for a question whose answer is "run the reference and see" (§9-D15).

**The generator.** A small checked-in script — `Scripts/gen-scope-corpus.mjs`,
run manually, never in the build — imports the pinned reference package
(`packages/oauth/oauth-scopes/src`, at `bddc99fb`), reads a plain-text list of
input scope strings, and for each emits one record:

```
<input>\t<canonical-output-or-the-literal-token NULL>
```

`canonical` is the reference's own parse-then-`toString()`; `NULL` is emitted
when the reference's parser returns `null`, which is upstream's sole failure
signal for the grammar layer. Output lands at
`Tests/SwanCoreTests/Fixtures/scope-corpus.tsv`, checked in, with a header line
recording the upstream commit (`bddc99fb`) and the generation date.

**The Swift side.** One test reads the fixture, runs `AtprotoScope.parse` +
canonical re-serialisation over each input, and asserts byte equality with the
recorded output (or non-parse where the record is `NULL`). A row's fixture line
number is reported on failure, so a red row points at its own record.

**What the corpus owns.** The encoder-boundary rows in §7.2.1 — **S12a, S12b,
S12c, S15** — plus the `~` asymmetry that §4.5 describes (raw in a positional,
`%7E` in a query value). Those are the rows most cheaply produced by running the
reference and most expensively produced by reading it. Mark them as
corpus-generated in §7.2.1 so nobody re-transcribes them by hand.

**What the corpus does NOT own.** Anything requiring a *judgement* Swan makes
differently from upstream — the §7.3 divergence fence, the §9-D5 reject-at-PAR
rule, Swan's byte budgets. The corpus records what upstream does; the fence
records where Swan deliberately differs. Never let a corpus regeneration
overwrite a fence row: a fence row changing is a design change, not a drift fix.

**Drift detection.** §7.6 step 7 regenerates the corpus at the pin and asserts a
**zero diff** against the checked-in fixture. A corpus that silently drifts from
the reference is exactly the failure this mechanism exists to prevent, and it is
invisible without the regeneration step.

### 7.2 Conformance vectors — the layers not covered by §5

#### 7.2.1 `ScopeStringSyntax` — `lib/syntax-string.test.ts:6-131`

| # | input | prefix | positional | params |
|---|---|---|---|---|
| S1 | `my-res` | `my-res` | *(none)* | — |
| S2 | `my-res:my-pos` | `my-res` | `my-pos` | — |
| S3 | `my-res:` | `my-res` | `""` (empty, legal, distinct from absent) | — |
| S4 | `my-res:foo?x=value&y=value-y` | `my-res` | `foo` | `x=[value]`, `y=[value-y]` |
| S5 | `my-res?x=value&y=value-y` | `my-res` | *(none)* | `x=[value]`, `y=[value-y]` |
| S6 | `my-res?x=foo&x=bar&x=baz` | `my-res` | *(none)* | `x=[foo,bar,baz]` — **order preserved, no dedup at this layer** |
| S7 | `rpc:foo.bar?aud=did:foo:bar?lxm=bar.baz` | `rpc` | `foo.bar` | `aud=["did:foo:bar?lxm=bar.baz"]` — everything after the *first* `?` is one query string |
| S8 | `my-res:my%20pos` | `my-res` | `my pos` | percent-decoded |
| S9 | `my-res?x=my%20value` | `my-res` | *(none)* | `single("x") == .present("my value")` |
| S10 | `my-res:my:pos` | `my-res` | `my:pos` | the second colon is data, not a delimiter |
| S11 | `my-res:pos?x=value` | `my-res` | `pos` | `single("x") == .present("value")` — the syntax layer is permissive; exclusivity is enforced by the schema (`parser.ts:124-127`) |

Also assert for every row: `single("nonexistent") == .absent` and
`multiple("nonexistent") == nil`; and for **S6**, `single("x") == .repeated([…])`
— the "present but malformed" signal, **not** `.absent` (`syntax-string.ts:21-22`).
This is the vector that proves the tri-state was not collapsed into `String?`.

Swan-added rows, no upstream counterpart. **S12a, S12b, S12c and S15 are
corpus-generated** (§7.1a): their expected bytes come from running the pinned
reference, not from transcription. S13 and S14 are Swan-judgement rows and stay
hand-written.

| # | input | expected |
|---|---|---|
| S12a | `my-res:%zz` (**positional**) | throws `.malformedPercentEncoding` — upstream's `decodeURIComponent` throws an uncaught `URIError` here (`syntax-string.ts:62-64`) |
| S12b | `my-res?x=%zz` (**query**) | **does NOT throw**; `single("x") == .present("%zz")`. `URLSearchParams` leaves an invalid `%` sequence as literal bytes (`syntax-string.ts:71`). The first draft threw here, which rejected scopes upstream accepts (§4.4) |
| S12c | `space:*?authority=did:web:ex%ample.com` | **parses** — `%` is in the DID charset (`syntax/src/did.ts:51`). Under §9-D5 a throw here would be a hard `invalid_scope` on the whole PAR: the exact interop failure this change exists to remove |
| S13 | `my-res?a=1&&b=2` | `a=[1]`, `b=[2]` — the empty pair is **skipped**, matching `URLSearchParams`, unlike `SwanCore.swift:218-227` |
| S14 | `my-res?x=a"b` | throws `.notAScopeToken` — `"` (0x22) is excluded by RFC 6749 §3.3 but admitted by Swan's current `$0 > 0x20 && $0 < 0x7F` (`SwanOAuthAuthorizationServerHTTP.swift:1059-1069`) |
| S15 | `blob?accept=image/png&accept=image/svg+xml` | parses; canonicalises to a string whose `accept` re-materialises a raw `+`; that canonical string then **fails to re-parse** (`+`→SP → `image/svg xml` → `isStringSlashString` rejects a SPACE, `mime.ts:10`). Pin the upstream lossiness (§4.5). **Do NOT assert "no family validator admits `+`" — that is false**, `blob`'s `accept` does |

#### 7.2.2 `isScopeString` prefix boundary — `lib/syntax.test.ts:32-42`

True iff `value == prefix`, or `value.hasPrefix(prefix)` **and** the next byte is
`:` (0x3A) or `?` (0x3F).

| prefix | value | expected |
|---|---|---|
| `prefix` | `prefix` | true |
| `prefix` | `prefix:positional` | true |
| `prefix` | `prefix?x=1` | true |
| `prefix` | `prefi` | false (too short) |
| `prefix` | `fix` | false |
| `prefix` | `prefixes` | false (superstring, no boundary byte) |
| `prefix` | `differentResource:positional` | false |

#### 7.2.3 Family vectors

Ported verbatim from §5: account (§5.1), blob (§5.2), identity (§5.3), repo
(§5.4), rpc (§5.5), space (§5.6.7), include (§5.7.1). The two `space:`
properties in §5.6.7 — anti-widening, and second-format idempotence with
`authority=*` survival — are the highest-value rows in the whole suite and must
not be dropped.

#### 7.2.4 Set-level dispatch — `scopes-set.test.ts:4-70`

| held scopes | query | expected |
|---|---|---|
| `[repo:com.example.foo]` | repo `{create, com.example.foo}` | true |
| `[repo:com.example.foo]` | repo `{create, com.example.bar}` | false |
| `[repo:com.example.foo?action=create]` | repo `{delete, com.example.foo}` | false |
| `[repo:not-a-valid-nsid]` | repo `{create, not-a-valid-nsid}` | **false — an unparseable HELD scope grants nothing, silently, no throw** |
| `[space:com.example.group?authority=did:plc:abc&skey=default&collection=com.example.event]` | space `{com.example.group, did:plc:abc, default, read}` | true |
| same | space `{…, authority: did:plc:other, read}` | false |

Row 4 is the layer distinction that §9-D5 turns on: **held** unparseable scopes
are silent at match time; **requested** unparseable scopes are rejected at PAR.
Assert both in the same file so the pair is visible.

#### 7.2.5 Transition scopes — `scope-permissions-transition.test.ts`

Swan implements no transition semantics (§4.7), so these are *recognition* and
*non-grant* assertions:

| # | vector | expected |
|---|---|---|
| T1 | `AtprotoScope.parse("transition:email")` | `.transitionEmail`, no throw |
| T2 | `AtprotoScope.parse("transition:generic")`, `("transition:chat.bsky")` | parse |
| T3 | a permissions value holding only `transition:generic` | `hasResourceScope == false`; every `allows*` false. **This pins a Swan DIVERGENCE, not conformance** — upstream's `transition:generic` grants all blob (`scope-permissions-transition.ts:39-45`), all repo (`:47-53`) and all non-`chat.bsky` rpc (`:64-80`). Name the test accordingly (`testTransitionGenericIsInertInSwanUnlikeUpstream`) so a future reader does not "fix" it toward upstream without wiring the routes first (§4.7) |
| T4 | `transition:generic` → `allowsSpace(anything)` | **false**, asserted explicitly (`scope-permissions-transition.ts:55-61`, test `:55-68`) — a legacy token must never reach a space; upstream keeps this as an override-to-super so it is a decision, not an omission. **This is the one transition arm where Swan and upstream agree** |
| T5 | `transition:email` → `allowsAccount({email, read})` | **false** in Swan; upstream returns **true** (`:27-37`). Same divergence class as T3 |

#### 7.2.6 The base-scope floor — §4.8's last two rows

| # | held / requested set | expected |
|---|---|---|
| B1 | requested `["space:app.example.forum?authority=*&skey=*&action=read"]`, no `atproto` | **accepted** at PAR. Swan's floor is `atproto` OR a `space:` grant (`OAuthValidatedSession.swift:91-95`), where upstream raises `InvalidScopeError` (`request-manager.ts:241-243`). Pins the divergence recorded in §4.8 |
| B2 | requested `["blob:image/*"]`, no `atproto`, no `space:` | **rejected**, `ScopeAdmissionError.missingBaseScope` → `invalid_scope`. Also asserts `hasResourceScope == false` for a blob-only set (§6.1) — the check that stops `identity:`/`blob:`-only tokens reaching the scope-less routes listed there |
| B3 | requested `["atproto", "openid"]` | **rejected at stage A**, `invalid_scope`, with `openid` named in the server-side log. Asserts the reject fires at the tokenizer, not at `AtprotoScope.parse`, which would report `.unknownPrefix` instead |

#### 7.2.7 `scope-permissions.test.ts` set-level vectors (304 L)

The first draft cited `scope-permissions.ts:37-109` as the model for
`SwanScopePermissions` and ported none of that file's 15 `it()` blocks. Four are
covered by no §5 family table either, and each is a distinct branch:

| upstream vector | cite | why it is not redundant |
|---|---|---|
| `blob:*` must be ignored | `scope-permissions.test.ts:42-47` | §5.2 has `blob:*/**` and `blob:*/png`, not bare `blob:*` — a different `isAccept` branch (`mime.ts:23`) |
| `blob:/image` must be ignored | `:48-53` | the `slashIndex == 0` branch (`mime.ts:6`) |
| `rpc:*?lxm=*` must be ignored | `:131-145` | §5.5 has `rpc?aud=*&lxm=*` and `rpc:*?aud=*`; this is the positional-lxm / named-lxm collision, a third shape |
| `assertRpc` combined-`aud`: a bare-DID `aud` is **rejected** against a `did#service` grant; a wildcard `aud=*` grant **accepts** a `did#service` request | `:270-303` | the only vectors distinguishing the two `AudParam` arms at the SET layer |

Also uncovered, from `lib/mime.test.ts` — each a distinct branch of
`isStringSlashString` (`mime.ts:3-13`), none exercised by §5.2's table:
`isAccept` rejects `image//png`, `/png`, `image/`, `image/**`, `*/png`, `*`,
`image/png/extra` (`:13-21`); `isMime` additionally rejects `image/*`, `*/*`,
`*/mime`, `image`, `image/ png` (`:29-40`).

#### 7.2.8 Route-level vectors, derived from the PDS enforcement inventory

The set-level vectors above prove the matcher. They do not prove the **mapping**
— which route asks which question — and that mapping is no longer Swan's to
invent (§9-D16). `packages/pds/src` carries 67 `authorize:` route callbacks; the
shape is `authorize: (permissions, { params }) => permissions.assertRpc(params)`
(`packages/pds/src/pipethrough.ts:68`), and the space plane funnels through one
shared helper that derives `(type, authority, skey)` from the space URI and
spreads the caller's op (`api/com/atproto/space/util.ts:87-100`).

**At minimum one vector per family**, so the §6 route→scope mapping table has
test backing rather than being an unexercised document:

| # | family | upstream anchor | Swan vector |
|---|---|---|---|
| R1 | `rpc` | `pipethrough.ts:68` (`assertRpc(params)`); 15 `permissions.assertRpc` sites incl. `api/app/bsky/feed/getTimeline.ts` | a token holding `rpc:<nsid>?aud=<did>#svc` reaches the mapped route; the same token against a different `lxm` is denied |
| R2 | `repo` | 5 `permissions.assertRepo` sites: `api/com/atproto/repo/createRecord.ts`, `putRecord.ts`, `deleteRecord.ts`, `applyWrites.ts` | create/put/delete each assert the matching `RepoAction`; a `create`-only grant is denied on delete |
| R3 | `blob` | 1 site: `api/com/atproto/repo/uploadBlob.ts` — `permissions.assertBlob({ mime: encoding })` | the assertion is keyed on the **request's `encoding`**, not on a declared MIME; `blob:image/*` accepts `image/png` and denies `application/pdf` |
| R4 | `identity` | 4 sites: `identity/updateHandle.ts` (`{attr:'handle'}`), `signPlcOperation.ts`, `submitPlcOperation.ts`, `requestPlcOperationSignature.ts` (all `{attr:'*'}`) | handle-change needs `{attr:'handle'}`; a PLC operation needs `{attr:'*'}` and is **not** satisfied by handle-only |
| R5 | `account` | 2 sites: `server/requestEmailConfirmation.ts` (`{attr:'email', action:'manage'}`), `repo/importRepo.ts` (`{attr:'repo', action:'manage'}`) | `read` does not satisfy `manage` on the same attr |
| R6 | `space` | 2 `permissions.assertSpace` sites + the helper: `api/com/atproto/space/listSpaces.ts:20`, `api/com/atproto/space/util.ts:94` | the Swan routes already wired; assert the op spread matches the helper's `{type, authority, skey, ...op}` shape |
| R7 | space **read vs read_self** | `space/util.ts:109-127` (`assertSpaceRead`) | an account credential reading another member's repo gets the **`RepoNotFound` non-oracle** (`:118-124`), not a scope error. Assert the error *identity*, not just the denial — the point of that branch is that it leaks nothing |

R1-R5 are **not yet wired in Swan** (§9-D16 records them as not-yet-ported
rather than absent-upstream). Their vectors are written against the facade
(`SwanScopePermissions.allowsRepo` / `allowsRPC` / …) and become route tests as
each route is wired. R6-R7 are wired today and are route tests now.

### 7.3 The Swan-divergence fence

Strings Swan **rejects today and must accept after the change** (or vice versa).
Each cites the exact line that rejects it now, so the fence fails loudly if the
rewrite is partial. Re-verified against `Sources/SwanCore/SwanCore.swift:198-244`.

| # | string | today | rejected at | after |
|---|---|---|---|---|
| D1 | `space:com.atmoboards.forum` | rejected | `SwanCore.swift:208-212` requires a `?` | parse; authority `self` (unresolved ⇒ matches nothing, M22) |
| D2 | `space:x.y.z?authority=*&action=create&action=update` | rejected | `:224` `keys.insert(...).inserted` fails on the repeat | parse; action `[create, update]` |
| D3 | `space:x.y.z?manage=create&manage=update&manage=delete` | rejected | `:224` | parse; manage all three |
| D4 | `space:x.y.z?authority=did:plc:abc` (no `skey`) | rejected | `:243` `requiredKeys == ["authority","skey"]` | parse; skey defaults to `*` |
| D5 | `space:x.y.z?authority=*&skey=*&action=read&manage=update` | rejected | `:243` `hasAction != hasManage` | parse; both lists populated, matched independently |
| D6 | `space:*?authority=did:plc:abc&skey=*&action=read` | passes `isQualified`, **fails** `isIssuableQualified` (`:178`, `validNSID("*")` needs ≥ 3 labels) | `:178` | **admitted at PAR.** Re-expressed for §9-D21: "issuable" is no longer a predicate — `isIssuableQualified` is deleted, not relocated. The three layers are asserted separately: it **registers** (lexical + budget only), it is **admitted at PAR** (parses, passes admission), and at the resource plane a `type=*` grant is subject to the §6.1 provenance fence |
| D7 | `space:x.y.z?authority=*&skey=*&action=read_self` (no collection) | fails `isIssuableQualified` unless `action == "read"` (`:195`) | `:195` | **admitted at PAR**; `read_self` needs no collection. Same three-layer split as D6. Note the fence does **not** move with the gate: `read_self` still fails `isExactReadOnlyDelegationGrant` (§5.6.3), so admitting the scope does not admit a delegation exchange — that is the point of §9-D21's "the dangers move to the right layer" |
| D8 | `space:x.y.z?authority=did:plc:a&%61uthority=did:plc:b&skey=*&action=read` | **rejected** — `SwanCore.swift:224` `keys.insert(...).inserted` fails once `%61uthority` decodes, and `strictQualifiedParameters` (`:352-375`) rejects the collision | — | **must stay rejected**, with `.repeatedSingleValuedParameter`: the two decoded keys collide, so `single("authority") == .repeated`. A percent-decoded key collision is a real attack surface. **Corrected from the first draft**, whose vector was `space:x?authority=a&%61uthority=b` and whose stated "before" was wrong twice over: it does **not** pass `isQualified` (`:243` requires `requiredKeys == ["authority","skey"]`, and it has no `skey`), and its "after" would not be `.repeatedSingleValuedParameter` either — the schema evaluates `type` first (declaration order, §4.6) and `x` is not a valid NSID, so the error would be `.invalidPositionalValue`. The vector as originally written fails. Use the string in this row, which reaches the intended predicate |
| D9 | a valid scope of 257…1024 bytes | passes `isQualified` (cap 4096, `:200`), **rejected at persistence** by `validScope` (cap 256, `OAuthControlStore.swift:2344-2350`) | — | accepted at **both** layers under the 1024-byte per-token cap (§6.4); assert at both, plus a 1025-byte scope rejected at both, plus an 8193-byte whole set rejected at the wire. **Plus the vector that only exists because §9-D17 splits the budgets:** a scope comfortably *within* the RAW-INPUT budget whose **expanded** form exceeds the EXPANDED-GRANT budget — e.g. a short bare `space:<type>` that `expandSpaceCollections` materialises into many collections, or an 80-byte `include:` that resolves to a large permission set. Assert it is **accepted at PAR** and fails at **token mint**, with a distinct error from the wire-side one, so the two budgets cannot be collapsed back into one by a later reader who sees the same number twice |
| D10 | `rpc:com.example.method1?&aud=*` | rejected | `:218` `omittingEmptySubsequences: false` + `pair.count == 2` | parse (upstream `rpc-permission.test.ts:313-315`) |
| D11 | `space:com.example.foo-bar` | **accepted** by `SpaceURI.isValidNSID` (`SwanSpaces.swift:83-93`) | — | **rejected** — the last NSID segment is a "name" and may not contain `-` (`nsid.ts:112-117`). §9-D3; audit persisted space URIs before cutover |
| D12 | `space:com.9example.foo` | **rejected** by `SpaceURI.isValidNSID` (`label.first?.isLetter == true` on every label) | — | **accepted** — only segment 0 may not start with a digit (`nsid.ts:109-111`) |

**Fence what must NOT change — the widening fence.** `permitsWholeSpaceRead` /
`permitsAggregateSpaceList` (`SwanCore.swift:258-309`) are consumer-side
membership tests used by `Sources/SwanHTTP/SwanSpaceDelegationXRPC.swift:78-86`
and `SwanSpaceListXRPC.swift:80-87`. Under a broader grammar, a bare
`space:<type>` grant or a **defaulted** `skey=*` / `action` list must **not**
silently start satisfying either predicate.

**The first draft's fence could not fire, and the reason it gave was false.** It
prescribed one negative vector — bare `space:app.example.forum` → both denied —
justified by "its `self` authority is unresolved at that layer". That rationale
does not survive this document's own design: §6.4 stores the **resolved**
authority in `oauth_control_token_families.scopes`, and §6.1's `allowsSpace`
resolves `self` **again** at match time from `subject`. `AccessGrant` carries a
subject (`DurableOAuthTokenService.swift:78-93`) and it is consumed at
`SwanOAuthResourceAuthorization.swift:160`, so the production path always has
one. The vector would be written, would pass against an unresolved fixture, and
would test nothing that ships.

**Replacement fence — eight vectors, all evaluated against a permissions value
carrying a concrete `subject`, i.e. the production shape.** Every "today"
column is re-verified against `SwanCore.swift:258-309`.

| # | grant | check | today | must stay |
|---|---|---|---|---|
| W1 | `space:app.example.forum` (bare, no query) | `getDelegationToken` | denied (`:208-212` requires a `?`) | **denied** — `action` is defaulted, not stated (§5.6.3) |
| W2 | `space:app.example.forum` (bare) | `listSpaces?type=app.example.forum` | denied | **denied** — `skey` and `action` are defaulted, not literal (§6.1) |
| W3 | `space:x.y.z?authority=did:plc:abc` | `getDelegationToken` | denied (`:243`, no `skey`) | **denied** |
| W4 | `space:x.y.z?authority=did:plc:abc&skey=*&action=read&action=create` | `getDelegationToken` | denied (`:224`, duplicate key) | **denied** — `action != [.read]` |
| W5 | `space:x.y.z?authority=did:plc:abc&skey=*&action=read&manage=delete` | `getDelegationToken` | denied (`:243`, `hasAction != hasManage`) | **denied** — non-empty `manage` |
| W6 | `space:x.y.z?authority=did:plc:abc&skey=*&action=read&collection=*` | `getDelegationToken` | denied (`:279`, key set) | **denied** — the amplification `SwanCore.swift:246-257` forbids |
| W7 | `space:x.y.z?authority=did:plc:abc&skey=*&action=read` | `getDelegationToken` for that tuple | **allowed** | **allowed** — the one positive; if this regresses, delegation is broken |
| W8 | `space:x.y.z?authority=*&skey=*&action=read` | `listSpaces` with `type=nil, authority=nil` | **allowed** (literal `*` in both dimensions) | **allowed** |

W1–W6 are the vectors the original fence would have missed: each carries a
concrete or wildcard authority and sails past an unresolved-`self` check.

### 7.4 The bulleted.app acceptance test

`Tests/SwanHTTPTests/RemoteClientPermissionedScopeE2ETests.swift`, one method per
stage plus one that runs all stages against a single fixture:

```
func testBulletedAppFiveScopesSurviveTheWholeFlow() async throws
```

The five scopes are the ones in §1.

**Stage 0 — discovery.** `GET /.well-known/oauth-authorization-server` → 200;
decode `scopes_supported` and assert it is exactly `["atproto"]` (§6.6). Then
assert the *inverse property* explicitly: a scope absent from `scopes_supported`
is still accepted at PAR. `scopes_supported` is a hint, not a gate — pinning
that as a test is what stops a future reader "fixing" the metadata instead of
the grammar.

**Stage 1 — parse.** Each of the five strings, fed to `AtprotoScope.parse`,
returns non-nil and re-serialises canonically. `blob:image/*` → `blob:image/*`.
The `space:` scope must canonicalise to the **exact** string in §5.6.1, because
`manage` ordering follows `SPACE_MANAGE_OPS` canonical order `create, update,
delete` (`space-permission.ts:32-36, 221-226`), not input order.

**Stage 2 — client registration.** Register a **remote HTTPS** client
(`https://bulleted.app/client-metadata.json`, not a localhost virtual client)
whose `scope` string is the five joined by spaces.
`OAuthClientMetadata.validate()` must accept it. This is the stage that fails
hardest today: `OAuthClientMetadata.swift:343-344` gates the
`isIssuableQualified` disjunct behind `isLocalhostDevelopmentClient &&`, so a
remote client can carry only bare `atproto`.

**The "both directions" assertion splits across two layers under §9-D21, and
must not be written as one.** The first draft asserted "a remote client whose
only scope is a *malformed* space scope is still rejected" at registration.
That pins the retired behaviour. Registration is lexical + budget only —
upstream validates `OAuthClientMetadata.scope` with `oauthScopeSchema` and
nothing else (`oauth-client-metadata.ts:36` → `oauth-scope.ts:17-19`,
`OAUTH_SCOPE_REGEXP` at `:5-6`) — so a *lexically valid but semantically
malformed* scope **registers fine and is rejected at PAR**. Assert, as three
separate cases:

| # | case | layer | expected |
|---|---|---|---|
| A2a | the five-scope remote HTTPS client | registration | **accepted** |
| A2b | a remote client whose only scope is `space:not an nsid?...` — lexically valid scope-token bytes, semantically malformed | registration | **accepted** (registration grants nothing) |
| A2b′ | the same client then requesting that scope at PAR | PAR/authorize | **rejected**, `invalid_scope` (§9-D5, §9-D21 layer 2) |
| A2c | a client whose scope string contains `"` (0x22) or `\` (0x5C), or exceeds the raw-input budget | registration | **rejected** — the lexical/budget floor is the *only* registration gate, so it must actually hold. Note Swan's current `parseScopes` (`OAuthClientMetadata.swift:438-447`) accepts any byte in `0x21...0x7E`, which admits `"` and `\` that `OAUTH_SCOPE_REGEXP` deliberately excludes; tighten it here |

A2b + A2b′ together are the pair that proves the layer boundary moved rather
than the check disappearing.

**Stage 3 — authorize + PAR.** POST the five-scope `scope` parameter to
`/oauth/par`, expect the DPoP-nonce challenge, retry with the nonce, get a
`request_uri`. `oauthServerScopes`
(`SwanOAuthAuthorizationServerHTTP.swift:1059-1069`) already tolerates these — it
is a printable-ASCII / byte-cap / ≤ 64-token filter that never calls
`isQualified` — so the real gates are the new stage-B parse plus
`OAuthValidatedSession.init`'s `hasATProtocolResourceScope` and
`scopes.isSubset(of: client.metadata.scopes)`
(`OAuthValidatedSession.swift:26-32, 91-95`). Assert the `request_uri` is issued
and the stored PAR row round-trips all five scopes (`encodeScopes` at
`:2233-2240` is a JSON array; the space scope is 68 bytes, well under the cap).

**Stage 4 — consent. This stage is a Stage-C blocker, not a formality (§9-D19).**
`GET /oauth/authorize?request_uri=…`, assert the rendered HTML, POST
`/oauth/authorize/consent` with `decision=approve` + CSRF, follow the redirect
to a code.

**What the first draft asserted, and why it is no longer enough.** It asserted
the weak property — all five raw strings appear, none silently dropped — and
deferred human-readable consent to a separate question. That deferral is
**withdrawn**. Upstream ships a semantic renderer
(`packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx`,
1287 L) that understands permission sets, fine-grained repo/rpc/space
permissions, and emits a specific warning for `identity:*`. Swan need not port
the React UI. It must not ship a grant screen whose entire content is the scope
bytes.

**S4.1 — semantic description for every permission Swan can actually grant.**
Positive control bounding the obligation: `grep -rn "include:" Sources/` → zero
hits, and `grep -rln 'transition:generic|"repo:"|"rpc:"|"account:"|"identity:"'
Sources/` → zero hits. Swan today can place exactly **two** things into a
granted token — the base `atproto` scope and `space:` permissions — so the
*minimum* renderer is small, and its smallness is the reason there is no excuse
for not shipping it.

| # | input | required rendering | upstream anchor |
|---|---|---|---|
| S4.1a | bare `atproto` **alone** | render **no** permission card at all | `scope-description.tsx:82-85` — the component returns `null` when the only scope is `atproto`. Today's page violates this: `SwanOAuthAuthorizationServerHTTP.swift:1170-1172` lists every element of `scopes.sorted()`, `atproto` included |
| S4.1b | any `space:` permission | one card, "Access permissioned spaces", plus one row per grant summarising its verbs (`manage` / `read` / `read_self` / write) in prose | `scope-description.tsx:826` (trigger), `:836` (title), `:961-1038` (`SpaceRow` per-verb detail) |
| S4.1c | a `space:` grant with `type == "*" && authority == "*"` | the universal-grant warning, in substance: the app is requesting access to **every space on the network**, a very broad permission, grant only to deeply trusted applications | `scope-description.tsx:1094-1110` |
| S4.1d | a space type Swan cannot name | fall back to the raw `type` NSID as the row label — **show the row**, never omit it | `scope-description.tsx:1067-1076`; same fallback discipline as `LangProp fallback={nsid}` at `:178` |

**S4.2 — the Phase-1 `include:` string, specified exactly.** Swan parses
`include:` and grants nothing from it (§5.7.2, §9-D4). Upstream's fallback for
an *unresolved* set is the bare NSID as a title (`scope-description.tsx:178`,
`:186-188`) — but upstream, having resolved sets, does grant them. Swan's
wording must therefore say more than upstream's fallback does. Assert this
string, verbatim, for every `include:` token that reaches consent:

> **Requested permission set `<nsid>`.** Swan does not currently grant
> capabilities derived from this set.

Two properties, both asserted: the row is **present** (never silently dropped —
matching upstream's fallback discipline), and it states plainly that **nothing
is granted** (diverging from upstream, which grants). Without the second half
the screen *over*-states the request and a user approves a capability Swan will
then deny at every call. §5.7.2's warn-log wording and this string must agree —
one wording, two surfaces.

**S4.3 — the `identity:*`-class warning, written now, not on the day it is
needed.** Upstream renders, for `allowsIdentity({attr:'*'})`, a warning of
specific force: the application "is asking for full control over your network
identity, meaning that it could **permanently break**, or even **steal**, your
account" (`scope-description.tsx:213-236`, copy at `:227`). Swan grants no
`identity:` permission today, so this is dead code the day it lands. Write it
anyway, and write it for **every permission family Swan can grant that carries
comparable risk** — the S4.1c universal-space warning is the member of that
class Swan *can* grant today, which is why it is mandatory rather than aspirational.
The rule: **no permission of this class ever reaches a Swan consent screen as
raw scope text.** Ship the string with the family, not after it.

**S4.4 — raw scope text survives as advanced detail.** The existing `<code>`
list is not deleted; it is demoted below the semantic cards. Advanced detail is
useful; it is just not consent.

**S4.5 — TWO consent renderers, and this stage must cover both.**
`SwanOAuthAuthorizationServerHTTP.swift:1170-1172` is the authorization-server
page (verified: `scopes.sorted().map { "<li><code>…" }`);
`Sources/SwanHTTP/SwanLocalhostOAuthHTTP.swift:819-821` (`consentPage`) is an
independent localhost renderer with its own identical `scopes.sorted()` `<li>`
list — and it is the page the §7.1 harness
(`Tests/SwanHTTPTests/LocalhostOAuthBrowserHTTPTests.swift`) actually drives.
The first draft named only the first, so work scoped from the old open question
would have missed the one the tests exercise. Assert S4.1-S4.4 against **each**.
Two renderers means the semantic descriptions must live in one shared function
that both call — a second copy of the consent copy is a second copy of the
security-relevant wording.

**Stage 5 — token mint.** Exchange the code at `/oauth/token` with a DPoP proof.
Assert the granted scope string contains all five **and** that
`space:…&action=read_self` has had its `authority` resolved from `self` to the
account's DID (§6.4). Without that resolution the grant matches nothing at
request time (M22) — this is the assertion most likely to be forgotten and most
likely to look like "the app is broken" in production. Also assert
`scopes_requested` holds the pre-resolution set and `scopes` holds the resolved
one (§6.7).

**Stage 6 — request-time enforcement.** With the minted token, drive six checks
through the real handlers, routed through
`AuthorizationContext.accountOAuth(subject:permissions:)`
(`SwanOAuthResourceAuthorization.swift` ~160) — the single point where a
validated scope set reaches a handler — rather than re-deriving scopes in the
test:

1. `read_self` on the account's own repo inside `app.bulleted.space` →
   **allowed**.
2. `read` across the whole space → **denied** (M14: `read_self` does not imply
   `read`).
3. `create` of a record in any collection → **denied** (M5: the scope names no
   `collection`, so it has no write targets). **Assert this as a Phase-1
   DIVERGENCE, not as conformance.** A conformant AS runs
   `expandSpaceCollections` (`lexicon-manager.ts:74-95`) at token mint and
   materialises the space type's declared collections into exactly this bare
   grant, so bulleted.app *would* be able to create records against a reference
   PDS. Phase 1 ships without that step (§5.7.5), so the test name says so:
   `testBareSpaceGrantHasNoWriteTargetsUntilPhase2`. Without this framing the
   test reads as "upstream behaviour verified" and the real gap goes unrecorded.
4. A space-lifecycle `update` → **allowed** via `manage=update`.
5. Every `include:`-derived capability → **denied**, and the Phase-1 warn log is
   present (§5.7.2). This is the assertion that makes the `include:` decision
   visible rather than a silent hole.
6. `getDelegationToken` for `app.bulleted.space` → **denied**. The grant's
   `action` is `[read_self]`, not a stated single `read`, so
   `isExactReadOnlyDelegationGrant` (§5.6.3) is false. This is the check that
   catches a regression of the critical delegation widening; it belongs in the
   acceptance test as well as in the §7.3 fence because it is the one place
   both a real token and a real handler are involved.

### 7.5 Migration tests

- **Persistence replay.** Select every distinct `scopes` blob from
  `oauth_control_token_families` and `oauth_control_par_requests`, run
  `AtprotoScope.parse` over each element, and **record the rejected count and the
  rejected strings**. Do **not** assert zero.

  **The first draft asserted zero on a false premise, and the premise is worth
  correcting in place because the same misreading would justify a dangerous
  stage-G gate.** It claimed "every string currently in those tables passed
  `isQualified` (`OAuthControlStore.swift:2352-2356` gates every INSERT)". That
  is not what `:2352-2356` does. Re-read:

  ```swift
  private func hasATProtocolResourceScope(_ scopes: Set<String>) -> Bool {
      scopes.contains("atproto") || scopes.contains { scope in
          PermissionedSpaceScopeSyntax.isQualified(scope)
      }
  }
  ```

  That is an **OR over the set**, not an all-satisfy over elements: a set
  `{atproto, <anything>}` passes. The only **per-element** gate is `validScope`
  (`:2345-2350`), which checks non-empty, ≤ 256 UTF-8 bytes, no whitespace and no
  control characters — and nothing else. §6.3's own text already said as much
  ("lets an unparseable companion scope ride along beside a good one"); §7.5
  argued from the opposite premise in the same document.

  So a live row may legitimately hold an unparseable companion scope, and:

  1. The **expected** result of this replay is a small, enumerable list, not
     zero. Its value is the *list*, which feeds the §6.3 stage-G rule and the
     §8.3 step-1 evidence gate.
  2. A non-empty list is **not** a blocker by itself. It is a blocker only if a
     rejected string is the *only* scope in its family row, since §9-D5 says a
     held unparseable scope grants nothing.
  3. It is still true that `isQualified` does not validate the type as an NSID or
     the authority as a DID (only `isIssuableQualified` does,
     `SwanCore.swift:175-196`), so `space:notannsid?authority=notadid&skey=k&action=read`
     could be persisted and the new schema rejects it on `validate`. That case is
     now one entry in the list rather than a claimed impossibility.
  4. **Refresh rotation must be tested against a seeded junk companion**: insert
     a family holding `{atproto, <unparseable>}`, rotate it, and assert the
     rotation **succeeds** with the junk scope logged and retained. Under the
     first draft's stage-G full re-parse it would fail and lock the session out
     permanently (§6.3).
- **Refresh survival — the `self` case, which is the one that breaks.**

  **The first draft's test could not fail on the real defect and is replaced.**
  It asserted that a stored scope string in a *non-canonical parameter order*
  still refreshes. That is a real but weak property (it exercises the formatter,
  not the operand), and it would have gone green while every `authority=self`
  grant in production failed to refresh — the contradiction §9-D20 fixes.

  The mechanism, verified on both sides: `DurableOAuthTokenService.swift:770`
  reads `requestedScopes.map({ $0 == family.binding.scopes }) ?? true` inside the
  guard at `:768-772`, throwing `OAuthControlStoreError.bindingMismatch` on
  mismatch. §9-D8 makes `family.binding.scopes` hold the **resolved** grant while
  the client re-presents its **requested** bytes. For `authority=self` — the
  upstream default (`space-permission.ts:183`) and therefore the common case —
  those two deliberately differ, so the comparison can never succeed.

  **The replacement test, in four steps:**

  1. Mint a grant whose scope **defaults to or explicitly contains** `self` —
     e.g. `space:app.example.forum?action=read_self` (authority omitted, defaults
     to `self`) and `space:app.example.forum?authority=self&skey=*&action=read_self`.
     Both shapes, since one exercises the default and one the literal.
  2. Assert the persisted rows **differ**: `scopes_requested` holds the
     pre-resolution bytes (`authority=self` / absent), `scopes` holds the
     resolved DID (§6.7). A test where they happen to be equal is not exercising
     this path — assert inequality explicitly, do not merely read both.
  3. Refresh using the **ORIGINAL requested** scope string — the exact bytes the
     client sent at PAR, not the resolved one, because the resolved one is
     something the client has never seen.
  4. Assert the refresh **succeeds**, and that the rotated family still carries
     the resolved scope. Under the baseline fixed in §9-D20 the comparison runs
     against `family.scopes_requested ?? family.scopes`; against
     `family.binding.scopes` it fails, so this test is red before the fix and
     green after — which is the whole point of replacing the old one.

  Keep the non-canonical-parameter-order assertion as a *separate, additional*
  case. It is a different property (formatter stability) and is still worth
  holding; it is simply not the case that breaks.
- **Additive-column back-compat, now on a live authorization path.** A row with
  `scopes_requested IS NULL` decodes as "requested == stored" (§6.7), not as
  "unknown". Since §9-D20 makes the refresh baseline `scopes_requested ??
  scopes`, this column is no longer audit-only: assert that a **pre-migration**
  row (`scopes_requested IS NULL`, no `self` ever resolved into it) refreshes
  unchanged through the `??` fallback. That is the case that proves the fallback
  is total rather than a convenience — §8.1's "old tokens are not re-minted"
  promise depends on it.

### 7.6 The verification gate

Swan's real build gate is `swift build --product swan`, and the suite hangs
intermittently on both macOS and Linux — the wedge sits at XCTest's async bridge
with no Swift concurrency worker present, so **a single green run is not proof of
anything**. The gate is built around that.

**Build (the hard gate):**

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Swan-merge3
xcrun --toolchain XcodeDefault swift build --product swan 2>&1 | tail -40
```

Never a bare `swift build` — a custom default toolchain wedges SwiftPM.
`--product swan` is the gate because it is the only invocation that proves the
executable links. Linux parity, which is where swan.place actually runs
(x86_64; no macOS ARM deploys), in the Linux docker build image from the repo
root: `swift build --product swan`. The documented `--build-tests` gate can
**never** pass in that image (missing apt deps, the `../Petrel` mount, VM disk);
do not treat a failed `--build-tests` there as a regression signal.

**Test (the soft gate, run N times).** `swift build` is library-only;
`swift test --skip-build` after a plain `swift build` runs **stale** test
binaries. Always:

```bash
xcrun --toolchain XcodeDefault swift build --build-tests 2>&1 | tail -20
```

Then the conformance suites, narrowest first — pure value tests, no actor, no
NIO, no DB, so they should never hang. If one of *these* hangs, that is a real
finding:

```bash
for i in 1 2 3 4 5; do
  echo "=== run $i ==="
  timeout 300 xcrun --toolchain XcodeDefault swift test --skip-build \
    --filter 'SwanCoreTests.(ScopeSyntaxConformance|ScopeFamilyVector|SpacePermissionMatch)Tests' \
    2>&1 | tee /tmp/scope-run-$i.log | tail -5
  echo "exit=$?"
done
```

Acceptance: **5/5 runs exit 0** with an identical passed-count. Extract the
count with

```bash
grep -c "^Test Case '-\[.*\]' passed" /tmp/scope-run-$i.log
```

— **not** by summing `Executed N tests` lines, which triple-counts across nested
suite levels and has produced wrong records here twice. A `SIGABRT` / stack
overflow prints **no** `test result:` line and lists only the failures it
reached, so a crashed run looks like a *smaller* failure set than a healthy one.
Treat a missing final summary line as a failed run regardless of what the failure
list says.

Then the wider suites, which are the ones that actually hang:

```bash
for i in 1 2 3; do
  timeout 900 xcrun --toolchain XcodeDefault swift test --skip-build \
    --filter 'SwanSpacesTests|SwanSQLiteTests' 2>&1 | tee /tmp/scope-wide-$i.log | tail -5
done
timeout 1800 xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter 'SwanHTTPTests.RemoteClientPermissionedScopeE2ETests' 2>&1 | tail -30
```

Acceptance for the wide suites: **3/3 runs agree on the passed-count and the
failure set**. A run that times out is neither a pass nor a fail — re-run it and
record the timeout separately. Two timeouts out of three on the same filter is
itself a finding worth chasing before merging.

**The gate as a checklist:**

1. `swift build --product swan` green on macOS **and** in the Linux image.
2. 5/5 identical green runs of the three `SwanCoreTests` scope suites.
3. 3/3 agreeing runs of `SwanSpacesTests` + `SwanSQLiteTests`, with the §7.3
   divergence fence green.
4. One green run of the bulleted.app acceptance test, with the Stage 5
   `self`→DID assertion and the Stage 6 six-way enforcement matrix present in
   the log.
5. The §8 step-1 production scope-string sweep executed, with the
   both-grammars-agree result pasted into the PR — **before** Stage B deploys,
   not after.
6. `swiftlint` where it applies; **never** plain `swiftformat` on this repo.
7. **Golden-corpus zero-diff.** Regenerate `Tests/SwanCoreTests/Fixtures/scope-corpus.tsv`
   from the pinned reference (`Scripts/gen-scope-corpus.mjs`, upstream
   `bddc99fb`, §7.1a) and assert `diff` is empty against the checked-in fixture.
   A non-empty diff means either the pin moved or the fixture was hand-edited;
   both are blockers, and neither is visible from a green test run, because the
   suite asserts Swift against the fixture, not the fixture against upstream.
8. **The refresh-survival `self` case (§7.5) green**, named in the PR by test
   name. It is called out separately from steps 2-4 because it is the one test
   whose absence previously let a refresh-breaking contradiction (§9-D20) sit in
   the spec unnoticed, and because it must be demonstrated **red before the
   §9-D20 operand fix** and green after.

Steps 1-4 prove the code. Step 5 proves the rollout, and it is the one most
likely to be skipped. Steps 7-8 prove the two things that were previously
provable only by reading: that the vectors still match upstream, and that
refresh actually works for the common grant shape.

---

## 8. Migration and rollout

### 8.1 What happens to tokens already issued

Old tokens are **not** re-minted. They keep their stored scope string and are
re-evaluated by the new matcher on every request. That is the actual migration:
**the matcher changes under existing tokens**, so the "what must NOT change"
fence in §7.3 *is* the migration test. Storage is format-stable (a JSON array of
strings in a BLOB), and the only schema change is one additive nullable column
(§6.7) — no backfill, no data rewrite.

Two risks to check before shipping, not after:

1. **Default drift.** An old row
   `space:x.y.z?authority=did:plc:abc&skey=default&action=read` is fully
   specified — its meaning is unchanged. There should be *no* old rows with
   omitted params, because the old grammar required `authority` and `skey`, so
   the `self`/`*` defaults cannot retroactively widen anything. **Verify against
   production before relying on it** (step 1 below).
2. **The NSID/DID tightening (D11, D12).** `SpaceURI` becomes stricter about
   NSIDs and DIDs (§4.1). A persisted space URI with a hyphenated final NSID
   segment or a trailing-colon DID would newly fail to parse. Enumerate and audit
   before cutover.
3. **Pre-migration rows must refresh through the `??` fallback.** Every row
   written before §6.7's additive column exists has `scopes_requested IS NULL`.
   §9-D20 makes the refresh baseline `family.scopes_requested ?? family.scopes`,
   so for those rows the fallback resolves to the stored value and the comparison
   is byte-identical to today's — which is exactly why "old tokens are not
   re-minted" remains true. This is not automatic; it is a property of the `??`,
   and §7.5 asserts it. If the fallback were ever narrowed to "only when
   non-NULL and only for `self` grants", every legacy session would stop
   refreshing on deploy.

### 8.2 Three stages, the first two dark

- **Stage A — parser only, no behaviour change.** Land the new parser as a
  *parallel* type. Keep every enforcement call site on
  `PermissionedSpaceScopeSyntax`. Add a shadow assertion — **log-only, never a
  `guard`** — at each of the seven enforcement points: when old and new disagree
  on a live scope, log both verdicts with the scope string. Run for a week
  against real traffic. This is the only way to get evidence about risk (1)
  without guessing. **Fully dark.**
- **Stage B — flip the matcher, keep issuance closed.** Switch `isQualified`-derived
  checks to the new matcher via the deprecated shim (§6.2). Remote clients still
  cannot register `space:` scopes (`OAuthClientMetadata.swift:343-344`). Existing
  tokens now run under the new matcher — the first stage with production risk,
  and Stage A's shadow log is what makes it safe. The byte budgets **separate**
  here (§6.4, §9-D17) — "unify" was the verb the first draft used and it is now
  wrong: there is one RAW-INPUT budget at the wire and one EXPANDED-GRANT budget
  at persistence/mint, and Stage B is where both are put in place with distinct
  error paths even though their initial numbers coincide. The additive column
  lands here too (§6.7), and with it §9-D20's refresh-baseline fix — the column
  and the fix must ship together, because the column without the fix leaves
  refresh comparing against the resolved grant.
- **Stage C — open issuance. Two preconditions, both new.**
  1. **The minimum semantic consent renderer (§7.4 Stage 4) is landed on BOTH
     consent pages.** §9-D19 makes this a blocker, not a follow-up. Stage C is
     the stage that lets an arbitrary remote client put arbitrary permissions in
     front of a user; opening it while the grant screen renders scope bytes is
     the combination the ruling forbids.
  2. Stage B is deployed and its shadow log is clean (unchanged).

  Then, **three** edits, not two — an earlier draft named only the last two, and
  omitting the first would leave half of the retired gate live:
  1. `OAuthClientMetadata.swift:292` — delete the
     `$0 == "atproto" || isIssuableQualified($0)` guard in
     `localhostDevelopmentMetadata`. This is the **registration** half of the
     two-member family allow-list audited in §6.2; leaving it means a localhost
     client still cannot *register* anything but `atproto` and `space:`, so the
     other two edits change nothing on that bridge.
  2. `OAuthClientMetadata.swift:344` — delete the **entire** scope predicate in
     `validate()`, including the `scopes.contains("atproto")` arm. **Note the end
     state**, since two earlier drafts each described this line differently and
     one of them contradicted D21: metadata validation keeps **no** base-scope or
     resource-scope predicate at all.

     Leaving `scopes.contains("atproto")` would still be *semantic* registration
     policy, and D21's own layer table says registration validates "a valid RFC
     scope-token list + budgets" and "anything semantic" is in the does-NOT
     column, with unknown and future names registering safely. A metadata
     document declaring only `some.future.permission:foo` is lexically valid;
     rejecting it at registration for lacking `atproto` contradicts both D21 and
     the stage-D row. Upstream's `oauthScopeSchema`
     (`oauth-types/src/oauth-scope.ts:5-19`) has no such requirement either.

     The `atproto` floor — and Swan's looser `atproto`-or-`space:` variant — live
     **solely at PAR/admission** (§6.3 stage E, `.missingBaseScope`). That is
     also where the error is coherent: `invalid_scope` on a request, rather than
     a client-metadata load failure for a document nobody has yet requested
     anything with.
  3. `localhostRequestedScopes`'s `isIssuableQualified` disjunct at `:460` —
     **delete, not re-express** (§9-D21).
  The first draft said "re-express over a parsed permission"; the ruling retires
  the gate rather than relocating it, so stage A′ becomes tokenizer + raw-input
  budget only, matching stage A. Leaving `:460` alone would leave the localhost
  flow — the flow the acceptance harness drives — rejecting four of
  bulleted.app's five scopes after everything else has shipped; re-expressing it
  would rebuild the retired gate over the new parser. Accept bulleted.app. Not
  dark by definition: this is the visible change. `scopes_supported` stays
  `["atproto"]` (§6.6). Also land §6.5.9(b): `SwanOAuthPARHTTP.swift:155` stops
  substituting the full registered set for an absent `scope` — which matters
  *more* under §9-D21, since registration now grants nothing and substituting the
  registered set would manufacture a grant out of a declaration.

  **The narrow escape hatch, and its exact shape.** If bulleted.app must be
  tested before the renderer lands, **feature-flag remote issuance narrowly** —
  an allowlist keyed on the specific client ID, off by default, with the raw-only
  consent page reachable only for that client — rather than removing the
  `isLocalhostDevelopmentClient &&` gate globally. The distinction is the whole
  ruling: a flag exposes one known test client to a weak consent screen; Stage C
  as written exposes every client on the internet. Do not describe the flag as
  "Stage C, early".
- **Separate track — the credential sender-constraint (§6.8).** This is **not**
  a fourth stage of the scope-grammar change. It is its own PR with its own
  sequencing (§9-D18), and **mint and consume land together inside it**: the
  `cnf.jkt` binding is minted from a verified proof *and* verified at
  presentation in the same change, with an unbound credential **rejected**
  (`packages/pds/src/auth-verifier.ts:392-398`). It has no ordering dependency on
  A/B/C in either direction — it touches the space-credential plane, not the
  scope grammar — so it may land before, between, or after them. What it may
  **not** do is ship half: mint-only would leave a credential nobody checks,
  which §9-D18 forbids being described as sender-constrained.

### 8.3 Order of operations against live swan.place with real accounts

1. **Evidence first.** Against the production DB (via the Doppler/psql or
   prod-db MCP path — do not copy credentials), enumerate every distinct scope
   string currently stored in `oauth_control_token_families.scopes` and
   `oauth_control_par_requests.scopes`, plus every persisted space URI (for D11 /
   D12). Run each through *both* grammars offline. Expected: identical verdicts
   on 100%. Any disagreement is a blocker, not a footnote. Cheap, and the step
   that makes the rest defensible.
2. Land Stage A behind the shadow log. Deploy. Watch for a week. The success
   criterion is **zero** disagreement lines, not "few".
3. Land Stage B. Deploy at a low-traffic hour. Immediate manual check with a real
   account: sign in with the existing iOS client, confirm an existing session
   still reads and writes.

   **Existing refresh tokens must still rotate, and the check must exercise a
   `self`-bearing grant.** `DurableOAuthTokenService.swift:770` compares
   `requestedScopes.map({ $0 == family.binding.scopes }) ?? true` on refresh. The
   first draft named the hazard as *re-canonicalisation* — a scope string that
   re-serialises differently under the new formatter. That hazard is real and the
   rule against it stands (**do not re-canonicalise stored scopes on refresh**,
   §9-D7), **but it is not the one that fires.** What fires is **resolution**:
   §6.4 resolves `self` on the mint path *and* on the refresh family-reuse path,
   and §9-D8 stores the resolved grant, so requested and stored bytes differ by
   construction for every `authority=self` grant — which, `self` being the
   upstream default (`space-permission.ts:183`), is nearly all of them. §9-D20
   fixes the operand (compare against `scopes_requested ?? scopes`); this manual
   step is how it is confirmed in production rather than only in a fixture.

   So the manual check is: take a **`self`-bearing** grant (one minted with
   `authority` omitted or literal `self`), confirm the stored `scopes_requested`
   and `scopes` differ, and confirm the client's refresh with its **original
   requested** scope string succeeds. A refresh check run against a
   fully-specified `authority=did:plc:…` grant proves nothing here, because for
   that shape the two sides are identical and the defect is invisible.
4. Land Stage C — **only after §7.4 Stage 4's semantic consent renderer is live
   on both consent pages** (§9-D19). Verify the renderer against a real browser
   session before the gate opens, not after: check that bare `atproto` renders no
   card, that a `space:` grant renders its verbs in prose, and that an
   `include:` token renders the "Swan does not currently grant capabilities
   derived from this set" row. Then test with bulleted.app against a throwaway
   account on swan.place before announcing. If bulleted.app must be exercised
   earlier, use the narrow per-client feature flag from §8.2, not an early Stage C.
5. Only then consider Phase 2 (`include:` resolution, §5.7.3-§5.7.6). Re-
   canonicalising historical rows is never required.

   **Phase 2 is a port, not speculative engineering** (§9-D14): the source is
   `packages/lex/lex-resolver/src/lex-resolver.ts` (577 L) with a published
   verification contract. **Gate:** the proof-verification path —
   commit-DID equality (`lex-resolver.ts:533-535`), commit signature (`:537-541`),
   MST membership (`:543-546`), record `$type` (`:548-553`), `lexicon.id == rkey`
   (`:480-485`) — must have vectors **before** any `include:`-derived capability
   is granted. A resolver without proof verification is worse than no resolver:
   Phase 1 denies every `include:`-derived call, which is a visible,
   fail-closed gap, whereas an unverified resolver would grant capabilities on
   the strength of an application response nobody proved came from signed repo
   state.

**Rollback.** Stages A and B are code-only apart from one additive nullable
column, which the previous binary ignores — rollback is a redeploy. Stage C is
also code-only, but any client that successfully registered a `space:` scope in
between will have a stored client-metadata row whose scopes the reverted code
rejects, so a Stage C rollback needs a companion cleanup of client rows
registered during the window. Note that **before** shipping C, not after.

---

## 9. Decisions taken, and open questions

### 9.1 Decisions — where the four design notes disagreed

**D1. The grammar lives in `SwanCore`, not a new `SwanScopes` target.**
`11-design-families.md` proposed a new `SwanScopes` depending on `SwanCore` *and
on `SwanSpaces`* (for `SpaceURI`). That is a dependency cycle: `SwanSpaces`
itself calls the grammar (`SwanSpaces.swift:315, 360`), so `SwanSpaces` would
have to depend on `SwanScopes` which depends on `SwanSpaces`. The other three
notes place the grammar in `SwanCore`, which `Package.swift:76-82` shows has no
Swan-target dependencies and which all five calling targets already reach.
Resolution: `SwanCore`, with match targets as plain `String` structs and a
`SwanSpaces` extension supplying the `SpaceURI` overloads (§3, §6.2). Cost: one
extra ergonomic file. Benefit: no new target, no inverted edge, and the
request-time matcher structurally cannot reach a network fetcher (§9-D8).

**D2. One naming scheme.** The four notes used three. Adopted: the grammar-layer
names from `10-design-grammar.md` (`ScopeStringSyntax`, `ScopeParameterBag`,
`ScopeParameterSchema`, `ScopeParameter`, `ScopeParameterValues`,
`ScopeParseError`, `AtprotoScope`, `AtprotoSyntax`), the family payload names
from `11-design-families.md` (`SpacePermission`, `RepoPermission`, …), and the
facade + target names from `12-design-enforcement.md` (`SwanScopePermissions`,
`SpaceScopeTarget`, `ScopeDenied`). Dropped: `ScopeSet`, `GrantedScopes`,
`SpaceScopeGrant`, `ATProtoScope`, `ATSyntax`, `ScopeParser`, `ScopeParamSpec`,
`ScopeSyntax`, `ScopeParamLookup` — each was a second name for something already
named. **Note the collision**: `SwanSpaces` already has a domain type called
`SpacePermission` (`SwanSpaces.swift:175-182`). Rename the domain type or
qualify at every use; do not let two `SpacePermission`s coexist unqualified
(§6.2).

**D3. `isValidNSID` follows upstream `nsid.ts`, not Swan's current
`SpaceURI`.** `10-design-grammar.md` argued for deliberately retaining Swan's
rule ("if the two disagree, the resource matcher's answer must win, and the
resource matcher is this function"). `11-design-families.md` argued the opposite
and enumerated three concrete divergences. Upstream wins, for two reasons.
First, the entire purpose of this grammar is interop: if Swan accepts
`com.example.foo-bar` as a space type where upstream rejects it, the same scope
string means different things on two servers, which is the failure this change
exists to remove. Second, one of the three divergences is a **false negative** —
Swan rejects `com.9example.foo`, which upstream accepts (`nsid.ts:109-111`) —
so "the matcher's answer wins" would keep a real client broken. The 10-note's
concern is real but is addressed by having exactly one implementation
(`AtprotoSyntax`) that both the grammar and `SpaceURI` call, rather than by
picking the looser rule. Consequence: `SpaceURI` becomes stricter; audit
persisted URIs before cutover (D11/D12 in §7.3, §8.1 risk 2).

**D4. `include:` ships in two phases.** `11-design-families.md` designed a full
resolver (network fetch, cache table, 24 h hard expiry);
`12-design-enforcement.md` said Swan supports no `include:` and needs none;
`13-design-tests.md` offered three options and recommended parse-and-hold first.
Resolution: **Phase 1 = parse-and-hold** (the type, the vectors, persisted
verbatim, grants nothing, logged at `.warn`, asserted explicitly in the
acceptance test); **Phase 2 = the resolver from §5.7.3-§5.7.6**. Reasoning:
parse-and-hold is the only option that unblocks the other four scopes without
building a resolver, it is testable today, and it keeps `include:` *parseable*
so it is not caught by D5's reject-at-PAR rule.

**The two-phase split survives; Phase 2's *content* is now a port, not a
choice among options.** The first statement of this decision framed Phase 2 as
Swan-designed engineering picked from three options, because the resolver
package was not visible in the truncated export (§2 constraint 5). It is
present: `packages/lex/lex-resolver/src/lex-resolver.ts`, 577 lines, with a
documented four-stage contract at `:184-191` and a verification path Swan must
reproduce (§9-D14). Phase 2 is therefore scheduling, not invention.

The honest cost paragraph stands unchanged: bulleted.app will authorize
successfully and then be denied on every `include:`-derived call — which is why
§7.4 Stage 6 check 5 asserts it rather than leaving it to be discovered. One
addition under §9-D19: the user is now **told this at consent time** ("Swan does
not currently grant capabilities derived from this set", §7.4 S4.2), so the cost
is disclosed rather than merely recorded. That does not remove the cost; it stops
the consent screen over-stating what was granted.

**D5. Swan rejects an unparseable *requested* scope at PAR; a *held* scope that
does not parse silently grants nothing.** `10-design-grammar.md`'s error table
mapped rows 3 and 5-12 to "drop the token, silent", matching
`request-manager.ts:177-185`. `12-design-enforcement.md` argued for rejection
with `invalid_scope`. These read as contradictory but are two different layers,
and both are adopted:
- **Request layer (PAR / authorize):** reject with `invalid_scope`. Upstream's
  silent drop relies on a "degrade then re-auth once support lands" mechanism
  (the `@NOTE` at `request-manager.ts:179-182`) that Swan does not have — no
  consent re-show, no resolver. Worse, a silent drop interacts badly with the
  subset check: a client asking for `atproto` + one malformed `space:` would
  silently receive an `atproto`-only token and then get an opaque 401 at the
  resource plane with nothing in the OAuth response pointing at the cause. Swan
  is fail-closed at every other scope boundary (`SwanSpaces.swift:305-311`,
  `SwanCore.swift:159-165`); silent narrowing would be the one lenient spot.
- **Match layer (already-persisted grants):** silent, no throw, grants nothing —
  `scopes-set.ts:47-55`, pinned by `scopes-set.test.ts:42-47` and §7.2.4 row 4.
  A stored string that a future binary cannot parse must not be able to fail a
  request open *or* crash it.
Both are asserted in the same test file so the pair is visible.

**D6. `ScopeDenied.needed` never reaches the wire.** Upstream's
`ScopeMissingError` is `expose = true`, status 403, and echoes the needed scope
(`scope-missing-error.ts`). Swan does not, because
`SwanOAuthResourceAuthorization.swift:9-16` already states the rule for this
boundary: every invalid, expired, replayed, token-binding and account-lifecycle
predicate becomes the same denial, "to avoid turning the protected-resource
boundary into a DPoP or account-status oracle". Adding a scope oracle beside it
would undo that. `needed` is logged server-side at `.info` with the route path
(§6.5.8).

**D7. Canonicalise both sides of the *subset* check; do NOT canonicalise the
*refresh equality* check.** `10-design-grammar.md` prescribed
`isCanonicalSubset(of:)` for every comparison; `13-design-tests.md` warned that
`DurableOAuthTokenService.swift:770` compares `requestedScopes ==
family.binding.scopes` on refresh and that re-canonicalising would break every
live session if the formatter ever changes. Both are right about different
comparisons:
- `binding.scopes.isSubset(of: client.metadata.scopes)`
  (`DurableOAuthTokenService.swift:1112-1113`) and
  `OAuthValidatedSession.swift:29` compare *requested* against *registered*,
  both supplied by the client in the same generation. A client can legitimately
  spell the same grant differently in its metadata and its request, so both
  sides are canonicalised before comparing. Without this, canonical form itself
  would introduce false negatives.

  **"Canonicalised" is now defined, because the first draft mandated it without
  saying what it was.** Upstream's only whole-*scope-string* normaliser is
  `normalizeAtprotoOauthScope` (`atproto-oauth-scope.ts:55-62`):

  ```ts
  scope.split(' ').map(normalizeAtprotoOauthScopeValue)
       .filter(isNonNullable).sort().join(' ')
  ```

  Three behaviours — per-value canonicalisation, **drop values that do not
  parse**, and `.sort()`. Swan adopts the first and the third and **rejects the
  second for the registered side**: if a *registered* scope in
  `client.metadata.scopes` fails to parse, upstream's normaliser removes it,
  which turns a subset check that passes today into a rejection and can lock out
  a client over a scope it is not currently asking for. Swan's rule, stated once:

  | side | unparseable value |
  |---|---|
  | requested | already rejected at stage A/B (§9-D5); cannot reach here |
  | registered | **kept, compared as its raw bytes**. Never silently dropped |

  Same rule covers §4.5's `blob`/`+` lossiness: a value whose canonical form
  fails to re-parse is compared raw on **both** sides rather than treated as
  absent. Vector for the pair belongs in §7.2.4.
- The refresh check compares a *stored* string against a *requested* one across
  binary generations. **It stays raw-string equality — but the stored operand is
  the REQUESTED baseline, not the resolved grant.** See §9-D20, which resolves a
  contradiction this decision and D8 previously created between them. The
  comparison is:

  ```
  requestedScopes == (family.scopes_requested ?? family.scopes)
  ```

  and **never** against `family.binding.scopes`, which under D8 holds the
  post-`self`-resolution value the client has never seen. Nothing may
  re-canonicalise a persisted scope byte; that rule is unchanged. What changed is
  *which* persisted bytes are compared.

A canonical-equality *fallback* on the refresh path (try raw first, then
canonical) would be sound — canonical equality means the same grant, so it can
only turn a spurious mismatch into a match — but it is deliberately **not** in
this rollout: it widens a security-relevant equality on the strength of a
formatter that has zero production mileage. **Do not read that deferral as the
missing piece for refresh.** It is not. Refresh is fixed by the operand change
above (§9-D20); the canonical fallback is an independent, optional widening for
a *different* failure mode (formatter drift), and shipping it would not have
fixed the `self` case, because a resolved DID and the literal `self` are not
canonically equal either. Revisit after Stage B's shadow log (§9-D20 closing).

**D8. Token-family rows store the *resolved* scope; the *requested* bytes move
to a new column.** `10-design-grammar.md` said "no storage migration, no byte
rewrite — the stored value stays the exact thing the client was granted, an
audit value". `12-design-enforcement.md` said resolved-in-place plus
`scopes_requested`. The latter wins, because §6.4's fail-closed rule makes
resolution *mandatory*: an unresolved `self` matches nothing, so a token family
storing `authority=self` would grant nothing at all on every request. Persisting
the resolved value is what makes the grant usable, and a stale binary reading a
resolved row sees a concrete DID where it expected `self`, which fails closed,
not open. PAR rows are unchanged — they have no subject and physically cannot
hold a resolved value.

**Correction: "`scopes_requested` is never read by an enforcement path" was
stated in the first draft and is now FALSE.** Left standing, that clause forbids
the very fix D7 needs, and the two decisions contradict each other (§9-D20). The
accurate statement, which is what D8 now asserts:

| reader | reads `scopes_requested`? |
|---|---|
| the resource-plane matcher (`allowsSpace` and friends, §6.1) | **never.** It enforces against the resolved `scopes` only. The 10-note's concern — that an audit column must not become a second source of authority — is honoured here, which is where it matters |
| consent display / audit | yes, as originally intended |
| **the refresh binding comparison** (`DurableOAuthTokenService.swift:770`) | **yes — it is the baseline** (`scopes_requested ?? scopes`, §9-D20) |

So `scopes_requested` is not an inert audit column: it sits on a live
authorization path from the moment the first resolved grant is written, and §6.7's
migration note says to review it as an authorization change with an additive
schema rather than as a schema change. What it is *not* is an input to the
matcher — that distinction is the one worth preserving, and "never read by an
enforcement path" was too blunt a way to say it.

**D9. One byte cap: 1024 per token, 8192 per set, enforced at the wire.**
`12-design-enforcement.md` proposed raising 256 → 1024 with an 8192 aggregate;
`13-design-tests.md` said "keep 256 or raise it, but do not ship with both", and
`10-design-grammar.md` kept 256 in its error table. Adopted: **1024 at all
FOUR surviving layers** — remote PAR tokenizer, **localhost tokenizer
(`localhostRequestedScopes`, `OAuthClientMetadata.swift:456-461`)**, `validScope`,
`validateScopes` — plus an 8192 whole-set budget enforced in **both tokenizers**,
with a defence-in-depth copy at persistence; `isQualified`'s 7…4096 disappears
with the shim. Reasoning: upstream has no length limit at all (§9-D17), a
multi-collection `space:` grant blows past 256 bytes with three or four NSIDs,
raising a cap is read-compatible (every existing row is ≤ 256 and re-validates),
and 64 × 1024 = 64 KB is why the per-token bump alone is unsafe.

Three corrections to the first statement of this decision. Two are from §6.4:
the localhost tokenizer's **4096-byte** cap was a **fifth** cap this decision
originally missed, so "the split disappears entirely" was only true once it moved
too; and the 8192 whole-set budget was originally placed at persistence, which is
too late — the 64 KB hazard is a *wire* hazard, and at persistence the request
has already been tokenized, parsed and (Phase 2) already triggered lexicon
resolution. 13's "do not ship with both" is satisfied only with both corrections
applied.

**Third correction: there are TWO budgets, not one enforced twice** (§9-D17).
The first statement described persistence as holding "a defence-in-depth copy of
the same 8192 budget". It is not the same budget, because it is not measuring
the same string:

| budget | measures | enforced at | fails as |
|---|---|---|---|
| **RAW-INPUT** | the bytes the client sent | both wire tokenizers (remote PAR, localhost) | a client error at PAR — the client sent too much |
| **EXPANDED-GRANT** | what Swan holds after **its own** transformations: `self` resolution, `expandSpaceCollections`, and (Phase 2) `include:` expansion | token mint and persistence | a **server-side** failure at mint — the client sent something legal that Swan grew past the limit |

The initial numbers coincide (1024 B/token, 64 tokens, 8192 B/set), and that
coincidence is exactly why they must be **named separately from the start**:
otherwise the first time they need to diverge, a reader finds one constant used
for two purposes and no way to tell which callers meant which. The motivating
failure is concrete — an 80-byte `include:` or a bare `space:<type>` passes PAR
comfortably under the raw budget and then inflates past it under Swan's own
expansion, producing a persistence failure **caused by Swan's transformation
rather than by the client**. §6.4 specifies the error and the surface (token
mint, not PAR); §7.3 row D9 carries the vector.

**Fourth: the caps are documented publicly.** Upstream has no length limit at
all — `oauthScopeSchema` (`packages/oauth/oauth-types/src/oauth-scope.ts:17-19`)
is `OAUTH_SCOPE_REGEXP` (`:5-6`) and nothing else, no byte cap and no token cap —
so a conformant client can construct a legal scope Swan refuses. Swan therefore
publishes its budgets in its interoperability documentation (`docs/`), and
**invents no nonstandard OAuth metadata field** to advertise them (§6.6, §9-D17).

**D10. `scopes_supported` stays `["atproto"]`.** `13-design-tests.md` Stage 0
said to assert Swan "now advertises the grammar"; its own §5 and
`12-design-enforcement.md` §4 both said advertise nothing new. The latter wins
and 13's Stage 0 is rewritten (§7.4 Stage 0) to assert `["atproto"]` **plus the
inverse property** — that a scope absent from `scopes_supported` is still
accepted. Reasoning: upstream deliberately never enumerates granular scopes
(`build-metadata.ts:28-38`, with an explicit "not a specced behavior" comment),
a `space:` scope's value space is infinite, and bulleted.app's failure was **not**
caused by a missing advertisement — it read all three documents successfully.
Adding a fake advertisement would paper over a grammar gap.

**D11. `transition:*` parses but grants nothing — a recorded DIVERGENCE, not
conformance.** Swan implements no transition semantics (grep of `Sources/` for
`transition:` returns nothing). Recognising the three static strings means a
client sending them is not rejected at PAR under D5; granting nothing means no
legacy scope reaches a space. `transition:generic` → `allowsSpace == false` is
asserted explicitly (§7.2.5 T4), replicating upstream's override-to-super, kept
"to keep that a decision rather than an oversight"
(`scope-permissions-transition.ts:55-61`).

**The first statement of this decision cited only that `allowsSpace` override
and thereby read as conformance.** Read in full, `:27-80` grants a great deal:
`transition:email` → `account:email?action=read` (`:27-37`);
`transition:generic` → all blob (`:39-45`), all repo (`:47-53`) and all rpc whose
`lxm` is `*` or does not start with `chat.bsky.` (`:64-80`); `transition:chat.bsky`
→ `chat.bsky.*` rpc (`:76-78`). Swan grants none of it. **A token Swan mints
carrying `transition:generic` is inert where a reference PDS honours it for repo,
rpc and blob.** The choice is defensible — `oauth-provider` recognises scopes via
`isAtprotoOauthScope`, not the transition subclass, and Swan wires no
`repo:`/`rpc:`/`blob:` routes (D12) — but the consequence is now stated, and
§7.2.5's T3/T5 pin it as a divergence with test names that say so (§4.7).

**Correction to the positive control cited in support of that choice.** The
first statement wrote "`grep -rn ScopePermissionsTransition oauth-provider/src`
→ 0" as if it established that the transition subclass is not a recognition
mechanism *upstream*. The grep is correct **for that directory** and misleading
as a statement about upstream: `ScopePermissionsTransition` is live in the
consent UI, constructed per render at
`packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx:80-81`
and used to drive every permission card. Restate the control's scope: it shows
`oauth-provider/src` recognises scopes via `isAtprotoOauthScope`; it shows
nothing about the tree beyond that directory. The **decision** is unaffected —
Swan wires no `repo:`/`rpc:`/`blob:` permission family into any route either way
(the routes exist; they consult no scope of those families) — but the argument may not
lean on an absence the control never established. The same sentence appeared in
§4.7 and is corrected there too.

**D12. The six `allows*` families ship now, even though only `space:` is
enforced.** A deliberate surface, reached today only by tests: it lets the XRPC
pipethrough (`SwanXRPCPipethrough.swift`) and the public repo mutation route
(`SwanPublicRepositoryMutationXRPC.swift:441`) adopt `rpc:` / `repo:` / `blob:`
later without a second facade being invented.

**The justification changes, though the decision does not.** The first statement
called this "a stated, deliberate dead surface", which read as *nothing consumes
these anywhere*. Upstream wires all six (§9-D16): `packages/pds/src` carries 67
`authorize:` route callbacks, with `permissions.assertRpc`×15,
`assertRepo`×5, `assertIdentity`×4, `assertAccount`×2, `assertBlob`×1
(`api/com/atproto/repo/uploadBlob.ts`) and `assertSpace`×2 plus the shared helper
at `api/com/atproto/space/util.ts:87-100`. So the surface is **not yet ported**
in Swan rather than dead in general, and each family has a named port target:
`assertRepo` → the record-write routes, `assertBlob` → blob upload, `assertRpc` →
`SwanXRPCPipethrough`, `assertIdentity` → handle update, `assertAccount` →
email/repo management. §7.2.8 gives each one a vector now, so the facade is
exercised against the shape it will have to satisfy rather than against an
invented one.

**D13-D21 below are RULINGS on what §9.2 previously carried as open questions.**
They are decisions, not options, and each names the section that implements it.
§9.2 is now a closed-questions record.

**D13. Port `@atproto/did` exactly. The reconstruction is REJECTED.**
*(was Q1 — implemented in §4.1, §5.5, §5.7.1, §3 file list)*
The first draft proposed shipping `isValidServiceRef` as
`isValidDID(didPart) && non-empty valid service id`, with **no method
allow-list**, reconstructed from test vectors because `packages/did` appeared
absent. It is present. The reconstruction is rejected on two counts, both
verified:
- **Too permissive on DID methods.** atproto allows exactly `'plc' | 'web'`
  (`packages/did/src/atproto.ts:19`), with
  `isAtprotoDid = isDidPlc(input) || isAtprotoDidWeb(input)` (`:27-29`) and the
  rejection message "Atproto only allows \"plc\" and \"web\" DID methods"
  (`:25`). A `did:web` **with a path component is refused** (`:74-92`), and
  `did:plc` is exactly 32 characters over `[a-z2-7]`
  (`packages/did/src/methods/plc.ts:5-21`). The method allow-list is
  **mandatory**, not forbidden. `did:plc:111` is rejected for length *and*
  charset, not for the "method-specific validation" the first draft guessed at.
- **Wrong on fragment grammar.** `isAtprotoDidRefAbsolute` is
  `isDidRefAbsolute(value) && isAtprotoDid(value.slice(0, value.indexOf('#')))`
  (`atproto.ts:230-234`), and `isDidRefAbsolute` requires **exactly one** `#`
  with a **non-empty RFC 3986 fragment** — `*( pchar / "/" / "?" )` including
  percent escapes (`packages/did/src/did-ref.ts:11-18` →
  `packages/did/src/lib/uri.ts:5-59`). "Non-empty valid service id" is neither
  the right shape nor the right charset.

**The new validator is SEPARATE.** `AtprotoSyntax.isValidAtprotoDIDRefAbsolute`
is added alongside — **not** in place of — the permissive generic
`AtprotoSyntax.isValidDID` (`@atproto/syntax`, `syntax/src/did.ts:51`), which
`SpaceURI` and `space?authority=` continue to use. Do not mutate the generic
validator to satisfy the strict one. The reason is a matcher asymmetry worth
stating plainly: **a did-ref appearing as a REQUEST TARGET does not make it a
valid `aud=` value in a grant.** `did:example:456#service_id` is a legitimate
request audience upstream while being an illegitimate grant audience — they are
different sides of the matcher, and collapsing them into one predicate widens
whichever side is looser.

**D14. Port `@atproto/lex-resolver`. The `repo.getRecord` design is WITHDRAWN as
the wrong security model.**
*(was Q2 — implemented in §5.7.4, §5.7.5, §8.3 step 5)*
The first draft designed Phase 2's resolver around
`GET /xrpc/com.atproto.repo.getRecord`. That returns an **application
response**: it proves nothing about signed repo state, and an authorization
decision derived from it trusts whatever the queried PDS chose to say. Upstream
fetches **`com.atproto.sync.getRecord`** and verifies a repo proof
(`packages/lex/lex-resolver/src/lex-resolver.ts:449-452`).

The normative sequence, which §5.7.4 now ports rather than infers: NSID →
`NSID.authority` (`:328`, `:350-352`) → DNS `TXT _lexicon.<authority>` (`:352`,
`:506-520`) → **exactly one** `did=` line, 0 or >1 being a hard error
(`:511-519`) → `at://<did>/com.atproto.lexicon.schema/<nsid>` (`:343`) → resolve
the DID to **both** a PDS endpoint **and a signing key** (`:423-439`) →
`com.atproto.sync.getRecord` (`:449-452`) → CAR read (`:529`) → **commit DID
equality** (`:533-535`) → **commit signature verification** (`:537-541`) → **MST
membership proof** for `collection/rkey` (`:543-546`) → record `$type` equals the
collection (`:548-553`) → lexicon schema validation (`:472-477`) → **`lexicon.id`
equals `uri.rkey`** (`:480-485`). Every failure is a typed `LexResolverError`
carrying the NSID; none is a silent drop.

**Swan's hardening is kept, and sits UNDERNEATH upstream semantics.** The SSRF
guard, deadlines and body limits in `OAuthRemoteFetchPolicy` govern the
*transport*; `sync.getRecord` plus proof verification governs *trust*. Neither
substitutes for the other. Note the implementation consequence the first draft
hid: the response is a **CAR, not JSON**, so `fetchJSON(from:)` alone cannot
serve this path and a bytes-returning sibling through the same policy is
required. **Phase 2 is no longer speculative engineering** — it is a port of a
577-line reference with a published verification contract, and §8.3 step 5 gates
it on having vectors for the proof path first.

**D15. The `~` encoder asymmetry is CONFIRMED. No human decision needed; make it
a generated golden vector.**
*(was Q3 — implemented in §4.5, §7.1a, §7.2.1, §7.6 step 7)*
The inference — `~` stays raw in a positional, becomes `%7E` in a query value —
is confirmed against the reference implementation. The residual risk was never
the inference; it was the **mechanism**: hand-transcribing reference behaviour
into a Swift table is how §9.1a R3's three wrong line numbers happened. So the
ruling is procedural: build a **tiny upstream-golden corpus generator** (§7.1a),
run the pinned `packages/oauth/oauth-scopes/src` parse/format over an input list,
emit `(input, canonical|NULL)` pairs as a checked-in fixture, and assert Swift
against the fixture. §7.6 step 7 regenerates and requires a zero diff, so
silent drift from the reference is caught rather than assumed away.

**D16. There IS an upstream model for request-time enforcement. Port the
applicable route mappings; classify only Swan-specific routes as local policy.**
*(was Q4 — implemented in §6.3, the §6 route→scope mapping table, §7.2.8)*
The premise "no upstream model exists" was false, and false for the truncated-tree
reason in §2 constraint 5: `packages/pds` was never in the export. Mechanically
inventoried at the pin: **67** `authorize:` route callbacks under
`packages/pds/src`; the callback shape is
`authorize: (permissions, { params }) => permissions.assertRpc(params)`
(`pipethrough.ts:68`); `permissions.assertRpc`×15, `assertRepo`×5,
`assertIdentity`×4, `assertAccount`×2, `assertSpace`×2, `assertBlob`×1; and the
space plane funnels through one shared helper that derives `(type, authority,
skey)` from the space URI and spreads the caller's op
(`api/com/atproto/space/util.ts:87-100`).

**Consequences, all three of which the old framing blocked.** (a) Swan's stage H
stays in `SwanSpaces` for Swan's own architectural reasons — synchronous,
actor-reachable, §2 constraint 1 — and **not** for want of a model. (b) The six
`allows*` families are *not yet ported* rather than dead (D12). (c) Any route
still labelled "Swan-specific local policy" must name the positive control that
found no counterpart **in `packages/pds`** — not in `oauth-scopes`, which is the
wrong search domain and the one that produced the false absences. At least one
prior "no upstream analogue" claim is already known false: the delegation
exchange is described in prose and implemented upstream at
`api/com/atproto/space/util.ts:102-127`, including the deliberate `RepoNotFound`
non-oracle at `:118-124`. Swan's fence is a *hardening* of an upstream concept,
not a Swan invention.

**D17. Keep the bounded limits, DOCUMENT them publicly, and define RAW-INPUT and
EXPANDED-GRANT as SEPARATE budgets.**
*(was Q5 — implemented in §6.4, §6.6, §7.3 row D9; recorded in D9 above)*
The numbers stand: 1024 B per token, 64 tokens, 8192 B per raw request. Upstream
has no length limit at all (`oauth-scope.ts:5-19` is lexical only), so a
conformant client can build a legal scope Swan refuses — which is a reason to
**publish** the limits, not to remove them. They go in Swan's interoperability
documentation under `docs/`, alongside the §9-D5 divergence (Swan rejects where
upstream drops). **No invented OAuth metadata field** — that rule from §6.6 is
kept verbatim; a nonstandard key in authorization-server metadata is a worse
interop outcome than a documented limit.

The second half is the substantive one: **two budgets, separately named, even
while the numbers match.** RAW-INPUT measures what arrived on the wire and fails
at PAR as a client error. EXPANDED-GRANT measures what Swan holds after its own
transformations — `self` resolution, `expandSpaceCollections`, Phase-2 `include:`
expansion — and fails at token mint as a server-side failure. The motivating
case: an 80-byte `include:` or a bare `space:<type>` passes PAR comfortably and
then inflates past the same number under Swan's expansion. Collapsing them into
one constant makes that failure look like the client's fault and leaves no error
code to distinguish the two.

**D18. The credential sender-constraint is a SEPARATE PR from the scope-grammar
change — but MINT and CONSUME land TOGETHER inside it.**
*(was Q6 — implemented in §6.8, §8.2 separate track, §7.1 credential suite)*
Splitting it out of the grammar change is right: it touches the space-credential
plane, not the grammar, and has no ordering dependency on stages A/B/C. Shipping
only the mint is **not** right, and the first draft's "consumption is flagged,
not designed here" is withdrawn.

**Upstream's consumption model exists** — it was in `packages/pds` and
`packages/space`, neither of which the first draft could see.
`packages/pds/src/auth-verifier.ts:392` reads `const jkt = payload.cnf?.jkt`;
`:393-398` throws `AuthRequiredError('space credential is not bound to a key',
'BadJwtCnf')` when it is missing; `:400` then verifies the DPoP proof against
that `jkt`. The comment at `:390-391` states the rule this spec needs, in
upstream's own words: *"an unbound credential must never fall through as a bearer
token for the whole space."* `packages/space/src/credential.ts` mints the claim
(`:105`) and models the optional-vs-required split explicitly through a
`requireCnf` spec flag (`:154-155`).

**Correcting §6.8.3 step 5.** "Optional on decode, always populated on issue" is
acceptable as *decoding* compatibility — a credential minted by an older
implementation must still parse. It must **not** mean *authorization*
compatibility. `decodes` and `authorizes` are two different predicates: an
unbound credential is **REJECTED** at consumption, never accepted as a bearer
credential. Swan's two consumption sites are already identified —
`DurableSpaceCredentialVerifier` (`SpaceCredentialAuthority.swift:872+`) and
`AuthorizationContext.spaceCredential(SpaceGrant)` (`SwanSpaces.swift:228`) — and
§7.1's credential suite asserts the `cnf`-less denial directly.

**D19. A minimum semantic consent renderer BLOCKS unrestricted Stage C.**
*(was Q7 — implemented in §7.4 Stage 4, §8.2 Stage C, §8.3 step 4)*
Upstream ships
`packages/oauth/oauth-provider-ui/src/components/utils/scope-description.tsx`
(1287 L): it understands permission sets, renders fine-grained repo/rpc/space
permissions, suppresses the card entirely when the only scope is bare `atproto`
(`:82-85`), never drops an undescribable row (falling back to the raw NSID,
`:178`), and emits a specific warning for `identity:*` that the application
"could **permanently break**, or even **steal**, your account" (`:213-236`, copy
at `:227`), plus a universal-space warning for `type=='*' && authority=='*'`
(`:1094-1110`).

Swan need **not** port the React UI.

**The requirement is stated over what Swan ACCEPTS AND PERSISTS, not over what it
can act on.** An earlier draft said "every permission it can actually grant", and
reasoned from §7.4's observation that Swan "can place exactly two things into a
granted token — `atproto` and `space:`". That reasoning stops being true the
moment D21 lands: registration becomes lexical, admission accepts every
recognised family, and a token can then legitimately contain

```
atproto  repo:app.example.record?action=create  blob:image/*  identity:handle
```

even though no Swan route consumes any of the last three today. Whether a route
consumes a scope **today** is irrelevant to informed consent — and scoping the
renderer to consumable scopes is precisely what would let later route wiring turn
a string the user was shown opaquely into a live capability, with no fresh
consent anywhere in that sequence.

So the rule is: **a semantic description for every recognised scope Swan will
accept and persist in a token.** Concretely, before Stage C:

- bare `atproto` — no card (upstream `:82-85`)
- `space:` — one card, verbs in prose, universal warning where applicable
- `account:`, `blob:`, `identity:`, `repo:`, `rpc:` — one card each, including
  the `identity:*` theft warning, whether or not Swan routes consume them yet
- `include:` (Phase 1) — the canonical inert string below
- `transition:email`, `transition:generic`, `transition:chat.bsky` — D11 admits
  these as inert, and they were equally unrepresentable under the retired
  allow-list, so they widen with everything else. Two coherent options: reject
  them at PAR until Swan implements their semantics (reversing D11), or describe
  them as recognised compatibility scopes that confer no capability in Swan.
  **Decision: the latter**, keeping D11 — with the same "recognised, grants
  nothing here" treatment the Phase-1 `include:` string gets. What is not
  acceptable is accepting them and rendering them as raw bytes.

It must also carry the explicit Phase-1 `include:`
string, *"Requested permission set `<nsid>`. Swan does not currently grant
capabilities derived from this set"*, which says more than upstream's bare-NSID
fallback because Swan, unlike upstream, grants nothing from it. Raw scope text stays, as
advanced detail below the semantic cards. Both consent renderers are in scope
(`SwanOAuthAuthorizationServerHTTP.swift:1170-1172` and
`SwanLocalhostOAuthHTTP.swift:819-821`), sharing one copy of the wording.

**The escape hatch is narrow and named.** If bulleted.app must be tested before
the renderer lands, **feature-flag remote issuance narrowly** — one client ID,
off by default — rather than globally opening the gate with raw-only consent.
Stage C without the renderer is not "Stage C, early"; it is a different and worse
change.

**D20. NO canonical fallback in this rollout — and FIRST fix the D7/D8
contradiction that makes refresh unworkable.**
*(was Q8 — implemented in D7 and D8 above, §6.4, §6.7, §7.5, §8.3 step 3)*

**The contradiction, verified on both sides.** D7 said the refresh check
"compares a *stored* string against a *requested* one … it stays raw-string
equality", and the Swan code it points at is
`DurableOAuthTokenService.swift:770` — `requestedScopes.map({ $0 ==
family.binding.scopes }) ?? true`, inside the guard at `:768-772`, throwing
`OAuthControlStoreError.bindingMismatch`. D8 changed `binding.scopes` to hold the
**resolved** grant, with the request bytes moved to `scopes_requested` (§6.7).
For `authority=self` — the upstream default (`space-permission.ts:183`) and after
§6.4 nearly every grant Swan issues — requested and resolved **deliberately
differ**. A client re-presenting its original requested scope on refresh would
therefore compare raw bytes against a value it has never seen and **always
fail**. As specified, refresh was broken for essentially every grant.

**The fix changes the OPERAND, not the comparison.** Raw-string equality is
retained; the baseline becomes the **REQUESTED** set:

```
requestedScopes == (family.scopes_requested ?? family.scopes)
```

The `??` is §6.7's NULL rule — `NULL` means "requested == stored", not
"unknown" — which makes the fallback **total**: pre-migration rows compare
exactly as they do today, so §8.1's "old tokens are not re-minted" survives. That
rule is now load-bearing for authorization, not only for audit, and §6.7's
migration note says to review the column accordingly.

**No canonical fallback in this rollout.** Trying canonical equality after raw
equality would be sound in principle but is deliberately deferred (D7). It is
emphatically **not** the fix for refresh: a resolved DID and the literal `self`
are not canonically equal, so the fallback would not have rescued a single
`self`-bearing grant. Revisit after Stage B's shadow log shows a week of
formatter agreement — a different question, about a different failure.

**The test changes too.** §7.5's old "non-canonical parameter order still
refreshes" vector is too weak to fail on this defect and is replaced by: mint a
scope that defaults to or contains `self`; assert stored `scopes_requested !=
scopes`; refresh with the **ORIGINAL requested** bytes; assert success. Red
before the operand fix, green after. §8.3 step 3 requires the same shape for the
manual production check, because a check run against a fully-specified
`authority=did:plc:…` grant cannot see the defect at all.

**D21. `isIssuableQualified` is RETIRED as a semantic client-metadata gate, and
is NOT re-expressed over the new parser.**
*(was Q9 — implemented in §6.2, §6.3 stages A′ and D, §7.4 Stage 2, §8.2 Stage C)*
The question asked which issuance shapes a remote HTTPS client may register — the
full upstream accept set, or `isIssuableQualified`'s narrower truth table
re-expressed over a parsed permission. The answer is **neither**. Upstream
separates the layers further than "pick an accept set":
`OAuthClientMetadata.scope` is validated **only** by `oauthScopeSchema`
(`packages/oauth/oauth-types/src/oauth-client-metadata.ts:36` →
`oauth-scope.ts:17-19`), which is `OAUTH_SCOPE_REGEXP` (`:5-6`) — RFC OAuth
scope-token lexical syntax, space-delimited, excluding `"` and `\`, with no
length cap and **no dictionary of known permission families at all**. Upstream
never asks at registration whether a token names a known family.

Swan's four boundaries, stated once so nothing re-grows in the wrong layer:

| layer | validates | does NOT validate |
|---|---|---|
| **client metadata (registration)** | a valid RFC scope-token list + Swan's documented byte/count budgets (§9-D17, raw-input) | anything semantic. **Registration grants nothing.** Unknown and future scope names may be declared safely |
| **PAR / authorize (admission)** | requested ⊆ declared; each requested scope parses under Swan's atproto parser and passes admission; malformed or unknown ⇒ **`invalid_scope`** (Swan deliberately rejects where upstream silently drops, `request-manager.ts:179-185`, §9-D5); base-scope rule; Phase-1 `include:` policy | matching, resolution, expansion |
| **token mint** | expand/materialise where implemented, resolve `self` (§6.4), preserve requested bytes separately (§6.7, §9-D20), enforce the expanded-grant budget | client identity |
| **resource plane** | the exact semantic matcher, including Swan's provenance fences for delegation and listing | anything about the client's registration |

**The dangers that once justified the gate now live in the right layer**, which
is why deleting it does not widen anything: `hasResourceScope` stays
atproto-or-space (it uses the structural `isQualified`, not
`isIssuableQualified` — `DurableOAuthTokenService.swift:1246-1249`), and the
delegation fence (`isExactReadOnlyDelegationGrant`, §5.6.3) plus the listing
fence (`allowsSpaceListing`, §6.1) are what stop a defaulted `self`, a `skey=*`,
or a defaulted action set amplifying into a delegation exchange or an aggregate
listing. Those fences are load-bearing **because** the gate is gone; do not
re-litigate them as redundant. Any invariant currently resting on
`isIssuableQualified` must be re-homed to the admission layer or to
`SpaceRecordAction` before the function is deleted, not after.

**D22. Lexicon authorities accept both atproto-blessed DID methods; PLC-only is
operator policy, not protocol.** *(implemented in §5.7.4)*

An earlier revision restricted Phase-2 lexicon authorities to `did:plc:`, on the
claim that a `did:web:` DID document "is fetched from the same origin that serves
the record". **That claim is false as stated and the restriction is withdrawn.**
The PDS comes from the document's own `#atproto_pds` service, and `extractPdsUrl`
is `new URL(service.serviceEndpoint)` (`packages/did/src/atproto.ts:145-160`);
`isAtprotoPersonalDataServerService` (`:174-186`) constrains the service *id* to
`<did>#atproto_pds` and the endpoint to being parseable, and nothing binds its
host to the DID's host. A `did:web:identity.example.com` whose PDS is
`https://pds.some-other-host.net` gets exactly the independence the proof chain
exists for.

Two further reasons the restriction was wrong:

- **It did not buy what it appeared to.** The first trust decision in the
  sequence is DNS (`_lexicon.<authority>` → `did=`). An attacker holding the
  authority's DNS repoints it at a `did:plc:` they control. PLC-only defends one
  narrow case — the `did:web` HTTPS origin compromised while its DNS stays
  honest — and nothing about authority compromise generally.
- **It contradicted this document.** §5.7.4 said PLC-only while the Phase-2
  vector table recorded a `did:web` lexicon authority as resolving.

Default: `allowedLexiconAuthorityDIDMethods = [.plc, .web]`, matching upstream
(`create-did-resolver.ts:21-35`, typed over `AtprotoIdentityDidMethods`). A
deployment wanting the stronger failure-domain separation sets `[.plc]`. Because
interop with the upstream permission model is the point of this work, a
unilateral method restriction would be an interop divergence, and any divergence
belongs here in §9 rather than buried in a subsection.

**D23. Provenance is DURABLE, and is persisted beside the effective grant. This
is a blocker for implementation.** *(new; §4.6, §6.4, §6.7, §7.5)*

§4.6 introduced `ScopeParameterValues.Provenance` (`.stated` / `.defaulted`)
because the two Swan hardening fences depend on it: `isExactReadOnlyDelegationGrant`
(§5.6.3) and `allowsSpaceListing` (§6.1) require certain parameters to have been
**literally written by the client**, not defaulted into place by the broadened
upstream grammar.

**The bits were not durable, and the fences read the wrong side of the boundary.**
Provenance lived only in `ScopeParameterValues`; token families persist *resolved*
strings; and `SwanScopePermissions` is reconstructed from those resolved strings
alone, with `scopes_requested` deliberately not read by the matcher. That leaves
two symmetric failures, and the second was found by running upstream's own
serialiser (`Scripts/upstream-scope-goldens`, fixture
`Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json`):

| direction | mechanism | consequence |
|---|---|---|
| **provenance invented** | `space:x.y.z?skey=*&action=read` has `authority` **defaulted**, so the delegation fence correctly refuses. Mint resolves `self` → the subject DID and persists `space:x.y.z?authority=did:plc:USER&skey=*&action=read`. Re-parsed at request time, all three values are literal | the delegation fence **flips false → true**: exactly the amplification the provenance machinery was added to prevent |
| **provenance destroyed** | canonical serialisation deletes values equal to their defaults. The golden corpus confirms `space:g?skey=*` canonicalises to bare `space:g` and `?authority=self` likewise | a fence requiring a **literal** `skey=*` can never fire again, silently disabling the listing fence |

**Rule: provenance is never reconstructed from a serialised scope string.** A
canonical string is a lossy projection in both directions; the only correct source
is the parse that produced it, carried forward unchanged.

**Chosen design — persist provenance beside the effective grant.** The token
family stores, alongside its effective scope list, a small per-scope record of
which parameter keys were stated. `SwanScopePermissions` is reconstructed from
*both*, and the two fences consult the stored bits rather than re-deriving them.
`withResolvedAuthority` takes provenance as an explicit argument and preserves it:
**resolving `self` changes the value, never the statedness.** Its earlier
pseudocode built a fresh `SpacePermission` with no provenance parameter at all,
which is where the invention entered.

Two alternatives were considered and rejected:

- *Use `scopes_requested` as the provenance source for the two fences, leaving
  ordinary matching on the resolved scopes.* Cheaper in schema, but it needs a
  separate rule for include-derived grants in Phase 2 — a grant with no requested
  counterpart — and it splits one question across two columns.
- *Do not persist resolved `self` at all; keep the original bytes and resolve
  against the bound subject at match time* (the Rust model). Genuinely elegant and
  provenance-preserving, but it reverses D8 and upstream's mint-time
  representation, which is a larger change than this rollout should carry. Worth
  revisiting if D8 is ever reopened.

**Required test, and it must not stop at the matcher.** §7.5 gains an end-to-end
sequence over the exact example above: request `space:x.y.z?skey=*&action=read`
→ **mint** → **persist** → **reload from storage** → call `getDelegationToken`.
The assertion is that the delegation fence still refuses, because `authority` was
never stated. A parse → matcher test passes even with the defect present; only
mint → persist → reload exercises the boundary where provenance was being lost.
Add the mirror case for the listing fence: a stated `skey=*` must survive
canonicalisation and still satisfy `allowsSpaceListing`.

### 9.1a Findings rejected

Two adversarial reviews (completeness lens, correctness lens) were run against
the first draft of this document. Nearly all findings were verified against
primary source and are now applied above. The following were **not** applied,
because verification showed them wrong or over-stated. They are recorded rather
than silently dropped, so a later reader does not re-raise them.

**R1 — "A scope-less PAR from bulleted.app mints its entire registered grant"
(completeness F7). REJECTED as stated; the underlying fact is real and is now
§6.5.9(b).** The finding is right that
`Sources/SwanHTTP/SwanOAuthPARHTTP.swift:155` reads
`scopes: form.scopes ?? metadata.scopes` and that `localhostRequestedScopes`
returns `nil` for an absent `scope` (`OAuthClientMetadata.swift:454`), so an
omitted `scope` is silently replaced by the full registered set. It is wrong that
bulleted.app can reach it. That file is the **localhost bridge**: its own type is
`SwanLocalhostPARHTTP` (`:12`), it is registered by
`registerLocalhostPAREndpoint` (`:52`), and its client metadata comes from
`OAuthClientMetadata.localhostDevelopmentMetadata` (`:149`). The remote AS PAR
route is `SwanOAuthAuthorizationServerHTTP.swift:173`, which tokenizes at `:828`
with `oauthServerScopes(fields["scope"] ?? "")`; that function's
`guard !values.isEmpty` (`:1061`) rejects an absent `scope` as
`OAuthServerRequestError.malformed`. A remote HTTPS client therefore cannot
reach the substitution, and Stage C does not change that. The defect is fixed
anyway — it is a silent widening on a live route — but the escalation framing
was not reproducible.

**R2 — "Both scalar-arity include fixtures expand into a live `repo:` write
grant" (completeness F1, gate 3). ACCEPTED for one fixture, REJECTED for the
other.** The mechanism is real and §5.7.3 now ports `getSingle`/`getMulti`'s
`null` tri-state in full. But only `include-scope.test.ts:494-508` — the repo
entry whose `collection` is the scalar `'com.example.calendar.event'` — is a
genuine widening: stringified into a one-element array it is a *valid* NSID and
would expand into a create/update/delete grant where upstream yields `[]`. The
companion at `:510-524` (`action: 'all'`) is **not**: `'all'` is not a member of
`RepoAction`, so `ScopeParameter.validate` rejects it and the entry is dropped
regardless of arity handling. One exploitable fixture is enough to justify the
fix; two was not accurate.

**R3 — the correctness review's own line numbers for the `include-scope.test.ts`
reject list. REJECTED; a third set of numbers is used.** The first draft cited
`:62-89`; the review corrected it to `:64-92`. Both are wrong. Read directly:
`for (const invalid of [` is at `:65`, the first entry `''` at `:66`, the last
entry at `:87`, and the closing `]) {` at `:88` — so the array spans `:66-87`
with 18 entries, `:86` and `:87` being duplicates, giving **17 distinct**. That
matches the "port all 17" count in §5.7.1, which was right for the wrong reason.
The review's other correction in the same finding — that
`include:com.example.baz?aud=did:web:example.com` is at `:85`, not `:82` — is
**accepted** and applied in §5.7.1 and §9-D13; `:81` is `'include:nsid'` and
`:82` is blank.

**A note on the limits of this list, which the reviews could not have known.**
Both adversarial reviews ran against the truncated reference export (§2
constraint 5), so neither could raise a finding that depended on a package
outside it. Two of the largest defects in the first draft were therefore invisible
to them and are recorded here rather than left to look like oversights:

- **Q6's premise was falsified by a package the reviews could not see.** "Nothing
  verifies `cnf`" is true of Swan and false of upstream:
  `packages/pds/src/auth-verifier.ts:392-400` verifies it and rejects an unbound
  credential outright, and `packages/space/src/credential.ts:154-155` models the
  optional-vs-required split with a `requireCnf` flag. What was framed as an open
  design question was a Swan gap with a ready fix (§9-D18).
- **The D7/D8 refresh contradiction was found by neither review.** It is the
  largest correctness defect found in this pass — as specified, refresh failed for
  every `self`-bearing grant — and it required reading D7, D8, §6.4, §6.7 and
  `DurableOAuthTokenService.swift:768-772` together, which is a cross-section read
  neither lens performed. It is recorded as a decision (§9-D20), not merely as an
  edit, because the fix changes what the persistence layer is *for*.

### 9.2 Questions closed, and what genuinely remains open

**All nine questions this document previously carried as "needing a human
ruling" are RULED.** They are recorded as decisions in §9.1, not restated as
questions here. Leaving any of them phrased as "ruling needed" would reopen a
settled decision, so this section is a **pointer table** for a reader arriving
from the earlier version, plus the short list of things that are actually still
open.

| was | subject | ruling now lives in | one-line answer |
|---|---|---|---|
| Q1 | `isAtprotoDidRefAbsolute` "reconstructed, not sourced" | **§9-D13**, implemented in §4.1 | Port `@atproto/did` exactly (`packages/did/src/atproto.ts:230-234`). Reconstruction rejected: too permissive on methods (`plc`+`web` only, `atproto.ts:19`), wrong on fragment grammar (`did-ref.ts:11-18`). Add a **separate** `isValidAtprotoDIDRefAbsolute`; do not mutate the generic DID validator |
| Q2 | `@atproto/lex-resolver` "absent"; Phase 2 has "no reference implementation to port" | **§9-D14**, implemented in §5.7.4, §8.3 step 5 | Present — 577 lines. Port it. The `repo.getRecord` design is **withdrawn** as the wrong security model; use `com.atproto.sync.getRecord` plus commit/MST proof verification. Swan's SSRF/deadline/body hardening sits underneath upstream semantics |
| Q3 | the `~` encoder asymmetry "inferred, not pinned" | **§9-D15**, implemented in §7.1a, §7.6 step 7 | Confirmed; no human decision needed. Pin it with a **generated** golden corpus, not a hand-transcribed vector |
| Q4 | "no upstream model for request-time enforcement" | **§9-D16**, implemented in §6.3, §7.2.8 | Premise false. 67 `authorize:` callbacks in `packages/pds/src`; inventory the `assert*` sites, port the applicable mappings, and classify **only** genuinely counterpart-less routes as local policy — each with a positive control run against `packages/pds` |
| Q5 | are the byte caps documented publicly or left operational? | **§9-D17**, implemented in §6.4, §6.6 | Documented publicly in `docs/`; **no invented OAuth metadata field**. Additionally: RAW-INPUT and EXPANDED-GRANT are **separate budgets** with separate enforcement points and error codes, even where the numbers coincide |
| Q6 | `cnf` consumption — same change or separate? | **§9-D18**, implemented in §6.8, §7.1 | Separate PR from the scope grammar, but **mint and consume land together** inside it. Upstream's consumption model exists (`auth-verifier.ts:392-400`); an unbound credential is **rejected**, never a bearer fall-through |
| Q7 | is a human-readable consent renderer a Stage-C blocker or a follow-up? | **§9-D19**, implemented in §7.4 Stage 4, §8.2 | **Blocker** for unrestricted Stage C. Semantic descriptions for every scope Swan **accepts and persists** — not merely every scope it can act on (§9-D19) — including the six families D21 newly admits and the three inert `transition:*` scopes, plus the explicit unresolved-`include:` string. Narrow per-client feature flag is the only earlier path |
| Q8 | canonical-equality fallback on refresh | **§9-D20**, implemented in D7/D8, §7.5, §8.3 step 3 | **No canonical fallback in this rollout** — and first fix the D7/D8 contradiction: the refresh baseline is `family.scopes_requested ?? family.scopes`, never the resolved `binding.scopes` |
| Q9 | which issuance shapes may a remote client register? | **§9-D21**, implemented in §6.2, §6.3, §7.4 Stage 2, §8.2 | **Neither** option. `isIssuableQualified` is **retired**, not re-expressed. Registration is lexical + budget only and grants nothing; the semantic work moves to PAR/authorize |

**Reading an old cross-reference.** Elsewhere in this document some passages
still cite a ruling as "§9-Qn ruling", meaning *the ruling on what used to be
Qn*. Those resolve through the table above: **Q1→D13, Q2→D14, Q3→D15, Q4→D16,
Q5→D17, Q6→D18, Q7→D19, Q8→D20, Q9→D21.** No §9-Qn reference anywhere in this
document points at an open question; every one points at a decision in §9.1.
Prefer the D-number when writing new text.

**The methodological note that outlives all nine.** Q1, Q2, Q4 and Q6 existed
only because the reference tree the first draft read contained three subtrees,
and its positive controls were run inside that constructed directory (§2
constraint 5). Four of nine "open questions" were artefacts of an unverified
absence claim, and one of them (Q2) had led the spec to design the wrong security
model. The durable rule: **before writing that something is absent, name the
positive control that proves the search domain would have contained it.**

---

#### Still open — and only these

These are genuinely unresolved. They are **not** blockers for the rollout in §8
unless marked otherwise; each says what would close it.

**O1. The exact expanded-grant budget numbers, once expansion exists.** §9-D17
fixes the *structure* — two budgets, separately named — and starts both at the
raw-input numbers (1024 B/token, 64 tokens, 8192 B/set). What the expanded-grant
numbers *should* be cannot be known until Phase 2's `include:` expansion and
`expandSpaceCollections` are running against real permission sets, since the
question is empirical: how far does a realistic scope actually inflate?
**Closes when** Phase 2 has expansion telemetry. **Not a blocker** — the
structure ships now and only a constant changes later.

**O2. Which `packages/pds` route mappings are in the FIRST port, and which
follow.** §9-D16 settles that the mappings are ported rather than invented, and
§7.2.8 gives each family a vector. It does not schedule them, because Swan wires
no `repo:`/`rpc:`/`blob:`/`identity:`/`account:` routes today and the sequencing
depends on which Swan surface adopts a family first. **Closes when** the first
non-`space:` route is wired; that PR picks up the mapping table row and its
vector. **Not a blocker** for stages A/B/C.

**O3. Whether the Phase-2 resolver's proof verification can meet Swan's
concurrency shape without a new dependency.** §9-D14 requires CAR parsing,
commit-signature verification and an MST membership walk. §2 constraint 4 forbids
new packages, and §2 constraint 1 keeps the request-time path synchronous and
non-isolated. The resolver runs at mint, never at request time (§3, §6.9), so the
isolation constraint is satisfiable — but whether the CBOR/CAR and signature work
is achievable with `Crypto` alone, inside the existing targets, is unverified
until someone attempts it. **Closes when** a spike lands the CAR reader.
**Blocker for Phase 2 only**, and §8.3 step 5 already gates Phase 2 on having the
proof-path vectors first.

**O4. Whether Swan's `identity:`-class warning ever has a family to attach to.**
§9-D19 requires the wording to be written now, so it activates the day such a
family exists. Whether Swan ever grants `identity:` or `account:` permissions is
a product question outside this spec. **Closes** by decision elsewhere; the
consent string is written either way, so nothing here blocks. Note that D19's
corrected principle — describe every scope Swan *accepts and persists*, not every
scope it can act on — already requires the `identity:` card before Stage C, so
this question is now about routes, not about consent.

**O5. Latent activation: a scope that was inert when consent was given must not
become effective without fresh authorization. BLOCKER FOR PHASE 2.**

Phase 1 accepts an `include:` scope, shows it as requested-but-not-granted,
persists it verbatim, and grants nothing from it. §5.7 then states that Phase 2
begins expanding those same persisted scopes. Read across time, that sequence
grants capability that no user ever approved:

1. At Phase-1 consent the permission set is **unresolved**, so Swan cannot say
   what it contains. The user is shown, honestly, *"Requested permission set
   `<nsid>`. Swan does not currently grant capabilities derived from this set."*
2. Phase 2 ships. The same opaque identifier now expands into concrete `repo:`,
   `rpc:` or `space:` authority — **inside an existing token family**, with no
   consent screen anywhere in the sequence, and the permission set's contents are
   controlled by its author, who may change them after step 1.

Upstream's behaviour, which §9-D5 rejects on other grounds, has the safer
migration property here: it narrows unsupported permissions away and the client
must re-authenticate once support lands.

**Rule, to be stated now and enforced in Phase 2:** *a scope that was inert at the
time of consent must not become effective in an existing token family merely
because the server later learned how to interpret it.* Phase-1 `include:` families
require fresh authorization before expansion takes effect.

The mechanism is deliberately left open — a family generation marker, an
`include_materialization_version` compared at match time, or forcing
re-authorization on families carrying an unexpanded `include:` are all workable,
and the choice depends on schema decisions Phase 2 will make anyway. What is
**not** open is whether the rule applies.

The same principle covers `transition:*`, which D11 admits as inert and §9-D19
requires be described as such: if Swan later implements their semantics, existing
families holding them do not silently gain capability. For the six directly
granted families, no rule is needed — the complete Stage-C renderer means the user
saw and approved exactly what the token holds.

Anything else a reader is tempted to reopen should be checked against §9.1
D1-D23 first. If a question is not in this list, it has been ruled.

---

## Erratum 01 (2026-08-15) — §6.1 listing fence amended

**Ruled by Josh ("Amend"), implemented in `allowsSpaceListing`
(`ScopePermissions.swift`) the same day.**

The original fence required a grant with stated keys exactly
`{authority, skey, action}`, literal `skey=*`, action exactly `[read]`, and no
stated `collection`/`manage`. Field evidence (bulleted.app against swan.place,
2026-08-14): no real client can produce that shape. The `spaceAccess`
permission-set expansion states `collection` and carries four actions; the
direct scope upstream clients mint uses `read_self`, which upstream accepts
for every `space.get*/list*` route (`space/util.ts:109-127`,
`assertSpaceRead`). The fence as sealed made `listSpaces` unreachable for
every conformant client.

**Amended contract:** a grant lists when (1) its `action` list was **stated**
(durable provenance, §9-D23 — this is the surviving §9-D21 witness: `action`
defaults to a list containing `read`, so a bare `space:<type>` still never
lists), (2) the stated actions include `read` or `read_self` (the route
self-scopes — `hostedSpaces` takes the token's own subject — so `read_self`
is sufficient for an inventory that is always OF SELF), and (3) type and
authority cover the request under the unchanged `aggregateDimension` rule
(a wildcard request still requires a wildcard grant; the route still refuses
to fetch broadly and censor rows).

Dropped: the stated-`skey` + literal-`skey=*` requirement (no upstream client
states `skey`; §9-D23 canonicalisation had already shown the literal test was
fragile), the exact-`[read]` action list, and the `collection`/`manage`
disqualifiers (a `manage`-only grant still fails the stated-`action`
witness). `spaceListingScopeNeeded` (logs only) now renders
`space:<type>?authority=<a>&action=read`.

Pinned by `ScopePermissionsFenceTests`: the amended acceptances (stated
`read` without stated `skey`; stated `read_self`; the verbatim bulleted.app
`spaceAccess` expansion shape) and the surviving refusals (bare grant;
unstated-action `manage` grant; wildcard request against concrete grant;
cross-authority; cross-type).

## Erratum 02 (2026-08-15) — §5.6.3 delegation fence amended

Ruled by Josh (option 2 of the presented three). The sealed
`isExactReadOnlyDelegationGrant` exchanged only a grant that was EXACTLY
`space:<type>?authority=X&skey=Y&action=read` — action stated and exactly
`[read]`, no collection, no manage, authority and skey both stated. No real
client's registered scopes produce that shape: bulleted.app's `spaceAccess`
expansion (stated authority/collection/action, four-action list, unstated
skey) failed four clauses, so every conformant `getDelegationToken` call
401'd and the entire space data plane was unreachable.

Renamed `isExchangeableDelegationGrant`; the amended contract:

1. `action` is STATED and CONTAINS `read` (upstream's read arm,
   `space-permission.ts:104-107`, plus Swan's surviving §9-D21 bare-grant
   witness: a defaulted action list contains `read` and still refuses).
   `read_self` alone remains non-exchangeable (§7.2 D7). Extra write verbs
   beside `read` are not an escalation for a credential that only reads —
   the caller already holds them.
2. The grant's space TYPE is concrete — the option-2 hardening Swan KEEPS
   over upstream. A wildcard-type grant never mints, including the sealed
   era's previously-exchangeable `space:*?authority=*&skey=*&action=read`
   (a deliberate tightening on that one axis, pinned in
   `SpaceDelegationMintingHTTPTests`).
3. Tuple coverage (type/authority/skey vs the target) is unchanged —
   `matches`, §5.6.3 steps 1-3.

**The knowingly conceded widening, recorded so it is never re-read as an
oversight:** a collection-qualified read grant now exchanges for a
whole-space read credential. The original hardening's analysis was CORRECT
— this is privilege amplification, and the sealed fence really did prevent
it. What changed is the recognition that the protocol's credential model
cannot represent a collection restriction: the space credential is not
collection-aware, so the conversion is inherently lossy, and every upstream
implementation performs it. A PDS that refuses it does not interoperate.
The satisfactory long-term fix is a delegated credential that carries the
originating grant's collection set (or is otherwise server-bound to it) —
at which point this concession should be revisited — not a stricter
predicate at this layer.

Dropped clauses: exact-`[read]`, no-collection, no-manage,
stated-authority/skey. Flipped tests are annotated in place
(`ScopePermissionsFenceTests`, `ScopeProvenanceDurabilityTests`,
`RefreshScopeRederivationTests`, `SpaceDelegationMintingHTTPTests`,
`RemoteClientPermissionedScopeE2ETests` stage 6.6 kept as a refusal).

## Erratum 03 (2026-08-15) — single-blob reads and the notify service contract

Ruled by Josh ("fix both, implement full robust tests and new machinery
for 2"). Two seams, one release.

### 1. §6.5.5's aggregate classification no longer covers single-blob reads

`getBlob` reached the repository facade with no record URI, so
`SpaceScopeTarget.record` derived `aggregate: true` and the §6.5.5 gate
refused every collection-qualified grant — bulleted.app's six-collection
grant 401'd on every blob it had itself just uploaded. Post-Erratum-02 the
same grant exchanges for a whole-space credential that reads the identical
bytes through the credential arm, so the refusal protected nothing while
breaking upstream's collection-independent read path.

`SpaceScopeTarget.blobRead` is the ONE deliberate `aggregate: false` +
`collection: nil` construction (its doc comment carries the boundary), and
`SpaceAuthorizationPolicy.requireBlobRead` applies it only on the
`accountOAuth` arm — credentials, self-reads, delegation/public refusals,
and cross-account/cross-verb refusals are unchanged and pinned
(`SpaceScopeTargetTests`). The CAR snapshot and every set-answering
surface KEEP the aggregate rule: they really do span collections.

### 2. `registerNotify` adopts the `service` subscriber contract

The reference evolved the lexicon: the subscriber names a `service`
identifier (`did[#fragment]`, resolved through its DID document to both the
delivery endpoint and the verifiable JWT audience); `endpoint` is the
pre-lexicon legacy, and `service` decides when both are sent. Swan's
exact-key parser refused any body carrying `service` (defect class
instance #7), which starved bulleted.app's events pipeline and made saved
records look unsaved.

Adopted, with new machinery end to end:

- **Resolution**: `SwanServiceEndpointResolver.endpoint(serviceIdentifier:)`
  — fragment form unchanged; a fragment-less identifier resolves only a
  single-service document (refuse-ambiguity kept over the reference's
  first-entry rule). Failures collapse to the lexicon's one error,
  `ServiceNotResolvable` (400), including a server with no resolver.
- **Storage**: `service_did` on the registrations table (nullable ALTER
  migration; legacy rows stay endpoint-only local discovery state and are
  NEVER dynamic destinations).
- **Fanout**: write intents enqueue for service-named registrations from
  both write paths — a member's announced write and a local authority
  apply — in the same transaction as the write. The old refusal reasoned
  from the pinned TypeScript PDS receiver (`iss == repo`); a registered
  subscriber is a service that named itself in a DID document, and the
  reference contract for it is authority-signed (`iss = space authority`,
  `aud = subscriber service`), which Swan's own `notifyWrite` receiver
  posture is unchanged by.
- **Delivery**: a service-named registration is its own destination —
  audience from the stored identity, endpoint from registration-time
  resolution — re-checked active at send. Egress: the peer-pinned
  transport gains `allowsDynamicPeerSelection`, connecting an UNPINNED
  endpoint to a member of the poster's policy-approved DNS answers
  (literal IP chosen before the socket opens, no second lookup, TLS still
  verifies the hostname; configured pins keep priority and a failed pin
  never falls back). Operator pins are therefore no longer required to
  enable delivery.

Pinned by `SwanServiceEndpointResolverTests`,
`SpaceNotificationHTTPTests` (decode shapes, resolution, refusals,
no-resolver, legacy regression, dynamic delivery seam),
`SpaceNotificationSQLiteTests` (fanout enqueue/expiry/accessor), and
`NIOPeerPinnedOAuthPostTransportTests` (dynamic selection end-to-end over
local TLS, pin priority, no-fallback).

Not adopted (recorded, not forgotten): `unregisterNotify` — Swan still
does not serve it; withdrawal is expiry or replacement. Same-host
different-account member writes still do not fan out (pre-existing
account-isolation gap, unreachable for single-user spaces).
