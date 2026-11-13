/// Phase 2 — expansion. Pure: given an already-resolved permission-set document,
/// turn `include:<nsid>` into the concrete `repo:` / `rpc:` / `space:` grants it
/// stands for. **Zero network, zero I/O.** Obtaining the document — and proving
/// it belongs to the authority's signed repo — is `SwanLexiconResolving` (§5.7.4,
/// lane P2-E), which lives in `SwanOAuth` because `SwanCore` imports no network
/// layer (§3's module fence).
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.7.3.
/// Upstream: `oauth-scopes/scopes/include-scope.ts:53-173`.

// MARK: - IncludedPermission

/// The concrete, matchable result of expanding an include.
public enum IncludedPermission: Sendable, Equatable {
    case repo(RepoPermission)
    case rpc(RpcPermission)
    case space(SpacePermission)
    /// There is deliberately NO `.include` case: a permission set cannot contain
    /// another include (`include-scope.ts:76-108` has no such branch — its
    /// dispatch is exactly `repo` / `space` / `rpc` / `return null`), so
    /// expansion is structurally depth-1 and needs no cycle detection. Positive
    /// control: grepped `include-scope.ts` and `lexicon-manager.ts` for
    /// "recursion" / "depth" — zero hits.
}

extension IncludedPermission {
    /// Gate 2 of `expand`. `nil` on ANY parse failure: a malformed
    /// `collection` / `action` / `lxm` drops the entry, it does not throw
    /// (`include-scope.ts:60-61`, which reads a `null` return).
    init?(_ syntax: LexPermissionSyntax) {
        do {
            switch syntax.prefix {
            case RepoPermission.prefix:
                self = .repo(try RepoPermission(parameters: RepoPermission.schema.parse(syntax)))
            case RpcPermission.prefix:
                self = .rpc(try RpcPermission(parameters: RpcPermission.schema.parse(syntax)))
            case SpacePermission.prefix:
                self = .space(try SpacePermission(parameters: SpacePermission.schema.parse(syntax)))
            default:
                // Unreachable: `lexSyntax(for:)` is the only producer and it
                // admits exactly these three prefixes. Kept as a total switch
                // rather than a `fatalError` — this value is derived from an
                // unvalidated document.
                return nil
            }
        } catch {
            return nil
        }
    }

    /// The canonical wire form of this grant, i.e. upstream's `toScopes`
    /// (`include-scope.ts:43-47`).
    public func canonicalScopeString() throws(ScopeParseError) -> String {
        switch self {
        case let .repo(permission): try permission.canonicalScopeString()
        case let .rpc(permission): try permission.canonicalScopeString()
        case let .space(permission): try permission.canonicalScopeString()
        }
    }
}

// MARK: - Expansion

extension IncludeScope {
    /// `include-scope.ts:53-67`. Three gates per entry, all silent-skip on
    /// failure — an unusable entry never fails the whole set.
    ///
    /// **The empty result is not an error** (§5.7.5): an `include:` every one of
    /// whose entries was dropped contributes nothing, and the caller must both
    /// log at `.warn` AND render §5.7.2's canonical consent string naming the
    /// NSID. A `.warn` reaches an operator; the person authorizing never sees it.
    ///
    /// This function is reached only with a document whose proof chain already
    /// verified. A proof failure is NEVER a drop (§5.7.5) — it terminates
    /// resolution before expansion is called at all, because otherwise an
    /// attacker-controlled PDS would choose which of a user's permissions
    /// survive by selectively corrupting proofs.
    public func expand(_ set: LexiconPermissionSet) -> [IncludedPermission] {
        set.permissions.compactMap { entry in
            // Gate 1: only repo / space / rpc survive. blob, account, identity
            // and anything unknown are dropped (include-scope.ts:76-108).
            guard let syntax = lexSyntax(for: entry) else { return nil }
            // Gate 2: the entry must parse as its family.
            guard let permission = IncludedPermission(syntax) else { return nil }
            // Gate 3: namespace authority.
            guard isAllowed(permission) else { return nil }
            return permission
        }
    }

    /// `include-scope.ts:43-47` — expansion rendered as canonical scope strings,
    /// which is the form PAR's consent payload and the token-mint rewrite both
    /// need.
    public func expandToScopeStrings(
        _ set: LexiconPermissionSet
    ) throws(ScopeParseError) -> [String] {
        var strings: [String] = []
        strings.reserveCapacity(set.permissions.count)
        for permission in expand(set) {
            strings.append(try permission.canonicalScopeString())
        }
        return strings
    }

    /// `include-scope.ts:69-109`, the `rpc` special cases:
    ///  - an entry naming a concrete `aud` (anything but `*`/absent) is rejected
    ///    outright (`:89-91`);
    ///  - an entry with `inheritAud: true`, no `aud`, and a non-nil `self.aud`
    ///    has this include's own `?aud=` spliced in (`:96-103`), and
    ///    `inheritAud` is REMOVED (`:101`) — left in place it is an unknown key
    ///    and §4.6 drops the entry.
    ///
    /// Returns the ADAPTER, not a scope string.
    ///
    /// **The splice requires a CONCRETE audience, and that is a deliberate
    /// fail-closed narrowing.** Upstream's `this.aud` is typed
    /// `AtprotoDidRefAbsolute | undefined` — its include parser validates `aud`
    /// with `isAtprotoDidRefAbsolute` alone (`include-scope.ts:183-187`), so
    /// `include:<nsid>?aud=*` never parses and `this.aud === '*'` is
    /// unreachable. Swan's §5.7.1 schema additionally accepts `"*"`, so the
    /// state IS reachable here; splicing it would mint `rpc:<lxm>?aud=*` — a
    /// wildcard-audience grant — from an include upstream rejects outright.
    /// `.any` therefore does not splice, and the entry drops on `inheritAud`
    /// being an unknown key, matching upstream's reachable behaviour exactly.
    /// The §5.7.1 divergence itself is reported, not patched here: it is
    /// Phase-1 grammar and not this lane's file.
    func lexSyntax(for entry: LexiconPermission) -> LexPermissionSyntax? {
        switch entry.resource {
        case RepoPermission.prefix, SpacePermission.prefix:
            // A space entry may not use a wildcard space type, but that is gate
            // 3's job (`isParentAuthorityOf("*")` is always false), not this
            // one's — upstream is explicit that `:80-83` only builds the syntax.
            return LexPermissionSyntax(permission: entry)

        case RpcPermission.prefix:
            let declaredAud = entry.fields["aud"]
            // :89-91 — a permission set may not name a specific audience.
            if let declaredAud, declaredAud != .string("*") { return nil }

            // :96-103 — all THREE conditions, and `inheritAud === true` is an
            // identity check against the boolean, not a truthiness test.
            if entry.fields["inheritAud"] == .bool(true),
               declaredAud == nil,
               case let .service(inherited)? = aud {
                var fields = entry.fields
                fields.removeValue(forKey: "inheritAud")
                fields["aud"] = .string(inherited)
                return LexPermissionSyntax(
                    permission: LexiconPermission(
                        type: entry.type, resource: entry.resource, fields: fields
                    )
                )
            }

            return LexPermissionSyntax(permission: entry)

        default:
            return nil
        }
    }

    /// `include-scope.ts:117-136`. Which NSIDs get checked differs per family:
    ///  - rpc:   EVERY `lxm` (`:120-122`)
    ///  - repo:  EVERY `collection` (`:124-126`)
    ///  - space: ONLY `type` (`:128-133`). `collection` is deliberately EXEMPT,
    ///           because "collections may live under a different authority"
    ///           (proposal 0016; tests "allows cross-namespace collections",
    ///           `:706-742`, which explicitly include `collection=*`).
    ///
    /// The gate is per ENTRY, and within an entry it is `.every` over that
    /// entry's own NSIDs — so one out-of-namespace collection drops the whole
    /// entry it appears in, while a sibling entry that is entirely in-namespace
    /// survives.
    func isAllowed(_ permission: IncludedPermission) -> Bool {
        switch permission {
        case let .rpc(rpc):
            return rpc.lxm.allSatisfy { isParentAuthorityOf($0.stringValue) }
        case let .repo(repo):
            return repo.collection.allSatisfy { isParentAuthorityOf($0.stringValue) }
        case let .space(space):
            return isParentAuthorityOf(space.spaceType.stringValue)
        }
    }

    /// `include-scope.ts:143-173`. Strips this include's NSID after the LAST dot
    /// and requires the candidate to share that exact prefix INCLUDING the dot.
    ///
    /// **UTF-8 byte units THROUGHOUT.** The first draft mixed
    /// `nsid.distance(from:to:)` (Character distance) with `other.utf8.count`
    /// (byte count). Safe for ASCII NSIDs, but `other` is an arbitrary string
    /// from a lexicon document at this point — gate 3 runs on values that only
    /// their family's `validate` has seen — and this function is `public`, so it
    /// can be called on unvalidated input. Upstream calls it "a security
    /// feature" (`:152-153`); a unit mismatch inside one is worth removing on
    /// sight rather than arguing is unreachable.
    ///
    /// Upstream counts UTF-16 code units (`String.length`, `charCodeAt`). The
    /// two agree on every value that can reach a grant: `nsid` is a validated,
    /// ASCII-only NSID, so the prefix comparison is byte-identical, and the
    /// length guard can only differ for a non-ASCII `other` whose prefix
    /// comparison then fails anyway.
    public func isParentAuthorityOf(_ other: String) -> Bool {
        // A bare wildcard is ALWAYS rejected — a permission set may not grant
        // "everything" (`:144-146`). Pinned for rpc (test `:427-441`) and for
        // space type (test `:690-703`, "too broad for a permission-set").
        guard other != "*" else { return false }

        let nsidBytes = Array(nsid.utf8)
        guard let groupPrefixEnd = nsidBytes.lastIndex(of: 0x2E) else {
            // Upstream THROWS here — "this is a security feature, let's be
            // strict about it" (`:152-155`). In Swift, return false and surface
            // the malformed NSID at parse time instead; `nsid` was already
            // validated as an NSID, so this branch is unreachable — and `false`
            // is the fail-closed answer if it ever is not.
            return false
        }

        let otherBytes = Array(other.utf8)
        // `:158-161` — `other` must be strictly longer than the group prefix.
        // Signed arithmetic, so an empty `other` yields `0 < -1` == false.
        guard groupPrefixEnd < otherBytes.count - 1 else { return false }
        // `:163-171` — share the group prefix up to and including the dot.
        return otherBytes.starts(with: nsidBytes[...groupPrefixEnd])
    }
}
