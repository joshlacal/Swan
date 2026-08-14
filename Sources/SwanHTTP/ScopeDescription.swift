import Foundation

/// A semantic scope classification, owned by this file and independent of
/// Lane 1's grammar layer (`Sources/SwanCore/OAuthScopes`, spec §4/§5),
/// which had not landed when this renderer was written.
///
/// This is deliberately NOT a validator. `AtprotoScope` (§4.7) rejects a
/// malformed scope before it is ever persisted; by the time a scope reaches
/// a consent page it has already survived that gate (§4.8, §9-D5). `classify`
/// therefore only has to pick the right card and its wording — a string it
/// cannot confidently parse becomes `.unrecognized` and still gets a row
/// (D19: "never drop an undescribable row", mirroring
/// `scope-description.tsx:178`'s NSID fallback) rather than being rejected
/// or silently dropped.
///
/// Once Lane 1's `AtprotoScope` ships, `classify(_:)` should become a thin
/// adapter over `AtprotoScope.parse` — the cases below are shaped one-for-one
/// against §4.7's `AtprotoScope` enum so that swap is mechanical, not a
/// rewrite.
enum ConsentScope: Sendable, Hashable {
    case atproto
    case transitionEmail
    case transitionGeneric
    case transitionChatBsky
    case account(attr: String, actions: [String])
    case blob(accept: [String])
    case identity(attr: String)
    case include(nsid: String)
    case repo(collection: [String], actions: [String])
    case rpc(aud: String, lxm: [String])
    case space(SpaceGrant)
    /// A scope byte string this bridge parser could not confidently place
    /// into a family. Renders as a fallback row rather than vanishing.
    case unrecognized(raw: String)

    /// Grant-side space fields (§5.6.2). Wildcards and the unresolved `self`
    /// sentinel are kept as raw strings here — this type only needs to
    /// describe a grant, not match one.
    struct SpaceGrant: Sendable, Hashable {
        let type: String        // NSID, or "*"
        let authority: String   // DID, "self" (unresolved default), or "*"
        /// A specific record key, or "*" (default — every record). D19 gap
        /// found in review: dropping this field made a single-record grant
        /// (`skey=abc123`) and an every-record grant (`skey=*`, the default)
        /// render identically. That's not a validation gap or a bridge-parser
        /// artifact — it's information the renderer must show regardless of
        /// how the scope was parsed, so it survives the `AtprotoScope.parse`
        /// swap unchanged.
        let skey: String
        let actions: [String]   // subset of read_self/read/create/update/delete
        let manage: [String]    // subset of create/update/delete (space lifecycle)
        let collection: [String]

        /// S4.1c — the universal-grant warning trigger.
        var isUniversal: Bool { type == "*" && authority == "*" }
    }

    private static let knownPrefixes = ["account", "blob", "identity", "include", "repo", "rpc", "space"]

    /// Best-effort classification for consent rendering. Handles both the
    /// positional form (`prefix:value?k=v`) and the fully-named form
    /// (`prefix?key=value...`) from §4.4, using simple `&`/`=` splitting and
    /// percent-decoding rather than the full grammar of §4.1/§4.6 (NSID/DID
    /// validation, canonical ordering, forbidden-combination checks) — none
    /// of that changes which card a scope needs.
    static func classify(_ raw: String) -> ConsentScope {
        switch raw {
        case "atproto": return .atproto
        case "transition:email": return .transitionEmail
        case "transition:generic": return .transitionGeneric
        case "transition:chat.bsky": return .transitionChatBsky
        default: break
        }

        for prefix in knownPrefixes {
            guard raw == prefix || raw.hasPrefix(prefix + ":") || raw.hasPrefix(prefix + "?") else {
                continue
            }
            let rest = raw.dropFirst(prefix.count)
            let (positional, params) = parseScopeBody(rest)
            return classifyFamily(prefix: prefix, positional: positional, params: params, raw: raw)
        }
        return .unrecognized(raw: raw)
    }

    /// A recognised prefix with a REQUIRED field genuinely absent (no
    /// positional value and no named form of it either — `space:`, `repo:`,
    /// an `rpc:` with no `aud`) is not "this family with an edge-case
    /// value"; it is missing the one thing the family cannot be described
    /// without. `.unrecognized` for those is a presence check, not a
    /// grammar check — it costs nothing borrowed from Lane 1's validator.
    ///
    /// What this deliberately still does NOT check: NSID/DID/record-key
    /// *shape* (`space:short`, `space:...?skey=a/b`), enum membership
    /// (`account:*` — attr must be email/repo/status), MIME structure
    /// (`blob:image`), forbidden parameter combinations (`rpc:*?aud=*`),
    /// or unknown query keys (`space:...?unknown=1`). Catching those means
    /// re-deriving §4/§5's grammar here — the exact second-implementation
    /// risk this bridge exists to avoid, and worse than the gap it would
    /// close: a byte string with one of those defects is rejected at PAR
    /// and never reaches a consent page in production (§4.8, §9-D5), so a
    /// half-built shadow validator would spend real complexity on strings
    /// this renderer will never actually see, while still not matching
    /// `AtprotoScope` exactly. `ScopeDescriptionTests` asserts this
    /// boundary against the pinned golden corpus precisely so it stays a
    /// stated, checked gap rather than a silent one, and closes for real
    /// the moment `classify` becomes an `AtprotoScope.parse` adapter.
    ///
    /// Two further divergence classes the corpus's 16 invalid entries do
    /// NOT exercise, found by Lane 1 reading this file against the real
    /// grammar rather than against the fixture: (1) a positional value AND
    /// the named form of the same key both present (`account:email?attr=repo`)
    /// — the real grammar hard-rejects this as `.positionalAndNamedConflict`;
    /// this classifier's `positional ?? params[...]?.first` silently prefers
    /// the positional value instead. (2) A single-valued key repeated
    /// (`space:x?authority=a&authority=b`) — the real grammar hard-rejects
    /// this as `.repeatedSingleValuedParameter`; here `params[...]?.first`
    /// silently takes the first. Both would render a confident card for a
    /// scope `AtprotoScope.parse` refuses outright. Neither is worth a
    /// bespoke check here for the same reason as the gaps above — they
    /// vanish for free on the swap.
    private static func classifyFamily(
        prefix: String, positional: String?, params: [String: [String]], raw: String
    ) -> ConsentScope {
        // A present-but-empty positional (`space:`, `repo:`) means the same
        // thing as an absent one for a REQUIRED field — treat both as nil so
        // the guards below see "missing", not "empty string supplied".
        let positional = positional.flatMap { $0.isEmpty ? nil : $0 }
        switch prefix {
        case "account":
            guard let attr = positional ?? params["attr"]?.first else { return .unrecognized(raw: raw) }
            return .account(attr: attr, actions: params["action"] ?? ["read"])
        case "blob":
            let accept = positional.map { [$0] } ?? (params["accept"] ?? [])
            guard !accept.isEmpty else { return .unrecognized(raw: raw) }
            return .blob(accept: accept)
        case "identity":
            guard let attr = positional ?? params["attr"]?.first else { return .unrecognized(raw: raw) }
            return .identity(attr: attr)
        case "include":
            guard let nsid = positional ?? params["nsid"]?.first else { return .unrecognized(raw: raw) }
            return .include(nsid: nsid)
        case "repo":
            let collection = positional.map { [$0] } ?? (params["collection"] ?? [])
            guard !collection.isEmpty else { return .unrecognized(raw: raw) }
            return .repo(collection: collection, actions: params["action"] ?? ["create", "update", "delete"])
        case "rpc":
            let lxm = positional.map { [$0] } ?? (params["lxm"] ?? [])
            // `aud` has no default (rpc-permission.ts:67-70) — genuinely
            // required, unlike `authority`/`skey`/`action` elsewhere.
            guard !lxm.isEmpty, let aud = params["aud"]?.first, !aud.isEmpty else {
                return .unrecognized(raw: raw)
            }
            return .rpc(aud: aud, lxm: lxm)
        case "space":
            guard let type = positional ?? params["type"]?.first else { return .unrecognized(raw: raw) }
            return .space(
                SpaceGrant(
                    type: type,
                    authority: params["authority"]?.first ?? "self",
                    skey: params["skey"]?.first ?? "*",
                    actions: params["action"] ?? ["read", "create", "update", "delete"],
                    manage: params["manage"] ?? [],
                    collection: params["collection"] ?? []
                ))
        default:
            return .unrecognized(raw: raw)
        }
    }

    /// `rest` is everything after the matched prefix: empty, or starting
    /// with `:` (positional form, optionally followed by `?params`) or `?`
    /// (named-only form).
    private static func parseScopeBody(_ rest: Substring) -> (positional: String?, params: [String: [String]]) {
        guard !rest.isEmpty else { return (nil, [:]) }
        var positional: String?
        var queryPart: Substring = ""
        if rest.hasPrefix(":") {
            let afterColon = rest.dropFirst()
            if let qIndex = afterColon.firstIndex(of: "?") {
                positional = String(afterColon[afterColon.startIndex..<qIndex])
                queryPart = afterColon[afterColon.index(after: qIndex)...]
            } else {
                positional = String(afterColon)
            }
        } else if rest.hasPrefix("?") {
            queryPart = rest.dropFirst()
        }
        var params: [String: [String]] = [:]
        for pair in queryPart.split(separator: "&", omittingEmptySubsequences: true) {
            guard let eqIndex = pair.firstIndex(of: "=") else { continue }
            let key = String(pair[pair.startIndex..<eqIndex])
            let rawValue = String(pair[pair.index(after: eqIndex)...])
            params[key, default: []].append(rawValue.removingPercentEncoding ?? rawValue)
        }
        return (positional, params)
    }
}

/// The one shared consent renderer for both Swan OAuth consent pages
/// (`SwanOAuthAuthorizationServerHTTP.swift`, `SwanLocalhostOAuthHTTP.swift`)
/// — spec §7.4 Stage 4 / §9-D19. A second copy of this wording is exactly
/// the defect §5.7.2 and §9-D19 warn about, so both call sites route through
/// `render(scopes:)` rather than building their own `<li>` list.
///
/// Renders a semantic card for every recognised scope Swan accepts and
/// persists — not merely every scope a Swan route consumes today (§9-D19)
/// — with the raw scope bytes demoted to an advanced-detail block beneath
/// the cards (S4.4). `atproto` alone never gets a card of its own (S4.1a);
/// it still appears in the raw/advanced list, since that list is unconditional.
enum ScopeDescription {
    /// - Parameter emptyPermissionSets: NSIDs of `include:` scopes that Phase-2
    ///   resolution proved and expanded to **zero** grants (§5.7.5). They render
    ///   through the same `includeCard` as an unexpanded Phase-1 `include:`,
    ///   because the wording §5.7.2 fixes — "Requested permission set `<nsid>`.
    ///   Swan does not currently grant capabilities derived from this set." — is
    ///   exactly true of both, and a second string saying the same thing is the
    ///   defect §9-D19 exists to prevent.
    ///
    ///   They arrive as a separate parameter rather than inside `scopes` because
    ///   by this point the `include:` string is gone: expansion replaced it, and
    ///   an empty expansion replaced it with nothing. Only the caller that ran
    ///   the resolver still knows the NSID was ever asked for.
    static func render(
        scopes: some Sequence<String>,
        emptyPermissionSets: [String] = []
    ) -> String {
        let sortedRaw = Array(Set(scopes)).sorted()

        var accountEntries: [(attr: String, actions: [String])] = []
        var blobAccepts: [[String]] = []
        var identityAttrs: [String] = []
        var includeNsids: [String] = emptyPermissionSets
        var repoEntries: [(collection: [String], actions: [String])] = []
        var rpcEntries: [(aud: String, lxm: [String])] = []
        var spaceGrants: [ConsentScope.SpaceGrant] = []
        var transitionRaws: [String] = []
        var unrecognizedRaws: [String] = []

        for raw in sortedRaw {
            switch ConsentScope.classify(raw) {
            case .atproto:
                break  // S4.1a — bare atproto never gets a card.
            case .transitionEmail, .transitionGeneric, .transitionChatBsky:
                transitionRaws.append(raw)
            case let .account(attr, actions):
                accountEntries.append((attr, actions))
            case let .blob(accept):
                blobAccepts.append(accept)
            case let .identity(attr):
                identityAttrs.append(attr)
            case let .include(nsid):
                includeNsids.append(nsid)
            case let .repo(collection, actions):
                repoEntries.append((collection, actions))
            case let .rpc(aud, lxm):
                rpcEntries.append((aud, lxm))
            case let .space(grant):
                spaceGrants.append(grant)
            case .unrecognized:
                unrecognizedRaws.append(raw)
            }
        }

        var cards: [String] = []
        if !accountEntries.isEmpty { cards.append(accountCard(accountEntries)) }
        if !blobAccepts.isEmpty { cards.append(blobCard(blobAccepts)) }
        if !identityAttrs.isEmpty { cards.append(identityCard(identityAttrs)) }
        if !repoEntries.isEmpty { cards.append(repoCard(repoEntries)) }
        if !rpcEntries.isEmpty { cards.append(rpcCard(rpcEntries)) }
        if !spaceGrants.isEmpty { cards.append(spaceCard(spaceGrants)) }
        // Deduplicated and sorted: a Phase-1 `include:` still in `scopes` and a
        // Phase-2 empty expansion naming the same NSID must not print twice.
        if !includeNsids.isEmpty {
            cards.append(includeCard(Array(Set(includeNsids)).sorted()))
        }
        if !transitionRaws.isEmpty { cards.append(transitionCard(transitionRaws)) }
        if !unrecognizedRaws.isEmpty { cards.append(unrecognizedCard(unrecognizedRaws)) }

        let cardsHTML = cards.isEmpty ? "" : "<p>Requested access:</p>" + cards.joined()
        let rawItems = sortedRaw.map { "<li><code>\(escape($0))</code></li>" }.joined()
        let advanced = "<details><summary>Advanced: raw scopes</summary><ul>\(rawItems)</ul></details>"
        return cardsHTML + advanced
    }

    // MARK: - Per-family cards

    private static func accountCard(_ entries: [(attr: String, actions: [String])]) -> String {
        let rows = entries.map { entry -> String in
            let verb = entry.actions.contains("manage") ? "Read and update" : "Read"
            return "<li>\(verb) your account's <code>\(escape(entry.attr))</code>.</li>"
        }.joined()
        return card(title: "Account", bodyHTML: "<ul>\(rows)</ul>")
    }

    private static func blobCard(_ acceptLists: [[String]]) -> String {
        let patterns = Array(Set(acceptLists.flatMap { $0 })).sorted()
        let rows = patterns.map { "<li><code>\(escape($0))</code></li>" }.joined()
        return card(title: "File uploads", bodyHTML: "<p>Upload files matching:</p><ul>\(rows)</ul>")
    }

    /// S4.3 — the `identity:*` theft warning is written into the family's
    /// own card, not deferred, per D19's "ship the string with the family".
    private static func identityCard(_ attrs: [String]) -> String {
        if attrs.contains("*") {
            let warning =
                "The application is asking for full control over your network identity, "
                + "meaning it could <b>permanently break</b>, or even <b>steal</b>, your account. "
                + "Only grant this permission to applications you really trust."
            return card(title: "Identity", bodyHTML: "<p>\(warning)</p>")
        }
        return card(title: "Identity", bodyHTML: "<p>Change your handle.</p>")
    }

    private static func repoCard(_ entries: [(collection: [String], actions: [String])]) -> String {
        let rows = entries.map { entry -> String in
            let verbs = joinedProse(entry.actions)
            let target = entry.collection.contains("*")
                ? "any collection"
                : entry.collection.map { "<code>\(escape($0))</code>" }.joined(separator: ", ")
            return "<li>\(verbs.capitalizedFirstLetter) records in \(target).</li>"
        }.joined()
        return card(
            title: "Repository",
            bodyHTML: "<p>Publish changes to your repository.</p><ul>\(rows)</ul>")
    }

    private static func rpcCard(_ entries: [(aud: String, lxm: [String])]) -> String {
        let rows = entries.map { entry -> String in
            let methods = entry.lxm.contains("*")
                ? "any method"
                : entry.lxm.map { "<code>\(escape($0))</code>" }.joined(separator: ", ")
            let service = entry.aud == "*" ? "any service" : "<code>\(escape(entry.aud))</code>"
            return "<li>Call \(methods) on \(service).</li>"
        }.joined()
        return card(title: "External service calls", bodyHTML: "<ul>\(rows)</ul>")
    }

    /// S4.1b (one card, verbs in prose per grant) + S4.1c (universal-grant
    /// warning) + S4.1d (unnamed space type falls back to the raw NSID —
    /// trivially true here since this renderer has no space-name directory
    /// to consult in the first place, so every label already IS the raw NSID).
    private static func spaceCard(_ grants: [ConsentScope.SpaceGrant]) -> String {
        let rows = grants.map(spaceRow).joined()
        let warning: String
        if grants.contains(where: { $0.isUniversal }) {
            warning =
                "<p role=\"status\"><b>This application is requesting access to every space "
                + "on the network.</b> This is a very broad permission. Only grant it to "
                + "applications you deeply trust.</p>"
        } else {
            warning = ""
        }
        return card(
            title: "Spaces",
            bodyHTML: "<p>Access permissioned spaces.</p><ul>\(rows)</ul>\(warning)")
    }

    private static func spaceRow(_ grant: ConsentScope.SpaceGrant) -> String {
        var details: [String] = []
        if !grant.manage.isEmpty {
            details.append("\(joinedProse(grant.manage).capitalizedFirstLetter) the space")
        }
        if grant.actions.contains("read") {
            details.append("read all data in the space")
        } else if grant.actions.contains("read_self") {
            details.append("read only your own data")
        }
        let writeVerbs = grant.actions.filter { ["create", "update", "delete"].contains($0) }
        // Empty `collection` means no write targets even if write verbs are
        // present — §5.6.2. "empty means NO WRITE TARGETS, not all collections".
        if !writeVerbs.isEmpty, !grant.collection.isEmpty {
            let target = grant.collection.contains("*")
                ? "any collection"
                : grant.collection.map { "<code>\(escape($0))</code>" }.joined(separator: ", ")
            details.append("\(joinedProse(writeVerbs)) records in \(target)")
        }
        if details.isEmpty { details.append("no access") }
        return "<li><b>\(spaceLabel(grant))</b>: \(details.joined(separator: "; ")).</li>"
    }

    private static func spaceLabel(_ grant: ConsentScope.SpaceGrant) -> String {
        let typeLabel = grant.type == "*" ? "All spaces" : "<code>\(escape(grant.type))</code> spaces"
        let base: String
        switch grant.authority {
        case "*": base = "\(typeLabel) on the network"
        case "self": base = "\(typeLabel) you own"
        default: base = "\(typeLabel) on <code>\(escape(grant.authority))</code>"
        }
        guard grant.skey != "*" else { return base }
        // A specific `skey` narrows the WHOLE grant — read, write, and
        // manage alike — to one record, not just a subset of reads (§5.6.3's
        // match arms all consult `skey` before any operation-specific
        // check). This has to be visible in the label itself, not buried
        // among the per-verb detail below, since it changes what every verb
        // there actually means: found in review as a live D19 gap — without
        // it, `skey=abc123` (one record) and the `skey=*` default (every
        // record in the space) rendered identically.
        return "\(base), limited to one record (<code>\(escape(grant.skey))</code>)"
    }

    /// S4.2 — the ONE canonical Phase-1 `include:` wording (§5.7.2, §9-D19),
    /// verbatim: "Requested permission set `<nsid>`. Swan does not currently
    /// grant capabilities derived from this set."
    private static func includeCard(_ nsids: [String]) -> String {
        let rows = nsids.map { nsid in
            "<li><b>Requested permission set \(escape(nsid)).</b> "
                + "Swan does not currently grant capabilities derived from this set.</li>"
        }.joined()
        return card(title: "Requested permission sets", bodyHTML: "<ul>\(rows)</ul>")
    }

    /// D11 / §9-D19 — `transition:*` is recognised and parses, but grants
    /// nothing in Swan. Same "recognised, grants nothing here" treatment as
    /// Phase-1 `include:`, so it must not render as raw bytes either.
    private static func transitionCard(_ rawScopes: [String]) -> String {
        let rows = rawScopes.map { raw in
            "<li><b>Legacy compatibility scope <code>\(escape(raw))</code>.</b> "
                + "Swan recognises this scope but does not currently grant any capability from it.</li>"
        }.joined()
        return card(title: "Legacy compatibility", bodyHTML: "<ul>\(rows)</ul>")
    }

    /// D19: "never drop an undescribable row." Anything this bridge parser
    /// could not place into a known family still gets a row here rather than
    /// vanishing from the semantic section.
    private static func unrecognizedCard(_ raws: [String]) -> String {
        let rows = raws.map { "<li><code>\(escape($0))</code></li>" }.joined()
        return card(title: "Other requested permissions", bodyHTML: "<ul>\(rows)</ul>")
    }

    // MARK: - Shared plumbing

    private static func card(title: String, bodyHTML: String) -> String {
        "<article><h3>\(escape(title))</h3>\(bodyHTML)</article>"
    }

    private static func joinedProse(_ items: [String]) -> String {
        switch items.count {
        case 0: return ""
        case 1: return items[0]
        case 2: return "\(items[0]) and \(items[1])"
        default: return items.dropLast().joined(separator: ", ") + ", and " + items[items.count - 1]
        }
    }

    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}

extension String {
    fileprivate var capitalizedFirstLetter: String {
        guard let first else { return self }
        return first.uppercased() + dropFirst()
    }
}
