import Foundation
import SwanCore

/// A semantic scope classification for consent rendering, shaped one-for-one
/// against `AtprotoScope` (`Sources/SwanCore/OAuthScopes`, spec §4.7) but
/// expressed in plain `String`/`[String]` rather than its typed sub-values.
/// The renderer only prints these values; it never matches or canonicalises
/// them, so carrying the richer types through this boundary adds no value.
///
/// `classify(_:)` is a thin adapter over the same `AtprotoScope.parse` grammar
/// used by admission. `ConsentScope` keeps only the display model local to
/// SwanHTTP; it does not re-derive scope syntax from raw prefixes.
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
    /// A scope rejected by today's parser. The complete original string is
    /// retained for the fallback card and Advanced details rather than being
    /// truncated, confidently misclassified, or silently dropped.
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
        /// render identically.
        let skey: String
        let actions: [String]   // subset of read_self/read/create/update/delete
        let manage: [String]    // subset of create/update/delete (space lifecycle)
        let collection: [String]

        /// S4.1c — the universal-grant warning trigger.
        var isUniversal: Bool { type == "*" && authority == "*" }
    }

    /// Maps the typed admission parser's cases and values into the renderer's
    /// string-only display model. Parser failure is deliberately fail-closed:
    /// it produces a raw fallback row instead of a known-family card.
    ///
    /// A valid `include:` loses its typed `aud` only when converted to the
    /// fixed no-capability card. With a resolver configured, productive
    /// includes are replaced by their concrete grants before rendering; an
    /// unexpanded pass-through include grants nothing, so its card is fixed.
    /// Parser-rejected legacy input takes `.unrecognized(raw:)`, which retains
    /// the full original scope, including all query parameters.
    static func classify(_ raw: String) -> ConsentScope {
        let scope: AtprotoScope
        do {
            scope = try AtprotoScope.parse(raw)
        } catch {
            return .unrecognized(raw: raw)
        }

        switch scope {
        case .atproto:
            return .atproto
        case .transitionEmail:
            return .transitionEmail
        case .transitionGeneric:
            return .transitionGeneric
        case .transitionChatBsky:
            return .transitionChatBsky
        case let .account(permission):
            return .account(
                attr: permission.attr.rawValue,
                actions: permission.action.map(\.rawValue))
        case let .blob(permission):
            return .blob(accept: permission.accept.map(\.stringValue))
        case let .identity(permission):
            return .identity(attr: permission.attr.rawValue)
        case let .include(scope):
            return .include(nsid: scope.nsid)
        case let .repo(permission):
            return .repo(
                collection: permission.collection.map(\.stringValue),
                actions: permission.action.map(\.rawValue))
        case let .rpc(permission):
            return .rpc(
                aud: permission.aud.stringValue,
                lxm: permission.lxm.map(\.stringValue))
        case let .space(permission):
            return .space(
                SpaceGrant(
                    type: permission.type.stringValue,
                    authority: permission.authority.stringValue,
                    skey: permission.skey.stringValue,
                    actions: permission.action.map(\.rawValue),
                    manage: permission.manage.map(\.rawValue),
                    collection: permission.collection.map(\.stringValue)
                ))
        }
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
    /// Productive `include:` scopes are expanded into concrete grants before
    /// this renderer runs. `emptyPermissionSets` carries the NSIDs whose
    /// expansion yielded zero grants (§5.7.5); they use the same canonical
    /// "grants nothing" wording as an unexpanded pass-through `include:`.
    ///
    /// They arrive as a separate parameter rather than inside `scopes` because
    /// by this point the `include:` string is gone: expansion replaced it, and
    /// an empty expansion replaced it with nothing. Only the caller that ran
    /// the resolver still knows the NSID was ever asked for.
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
        // Deduplicated and sorted: an unexpanded pass-through `include:` still
        // in `scopes` and an empty expansion naming the same NSID print once.
        if !includeNsids.isEmpty {
            cards.append(includeCard(Array(Set(includeNsids)).sorted()))
        }
        if !transitionRaws.isEmpty { cards.append(transitionCard(transitionRaws)) }
        if !unrecognizedRaws.isEmpty { cards.append(unrecognizedCard(unrecognizedRaws)) }

        let cardsHTML = cards.isEmpty
            ? ""
            : "<p class=\"text-sm text-base-content/60\">Requested access:</p>" + cards.joined()
        let rawItems = sortedRaw.map {
            "<li><code class=\"font-mono\">\(escape($0))</code></li>"
        }.joined()
        let advanced = """
        <details class="collapse collapse-arrow border-base-300 bg-base-100 border text-sm">\
        <summary class="collapse-title min-h-0 py-2 text-sm font-medium">Advanced: raw scopes</summary>\
        <ul class="collapse-content flex flex-wrap gap-2 pb-2">\(rawItems)</ul></details>
        """
        return cardsHTML + advanced
    }

    // MARK: - Per-family cards

    private static func accountCard(_ entries: [(attr: String, actions: [String])]) -> String {
        let rows = entries.map { entry -> String in
            let verb = entry.actions.contains("manage") ? "Read and update" : "Read"
            return "<li>\(verb) your account's <code>\(escape(entry.attr))</code>.</li>"
        }.joined()
        return card(title: "Account", bodyHTML: "<ul class=\"list-disc pl-5 flex flex-col gap-1\">\(rows)</ul>")
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
        return card(title: "External service calls", bodyHTML: "<ul class=\"list-disc pl-5 flex flex-col gap-1\">\(rows)</ul>")
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

    /// S4.2 — the one canonical wording for an unexpanded or empty `include:`
    /// (§5.7.2, §9-D19). Productive includes have already been replaced by
    /// their concrete grants before rendering.
    private static func includeCard(_ nsids: [String]) -> String {
        let rows = nsids.map { nsid in
            "<li><b>Requested permission set \(escape(nsid)).</b> "
                + "Swan does not currently grant capabilities derived from this set.</li>"
        }.joined()
        return card(title: "Requested permission sets", bodyHTML: "<ul class=\"list-disc pl-5 flex flex-col gap-1\">\(rows)</ul>")
    }

    /// D11 / §9-D19 — `transition:*` is recognised and parses, but grants
    /// nothing in Swan. Same "recognised, grants nothing here" treatment as
    /// an unexpanded or empty `include:`, so it must not render as raw bytes.
    private static func transitionCard(_ rawScopes: [String]) -> String {
        let rows = rawScopes.map { raw in
            "<li><b>Legacy compatibility scope <code>\(escape(raw))</code>.</b> "
                + "Swan recognises this scope but does not currently grant any capability from it.</li>"
        }.joined()
        return card(title: "Legacy compatibility", bodyHTML: "<ul class=\"list-disc pl-5 flex flex-col gap-1\">\(rows)</ul>")
    }

    /// D19: "never drop an undescribable row." Anything the typed parser
    /// rejects still gets its full raw scope here rather than vanishing from
    /// the semantic section.
    private static func unrecognizedCard(_ raws: [String]) -> String {
        let rows = raws.map { "<li><code>\(escape($0))</code></li>" }.joined()
        return card(title: "Other requested permissions", bodyHTML: "<ul class=\"list-disc pl-5 flex flex-col gap-1\">\(rows)</ul>")
    }

    // MARK: - Shared plumbing

    private static func card(title: String, bodyHTML: String) -> String {
        """
        <article class="card card-border bg-base-200/60 text-sm">\
        <div class="card-body gap-2 p-4"><h3 class="card-title text-base">\(escape(title))</h3>\
        \(bodyHTML)</div></article>
        """
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
