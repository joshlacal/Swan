import Foundation
import SwanCore

public enum AppPasswordScopeError: Error, Sendable, Equatable {
    /// At least one scope string does not parse.
    ///
    /// Reported rather than dropped. tranquil never calls its own validator, so
    /// an unparseable scope becomes `Unknown` and grants nothing — it fails
    /// closed, but the user is told they created a working credential when they
    /// did not, and finds out only when the client starts failing.
    case unparseable([String])
    /// The set carries no `atproto`, so it would authorize nothing at all.
    case missingBaseScope
}

/// The scope sets offered when creating an app password.
///
/// The names and the first three are tranquil's; the fourth is the one that
/// matters here.
public enum AppPasswordPreset: String, Sendable, CaseIterable {
    /// Everything the legacy surface can reach.
    ///
    /// Spelled out rather than left empty. tranquil's "Full" preset is *no*
    /// scopes, which in Swan grants nothing: the matcher fails closed, so an
    /// empty set would produce a credential that authenticates and then refuses
    /// every request.
    case full

    /// Reads only. No `repo:` and no `blob:`, so nothing can be written.
    case readOnly

    /// One collection, one action, plus the blob upload a post with an image
    /// needs.
    case postOnly

    /// What the official Bluesky client needs, end to end.
    ///
    /// This is exactly the transition scope set every real client already
    /// requests — Catbird's `AuthManager` asks for
    /// `"atproto transition:generic transition:chat.bsky"`, nest's
    /// `default.toml` for the same, and the live server advertises all three in
    /// `scopes_supported`.
    ///
    /// **It carries the whole mitigation for the too-narrow-preset risk.** The
    /// client never inspects scopes, and Swan's denial is deliberately opaque
    /// (§9-D6), so a preset that is slightly too narrow surfaces as unexplained
    /// 403s mid-session with nothing in the response to explain them. Being able
    /// to express it as "the scopes the official app has always used" rather
    /// than as a hand-assembled list of `repo:`/`rpc:`/`blob:` grants is what
    /// makes that risk small: there is nothing to get subtly wrong.
    ///
    /// `transition:generic` covers repo writes on every collection, blob upload,
    /// and RPC to everything outside `chat.bsky.`; `transition:chat.bsky` adds
    /// direct messages. Neither reaches a space — see `allowsSpace`.
    case blueskyApp

    /// - Parameter appViewAudience: the fragment-qualified audience the
    ///   pipethrough builds for the configured AppView, e.g.
    ///   `did:web:api.bsky.app#bsky_appview`. Required because `rpc:` grants
    ///   name a CONCRETE audience — see `readOnly`.
    public func scopes(appViewAudience: String) -> [String] {
        switch self {
        case .full:
            ["atproto", "transition:generic", "transition:chat.bsky", "transition:email"]
        case .readOnly:
            // The design spells this `rpc:app.bsky.*?aud=* rpc:chat.bsky.*?aud=*`,
            // which does not parse and never could: `lxm` is `*` or an exact
            // NSID, with no prefix form, and `matches` is exact-string on it
            // (`rpc-permission.ts:43-49`). `rpc:*?aud=*` is separately forbidden
            // outright — "any audience + any method" is never a legitimate grant
            // (`:86-88`).
            //
            // So a read-only grant has to name its audience. That is also the
            // safer shape: it cannot be pointed at an arbitrary third-party
            // service by a client that sets `atproto-proxy`.
            //
            // Read-only holds because nothing WRITTEN goes through `rpc:` —
            // repo writes and blob uploads are local routes gated by `repo:` and
            // `blob:`, and this preset grants neither.
            [
                "atproto",
                "rpc:*?aud=\(percentEncodedFragment(appViewAudience))",
                "account:status?action=read",
            ]
        case .postOnly:
            ["atproto", "repo:app.bsky.feed.post?action=create", "blob:*/*"]
        case .blueskyApp:
            ["atproto", "transition:generic", "transition:chat.bsky"]
        }
    }

    /// The space-separated form stored on the app-password row.
    public func scopeString(appViewAudience: String) -> String {
        scopes(appViewAudience: appViewAudience).joined(separator: " ")
    }

    /// `#` separates a scope's value from nothing in this grammar, but it is the
    /// service-fragment delimiter inside the value, so it travels encoded.
    private func percentEncodedFragment(_ value: String) -> String {
        value.replacingOccurrences(of: "#", with: "%23")
    }
}

public enum AppPasswordScopes {
    /// Validates a requested scope set and returns its canonical stored form.
    ///
    /// §D6: reject at creation. A scope that cannot be parsed must not become a
    /// credential — the whole failure mode this prevents is a user being told
    /// they made a working app password that in fact grants nothing.
    public static func validate(_ requested: [String]) throws -> String {
        var rejected: [String] = []
        for scope in requested where (try? AtprotoScope.parse(scope)) == nil {
            rejected.append(scope)
        }
        guard rejected.isEmpty else {
            throw AppPasswordScopeError.unparseable(rejected)
        }
        guard requested.contains("atproto") else {
            throw AppPasswordScopeError.missingBaseScope
        }
        return requested.joined(separator: " ")
    }

    /// The backward-compatible default for a client that does not know about
    /// scopes, from the `privileged` boolean it does send.
    ///
    /// Matches the design's stated default: `privileged: false` →
    /// `transition:generic`; otherwise adds `transition:chat.bsky`, which is
    /// exactly what `privileged` has always meant — whether direct messages are
    /// reachable.
    public static func defaultScopes(privileged: Bool) -> String {
        privileged
            ? "atproto transition:generic transition:chat.bsky"
            : "atproto transition:generic"
    }
}
