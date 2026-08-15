import Foundation
import Testing
@testable import SwanCore

/// Vectors ported from `oauth-scopes/src/scope-permissions-transition.test.ts`,
/// whose subject is instantiated UNCONDITIONALLY for every OAuth credential by
/// `packages/pds/src/auth-verifier.ts:658`. These therefore describe the
/// behaviour of an ordinary Swan OAuth token, not of some opt-in legacy mode.
///
/// They exist because wiring `require*` to a route without this port would deny
/// every credential in the wild: transition scopes are flat cases in
/// `AtprotoScope`, so they produce no `.repo` / `.rpc` / `.blob` grant for the
/// family matchers to find.
@Suite("transition: scopes stand in for the modern families")
struct OAuthScopesTransitionTests {
    private func permissions(_ scopes: String...) -> SwanScopePermissions {
        SwanScopePermissions(rawScopes: Set(scopes), subject: "did:plc:subject")
    }

    // MARK: repo (`:47-53`)

    @Test
    func transitionGenericAllowsAnyRepoWrite() {
        let p = permissions("atproto", "transition:generic")
        for action in RepoAction.allCases {
            #expect(p.allowsRepo(.init(collection: "app.bsky.feed.post", action: action)))
            #expect(p.allowsRepo(.init(collection: "com.example.anything", action: action)))
        }
    }

    /// The regression this whole port exists to prevent: without it, an
    /// `atproto`-only credential is denied by a newly-wired `requireRepo`.
    @Test
    func atprotoAloneGrantsNoRepoWrite() {
        let p = permissions("atproto")
        #expect(!p.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
    }

    @Test
    func modernRepoGrantStillNarrows() {
        let p = permissions("atproto", "repo:app.bsky.feed.like?action=create")
        #expect(p.allowsRepo(.init(collection: "app.bsky.feed.like", action: .create)))
        #expect(!p.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
        #expect(!p.allowsRepo(.init(collection: "app.bsky.feed.like", action: .delete)))
    }

    // MARK: blob (`:39-45`)

    @Test
    func transitionGenericAllowsAnyBlobMime() {
        let p = permissions("atproto", "transition:generic")
        #expect(p.allowsBlob(.init(mime: "image/png")))
        #expect(p.allowsBlob(.init(mime: "video/mp4")))
    }

    @Test
    func atprotoAloneGrantsNoBlobUpload() {
        #expect(!permissions("atproto").allowsBlob(.init(mime: "image/png")))
    }

    // MARK: rpc (`:64-80`) — the DM split

    @Test
    func transitionGenericAllowsNonChatRPCAndWildcard() {
        let p = permissions("atproto", "transition:generic")
        #expect(p.allowsRPC(.init(lxm: "*", aud: "did:web:api.bsky.app")))
        #expect(p.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: "did:web:api.bsky.app")))
    }

    /// The one thing a non-privileged legacy credential must not reach.
    @Test
    func transitionGenericAloneCannotReachChat() {
        let p = permissions("atproto", "transition:generic")
        #expect(!p.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:api.bsky.chat")))
    }

    @Test
    func transitionChatBskyReachesChatAndNothingElse() {
        let p = permissions("atproto", "transition:chat.bsky")
        #expect(p.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:api.bsky.chat")))
        #expect(!p.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: "did:web:api.bsky.app")))
    }

    @Test
    func bothTransitionScopesReachEverything() {
        let p = permissions("atproto", "transition:generic", "transition:chat.bsky")
        #expect(p.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:api.bsky.chat")))
        #expect(p.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: "did:web:api.bsky.app")))
    }

    /// `chat.bsky.` is a dot-boundary prefix, so a lookalike NSID must not be
    /// swept into the chat arm — nor out of the generic one.
    @Test
    func chatPrefixIsDotBounded() {
        let p = permissions("atproto", "transition:generic")
        #expect(p.allowsRPC(.init(lxm: "chat.bskyfoo.convo.list", aud: "did:web:x")))
        #expect(!permissions("atproto", "transition:chat.bsky")
            .allowsRPC(.init(lxm: "chat.bskyfoo.convo.list", aud: "did:web:x")))
    }

    // MARK: account (`:27-37`)

    @Test
    func transitionEmailGrantsExactlyEmailRead() {
        let p = permissions("atproto", "transition:email")
        #expect(p.allowsAccount(.init(attr: .email, action: .read)))
        #expect(!p.allowsAccount(.init(attr: .email, action: .manage)))
        #expect(!p.allowsAccount(.init(attr: .repo, action: .read)))
        #expect(!p.allowsAccount(.init(attr: .status, action: .read)))
    }

    // MARK: space (`:55-62`) — the deliberate non-grant

    /// Upstream overrides `allowsSpace` to call `super` and nothing else, so the
    /// omission is a decision. Swan holds the same line, and has a second reason
    /// to: an app password with no declared scopes defaults to
    /// `transition:generic`, so a transition arm here would hand every legacy
    /// bearer credential the permissioned-data surface.
    @Test
    func noTransitionScopeReachesASpace() {
        let p = permissions("atproto", "transition:generic", "transition:chat.bsky", "transition:email")
        let space = { (operation: SpaceScopeTarget.Operation) in
            SpaceScopeTarget(
                type: "com.example.space",
                authority: "did:plc:author",
                skey: "key",
                operation: operation
            )
        }
        #expect(!p.allowsSpace(space(.read(aggregate: false, collection: nil))))
        #expect(!p.allowsSpace(space(.readSelf(aggregate: false, collection: nil))))
        #expect(!p.allowsSpace(space(.write(.create, collection: "com.example.record"))))
        #expect(!p.allowsSpace(space(.delegationExchange)))
    }

    /// `hasResourceScope` is the authorization floor. Transition scopes must not
    /// widen it — it stays `atproto` or a `space:` grant, per the route map at
    /// the top of `ScopePermissions.swift`.
    @Test
    func transitionScopesDoNotWidenTheResourceFloor() {
        #expect(!permissions("transition:generic").hasResourceScope)
        #expect(permissions("atproto").hasResourceScope)
    }
}
