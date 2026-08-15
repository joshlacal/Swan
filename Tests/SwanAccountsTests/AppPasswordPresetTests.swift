import Foundation
import SwanAccounts
import SwanCore
import Testing

/// Presets and creation-time scope validation.
///
/// Every preset is asserted to actually grant what its name claims, because the
/// client never inspects scopes and Swan's denial is opaque — a preset that is
/// subtly too narrow shows up as unexplained 403s mid-session, which is the most
/// likely way this feature disappoints in practice.
@Suite("app-password presets and scope validation")
struct AppPasswordPresetTests {
    /// The audience the pipethrough builds for the configured AppView.
    private static let appView = "did:web:api.bsky.app#bsky_appview"

    private func permissions(_ preset: AppPasswordPreset) -> SwanScopePermissions {
        SwanScopePermissions(
            rawScopes: Set(preset.scopes(appViewAudience: Self.appView)),
            subject: "did:plc:subject"
        )
    }

    @Test
    func everyPresetParsesCleanly() throws {
        for preset in AppPasswordPreset.allCases {
            let stored = try AppPasswordScopes.validate(preset.scopes(appViewAudience: Self.appView))
            #expect(!stored.isEmpty, "\(preset) must produce a stored scope string")
            let value = permissions(preset)
            #expect(value.rejected.isEmpty, "\(preset) must have no unparseable scopes")
            #expect(value.hasBaseATProtocolScope, "\(preset) must authorize a session at all")
        }
    }

    /// The one that must work end to end, asserted against each thing the
    /// official client actually does.
    @Test
    func theBlueskyAppPresetCoversWhatTheOfficialClientDoes() {
        let value = permissions(.blueskyApp)
        // Post, like, delete — any collection.
        #expect(value.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
        #expect(value.allowsRepo(.init(collection: "app.bsky.feed.like", action: .create)))
        #expect(value.allowsRepo(.init(collection: "app.bsky.graph.follow", action: .delete)))
        // Upload an image.
        #expect(value.allowsBlob(.init(mime: "image/jpeg")))
        #expect(value.allowsBlob(.init(mime: "video/mp4")))
        // Read a timeline, and reach DMs.
        #expect(value.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: "did:web:api.bsky.app")))
        #expect(value.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:api.bsky.chat")))
    }

    /// No preset reaches a space. `transition:*` has no space arm by design, so
    /// this holds even for `.full`.
    @Test
    func noPresetReachesASpace() {
        for preset in AppPasswordPreset.allCases {
            let value = permissions(preset)
            let target = SpaceScopeTarget(
                type: "com.example.space",
                authority: "did:plc:subject",
                skey: "key",
                operation: .read(aggregate: false, collection: nil)
            )
            #expect(!value.allowsSpace(target), "\(preset) must not reach a space")
        }
    }

    @Test
    func readOnlyWritesNothing() {
        let value = permissions(.readOnly)
        #expect(value.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: Self.appView)))
        #expect(!value.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
        #expect(!value.allowsBlob(.init(mime: "image/png")))
    }

    @Test
    func postOnlyWritesExactlyOneCollection() {
        let value = permissions(.postOnly)
        #expect(value.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
        #expect(!value.allowsRepo(.init(collection: "app.bsky.feed.post", action: .delete)))
        #expect(!value.allowsRepo(.init(collection: "app.bsky.feed.like", action: .create)))
        #expect(value.allowsBlob(.init(mime: "image/png")))
        // Grants zero rpc:, which is why it must never be able to obtain a
        // service token — see the getServiceAuth note in ScopePermissions.swift.
        #expect(!value.allowsRPC(.init(lxm: "app.bsky.feed.getTimeline", aud: "did:web:api.bsky.app")))
    }

    // MARK: - Validation (§D6)

    @Test
    func unparseableScopesAreRefusedAtCreation() {
        #expect(throws: AppPasswordScopeError.self) {
            try AppPasswordScopes.validate(["atproto", "repo:not a valid nsid"])
        }
        // `rpc:*?aud=*` is rejected outright rather than treated as a wildcard —
        // one of the three load-bearing grammar details.
        #expect(throws: AppPasswordScopeError.self) {
            try AppPasswordScopes.validate(["atproto", "rpc:*?aud=*"])
        }
    }

    /// A set with no `atproto` authenticates and then refuses everything, which
    /// is precisely the "you were told it works" failure §D6 exists to prevent.
    @Test
    func aSetWithoutTheBaseScopeIsRefused() {
        #expect(throws: AppPasswordScopeError.self) {
            try AppPasswordScopes.validate(["transition:generic"])
        }
    }

    @Test
    func theBackwardCompatibleDefaultTracksPrivileged() {
        #expect(AppPasswordScopes.defaultScopes(privileged: false)
            == "atproto transition:generic")
        #expect(AppPasswordScopes.defaultScopes(privileged: true)
            == "atproto transition:generic transition:chat.bsky")

        // `privileged` has always meant exactly one thing: whether DMs are
        // reachable. Pin that it still does.
        let plain = SwanScopePermissions(
            rawScopes: Set(AppPasswordScopes.defaultScopes(privileged: false)
                .split(separator: " ").map(String.init)),
            subject: "did:plc:subject"
        )
        #expect(!plain.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:x")))
        let privileged = SwanScopePermissions(
            rawScopes: Set(AppPasswordScopes.defaultScopes(privileged: true)
                .split(separator: " ").map(String.init)),
            subject: "did:plc:subject"
        )
        #expect(privileged.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:x")))
    }
}
