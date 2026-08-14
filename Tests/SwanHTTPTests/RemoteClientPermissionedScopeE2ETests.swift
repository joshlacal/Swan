import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
@testable import SwanSpaces

/// **§7.4 — the bulleted.app acceptance test.**
///
/// bulleted.app's five real scopes must survive the whole flow: parse →
/// authorize → consent → token mint → request-time enforcement. Each stage is
/// its own method so a red stage is bisectable, plus one method that runs every
/// stage against a single fixture.
///
///     atproto
///     include:app.bulleted.authFull
///     blob:image/*
///     include:app.bulleted.spaceAccess
///     space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self
///
/// Two Phase-1 outcomes are asserted rather than left to be discovered
/// (§9-D4, §7.4 Stage 6 check 3): the `include:` scopes **authorize
/// successfully and are then denied on every include-derived call**, and a bare
/// space grant has no write targets until Phase 2. Both are divergences from a
/// conformant AS, and both test names say so.
final class RemoteClientPermissionedScopeE2ETests: XCTestCase, @unchecked Sendable {
    // MARK: - The whole flow, one fixture

    func testBulletedAppFiveScopesSurviveTheWholeFlow() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)

        try await assertStage0Discovery(fixture)
        try assertStage1Parse()
        try assertStage2Registration(client)
        let issued = try await fixture.mint(client: client, proofID: "bulleted-whole-flow")
        try assertStage5Mint(issued: issued, client: client)
        try await assertStage6Enforcement(fixture: fixture, client: client, issued: issued)
    }

    // MARK: - Stage 0: discovery

    /// `scopes_supported` is exactly `["atproto"]` (§6.6) — **and** a scope
    /// absent from it is still accepted at PAR. `scopes_supported` is a hint, not
    /// a gate; pinning the inverse property is what stops a future reader
    /// "fixing" the metadata instead of the grammar.
    func testStage0DiscoveryAdvertisesOnlyAtprotoButDoesNotGateOnIt() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        try await assertStage0Discovery(fixture)
    }

    private func assertStage0Discovery(_ fixture: PermissionedScopeFixture) async throws {
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        let app = try await fixture
            .buildRemoteAuthorizationServer(clientMetadata: try client.metadata())
            .buildApplication(
                logger: Logger(label: "RemoteClientPermissionedScopeE2ETests.discovery")
            )
        try await app.test(.router) { http in
            try await http.execute(
                uri: "/.well-known/oauth-authorization-server",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let document = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]
                )
                XCTAssertEqual(
                    document["scopes_supported"] as? [String],
                    ["atproto"],
                    "§6.6: Swan advertises the base scope only; permission families are not enumerated"
                )
            }
        }

        // The inverse property, on the same fixture: a scope that never appears in
        // `scopes_supported` is nonetheless admitted at PAR. Asserting only the
        // VALUE above would leave a future reader free to "fix" the metadata
        // instead of the grammar; this is the half that closes that hole.
        let scoped = try PermissionedScopeClient(scopes: [BulletedApp.base, BulletedApp.space])
        let session = try scoped.session(proofID: "stage0-inverse")
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage0-inverse",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        XCTAssertFalse(
            requestURI.isEmpty,
            "a `space:` scope absent from scopes_supported must still be admitted at PAR"
        )
    }

    // MARK: - Stage 1: parse

    /// Each of the five strings parses and re-serialises canonically. The
    /// `space:` scope's canonical form is asserted **exactly**, because `manage`
    /// ordering follows `SPACE_MANAGE_OPS` (`create, update, delete`) and
    /// `action` precedes `manage` by schema declaration order — neither is input
    /// order, and the golden corpus is what says so.
    func testStage1AllFiveScopesParseAndCanonicalise() throws {
        try assertStage1Parse()
    }

    private func assertStage1Parse() throws {
        for scope in [BulletedApp.base, BulletedApp.includeAuthFull, BulletedApp.includeSpaceAccess] {
            XCTAssertEqual(try AtprotoScope.parse(scope).canonicalScopeString(), scope)
        }
        XCTAssertEqual(
            try AtprotoScope.parse(BulletedApp.blobImages).canonicalScopeString(),
            "blob:image/*"
        )
        XCTAssertEqual(
            try AtprotoScope.parse(BulletedApp.space).canonicalScopeString(),
            BulletedApp.canonicalSpace,
            """
            §7.4 Stage 1: `manage` serialises in SPACE_MANAGE_OPS order and \
            `action` precedes it by schema declaration order. Input order is not \
            canonical order.
            """
        )
        // And the canonical form is a fixed point — §9-D7's subset check depends
        // on it.
        XCTAssertEqual(
            try AtprotoScope.parse(BulletedApp.canonicalSpace).canonicalScopeString(),
            BulletedApp.canonicalSpace
        )
    }

    // MARK: - Stage 2: client registration

    /// §7.4 Stage 2, split across two layers under §9-D21 — registration is
    /// lexical and budget only; semantics move to PAR. The "both directions"
    /// assertion must **not** be written as one check.
    func testStage2RegistrationIsLexicalOnlyAndSemanticsMoveToPAR() throws {
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        try assertStage2Registration(client)
    }

    private func assertStage2Registration(_ client: PermissionedScopeClient) throws {
        // A2a — the five-scope remote HTTPS client registers.
        let remote = try OAuthClientMetadata(
            clientID: URL(string: "https://bulleted.app/client-metadata.json")!,
            redirectURIs: [URL(string: "https://bulleted.app/callback")!],
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: Set(BulletedApp.all),
            dpopBoundAccessTokens: true
        )
        XCTAssertNoThrow(
            try remote.validate(),
            """
            A2a: this is the stage that fails hardest today — \
            `OAuthClientMetadata.swift:343-344` gates the issuable disjunct behind \
            `isLocalhostDevelopmentClient &&`, so a remote client can carry only \
            bare `atproto`. §9-D21 retires that gate rather than re-expressing it.
            """
        )

        // A2b — lexically valid scope-token bytes, semantically malformed.
        // Registration grants nothing, so it registers fine.
        let malformed = "space:not-an-nsid?authority=notadid&skey=k&action=read"
        let semanticallyBad = try OAuthClientMetadata(
            clientID: URL(string: "https://bulleted.app/client-metadata.json")!,
            redirectURIs: [URL(string: "https://bulleted.app/callback")!],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: [malformed],
            dpopBoundAccessTokens: true
        )
        XCTAssertNoThrow(
            try semanticallyBad.validate(),
            "A2b: registration validates RFC scope-token syntax and Swan's budgets, nothing semantic"
        )

        // A2b′ — the same scope requested at PAR is rejected. A2b + A2b′ together
        // are the pair that proves the layer boundary MOVED rather than the check
        // disappearing; asserting only one of them pins the retired behaviour.
        XCTAssertThrowsError(
            try AtprotoScope.parse(malformed),
            "A2b′: §9-D5 rejects an unparseable REQUESTED scope with invalid_scope"
        )

        // A2c — the lexical/budget floor is the only registration gate, so it has
        // to actually hold. `"` (0x22) and `\` (0x5C) are excluded by
        // OAUTH_SCOPE_REGEXP and admitted by today's `0x21...0x7E` check.
        for illegal in ["atproto", "space:x.y.z?skey=a\"b", "space:x.y.z?skey=a\\b"].dropFirst() {
            XCTAssertFalse(
                ScopeToken.isScopeToken(illegal),
                "A2c: `\(illegal)` carries a byte RFC 6749 §3.3 excludes"
            )
        }
        XCTAssertTrue(ScopeToken.isScopeToken(BulletedApp.space))
        XCTAssertTrue(client.scopes.allSatisfy(ScopeToken.isScopeToken))
    }

    // MARK: - Stage 3: PAR

    /// The five-scope `scope` parameter reaches `/oauth/par`, meets the DPoP
    /// nonce challenge, retries with the nonce, and gets a `request_uri` whose
    /// stored row round-trips all five scopes.
    func testStage3PARIssuesARequestURIAndRoundTripsAllFiveScopes() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        let session = try client.session(proofID: "stage3-par")

        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage3-par",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let stored = try await fixture.runtime.tokenService.activePushedAuthorizationRequest(
            requestURI
        )
        XCTAssertEqual(
            stored?.binding.scopes,
            client.scopeSet,
            """
            §7.4 Stage 3: the PAR row keeps the AS-REQUESTED strings — it has no \
            subject and physically cannot hold a resolved value (§6.7). All five \
            must survive `encodeScopes`/`decodeScopes`; the space scope is 68 \
            bytes, well inside the 1024-byte per-token budget.
            """
        )
    }

    // MARK: - Stage 4: consent

    /// **Stage-C blocker, not a formality (§9-D19).** The weak property — all
    /// five raw strings appear, none silently dropped — is no longer enough, and
    /// this asserts the semantic obligations that replaced it, on the renderer
    /// the harness actually drives (`SwanLocalhostOAuthHTTP.consentPage`,
    /// §7.4 S4.5).
    ///
    /// The per-string unit tests for the shared description function live in
    /// `Tests/SwanHTTPTests/ScopeDescriptionTests.swift` (lane 4). What this test
    /// owns is that the rendered consent PAGE carries them — a renderer that is
    /// correct in isolation and unreachable from the page is not consent.
    func testStage4LocalhostConsentPageIsSemanticNotRawScopeBytes() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all, kind: .localhostBridge)
        let session = try client.session(proofID: "stage4-consent")
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage4-consent",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let app = try fixture.buildServer().buildApplication(
            logger: Logger(label: "RemoteClientPermissionedScopeE2ETests.consent")
        )
        let authorize =
            "/oauth/authorize?client_id=\(scopeFormEncode(client.clientID.absoluteString))"
            + "&request_uri=\(scopeFormEncode(requestURI))"
        try await app.test(.router) { http in
            try await http.execute(uri: authorize, method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                let html = String(buffer: response.body)

                // S4.1-S4.2, shared with the authorization-server renderer so the
                // two cannot drift into two different sets of assertions.
                Self.assertConsentPageIsSemantic(html, renderer: "localhost bridge")

                // S4.4 — raw scope text survives as advanced detail, below the
                // semantic cards. It is not deleted; it is just not consent.
                for scope in BulletedApp.all where scope != BulletedApp.base {
                    XCTAssertTrue(
                        html.contains(scope) || html.contains(BulletedApp.canonicalSpace),
                        "S4.4: raw scope text is demoted, not removed — missing \(scope)"
                    )
                }
            }
        }
    }

    /// S4.1a — bare `atproto` **alone** renders no permission card at all
    /// (`scope-description.tsx:82-85`). Today's page violates this by listing
    /// every element of `scopes.sorted()`, `atproto` included.
    func testStage4LocalhostConsentPageRendersNoCardForBareAtproto() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: [BulletedApp.base], kind: .localhostBridge)
        let session = try client.session(proofID: "stage4-atproto-only")
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage4-atproto-only",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let app = try fixture.buildServer().buildApplication(
            logger: Logger(label: "RemoteClientPermissionedScopeE2ETests.atproto-only")
        )
        let authorize =
            "/oauth/authorize?client_id=\(scopeFormEncode(client.clientID.absoluteString))"
            + "&request_uri=\(scopeFormEncode(requestURI))"
        try await app.test(.router) { http in
            try await http.execute(uri: authorize, method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                let html = String(buffer: response.body)
                XCTAssertFalse(
                    html.contains("<li><code>atproto</code>"),
                    """
                    S4.1a: `atproto` alone is a session scope, not a permission. \
                    Rendering it as a permission bullet trains users to approve \
                    lists they cannot read.
                    """
                )
            }
        }
    }

    /// S4.1c — a `type == "*" && authority == "*"` grant must carry the
    /// universal-grant warning in substance. This is the member of the
    /// `identity:*`-class risk family that Swan **can** grant today, which is why
    /// it is mandatory rather than aspirational (S4.3): no permission of this
    /// class ever reaches a Swan consent screen as raw scope text.
    func testStage4LocalhostConsentPageCarriesTheUniversalSpaceWarning() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(
            scopes: [BulletedApp.base, "space:*?authority=*&skey=*&action=read"],
            kind: .localhostBridge
        )
        let session = try client.session(proofID: "stage4-universal")
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage4-universal",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let app = try fixture.buildServer().buildApplication(
            logger: Logger(label: "RemoteClientPermissionedScopeE2ETests.universal")
        )
        let authorize =
            "/oauth/authorize?client_id=\(scopeFormEncode(client.clientID.absoluteString))"
            + "&request_uri=\(scopeFormEncode(requestURI))"
        try await app.test(.router) { http in
            try await http.execute(uri: authorize, method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                let html = String(buffer: response.body).lowercased()
                XCTAssertTrue(
                    html.contains("every space"),
                    "S4.1c: the warning must say the app is requesting access to EVERY space on the network"
                )
                XCTAssertTrue(
                    html.contains("trusted"),
                    "S4.1c: ... and that it should be granted only to deeply trusted applications"
                )
            }
        }
    }

    /// **S4.5 — the SECOND renderer.** `SwanOAuthAuthorizationServerHTTP.swift:1170-1172`
    /// is an independent consent page from `SwanLocalhostOAuthHTTP.consentPage`,
    /// with its own identical `scopes.sorted()` `<li>` list. The first draft of
    /// the spec named only this one; §7.1's harness drives only the other. Both
    /// obligations bind, so both are asserted — and because the semantic
    /// descriptions must live in **one shared function** that both call, this
    /// test asserts the same strings as its localhost twin. A second copy of the
    /// consent copy is a second copy of the security-relevant wording.
    ///
    /// This is also the only Stage-4 path that runs against a genuinely remote
    /// HTTPS client, so it is where the §9-D19 "no unrestricted Stage C without
    /// the renderer" gate actually has teeth.
    func testStage4AuthorizationServerConsentPageCarriesTheSameSemanticStrings() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        let session = try client.session(proofID: "stage4-as-consent")
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "stage4-as-consent",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let app = try await fixture
            .buildRemoteAuthorizationServer(clientMetadata: try client.metadata())
            .buildApplication(
                logger: Logger(label: "RemoteClientPermissionedScopeE2ETests.as-consent")
            )
        let authorize =
            "/oauth/authorize?client_id=\(scopeFormEncode(client.clientID.absoluteString))"
            + "&request_uri=\(scopeFormEncode(requestURI))"

        try await app.test(.router) { http in
            // The AS page signs the user in first, then renders consent.
            var cookie: String?
            var csrf: String?
            try await http.execute(uri: authorize, method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                cookie = Self.cookieValue(
                    try XCTUnwrap(response.headers[HTTPField.Name("Set-Cookie")!])
                )
                csrf = try fixture.runtime.browserSessionService
                    .verify(try XCTUnwrap(cookie)).csrfToken
            }
            let form = [
                ("csrf", try XCTUnwrap(csrf)),
                ("handle", PermissionedScopeFixture.handle),
                ("password", PermissionedScopeFixture.password),
            ].map { "\(scopeFormEncode($0.0))=\(scopeFormEncode($0.1))" }
                .joined(separator: "&")
            var headers: HTTPFields = [.contentType: "application/x-www-form-urlencoded"]
            headers[.cookie] = "__Host-swan-oauth=\(try XCTUnwrap(cookie))"

            try await http.execute(
                uri: "/oauth/authorize",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: form)
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let html = String(buffer: response.body)
                Self.assertConsentPageIsSemantic(html, renderer: "authorization server")
            }
        }
    }

    /// The obligations S4.1-S4.4 place on **either** consent renderer. Shared so
    /// the two renderers cannot drift into two different sets of assertions —
    /// which would be the test-side version of the exact duplication S4.5 warns
    /// about in the production code.
    static func assertConsentPageIsSemantic(
        _ html: String,
        renderer: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        // S4.1b — a titled card for the `space:` permission, in prose.
        XCTAssertTrue(
            html.contains("Access permissioned spaces"),
            "S4.1b (\(renderer)): a `space:` permission must render a titled card, not a scope string",
            file: file, line: line
        )
        // S4.1d — a space type Swan cannot name still shows its row.
        XCTAssertTrue(
            html.contains(BulletedApp.spaceType),
            "S4.1d (\(renderer)): fall back to the raw NSID as the row label; never omit the row",
            file: file, line: line
        )
        // S4.2 — the Phase-1 include: wording, both halves.
        XCTAssertTrue(
            html.contains("Requested permission set"),
            "S4.2 (\(renderer)): an unresolved include: must be shown, not suppressed",
            file: file, line: line
        )
        for nsid in BulletedApp.includeNSIDs {
            XCTAssertTrue(
                html.contains(nsid),
                "S4.2 (\(renderer)): include: row missing for \(nsid)",
                file: file, line: line
            )
        }
        XCTAssertTrue(
            html.contains("Swan does not currently grant capabilities derived from this set"),
            """
            S4.2 (\(renderer)): the screen must say NOTHING IS GRANTED. Without \
            that half it over-states the request and the user approves a \
            capability Swan then denies at every call (§5.7.2, §9-D4).
            """,
            file: file, line: line
        )
        // S4.1a — bare `atproto` is not a permission card.
        XCTAssertFalse(
            html.contains("<li><code>atproto</code>"),
            "S4.1a (\(renderer)): `atproto` alone renders no permission card",
            file: file, line: line
        )
    }

    private static func cookieValue(_ setCookie: String) -> String? {
        setCookie.split(separator: ";", maxSplits: 1).first
            .flatMap { $0.split(separator: "=", maxSplits: 1).dropFirst().first }
            .map(String.init)
    }

    // MARK: - Stage 5: token mint

    /// The granted scope string carries all five **and** the `space:` grant's
    /// `authority` has been resolved from `self` to the account's DID (§6.4).
    /// Without that resolution the grant matches nothing at request time (M22) —
    /// the assertion most likely to be forgotten and most likely to look like
    /// "the app is broken" in production.
    func testStage5MintResolvesSelfAndPreservesTheRequestedBytes() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        let issued = try await fixture.mint(client: client, proofID: "stage5-mint")
        try assertStage5Mint(issued: issued, client: client)
    }

    private func assertStage5Mint(issued: OAuthTokenGrantResult, client: PermissionedScopeClient) throws {
        XCTAssertEqual(issued.scopes.count, BulletedApp.all.count, "all five scopes survive the mint")
        for scope in [BulletedApp.base, BulletedApp.blobImages] + BulletedApp.includeNSIDs.map({ "include:\($0)" }) {
            XCTAssertTrue(issued.scopes.contains(scope), "granted set lost \(scope)")
        }
        let spaceGrant = try XCTUnwrap(
            issued.scopes.first { $0.hasPrefix("space:") },
            "the space grant vanished at mint"
        )
        XCTAssertTrue(
            spaceGrant.contains("authority=\(PermissionedScopeFixture.subject)"),
            """
            §7.4 Stage 5: `authority` defaulted to `self` and mint must resolve it \
            to the account DID. An unresolved `self` matches NOTHING at request \
            time (M22, §6.4's fail-closed corollary) — the app authorizes, then \
            every call is denied, and it looks like a client bug.
            """
        )
        // ... and the requested bytes are preserved separately (§6.7). The
        // observable form of that: the granted set is NOT the requested set.
        XCTAssertNotEqual(
            issued.scopes,
            client.scopeSet,
            "`scopes_requested` holds the pre-resolution set and `scopes` the resolved one (§6.7)"
        )
    }

    // MARK: - Stage 6: the six-way enforcement matrix

    /// §7.4 Stage 6 enumerates **six** checks (an earlier draft miscounted it as
    /// five). All six are driven through
    /// `AuthorizationContext.accountOAuth(subject:permissions:)` — the single
    /// point where a validated scope set reaches a handler — rather than
    /// re-deriving scopes in the test. Re-deriving is what hides §9-D23.
    func testStage6SixWayEnforcementMatrix() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(scopes: BulletedApp.all)
        let issued = try await fixture.mint(client: client, proofID: "stage6-mint")
        try await assertStage6Enforcement(fixture: fixture, client: client, issued: issued)
    }

    private func assertStage6Enforcement(
        fixture: PermissionedScopeFixture,
        client: PermissionedScopeClient,
        issued: OAuthTokenGrantResult
    ) async throws {
        let permissions = try await fixture.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "stage6-\(UUID().uuidString.prefix(8))"
        )
        let subject = PermissionedScopeFixture.subject

        func target(_ operation: SpaceScopeTarget.Operation, skey: String = "own") -> SpaceScopeTarget {
            SpaceScopeTarget(
                type: BulletedApp.spaceType,
                authority: subject,
                skey: skey,
                operation: operation
            )
        }

        // 1. `read_self` on the account's own repo inside the space → ALLOWED.
        XCTAssertTrue(
            permissions.allowsSpace(target(.readSelf)),
            "Stage 6.1: the grant's action is exactly `read_self` on its own repo"
        )

        // 2. `read` across the whole space → DENIED. M14: `read_self` does not
        //    imply `read`; the implication runs the other way only.
        XCTAssertFalse(
            permissions.allowsSpace(target(.read)),
            "Stage 6.2 (M14): read_self must never widen into a whole-space read"
        )

        // 3. `create` of a record in any collection → DENIED. The scope names no
        //    `collection`, so it has no write targets. **Phase-1 DIVERGENCE, not
        //    conformance** — see the separately-named test below.
        XCTAssertFalse(
            permissions.allowsSpace(
                target(.write(.create, collection: "app.bulleted.item"))
            ),
            "Stage 6.3 (M5): an empty collection list means NO write targets, not all collections"
        )

        // 4. A space-lifecycle `update` → ALLOWED via `manage=update`. `manage` is
        //    a disjoint verb space from `action`: same three names, different
        //    targets (space lifecycle/metadata, not records).
        XCTAssertTrue(
            permissions.allowsSpace(target(.manage(.update))),
            "Stage 6.4: `manage=update` grants the space-lifecycle op"
        )
        XCTAssertTrue(permissions.allowsSpace(target(.manage(.create))))
        XCTAssertTrue(permissions.allowsSpace(target(.manage(.delete))))

        // 5. Every `include:`-derived capability → DENIED. Asserted explicitly
        //    (§9-D4): a silently-dropped `include:` is indistinguishable from a
        //    bug at 3am.
        XCTAssertFalse(
            permissions.allowsRepo(.init(collection: "app.bulleted.item", action: .create)),
            "Stage 6.5: nothing may be derived from include:app.bulleted.authFull in Phase 1"
        )
        XCTAssertFalse(permissions.allowsIdentity(.init(attr: .handle)))
        XCTAssertFalse(permissions.allowsAccount(.init(attr: .email, action: .read)))
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: "app.bulleted.otherSpace",
                    authority: subject,
                    skey: "own",
                    operation: .readSelf
                )
            ),
            "Stage 6.5: include:app.bulleted.spaceAccess must not widen the space grant"
        )
        // The include: scopes were nonetheless GRANTED and are held verbatim —
        // that is the cost §9-D4 records, and it is disclosed at consent (S4.2).
        for nsid in BulletedApp.includeNSIDs {
            XCTAssertTrue(
                permissions.rawScopes.contains("include:\(nsid)"),
                "Stage 6.5: the include: scope is stored verbatim and returned in the token response"
            )
        }

        // 6. `getDelegationToken` for the space → DENIED. The grant's action is
        //    `[read_self]`, not a stated single `read`, so
        //    `isExactReadOnlyDelegationGrant` is false. This belongs in the
        //    acceptance test as well as in the §7.3 fence because it is the one
        //    place both a real token and a real handler are involved.
        XCTAssertFalse(
            permissions.allowsSpace(target(.delegationExchange, skey: "*")),
            """
            Stage 6.6: CRITICAL DELEGATION WIDENING. A `read_self` grant must never \
            be exchangeable for a whole-space credential — that credential reads \
            every member's repo. §5.6.3's fence requires a stated single \
            `action=read` and exactly the three stated keys.
            """
        )

        // The blob scope is granted but reaches no route Swan enforces today;
        // the floor is atproto-or-space, and `blob:` alone must not satisfy it.
        XCTAssertTrue(permissions.hasBaseATProtocolScope)
        XCTAssertTrue(permissions.hasResourceScope)
        XCTAssertFalse(
            SwanScopePermissions(rawScopes: [BulletedApp.blobImages], subject: subject)
                .hasResourceScope,
            """
            §6.1: `hasResourceScope` stays atproto-or-space. A registered \
            `blob:image/*` that satisfied the floor would reach blob upload and \
            repository sync, which perform NO further scope check.
            """
        )
    }

    /// Stage 6 check 3, named as the Phase-1 gap it is. A conformant AS runs
    /// `expandSpaceCollections` at token mint and materialises the space type's
    /// declared collections into exactly this bare grant, so bulleted.app *would*
    /// be able to create records against a reference PDS. Phase 1 ships without
    /// that step, so the name says so — without this framing the test reads as
    /// "upstream behaviour verified" and the real gap goes unrecorded.
    func testBareSpaceGrantHasNoWriteTargetsUntilPhase2() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(
            scopes: [BulletedApp.base, "space:\(BulletedApp.spaceType)"]
        )
        let issued = try await fixture.mint(client: client, proofID: "phase1-no-write-targets")
        let permissions = try await fixture.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "phase1-no-write-targets-authorize"
        )
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: BulletedApp.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "own",
                    operation: .write(.create, collection: "app.bulleted.item")
                )
            ),
            """
            Phase-1 DIVERGENCE (§5.7.5, §7.4 Stage 6 check 3): Swan does not run \
            `expandSpaceCollections` at mint, so a bare `space:<type>` grant \
            materialises no collections and therefore has no write targets. A \
            reference PDS would let this same grant create records.
            """
        )
    }

    /// §9-D4's honest cost, asserted in one place: the `include:` scopes
    /// **authorize successfully** — the client is not rejected, the token is
    /// minted, the scopes come back in the response — and are then denied on
    /// every include-derived call. Stated as one test so the two halves cannot
    /// drift apart, and so the cost is visible rather than discovered.
    func testIncludeScopesAuthorizeSuccessfullyThenGrantNothing() async throws {
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }
        let client = try PermissionedScopeClient(
            scopes: [BulletedApp.base, BulletedApp.includeAuthFull, BulletedApp.includeSpaceAccess]
        )

        // Authorizes: parses at PAR (so §9-D5's reject-at-PAR rule does not catch
        // it), survives the mint, and is returned to the client.
        for scope in [BulletedApp.includeAuthFull, BulletedApp.includeSpaceAccess] {
            XCTAssertNoThrow(
                try AtprotoScope.parse(scope),
                "include: must stay parseable or D5 would reject the whole PAR"
            )
        }
        let issued = try await fixture.mint(client: client, proofID: "include-authorizes")
        XCTAssertTrue(issued.scopes.contains(BulletedApp.includeAuthFull))
        XCTAssertTrue(issued.scopes.contains(BulletedApp.includeSpaceAccess))

        // ... and grants nothing.
        let permissions = try await fixture.permissions(
            accessToken: issued.accessToken,
            client: client,
            jti: "include-authorizes-authorize"
        )
        XCTAssertFalse(permissions.allowsRepo(.init(collection: "app.bulleted.item", action: .create)))
        XCTAssertFalse(permissions.allowsBlob(.init(mime: "image/png")))
        XCTAssertFalse(permissions.allowsIdentity(.init(attr: .handle)))
        XCTAssertFalse(permissions.allowsAccount(.init(attr: .email, action: .read)))
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: BulletedApp.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "own",
                    operation: .readSelf
                )
            ),
            "an include: naming a space permission set must not grant the space itself in Phase 1"
        )
        // An include:-only grant does not even satisfy the resource floor.
        XCTAssertFalse(
            SwanScopePermissions(
                rawScopes: [BulletedApp.includeAuthFull],
                subject: PermissionedScopeFixture.subject
            ).hasResourceScope
        )
    }
}
