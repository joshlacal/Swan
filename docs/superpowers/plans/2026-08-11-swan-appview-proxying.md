# Swan AppView Proxying — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the `app.bsky.*` surface Swan does not implement by proxying to an AppView with per-account service auth, plus local preferences storage, so a signed-in swan.place account works in Catbird and other AT Protocol clients.

**Architecture:** A `/xrpc/*` fallback that fires only when no local Swan route matched. Routing is a pure function (NSID + `atproto-proxy` header → target service); resolution, JWT minting, and forwarding are separate units behind it. All outbound traffic reuses Swan's existing resolve → policy-check → pin discipline.

**Tech Stack:** Swift 6, Hummingbird 2, SQLiteNIO, swift-crypto (P256/ES256), XCTest + HummingbirdTesting.

**Spec:** `docs/superpowers/specs/2026-08-11-swan-appview-proxying-design.md`

## Global Constraints

- Local Swan routes always win; `com.atproto.space.*` and `blue.catbird.*` are never proxied even if unmatched.
- Proxying requires an authenticated account. Unauthenticated → 401.
- Default AppView: DID `did:web:api.bsky.app`, service fragment `bsky_appview`, endpoint `https://api.bsky.app`. Configurable by CLI flag.
- A malformed/unresolvable `atproto-proxy` header is a **400** — never a silent fallback to the default AppView.
- Ozone/moderation lexicons are unrouted (404). Do not default them to the AppView.
- Inbound `Authorization`, `Cookie`, and any DPoP header MUST be stripped before forwarding. Only an explicit allow-list is forwarded.
- Outbound requests are https-only and MUST go through the existing peer-pinning path (`OAuthRemoteFetchPolicy` + `OAuthHostnameResolving` + a pinned transport). Do not introduce a plain HTTP client. Peer-pinning is an SSRF/DNS-rebinding control, not a host allow-list — it already permits arbitrary public hosts.
- Preferences are stored as plaintext JSON keyed by account DID, scoped strictly to the authenticated account.
- Swift 6 strict concurrency: all shared types `Sendable`. 2-space indentation in `SwanHTTP` (match surrounding file style; `SwanOAuth`/`SwanStorage` use 4).
- Run `swiftformat` per repo config before each commit.
- Do not hand-edit generated lexicon types.

---

### Task 1: Proxy routing decision (pure)

The routing decision is pure and I/O-free so every branch is unit-testable without a network.

**Files:**
- Create: `Sources/SwanHTTP/SwanXRPCProxyRouting.swift`
- Test: `Tests/SwanHTTPTests/SwanXRPCProxyRoutingTests.swift`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `public enum SwanXRPCProxyRoute: Sendable, Equatable { case configuredAppView(did: String); case resolvedService(did: String, fragment: String) }`
  - `public enum SwanXRPCProxyRoutingFailure: Error, Sendable, Equatable { case denied; case unrouted; case malformedProxyHeader }`
  - `public struct SwanXRPCProxyRouter: Sendable { public init(appViewDID: String); public func route(nsid: String, proxyHeader: String?) throws -> SwanXRPCProxyRoute }`

- [ ] **Step 1: Write the failing tests**

```swift
import XCTest

@testable import SwanHTTP

final class SwanXRPCProxyRoutingTests: XCTestCase {
  private let router = SwanXRPCProxyRouter(appViewDID: "did:web:api.bsky.app")

  func testAppBskyDefaultsToConfiguredAppView() throws {
    let route = try router.route(nsid: "app.bsky.actor.getProfile", proxyHeader: nil)
    XCTAssertEqual(route, .configuredAppView(did: "did:web:api.bsky.app"))
  }

  func testSwanOwnedNamespacesAreDeniedEvenWithoutLocalRoute() {
    for nsid in ["com.atproto.space.listSpaces", "blue.catbird.mlsChat.getConvos"] {
      XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
        XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
      }
    }
  }

  func testDenyListWinsOverExplicitProxyHeader() {
    XCTAssertThrowsError(
      try router.route(
        nsid: "com.atproto.space.listSpaces",
        proxyHeader: "did:web:evil.example#bsky_appview")
    ) { error in
      XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
    }
  }

  func testOzoneAndUnknownNamespacesAreUnrouted() {
    for nsid in ["tools.ozone.moderation.emitEvent", "com.example.custom.method"] {
      XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
        XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted)
      }
    }
  }

  func testExplicitProxyHeaderNamingConfiguredAppViewSkipsResolution() throws {
    let route = try router.route(
      nsid: "app.bsky.actor.getProfile",
      proxyHeader: "did:web:api.bsky.app#bsky_appview")
    XCTAssertEqual(route, .configuredAppView(did: "did:web:api.bsky.app"))
  }

  func testExplicitProxyHeaderForOtherServiceRequiresResolution() throws {
    let route = try router.route(
      nsid: "app.bsky.actor.getProfile",
      proxyHeader: "did:web:labeler.example#atproto_labeler")
    XCTAssertEqual(
      route, .resolvedService(did: "did:web:labeler.example", fragment: "atproto_labeler"))
  }

  // An explicit header for a lexicon that has no default route is still honoured:
  // the client asked for a specific service, so "unrouted" does not apply.
  func testExplicitProxyHeaderHonouredForOtherwiseUnroutedLexicon() throws {
    let route = try router.route(
      nsid: "tools.ozone.moderation.emitEvent",
      proxyHeader: "did:web:mod.example#atproto_labeler")
    XCTAssertEqual(route, .resolvedService(did: "did:web:mod.example", fragment: "atproto_labeler"))
  }

  func testMalformedProxyHeaderIsRejectedAndNeverFallsBack() {
    // Each of these must fail closed rather than silently using the AppView.
    let malformed = [
      "",                              // empty
      "did:web:api.bsky.app",          // no fragment
      "#bsky_appview",                 // no DID
      "did:web:api.bsky.app#",         // empty fragment
      "not-a-did#bsky_appview",        // not a DID
      "did:web:api.bsky.app#a#b",      // two fragments
      "did:web:api.bsky.app #frag",    // whitespace
    ]
    for header in malformed {
      XCTAssertThrowsError(
        try router.route(nsid: "app.bsky.actor.getProfile", proxyHeader: header),
        "expected rejection for \(header)"
      ) { error in
        XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .malformedProxyHeader)
      }
    }
  }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanXRPCProxyRoutingTests`
Expected: FAIL — `cannot find 'SwanXRPCProxyRouter' in scope`.

- [ ] **Step 3: Implement the router**

```swift
import Foundation

/// Where a proxied XRPC request should be sent.
public enum SwanXRPCProxyRoute: Sendable, Equatable {
  /// The configured AppView. Its endpoint is known from configuration, so no
  /// DID document resolution is needed.
  case configuredAppView(did: String)
  /// Some other service: resolve this DID's document and select the service
  /// entry whose id matches `fragment`.
  case resolvedService(did: String, fragment: String)
}

public enum SwanXRPCProxyRoutingFailure: Error, Sendable, Equatable {
  /// A Swan-owned namespace. Never leaves this host.
  case denied
  /// No default route and no explicit target.
  case unrouted
  /// `atproto-proxy` was present but unusable. Deliberately NOT a fallback to
  /// the default: forwarding to a service the client did not name would send
  /// the account's traffic somewhere it did not ask for.
  case malformedProxyHeader
}

/// Decides where an XRPC request goes. Pure: no I/O, no network.
///
/// Only consulted when no local Swan route matched, so local routes always
/// win. The deny-list is deliberately redundant with that ordering — a future
/// refactor that drops or renames a local route must not silently begin
/// forwarding Swan-owned traffic to a third party.
public struct SwanXRPCProxyRouter: Sendable {
  private static let deniedPrefixes = ["com.atproto.space.", "blue.catbird."]
  private static let appViewPrefix = "app.bsky."

  private let appViewDID: String

  public init(appViewDID: String) {
    self.appViewDID = appViewDID
  }

  public func route(nsid: String, proxyHeader: String?) throws -> SwanXRPCProxyRoute {
    // Deny-list first: an explicit header must never override it.
    guard !Self.deniedPrefixes.contains(where: { nsid.hasPrefix($0) }) else {
      throw SwanXRPCProxyRoutingFailure.denied
    }
    if let proxyHeader {
      let (did, fragment) = try Self.parseProxyHeader(proxyHeader)
      if did == appViewDID { return .configuredAppView(did: did) }
      return .resolvedService(did: did, fragment: fragment)
    }
    guard nsid.hasPrefix(Self.appViewPrefix) else {
      throw SwanXRPCProxyRoutingFailure.unrouted
    }
    return .configuredAppView(did: appViewDID)
  }

  private static func parseProxyHeader(_ value: String) throws -> (did: String, fragment: String) {
    let parts = value.split(separator: "#", omittingEmptySubsequences: false)
    guard parts.count == 2 else { throw SwanXRPCProxyRoutingFailure.malformedProxyHeader }
    let did = String(parts[0])
    let fragment = String(parts[1])
    guard !did.isEmpty, !fragment.isEmpty,
      did.hasPrefix("did:"), did.utf8.count <= 2_048, fragment.utf8.count <= 512,
      did.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }),
      fragment.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f })
    else { throw SwanXRPCProxyRoutingFailure.malformedProxyHeader }
    return (did, fragment)
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanXRPCProxyRoutingTests`
Expected: PASS, all cases.

- [ ] **Step 5: Format and commit**

```bash
swiftformat Sources/SwanHTTP/SwanXRPCProxyRouting.swift Tests/SwanHTTPTests/SwanXRPCProxyRoutingTests.swift
jj describe -m "SwanHTTP: XRPC proxy routing decision"
jj new
```

---

### Task 2: Service-auth JWT for arbitrary NSIDs

`SpaceServiceJWT.create` rejects any method not prefixed `com.atproto.` (`SpaceServiceAuthentication.swift:484-491`), so it cannot mint tokens for `app.bsky.*`. Do **not** loosen that validator: it guards Swan's own space-service path. Add a separate minting entry point for proxy tokens.

Swan only *creates* these tokens (the AppView verifies them), so a wider method space here does not weaken any inbound verification Swan performs.

**Files:**
- Create: `Sources/SwanOAuth/ProxyServiceAuthentication.swift`
- Test: `Tests/SwanOAuthTests/ProxyServiceAuthenticationTests.swift`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `public enum ProxyServiceJWT { public static func create(issuer: String, audience: String, method: String, eventID: String, key: P256.Signing.PrivateKey, now: Date = Date(), lifetime: TimeInterval = 60) throws -> String }`

- [ ] **Step 1: Write the failing tests**

```swift
import Crypto
import Foundation
import XCTest

@testable import SwanOAuth

final class ProxyServiceAuthenticationTests: XCTestCase {
  private let key = P256.Signing.PrivateKey()
  private let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
  private let audience = "did:web:api.bsky.app"

  private func claims(_ compact: String) throws -> [String: Any] {
    let parts = compact.split(separator: ".")
    XCTAssertEqual(parts.count, 3)
    var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    let data = try XCTUnwrap(Data(base64Encoded: b64))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }

  func testMintsTokenForAppBskyMethod() throws {
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    let compact = try ProxyServiceJWT.create(
      issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
      eventID: "abc123", key: key, now: now, lifetime: 60)
    let payload = try claims(compact)
    XCTAssertEqual(payload["iss"] as? String, issuer)
    XCTAssertEqual(payload["aud"] as? String, audience)
    XCTAssertEqual(payload["lxm"] as? String, "app.bsky.actor.getProfile")
    XCTAssertEqual(payload["jti"] as? String, "abc123")
    XCTAssertEqual(payload["iat"] as? Int64, 1_700_000_000)
    XCTAssertEqual(payload["exp"] as? Int64, 1_700_000_060)
  }

  func testSignatureVerifiesAgainstIssuerKey() throws {
    let compact = try ProxyServiceJWT.create(
      issuer: issuer, audience: audience, method: "app.bsky.feed.getTimeline",
      eventID: "j1", key: key)
    let parts = compact.split(separator: ".")
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    var b64 = String(parts[2]).replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    let raw = try XCTUnwrap(Data(base64Encoded: b64))
    let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
    XCTAssertTrue(key.publicKey.isValidSignature(signature, for: signingInput))
  }

  func testRejectsMalformedInputs() {
    // Non-NSID methods, bad DIDs, and out-of-range lifetimes must not mint.
    XCTAssertThrowsError(
      try ProxyServiceJWT.create(
        issuer: issuer, audience: audience, method: "not an nsid", eventID: "j", key: key))
    XCTAssertThrowsError(
      try ProxyServiceJWT.create(
        issuer: "nope", audience: audience, method: "app.bsky.actor.getProfile",
        eventID: "j", key: key))
    XCTAssertThrowsError(
      try ProxyServiceJWT.create(
        issuer: issuer, audience: "", method: "app.bsky.actor.getProfile",
        eventID: "j", key: key))
    XCTAssertThrowsError(
      try ProxyServiceJWT.create(
        issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
        eventID: "j", key: key, lifetime: 0))
    XCTAssertThrowsError(
      try ProxyServiceJWT.create(
        issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
        eventID: "j", key: key, lifetime: 3_600))
  }

  func testCollectionOfMethodsAcceptedAcrossNamespaces() throws {
    for method in [
      "app.bsky.actor.getProfile", "app.bsky.feed.getTimeline",
      "tools.ozone.moderation.emitEvent", "com.atproto.repo.getRecord",
    ] {
      XCTAssertNoThrow(
        try ProxyServiceJWT.create(
          issuer: issuer, audience: audience, method: method, eventID: "j", key: key))
    }
  }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter ProxyServiceAuthenticationTests`
Expected: FAIL — `cannot find 'ProxyServiceJWT' in scope`.

- [ ] **Step 3: Implement the minter**

```swift
import Crypto
import Foundation
import SwanCore

/// Inter-service auth for proxied XRPC, mirroring
/// `com.atproto.server.getServiceAuth`.
///
/// Deliberately separate from `SpaceServiceJWT`, whose method validator is
/// restricted to `com.atproto.*` to guard Swan's own space-service path.
/// Widening that validator would loosen a control on traffic Swan *verifies*;
/// this type only *mints* tokens that a remote service verifies, so a general
/// NSID space here weakens nothing on this host.
public enum ProxyServiceJWT {
  public static let maximumLifetime: TimeInterval = 60

  private struct Header: Encodable {
    let alg = "ES256"
    let typ = "JWT"
  }

  private struct Claims: Encodable {
    let iss: String
    let aud: String
    let lxm: String
    let jti: String
    let iat: Int64
    let exp: Int64
  }

  public static func create(
    issuer: String,
    audience: String,
    method: String,
    eventID: String,
    key: P256.Signing.PrivateKey,
    now: Date = Date(),
    lifetime: TimeInterval = maximumLifetime
  ) throws -> String {
    guard isValidDID(issuer),
      isPrintable(audience, maximumBytes: 4_096),
      isValidNSID(method),
      isPrintable(eventID, maximumBytes: 256),
      lifetime > 0, lifetime <= maximumLifetime,
      lifetime.rounded(.towardZero) == lifetime,
      now.timeIntervalSince1970.isFinite
    else {
      throw SwanError.malformed("proxy service authentication claims are invalid")
    }
    let iat = Int64(now.timeIntervalSince1970.rounded(.towardZero))
    let (exp, overflow) = iat.addingReportingOverflow(Int64(lifetime))
    guard !overflow else {
      throw SwanError.malformed("proxy service authentication expiry is invalid")
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let header = try encoder.encode(Header())
    let claims = try encoder.encode(
      Claims(iss: issuer, aud: audience, lxm: method, jti: eventID, iat: iat, exp: exp))
    let signingInput = "\(base64URL(header)).\(base64URL(claims))"
    let signature = try key.signature(for: Data(signingInput.utf8))
    return "\(signingInput).\(base64URL(signature.rawRepresentation))"
  }

  private static func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func isPrintable(_ value: String, maximumBytes: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= maximumBytes
      && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
  }

  private static func isValidDID(_ value: String) -> Bool {
    value.hasPrefix("did:") && isPrintable(value, maximumBytes: 2_048)
      && !value.contains("#")
  }

  /// Dotted segments of alphanumerics/hyphen, at least three segments.
  private static func isValidNSID(_ value: String) -> Bool {
    guard value.utf8.count <= 317 else { return false }
    let segments = value.split(separator: ".", omittingEmptySubsequences: false)
    guard segments.count >= 3 else { return false }
    return segments.allSatisfy { segment in
      !segment.isEmpty
        && segment.utf8.allSatisfy {
          ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
            || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
            || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
            || $0 == UInt8(ascii: "-")
        }
    }
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter ProxyServiceAuthenticationTests`
Expected: PASS.

- [ ] **Step 5: Confirm the existing space validator is untouched**

Run: `xcrun --toolchain XcodeDefault swift test --filter SpaceServiceAuthentication`
Expected: PASS — no regression in the existing service-auth path.

- [ ] **Step 6: Format and commit**

```bash
swiftformat Sources/SwanOAuth/ProxyServiceAuthentication.swift Tests/SwanOAuthTests/ProxyServiceAuthenticationTests.swift
jj describe -m "SwanOAuth: service-auth JWT minting for proxied XRPC methods"
jj new
```

---

### Task 3: Service endpoint resolution

Resolves `resolvedService(did:fragment:)` to an https endpoint. Reuses `OAuthRemoteDocumentFetcher`, which already performs resolve → policy-check → pin → GET, so no new outbound path is introduced.

**Files:**
- Create: `Sources/SwanOAuth/SwanServiceEndpointResolver.swift`
- Test: `Tests/SwanOAuthTests/SwanServiceEndpointResolverTests.swift`

**Interfaces:**
- Consumes: `SwanXRPCProxyRoute` (Task 1) — conceptually; this task takes `did`/`fragment` strings directly.
- Produces:
  - `public protocol SwanDIDDocumentFetching: Sendable { func documentJSON(forDID did: String) async throws -> Data }`
  - `public struct SwanServiceEndpointResolver: Sendable { public init(documents: any SwanDIDDocumentFetching); public func endpoint(did: String, fragment: String) async throws -> URL }`
  - `public enum SwanServiceResolutionFailure: Error, Sendable, Equatable { case unresolvableService }`

- [ ] **Step 1: Write the failing tests**

```swift
import Foundation
import XCTest

@testable import SwanOAuth

private struct StubDocuments: SwanDIDDocumentFetching {
  let json: String
  func documentJSON(forDID did: String) async throws -> Data { Data(json.utf8) }
}

private struct FailingDocuments: SwanDIDDocumentFetching {
  struct Boom: Error {}
  func documentJSON(forDID did: String) async throws -> Data { throw Boom() }
}

final class SwanServiceEndpointResolverTests: XCTestCase {
  private func resolver(_ json: String) -> SwanServiceEndpointResolver {
    SwanServiceEndpointResolver(documents: StubDocuments(json: json))
  }

  private let document = """
    {"id":"did:web:api.bsky.app","service":[
      {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://api.bsky.app"},
      {"id":"#other","type":"Other","serviceEndpoint":"https://other.example"}]}
    """

  func testSelectsServiceByFragment() async throws {
    let url = try await resolver(document).endpoint(
      did: "did:web:api.bsky.app", fragment: "bsky_appview")
    XCTAssertEqual(url, URL(string: "https://api.bsky.app")!)
  }

  func testAcceptsFullyQualifiedServiceID() async throws {
    let json = """
      {"id":"did:web:x.example","service":[
        {"id":"did:web:x.example#bsky_appview","type":"BskyAppView",
         "serviceEndpoint":"https://x.example"}]}
      """
    let url = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
    XCTAssertEqual(url, URL(string: "https://x.example")!)
  }

  func testMissingFragmentIsUnresolvable() async {
    do {
      _ = try await resolver(document).endpoint(
        did: "did:web:api.bsky.app", fragment: "nope")
      XCTFail("expected failure")
    } catch {
      XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
    }
  }

  func testNonHTTPSEndpointIsRejected() async {
    let json = """
      {"id":"did:web:x.example","service":[
        {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"http://x.example"}]}
      """
    do {
      _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
      XCTFail("expected failure")
    } catch {
      XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
    }
  }

  func testMalformedDocumentIsUnresolvable() async {
    for json in ["{}", "not json", #"{"service":[]}"#, #"{"service":"nope"}"#] {
      do {
        _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
        XCTFail("expected failure for \(json)")
      } catch {
        XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
      }
    }
  }

  func testFetchFailureIsUnresolvable() async {
    do {
      _ = try await SwanServiceEndpointResolver(documents: FailingDocuments())
        .endpoint(did: "did:web:x.example", fragment: "bsky_appview")
      XCTFail("expected failure")
    } catch {
      XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
    }
  }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanServiceEndpointResolverTests`
Expected: FAIL — `cannot find 'SwanServiceEndpointResolver' in scope`.

- [ ] **Step 3: Implement the resolver**

```swift
import Foundation

/// Supplies a DID document as raw JSON. Implementations must fetch through
/// Swan's peer-pinned path; this protocol exists so resolution logic is
/// testable without a network.
public protocol SwanDIDDocumentFetching: Sendable {
  func documentJSON(forDID did: String) async throws -> Data
}

public enum SwanServiceResolutionFailure: Error, Sendable, Equatable {
  case unresolvableService
}

/// Resolves a `did#fragment` service reference to its https endpoint.
///
/// Every failure collapses to `.unresolvableService`: the caller turns that
/// into a 400, and distinguishing "no such DID" from "no such fragment" would
/// leak remote lookup detail without helping a legitimate client.
public struct SwanServiceEndpointResolver: Sendable {
  private struct Document: Decodable {
    struct Service: Decodable {
      let id: String
      let serviceEndpoint: String
    }
    let service: [Service]?
  }

  private let documents: any SwanDIDDocumentFetching

  public init(documents: any SwanDIDDocumentFetching) {
    self.documents = documents
  }

  public func endpoint(did: String, fragment: String) async throws -> URL {
    let data: Data
    do {
      data = try await documents.documentJSON(forDID: did)
    } catch {
      throw SwanServiceResolutionFailure.unresolvableService
    }
    guard let document = try? JSONDecoder().decode(Document.self, from: data),
      let services = document.service
    else { throw SwanServiceResolutionFailure.unresolvableService }
    // A service id may be written "#frag" or "did:...#frag".
    guard
      let match = services.first(where: {
        $0.id == "#\(fragment)" || $0.id == "\(did)#\(fragment)"
      }),
      let url = URL(string: match.serviceEndpoint),
      url.scheme?.lowercased() == "https",
      let host = url.host, !host.isEmpty,
      url.user == nil, url.password == nil
    else { throw SwanServiceResolutionFailure.unresolvableService }
    return url
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanServiceEndpointResolverTests`
Expected: PASS.

- [ ] **Step 5: Format and commit**

```bash
swiftformat Sources/SwanOAuth/SwanServiceEndpointResolver.swift Tests/SwanOAuthTests/SwanServiceEndpointResolverTests.swift
jj describe -m "SwanOAuth: resolve did#fragment service references to https endpoints"
jj new
```

---

### Task 4: Peer-pinned proxy transport (GET and POST)

The existing `OAuthRemoteTransport` exposes only `get`. Proxying needs POST as well (e.g. `app.bsky.graph.muteActor`). Add a transport that supports both while going through the same resolve → policy-check → pin path.

**Read first:** `Sources/SwanOAuth/NIOPeerPinnedOAuthPostTransport.swift` — a POST transport already exists for OAuth and is the template. Reuse its channel setup rather than writing new NIO plumbing.

**Files:**
- Create: `Sources/SwanOAuth/SwanProxyHTTPTransport.swift`
- Test: `Tests/SwanOAuthTests/SwanProxyHTTPTransportTests.swift`

**Interfaces:**
- Consumes: `OAuthIPAddress`, `OAuthRemoteHTTPResponse`, `OAuthRemoteFetchPolicy`, `OAuthHostnameResolving` (existing, `SwanOAuth`).
- Produces:
  - `public struct SwanProxyRequest: Sendable { public let method: String; public let url: URL; public let headers: [(name: String, value: String)]; public let body: Data? }`
  - `public protocol SwanProxySending: Sendable { func send(_ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int) async throws -> OAuthRemoteHTTPResponse }`
  - `public struct SwanPeerPinnedProxySender: SwanProxySending { public init(policy: OAuthRemoteFetchPolicy, resolver: any OAuthHostnameResolving, transport: any SwanProxyTransporting) }`
  - `public protocol SwanProxyTransporting: Sendable { func send(_ request: SwanProxyRequest, approvedPeers: Set<OAuthIPAddress>, timeout: TimeInterval, maximumBodyBytes: Int) async throws -> OAuthRemoteHTTPResponse }`

- [ ] **Step 1: Write the failing tests**

These cover the *policy* layer — that the sender validates and pins before handing off. The NIO transport itself is exercised in Task 7's live verification.

```swift
import Foundation
import XCTest

@testable import SwanOAuth

private actor RecordingTransport: SwanProxyTransporting {
  private(set) var approved: Set<OAuthIPAddress> = []
  private(set) var sent: SwanProxyRequest?

  func send(
    _ request: SwanProxyRequest, approvedPeers: Set<OAuthIPAddress>,
    timeout: TimeInterval, maximumBodyBytes: Int
  ) async throws -> OAuthRemoteHTTPResponse {
    approved = approvedPeers
    sent = request
    return OAuthRemoteHTTPResponse(status: 200, headers: [], body: Data("{}".utf8))
  }
  func recorded() -> (Set<OAuthIPAddress>, SwanProxyRequest?) { (approved, sent) }
}

private struct StubResolver: OAuthHostnameResolving {
  let addresses: [OAuthIPAddress]
  func resolve(host: String) async throws -> [OAuthIPAddress] { addresses }
}

final class SwanProxyHTTPTransportTests: XCTestCase {
  private func sender(
    resolving addresses: [String], transport: any SwanProxyTransporting
  ) -> SwanPeerPinnedProxySender {
    SwanPeerPinnedProxySender(
      policy: OAuthRemoteFetchPolicy(),
      resolver: StubResolver(addresses: addresses.compactMap(OAuthIPAddress.init(literal:))),
      transport: transport)
  }

  func testPinsResolvedPublicAddress() async throws {
    let transport = RecordingTransport()
    let sender = sender(resolving: ["93.184.216.34"], transport: transport)
    _ = try await sender.send(
      SwanProxyRequest(
        method: "GET", url: URL(string: "https://api.bsky.app/xrpc/app.bsky.actor.getProfile")!,
        headers: [], body: nil),
      timeout: 5, maximumBodyBytes: 1_000_000)
    let (approved, sent) = await transport.recorded()
    XCTAssertEqual(approved, Set([OAuthIPAddress(literal: "93.184.216.34")!]))
    XCTAssertEqual(sent?.method, "GET")
  }

  func testRejectsPrivateAndReservedAddresses() async {
    // Each of these must fail closed: a hostile service DID whose DNS answers
    // with an internal address must never be connected to.
    for address in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"] {
      let sender = sender(resolving: [address], transport: RecordingTransport())
      do {
        _ = try await sender.send(
          SwanProxyRequest(
            method: "GET", url: URL(string: "https://evil.example/xrpc/x")!, headers: [], body: nil),
          timeout: 5, maximumBodyBytes: 1_000)
        XCTFail("expected rejection for \(address)")
      } catch {}
    }
  }

  func testRejectsNonHTTPSURL() async {
    let sender = sender(resolving: ["93.184.216.34"], transport: RecordingTransport())
    do {
      _ = try await sender.send(
        SwanProxyRequest(
          method: "GET", url: URL(string: "http://api.bsky.app/xrpc/x")!, headers: [], body: nil),
        timeout: 5, maximumBodyBytes: 1_000)
      XCTFail("expected rejection")
    } catch {}
  }

  func testRejectsUnsupportedMethod() async {
    let sender = sender(resolving: ["93.184.216.34"], transport: RecordingTransport())
    for method in ["DELETE", "PUT", "CONNECT"] {
      do {
        _ = try await sender.send(
          SwanProxyRequest(
            method: method, url: URL(string: "https://api.bsky.app/xrpc/x")!, headers: [],
            body: nil),
          timeout: 5, maximumBodyBytes: 1_000)
        XCTFail("expected rejection for \(method)")
      } catch {}
    }
  }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanProxyHTTPTransportTests`
Expected: FAIL — `cannot find 'SwanPeerPinnedProxySender' in scope`.

- [ ] **Step 3: Implement the sender**

```swift
import Foundation
import SwanCore

public struct SwanProxyRequest: Sendable {
  public let method: String
  public let url: URL
  public let headers: [(name: String, value: String)]
  public let body: Data?

  public init(method: String, url: URL, headers: [(name: String, value: String)], body: Data?) {
    self.method = method
    self.url = url
    self.headers = headers
    self.body = body
  }
}

/// Opens the socket to an already-approved peer literal.
public protocol SwanProxyTransporting: Sendable {
  func send(
    _ request: SwanProxyRequest, approvedPeers: Set<OAuthIPAddress>,
    timeout: TimeInterval, maximumBodyBytes: Int
  ) async throws -> OAuthRemoteHTTPResponse
}

public protocol SwanProxySending: Sendable {
  func send(
    _ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int
  ) async throws -> OAuthRemoteHTTPResponse
}

/// Validates the URL, resolves the host, policy-checks every resolved literal,
/// and pins the connection to them.
///
/// This is the same resolve → policy-check → pin discipline the OAuth document
/// fetcher uses. It is an SSRF and DNS-rebinding control, not a host
/// allow-list: arbitrary public hosts are permitted, which is what lets the
/// proxy reach any AppView, labeler, or feed service.
public struct SwanPeerPinnedProxySender: SwanProxySending {
  private static let permittedMethods: Set<String> = ["GET", "POST"]

  private let policy: OAuthRemoteFetchPolicy
  private let resolver: any OAuthHostnameResolving
  private let transport: any SwanProxyTransporting

  public init(
    policy: OAuthRemoteFetchPolicy,
    resolver: any OAuthHostnameResolving,
    transport: any SwanProxyTransporting
  ) {
    self.policy = policy
    self.resolver = resolver
    self.transport = transport
  }

  public func send(
    _ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int
  ) async throws -> OAuthRemoteHTTPResponse {
    guard Self.permittedMethods.contains(request.method) else {
      throw SwanError.malformed("proxied method is not permitted")
    }
    let host = try policy.validateURL(request.url)
    let resolved = try await resolver.resolve(host: host)
    try policy.validateResolved(resolved, host: host)
    return try await transport.send(
      request, approvedPeers: Set(resolved), timeout: timeout,
      maximumBodyBytes: maximumBodyBytes)
  }
}
```

- [ ] **Step 4: Implement the NIO transport**

Add `SwanNIOPeerPinnedProxyTransport: SwanProxyTransporting` in the same file, modelled directly on `NIOPeerPinnedOAuthPostTransport`: pick the lowest-sorted approved peer deterministically, connect to that literal, set SNI to the URL hostname so certificate name verification still applies, write the method/path/headers/body, and cap the response at `maximumBodyBytes`.

Do not copy the OAuth transport's body — factor the shared channel setup if it is cleanly separable, and otherwise keep the duplication minimal and comment why.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanProxyHTTPTransportTests`
Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
swiftformat Sources/SwanOAuth/SwanProxyHTTPTransport.swift Tests/SwanOAuthTests/SwanProxyHTTPTransportTests.swift
jj describe -m "SwanOAuth: peer-pinned GET/POST transport for XRPC proxying"
jj new
```

---

### Task 5: Account preferences store and routes

Independent of the proxy path. `getPreferences`/`putPreferences` cannot be proxied — the AppView does not store them, and forwarding would silently discard the user's saved feeds and content settings.

**Files:**
- Create: `Sources/SwanStorage/ActorPreferencesStore.swift`
- Create: `Sources/SwanSQLite/ActorPreferencesStore.swift`
- Create: `Sources/SwanHTTP/SwanActorPreferencesXRPC.swift`
- Test: `Tests/SwanHTTPTests/SwanActorPreferencesXRPCTests.swift`

**Interfaces:**
- Consumes: the existing DPoP resource-authorization pattern. Read `Sources/SwanHTTP/SwanAccountEmailXRPC.swift:760` (`authorizedSubject(request:path:now:)`) and mirror it exactly — same authorizer protocol, same failure mapping.
- Produces:
  - `public protocol ActorPreferencesStore: Sendable { func actorPreferences(did: String) async throws -> Data?; func setActorPreferences(did: String, json: Data) async throws }`
  - `public func registerSwanActorPreferencesXRPC(on router: Router<SwanHTTPRequestContext>, ...)`

- [ ] **Step 1: Write the failing tests**

```swift
import Foundation
import HummingbirdTesting
import XCTest

@testable import SwanHTTP

final class SwanActorPreferencesXRPCTests: XCTestCase, @unchecked Sendable {
  // Build the app with a signed-in account, following the harness used by
  // AccountEmailXRPCTests.

  func testUnwrittenPreferencesReturnEmptyArray() async throws {
    // GET /xrpc/app.bsky.actor.getPreferences for an account that never wrote
    // preferences returns {"preferences":[]} and 200 — never 404, which would
    // make a client treat the account as broken.
  }

  func testRoundTripsWrittenPreferences() async throws {
    // PUT then GET returns exactly what was written.
  }

  func testRejectsUnauthenticatedRequests() async throws {
    // Both routes without a session → 401.
  }

  func testOneAccountCannotReadAnothersPreferences() async throws {
    // Account B's session must never observe account A's preferences.
  }

  func testRejectsMalformedPreferencesBody() async throws {
    // Non-JSON, and JSON whose "preferences" is not an array → 400.
  }
}
```

Fill each body using the setup in `Tests/SwanHTTPTests/AccountEmailXRPCTests.swift`; that file already builds an app with an authenticated account and is the correct template.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanActorPreferencesXRPCTests`
Expected: FAIL — routes return 404.

- [ ] **Step 3: Implement the storage protocol and schema**

Follow `Sources/SwanSQLite/AccountLoginAdmissionStore.swift` exactly: protocol in `SwanStorage`, implementation as an `extension SQLiteControlDatabase`, and a `migrateActorPreferencesSchema()` registered alongside the other migrations.

```sql
CREATE TABLE IF NOT EXISTS actor_preferences (
    did TEXT PRIMARY KEY NOT NULL CHECK(length(did) BETWEEN 1 AND 2048),
    preferences_json BLOB NOT NULL CHECK(length(preferences_json) <= 1048576),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
) WITHOUT ROWID
```

The 1 MiB cap bounds what one account can store; `putPreferences` rejects a larger body with **413 Payload Too Large** rather than failing at the database CHECK constraint. (Corrected 2026-08-11: this plan originally said 400. 413 is the correct HTTP semantic and matches the precedent already set by `SwanAccountEmailXRPC.swift:837` for oversized payloads. Ruled by Josh during execution.)

- [ ] **Step 4: Implement the two routes**

`getPreferences` returns `{"preferences": []}` when no row exists. `putPreferences` validates that the body decodes and that `preferences` is an array before writing, and always writes under the authenticated DID — never a DID taken from the request.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanActorPreferencesXRPCTests`
Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
swiftformat Sources/SwanStorage/ActorPreferencesStore.swift Sources/SwanSQLite/ActorPreferencesStore.swift Sources/SwanHTTP/SwanActorPreferencesXRPC.swift Tests/SwanHTTPTests/SwanActorPreferencesXRPCTests.swift
jj describe -m "SwanHTTP: local app.bsky.actor preferences storage and routes"
jj new
```

---

### Task 6: Pipethrough handler, configuration, and wiring

Joins Tasks 1-4 into a live route and adds the CLI flags.

**Files:**
- Create: `Sources/SwanHTTP/SwanXRPCPipethrough.swift`
- Modify: `Sources/SwanHTTP/SwanHTTP.swift` (register the fallback; extend the configuration struct)
- Modify: `Sources/swan/SwanCommand.swift` (add flags)
- Test: `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift`

**Interfaces:**
- Consumes: `SwanXRPCProxyRouter.route(nsid:proxyHeader:)`, `ProxyServiceJWT.create(...)`, `SwanServiceEndpointResolver.endpoint(did:fragment:)`, `SwanProxySending.send(_:timeout:maximumBodyBytes:)`, `AccountKeyStore.key(for:)`.
- Produces: a registered `/xrpc/**` fallback route.

New CLI flags on `serve`:
- `--appview-did` (default `did:web:api.bsky.app`)
- `--appview-url` (default `https://api.bsky.app`)
- `--appview-service-fragment` (default `bsky_appview`)
- `--disable-appview-proxy` (off by default; proxying is on out of the box)

- [ ] **Step 1: Verify router precedence before building on it**

Hummingbird's behaviour for a `/xrpc/**` catch-all alongside specific `/xrpc/<nsid>` routes must be confirmed, not assumed. Write this test first:

```swift
func testCatchAllNeverShadowsALocalRoute() async throws {
  // With the proxy fallback registered, GET /xrpc/com.atproto.server.describeServer
  // must still be served locally and must NOT be proxied.
}
```

If the catch-all shadows specific routes, do not fight the router: register the fallback as a middleware that runs only after route matching fails, and note the change in the commit message.

- [ ] **Step 2: Write the remaining failing tests**

```swift
func testProxiesAppBskyToConfiguredAppView() async throws {
  // Stub sender records the outbound request. Assert: URL host is the
  // configured AppView, path and query are preserved verbatim.
}

func testStripsInboundCredentialHeaders() async throws {
  // Send a request carrying Authorization, Cookie and DPoP. Assert positively
  // that NONE of them appear in the outbound request, and that the outbound
  // Authorization is the minted service JWT with lxm bound to the called NSID.
}

func testForwardsOnlyAllowListedHeaders() async throws {
  // accept-language and atproto-accept-labelers pass; x-custom does not.
}

func testUnauthenticatedRequestIsRejectedWithoutContactingUpstream() async throws {
  // 401, and the stub sender records zero outbound requests.
}

func testUpstreamErrorStatusAndBodyPassThrough() async throws {
  // Upstream 400 with a body → client sees the same status and body.
}

func testUnreachableUpstreamBecomes502() async throws {}

func testMalformedProxyHeaderIsRejectedWithoutContactingUpstream() async throws {
  // 400, zero outbound requests — proves no silent fallback to the AppView.
}

func testDeniedNamespaceIsNotProxied() async throws {
  // com.atproto.space.* → 404, zero outbound requests.
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanXRPCPipethroughTests`
Expected: FAIL.

- [ ] **Step 4: Implement the handler**

Order of operations, which the tests above pin down:

1. Extract the NSID from the path. Reject anything that is not a well-formed NSID with 404.
2. Require an authenticated account (401 otherwise) **before** any routing or outbound work.
3. `router.route(nsid:proxyHeader:)` → map `.denied`/`.unrouted` to 404 and `.malformedProxyHeader` to 400.
4. Resolve the endpoint: `.configuredAppView` uses the configured URL directly; `.resolvedService` goes through `SwanServiceEndpointResolver`, mapping failure to 400.
5. Mint the JWT with `iss` = authenticated DID, `aud` = target service DID, `lxm` = NSID.
6. Build the outbound request: preserve path and query; set `Authorization: Bearer <jwt>`; copy only allow-listed headers.
7. Send; stream the response back with upstream status and content-type; map transport failure to 502.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanXRPCPipethroughTests`
Expected: PASS.

- [ ] **Step 6: Run the full suite for regressions**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS. Count passing cases with `grep -c "Test Case .* passed"` — do **not** sum `Executed N tests` lines, which triple-counts nested suite summaries.

- [ ] **Step 7: Format and commit**

```bash
swiftformat Sources/SwanHTTP/SwanXRPCPipethrough.swift Sources/SwanHTTP/SwanHTTP.swift Sources/swan/SwanCommand.swift Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift
jj describe -m "SwanHTTP: proxy unmatched app.bsky XRPC to the configured AppView"
jj new
```

---

### Task 7: Deploy and verify against the live account

A clean build is not "done". Per the project's verification rules the change must be observable in the running app.

**Files:** none — this task is verification.

- [ ] **Step 1: Build and deploy**

```bash
xcrun --toolchain XcodeDefault swift build
rsync -az --exclude '.build' --exclude '.git' --exclude '.jj' \
  Sources/ netcup:/home/josh/dev/swan-src/Swan/Sources/
ssh netcup 'cd /home/josh/dev/swan-src && sudo docker build -f Swan/Dockerfile -t swan:local . && sudo systemctl restart swan.service'
```

The build context is `swan-src` with `-f Swan/Dockerfile`, **not** `swan-src/Swan` — the Dockerfile uses `Swan/`-prefixed paths. There is also a stale unused `swan-src/Sources`; do not sync there.

- [ ] **Step 2: Confirm the service is healthy**

```bash
ssh netcup 'systemctl is-active swan.service'
curl -s -o /dev/null -w "%{http_code}\n" https://swan.place/.well-known/oauth-authorization-server
```
Expected: `active`, `200`.

- [ ] **Step 3: Verify the 404s are gone**

The specific failure this project exists to fix is `app.bsky.actor.getProfile` 404ing. In the nest journal, that request must now return 200:

```bash
ssh netcup 'sudo journalctl -u catbird-nest-prod.service --since @<epoch> --no-pager | grep -E "getProfile|BFF-RESP-ERR" | tail -20'
```

Use `--since @<epoch>`, not a wall-clock string: journalctl on this host interprets those as local time (UTC+2) and silently reads a two-hour-off window.

- [ ] **Step 4: Verify in the running app**

Sign in to the swan.place account in Catbird, open a profile and a feed, and capture a screenshot. If anything fails to render, capture the nest log for the failing lexicon and stop — do not claim success.

- [ ] **Step 5: Record the result**

Append the outcome (screenshot path, the lexicons confirmed working, and anything still 404ing) to this plan file, then commit.

```bash
jj describe -m "docs: record AppView proxying live verification"
jj new
```

---

## Self-review

**Spec coverage.** D1 infer-the-header → Task 1. D2 auth required → Task 6 step 4.2 and its test. D3 configurable AppView with default → Task 6 flags. D4 plaintext preferences → Task 5. Unit 1 router → Task 1. Unit 2 service auth → Task 2. Unit 3 pipethrough → Tasks 4 and 6. Unit 4 preferences → Task 5. Error-handling table → Task 6 step 4. Peer-pinning reuse → Task 4. Live verification → Task 7.

**Known gap, deliberately carried:** Task 5's test bodies are described rather than written out, because they depend on the existing `AccountEmailXRPCTests` harness whose exact setup should be read rather than guessed at. Each test's assertion is stated precisely. This is the one place the implementer must read an existing file to proceed, and it is named explicitly.

**Type consistency.** `SwanXRPCProxyRoute`, `SwanXRPCProxyRoutingFailure`, `SwanServiceResolutionFailure`, `SwanProxyRequest`, `SwanProxySending`, `SwanProxyTransporting`, `ProxyServiceJWT.create`, and `ActorPreferencesStore` are used with identical names and signatures in the Interfaces blocks and the code.

**Risk carried into implementation:** Task 6 Step 1 (router precedence) is the one unverified assumption in the plan and is deliberately the first step of that task, so it fails fast rather than after the handler is built.
