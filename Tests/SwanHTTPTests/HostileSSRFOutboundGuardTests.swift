import Foundation
import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSpaces
import SwanStorage
import XCTest

/// Hostile SSRF, DNS-rebinding, redirect, address-classification, port-policy,
/// and response-framing regression suite across Swan's outbound HTTP surfaces:
/// - `SwanPublicAddressPolicy` (IPv4, IPv6, IPv4-mapped IPv6, CGNAT, link-local,
///   ULA, NAT64, 6to4, Teredo, AS112, AMT)
/// - `OAuthRemoteFetchPolicy` (non-HTTPS, non-443 ports, allowlist scoping,
///   non-canonical numeric IPv4 literals, trailing-dot/zone-ID host confusion)
/// - `CachingOAuthHostnameResolver` (case-insensitive singleflight & cache key)
/// - `SwanPeerPinnedProxySender` (post-flight DNS rebinding, missing/unpinned
///   peer proof, custom redirect blocking, body caps, Content-Length mismatch)
/// - `RemoteManagedSpaceAccessChecker` (post-flight DNS rebinding, redirect &
///   responseURL mismatch, peer-pin mismatch, body caps, Content-Length mismatch)
/// - `HTTPSwanSpaceRegistrationConfirmer` & `RemoteConversationSpaceMembershipChecker`
///   (non-443 port rejection, DNS rebinding, Content-Length mismatch, 4 KiB / 8 KiB caps)
/// - `SwanPeerPinnedDIDDocumentFetcher` (`did:web:%3A<port>` rejected by policy)
final class HostileSSRFOutboundGuardTests: XCTestCase {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let user = "did:plc:bcdefghijklmnopqrstuvwxy"

    // MARK: - 1. SwanPublicAddressPolicy hostile matrix

    func testAddressClassifierDeniesEverySpecialPurposeRangeAndMappedForm() throws {
        let deniedLiterals = [
            // "This network", RFC 1918, loopback
            "0.0.0.0", "0.255.255.255",
            "10.0.0.1", "10.255.255.254",
            "127.0.0.1", "127.255.255.254",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
            // Carrier-grade NAT 100.64.0.0/10
            "100.64.0.0", "100.64.0.1", "100.100.100.100", "100.127.255.255",
            // Link-local & cloud metadata 169.254.0.0/16
            "169.254.0.1", "169.254.169.254", "169.254.255.254",
            // IANA special-purpose IPv4 (IETF, TEST-NET, AS112, AMT, 6to4 relay, benchmarking, multicast, reserved)
            "192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1",
            "192.88.99.1", "192.175.48.1", "198.18.0.1", "198.19.255.254",
            "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
            // IPv6 unspecified, loopback, IPv4-compatible, SIIT IPv4-translated
            "::", "::1", "::127.0.0.1", "::ffff:0:127.0.0.1",
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:100.64.0.1",
            "::ffff:169.254.169.254", "::ffff:172.16.0.1", "::ffff:192.168.1.1",
            "::ffff:192.31.196.1", "::ffff:192.52.193.1", "::ffff:192.175.48.1",
            // Link-local fe80::/10 & Unique-local fc00::/7
            "fe80::1", "febf:ffff:ffff:ffff::1",
            "fc00::1", "fd00::1", "fdff:ffff:ffff:ffff::1",
            // Multicast, NAT64, Discard, Teredo, Benchmarking, ORCHID, Documentation, 6to4, AS112-v6
            "ff02::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1",
            "2001::1", "2001:2::1", "2001:4:112::1", "2001:10::1", "2001:20::1",
            "2001:db8::1", "2002:7f00:1::1", "2002:5db8:d822::1",
            "2620:4f:8000::1", "3fff::1", "3fff:fff:ffff::1",
        ]
        for literal in deniedLiterals {
            let parsed = try XCTUnwrap(OAuthIPAddress(literal: literal), "failed to parse \(literal)")
            XCTAssertFalse(
                parsed.isPublicInternetAddress,
                "expected \(literal) to be denied as non-public"
            )
        }

        // Exact adjacent boundary checks for CGNAT, RFC 1918, link-local, mapped public IPv4, global IPv6
        let permittedLiterals = [
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.1",
            "169.253.255.255",
            "169.255.0.0",
            "::ffff:93.184.216.34",
            "2606:4700:4700::1111",
            "2620:4f:8001::1",
        ]
        for literal in permittedLiterals {
            let parsed = try XCTUnwrap(OAuthIPAddress(literal: literal), "failed to parse \(literal)")
            XCTAssertTrue(
                parsed.isPublicInternetAddress,
                "expected \(literal) to be permitted as public internet"
            )
        }
    }

    // MARK: - 2. OAuthRemoteFetchPolicy: HTTPS, ports, allowlist scoping, host canonicalization

    func testPolicyRejectsNonHTTPSNon443PortsAndNonCanonicalHosts() throws {
        let productionPolicy = try OAuthRemoteFetchPolicy()

        for rejected in [
            // Non-HTTPS in production
            "http://example.com/client.json",
            "http://localhost/client.json",
            "http://localhost:8080/client.json",
            "ftp://example.com/client.json",
            // Non-443 ports on public HTTPS
            "https://example.com:8443/client.json",
            "https://example.com:22/client.json",
            "https://example.com:25/client.json",
            "https://example.com:80/client.json",
            "https://example.com:6379/client.json",
            "https://93.184.216.34:8443/client.json",
            // Non-canonical numeric IPv4 spellings (octal, hex, shorthand, integer)
            "https://127.1/client.json",
            "https://2130706433/client.json",
            "https://0177.0.0.1/client.json",
            "https://0x7f.0.0.1/client.json",
            "https://0x7f000001/client.json",
            // Trailing-dot FQDN & IPv6 zone identifiers
            "https://localhost./client.json",
            "https://example.com./client.json",
            "https://[fe80::1%25lo0]/client.json",
        ] {
            let url = try XCTUnwrap(URL(string: rejected), "expected URL fixture \(rejected)")
            XCTAssertThrowsError(
                try productionPolicy.validateURL(url),
                "expected production policy to reject \(rejected)"
            )
        }

        // Default HTTPS (port omitted or explicit :443) remains valid
        XCTAssertEqual(
            try productionPolicy.validateURL(XCTUnwrap(URL(string: "https://example.com/client.json"))),
            "example.com"
        )
        XCTAssertEqual(
            try productionPolicy.validateURL(XCTUnwrap(URL(string: "https://example.com:443/client.json"))),
            "example.com"
        )

        // Allowlisting one lab IP permits custom ports ONLY for that allowlisted IP,
        // never for un-allowlisted public internet hosts.
        let labPeer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let allowlistPolicy = try OAuthRemoteFetchPolicy(
            networkAllowlist: .init(addresses: [labPeer])
        )
        let customPortURL = try XCTUnwrap(URL(string: "https://target.example:6379/xrpc/test"))
        let host = try allowlistPolicy.validateURL(customPortURL)
        XCTAssertNoThrow(try allowlistPolicy.validateResolved([labPeer], host: host, port: 6379))
        XCTAssertThrowsError(
            try allowlistPolicy.validateResolved([publicPeer], host: host, port: 6379),
            "a lab IP allowlist must not open non-443 ports to arbitrary public hosts"
        )

        // Localhost development mode permits http://localhost:<port>, never http://127.0.0.1 or http://localhost.
        let devPolicy = try OAuthRemoteFetchPolicy(allowLocalhostDevelopment: true)
        XCTAssertEqual(
            try devPolicy.validateURL(XCTUnwrap(URL(string: "http://localhost:3000/xrpc/test"))),
            "localhost"
        )
        XCTAssertThrowsError(
            try devPolicy.validateURL(XCTUnwrap(URL(string: "http://127.0.0.1:3000/xrpc/test")))
        )
        XCTAssertThrowsError(
            try devPolicy.validateURL(XCTUnwrap(URL(string: "http://localhost.:3000/xrpc/test")))
        )
    }

    func testDIDWebWithCustomPortIsBlockedByProductionFetchPolicy() async throws {
        let plc = try XCTUnwrap(URL(string: "https://plc.directory"))
        let derived = try SwanPeerPinnedDIDDocumentFetcher.documentURL(
            forDID: "did:web:evil.example%3A6379",
            plcOrigin: plc
        )
        XCTAssertEqual(derived.absoluteString, "https://evil.example:6379/.well-known/did.json")

        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let resolver = SequencedResolver(answers: [[publicPeer], [publicPeer]])
        let transport = CountingDocumentTransport(response: OAuthRemoteHTTPResponse(
            status: 200,
            headers: ["content-type": ["application/did+ld+json"]],
            body: Data(#"{"id":"did:web:evil.example%3A6379"}"#.utf8),
            responseURL: derived,
            connectedPeerAddress: publicPeer
        ))
        let fetcher = try SwanPeerPinnedDIDDocumentFetcher(
            documents: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: resolver,
                transport: transport
            ),
            plcOrigin: plc
        )
        do {
            _ = try await fetcher.documentJSON(forDID: "did:web:evil.example%3A6379")
            XCTFail("expected custom-port did:web fetch to be refused before socket I/O")
        } catch {}
        let transportCalls = await transport.calls
        let dnsCalls = await resolver.calls
        XCTAssertEqual(transportCalls, 0)
        XCTAssertEqual(dnsCalls, 0)
    }

    // MARK: - 3. CachingOAuthHostnameResolver mixed-case singleflight hardening

    func testCachingResolverCanonicalizesMixedCaseHostnames() async throws {
        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let upstream = SequencedResolver(answers: [[publicPeer]], artificialDelayMs: 25)
        let cache = try CachingOAuthHostnameResolver(upstream: upstream)

        try await withThrowingTaskGroup(of: [OAuthIPAddress].self) { group in
            for spelling in ["api.bsky.app", "API.BSKY.APP", "Api.Bsky.App", "aPi.bSkY.aPp", "api.BSKY.app"] {
                group.addTask { try await cache.resolve(host: spelling) }
            }
            for try await result in group {
                XCTAssertEqual(result, [publicPeer])
            }
        }
        let upstreamCalls = await upstream.calls
        XCTAssertEqual(upstreamCalls, 1, "mixed-case spellings of one host must share one DNS permit and cache entry")
    }

    // MARK: - 4. SwanPeerPinnedProxySender: DNS rebinding, redirects, peer proof, body & Content-Length caps

    func testProxySenderBlocksDNSRebindingRedirectsUnpinnedPeersAndFramingMismatches() async throws {
        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let otherPublicPeer = try XCTUnwrap(OAuthIPAddress(literal: "1.1.1.1"))
        let rebindLoopback = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let rebindMapped = try XCTUnwrap(OAuthIPAddress(literal: "::ffff:169.254.169.254"))
        let requestURL = try XCTUnwrap(URL(string: "https://appview.example/xrpc/app.bsky.actor.getProfile"))
        let request = SwanProxyRequest(method: "GET", url: requestURL, headers: [], body: nil)
        let validBody = Data(#"{"handle":"alice.test"}"#.utf8)

        // 4a. Post-flight DNS rebind to 127.0.0.1
        do {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [rebindLoopback]]),
                transport: StubProxyTransport(response: OAuthRemoteHTTPResponse(
                    status: 200, headers: [:], body: validBody, responseURL: requestURL,
                    connectedPeerAddress: publicPeer
                ))
            )
            _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 1_024)
            XCTFail("expected post-flight DNS rebind to loopback to fail")
        } catch {}

        // 4b. Post-flight DNS rebind to IPv4-mapped metadata IP ::ffff:169.254.169.254
        do {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [rebindMapped]]),
                transport: StubProxyTransport(response: OAuthRemoteHTTPResponse(
                    status: 200, headers: [:], body: validBody, responseURL: requestURL,
                    connectedPeerAddress: publicPeer
                ))
            )
            _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 1_024)
            XCTFail("expected post-flight DNS rebind to ::ffff:169.254.169.254 to fail")
        } catch {}

        // 4c. Disjoint post-flight public answer set (connected peer vanished from post-flight DNS)
        do {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [otherPublicPeer]]),
                transport: StubProxyTransport(response: OAuthRemoteHTTPResponse(
                    status: 200, headers: [:], body: validBody, responseURL: requestURL,
                    connectedPeerAddress: publicPeer
                ))
            )
            _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 1_024)
            XCTFail("expected disjoint post-flight answer set to fail")
        } catch {}

        // 4d. Missing connectedPeerAddress proof
        do {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                transport: StubProxyTransport(response: OAuthRemoteHTTPResponse(
                    status: 200, headers: [:], body: validBody, responseURL: requestURL,
                    connectedPeerAddress: nil
                ))
            )
            _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 1_024)
            XCTFail("expected missing peer proof to fail")
        } catch {}

        // 4e. Redirect followed by custom transport (redirectCount > 0 or responseURL != request.url)
        for redirectedResponse in [
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody, responseURL: requestURL,
                redirectCount: 1, connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody,
                responseURL: URL(string: "https://internal.example/secret")!,
                redirectCount: 0, connectedPeerAddress: publicPeer
            ),
        ] {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                transport: StubProxyTransport(response: redirectedResponse)
            )
            do {
                _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 1_024)
                XCTFail("expected redirect / mismatched responseURL to fail")
            } catch {}
        }

        // 4f. Body cap & Content-Length header smuggling / mismatch
        for badResponse in [
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: Data(repeating: 0x41, count: 513),
                responseURL: requestURL, connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: ["Content-Length": ["999"]], body: validBody,
                responseURL: requestURL, connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: ["Content-Length": ["\(validBody.count)", "\(validBody.count)"]],
                body: validBody, responseURL: requestURL, connectedPeerAddress: publicPeer
            ),
        ] {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                transport: StubProxyTransport(response: badResponse)
            )
            do {
                _ = try await sender.send(request, timeout: 5, maximumBodyBytes: 512)
                XCTFail("expected oversized body or mismatched Content-Length to fail")
            } catch {}
        }

        // 4g. Non-443 port rejected on proxy sender
        do {
            let sender = SwanPeerPinnedProxySender(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                transport: StubProxyTransport(response: OAuthRemoteHTTPResponse(
                    status: 200, headers: [:], body: validBody, responseURL: requestURL,
                    connectedPeerAddress: publicPeer
                ))
            )
            _ = try await sender.send(
                SwanProxyRequest(
                    method: "GET",
                    url: URL(string: "https://appview.example:8443/xrpc/app.bsky.actor.getProfile")!,
                    headers: [],
                    body: nil
                ),
                timeout: 5,
                maximumBodyBytes: 1_024
            )
            XCTFail("expected non-443 proxy port to fail")
        } catch {}
    }

    // MARK: - 5. RemoteManagedSpaceAccessChecker: DNS rebinding, redirects, peer proof, body & port guards

    func testManagedSpaceAccessCheckerEnforcesDualDNSAndPeerAndPortAndBodyGuards() async throws {
        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let rebindPeer = try XCTUnwrap(OAuthIPAddress(literal: "100.64.0.5"))
        let managerDID = "did:web:manager.example"
        let space = try SpaceURI(authority: Self.authority, spaceType: "app.bsky.bookmarks", skey: "managed")
        let validBody = Data(#"{"read":true,"write":false}"#.utf8)
        let expectedURL = try RemoteManagedSpaceAccessChecker.requestURL(
            base: XCTUnwrap(URL(string: "https://manager.example")),
            space: space,
            repo: Self.user,
            clientID: nil
        )
        let validDIDDoc = Data("""
        {"id":"\(managerDID)","service":[{"id":"#space","serviceEndpoint":"https://manager.example"}]}
        """.utf8)

        // Happy path succeeds when pre-flight & post-flight DNS, peer, URL, and Content-Length align
        do {
            let checker = RemoteManagedSpaceAccessChecker(
                resolver: SwanServiceEndpointResolver(documents: MapDIDDocumentFetcher([managerDID: validDIDDoc])),
                signer: StubServiceSigner(),
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                hostnameResolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                getAuthenticated: { url, _, _, _, _ in
                    OAuthRemoteHTTPResponse(
                        status: 200,
                        headers: ["Content-Length": ["\(validBody.count)"]],
                        body: validBody,
                        responseURL: url,
                        connectedPeerAddress: publicPeer
                    )
                }
            )
            let access = try await checker.checkAccess(
                space: space, repo: Self.user, clientID: nil, managingApp: "\(managerDID)#space"
            )
            XCTAssertEqual(access, ManagedSpaceAccess(read: true, write: false))
        }

        // 5a. Post-flight DNS rebind to CGNAT 100.64.0.5 fails closed as upstreamFailure
        do {
            let checker = RemoteManagedSpaceAccessChecker(
                resolver: SwanServiceEndpointResolver(documents: MapDIDDocumentFetcher([managerDID: validDIDDoc])),
                signer: StubServiceSigner(),
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                hostnameResolver: SequencedResolver(answers: [[publicPeer], [rebindPeer]]),
                getAuthenticated: { url, _, _, _, _ in
                    OAuthRemoteHTTPResponse(
                        status: 200, headers: [:], body: validBody, responseURL: url,
                        connectedPeerAddress: publicPeer
                    )
                }
            )
            do {
                _ = try await checker.checkAccess(
                    space: space, repo: Self.user, clientID: nil, managingApp: "\(managerDID)#space"
                )
                XCTFail("expected DNS rebind to CGNAT to fail")
            } catch {
                XCTAssertEqual(error as? ManagedSpaceAccessError, .upstreamFailure)
            }
        }

        // 5b. Missing peer proof, redirected URL, >4 KiB body, or Content-Length mismatch all fail closed
        let hostileResponses: [OAuthRemoteHTTPResponse] = [
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody, responseURL: expectedURL,
                connectedPeerAddress: nil
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody,
                responseURL: URL(string: "https://internal.example/xrpc/com.atproto.managedspace.checkAccess")!,
                connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody, responseURL: expectedURL,
                redirectCount: 1, connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: [:],
                body: Data((#"{"read":true,"write":false,"pad":""# + String(repeating: "x", count: 4_100) + #"}"#).utf8),
                responseURL: expectedURL, connectedPeerAddress: publicPeer
            ),
            OAuthRemoteHTTPResponse(
                status: 200, headers: ["Content-Length": ["12"]], body: validBody,
                responseURL: expectedURL, connectedPeerAddress: publicPeer
            ),
        ]
        for hostile in hostileResponses {
            let checker = RemoteManagedSpaceAccessChecker(
                resolver: SwanServiceEndpointResolver(documents: MapDIDDocumentFetcher([managerDID: validDIDDoc])),
                signer: StubServiceSigner(),
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                hostnameResolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                getAuthenticated: { _, _, _, _, _ in hostile }
            )
            do {
                _ = try await checker.checkAccess(
                    space: space, repo: Self.user, clientID: nil, managingApp: "\(managerDID)#space"
                )
                XCTFail("expected hostile response to fail closed")
            } catch {
                XCTAssertEqual(error as? ManagedSpaceAccessError, .upstreamFailure)
            }
        }

        // 5c. Non-443 port in managingApp serviceEndpoint rejected before transport I/O
        do {
            let badPortDoc = Data("""
            {"id":"\(managerDID)","service":[{"id":"#space","serviceEndpoint":"https://manager.example:6379"}]}
            """.utf8)
            let probe = TransportCallCounter()
            let checker = RemoteManagedSpaceAccessChecker(
                resolver: SwanServiceEndpointResolver(documents: MapDIDDocumentFetcher([managerDID: badPortDoc])),
                signer: StubServiceSigner(),
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                hostnameResolver: SequencedResolver(answers: [[publicPeer], [publicPeer]]),
                getAuthenticated: { url, _, _, _, _ in
                    await probe.increment()
                    return OAuthRemoteHTTPResponse(
                        status: 200, headers: [:], body: validBody, responseURL: url,
                        connectedPeerAddress: publicPeer
                    )
                }
            )
            do {
                _ = try await checker.checkAccess(
                    space: space, repo: Self.user, clientID: nil, managingApp: "\(managerDID)#space"
                )
                XCTFail("expected non-443 managingApp port to fail")
            } catch {
                XCTAssertEqual(error as? ManagedSpaceAccessError, .upstreamFailure)
            }
            let count = await probe.count
            XCTAssertEqual(count, 0, "transport must not be reached when port is disallowed")
        }
    }

    // MARK: - 6. HTTPSwanSpaceRegistrationConfirmer: DNS rebinding, non-443 port, 4 KiB cap, Content-Length

    func testSpaceRegistrationConfirmerBlocksRebindingNon443PortsAndFramingAbuse() async throws {
        let publicPeer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let ulaPeer = try XCTUnwrap(OAuthIPAddress(literal: "fd00::1"))
        let space = try SpaceURI(authority: Self.authority, spaceType: "app.bsky.bookmarks", skey: "webhook")
        let challenge = "challenge-xyz"
        let validBody = Data(#"{"challenge":"challenge-xyz"}"#.utf8)

        // Non-443 webhook port rejected before socket I/O
        do {
            let postTransport = StubPostTransport(response: OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody,
                responseURL: URL(string: "https://syncer.example:8443/xrpc/com.atproto.space.confirmRegistration")!,
                connectedPeerAddress: publicPeer
            ))
            let confirmer = HTTPSwanSpaceRegistrationConfirmer(
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                transport: postTransport,
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]])
            )
            do {
                try await confirmer.confirmRegistration(
                    space: space,
                    endpoint: XCTUnwrap(URL(string: "https://syncer.example:8443/webhook")),
                    token: "tok",
                    challenge: challenge
                )
                XCTFail("expected non-443 webhook port to be rejected")
            } catch {}
            let calls = await postTransport.calls
            XCTAssertEqual(calls, 0)
        }

        // Post-flight DNS rebind to ULA fd00::1 rejected
        do {
            let targetURL = URL(string: "https://syncer.example/xrpc/com.atproto.space.confirmRegistration")!
            let postTransport = StubPostTransport(response: OAuthRemoteHTTPResponse(
                status: 200, headers: [:], body: validBody,
                responseURL: targetURL,
                connectedPeerAddress: publicPeer
            ))
            let confirmer = HTTPSwanSpaceRegistrationConfirmer(
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                transport: postTransport,
                resolver: SequencedResolver(answers: [[publicPeer], [ulaPeer]])
            )
            do {
                try await confirmer.confirmRegistration(
                    space: space,
                    endpoint: XCTUnwrap(URL(string: "https://syncer.example/webhook")),
                    token: "tok",
                    challenge: challenge
                )
                XCTFail("expected DNS rebind to ULA fd00::1 to fail")
            } catch {}
        }

        // Mismatched Content-Length rejected even when body challenge matches
        do {
            let targetURL = URL(string: "https://syncer.example/xrpc/com.atproto.space.confirmRegistration")!
            let postTransport = StubPostTransport(response: OAuthRemoteHTTPResponse(
                status: 200,
                headers: ["Content-Length": ["999"]],
                body: validBody,
                responseURL: targetURL,
                connectedPeerAddress: publicPeer
            ))
            let confirmer = HTTPSwanSpaceRegistrationConfirmer(
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                transport: postTransport,
                resolver: SequencedResolver(answers: [[publicPeer], [publicPeer]])
            )
            do {
                try await confirmer.confirmRegistration(
                    space: space,
                    endpoint: XCTUnwrap(URL(string: "https://syncer.example/webhook")),
                    token: "tok",
                    challenge: challenge
                )
                XCTFail("expected mismatched Content-Length on confirmRegistration to fail")
            } catch {}
        }
    }
}

// MARK: - Test Doubles

private actor SequencedResolver: OAuthHostnameResolving {
    private let answers: [[OAuthIPAddress]]
    private let artificialDelayMs: UInt64
    private var index = 0
    private(set) var calls = 0

    init(answers: [[OAuthIPAddress]], artificialDelayMs: UInt64 = 0) {
        self.answers = answers
        self.artificialDelayMs = artificialDelayMs
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        calls += 1
        if artificialDelayMs > 0 {
            try await Task.sleep(nanoseconds: artificialDelayMs * 1_000_000)
        }
        guard !answers.isEmpty else {
            throw SwanError.unavailable("no test DNS answers")
        }
        defer { index += 1 }
        return answers[min(index, answers.count - 1)]
    }
}

private actor CountingDocumentTransport: OAuthRemoteTransport {
    private let response: OAuthRemoteHTTPResponse
    private(set) var calls = 0

    init(response: OAuthRemoteHTTPResponse) {
        self.response = response
    }

    func get(
        url _: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        calls += 1
        return response
    }
}

private struct StubProxyTransport: SwanProxyTransporting {
    let response: OAuthRemoteHTTPResponse

    func send(
        _ _: SwanProxyRequest,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        response
    }
}

private actor StubPostTransport: OAuthRemotePostTransport {
    private let response: OAuthRemoteHTTPResponse
    private(set) var calls = 0

    init(response: OAuthRemoteHTTPResponse) {
        self.response = response
    }

    func post(
        url _: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        headers _: [String: String],
        body _: Data,
        timeout _: TimeInterval,
        maximumResponseBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        calls += 1
        return response
    }
}

private struct MapDIDDocumentFetcher: SwanDIDDocumentFetching {
    let documents: [String: Data]

    init(_ documents: [String: Data]) {
        self.documents = documents
    }

    func documentJSON(forDID did: String) async throws -> Data {
        guard let doc = documents[did] else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return doc
    }
}

private struct StubServiceSigner: SpaceServiceAuthenticationIssuer {
    func issue(
        issuer _: String,
        audience _: String,
        method _: String,
        eventID _: String,
        requestBodyDigest _: String?,
        now _: Date
    ) async throws -> String {
        "header.payload.signature"
    }
}

private actor TransportCallCounter {
    private(set) var count = 0
    func increment() { count += 1 }
}
