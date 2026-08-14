import Foundation
import SwanCore

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

        /// The document's own subject. Optional only so a document that omits
        /// it decodes and is then *rejected* below with the same
        /// `.unresolvableService` as everything else, rather than failing
        /// decode and taking a different path to the same answer.
        let id: String?
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
        // Bind the document to the DID that was asked for. Without this the
        // fetch path's answer is trusted on its own: a `did:web` host that
        // serves (or is made to serve) some other subject's document — via a
        // shared host, a stale cache entry, or a path that is not the one the
        // method-specific id names — silently selects that subject's endpoint.
        //
        // The comparison is byte-exact against the DID string as received,
        // and no normalisation is applied: any normalisation here would be a
        // second, weaker grammar than the one
        // `SwanPeerPinnedDIDDocumentFetcher` already used to derive the fetch
        // URL, which is exactly how a mismatch gets accepted.
        //
        // So this also refuses two spellings that name the same `did:web`
        // subject but are not the same string: a differently percent-encoded
        // port (`%3A` vs `:`) and a differently cased host. DNS is
        // case-insensitive and the fetch would succeed either way, so a caller
        // that spells the DID differently from the document it is asking about
        // now gets `.unresolvableService` where it previously got the
        // endpoint. That is deliberate — the caller controls the spelling
        // (`SwanXRPCPipethrough` passes the `atproto-proxy` header through
        // unfolded) and the remedy is to name the subject as its document
        // does. `testDecodedPortSpellingDoesNotMatchEncodedDocumentID` and
        // `testHostCaseDifferenceDoesNotMatchDocumentID` pin both, so a later
        // "helpful" normalisation fails loudly instead of silently widening
        // what may be bound.
        //
        // A document with no `id` at all is rejected: `id` is required by DID
        // Core, and a document that will not name its own subject cannot be
        // bound to one.
        guard document.id == did else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        // A service id may be written "#frag" or "did:...#frag". Exactly one
        // entry may match: a document that declares the same service id twice
        // is malformed, and picking the first would let a later duplicate be
        // appended to a document to shadow-or-be-shadowed depending only on
        // ordering. Refuse the ambiguity instead of resolving it.
        let matches = services.filter {
            $0.id == "#\(fragment)" || $0.id == "\(did)#\(fragment)"
        }
        guard
            matches.count == 1,
            let match = matches.first,
            let url = URL(string: match.serviceEndpoint),
            url.scheme?.lowercased() == "https",
            let host = url.host, !host.isEmpty,
            url.user == nil, url.password == nil
        else { throw SwanServiceResolutionFailure.unresolvableService }
        return url
    }
}

/// The production ``SwanDIDDocumentFetching`` conformer.
///
/// It deliberately owns no HTTP client of its own: every fetch goes through
/// ``OAuthRemoteDocumentFetcher``, which is the peer-pinned resolve →
/// policy-check → pin path already used for OAuth client metadata. A hostile
/// `did:web` host therefore cannot reach a private or loopback address, and a
/// DNS rebind between resolution and connection is rejected.
///
/// Only two DID methods are supported, and both are resolved from an operator
/// configured origin or from the DID itself — never from a redirect, and never
/// from a `Location` header (the fetcher requires `redirectCount == 0`).
public struct SwanPeerPinnedDIDDocumentFetcher: SwanDIDDocumentFetching {
    private let documents: OAuthRemoteDocumentFetcher
    private let plcOrigin: URL

    /// - Parameter plcOrigin: the PLC directory origin. Callers pass the
    ///   already-configured `PLCClientConfiguration.origin` so this type never
    ///   becomes a second, independently drifting copy of that setting.
    public init(documents: OAuthRemoteDocumentFetcher, plcOrigin: URL) throws {
        guard let components = URLComponents(url: plcOrigin, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              scheme == "https" || (scheme == "http" && host == "localhost") else {
            throw SwanError.malformed("PLC directory origin for DID resolution is invalid")
        }
        self.documents = documents
        self.plcOrigin = plcOrigin
    }

    public func documentJSON(forDID did: String) async throws -> Data {
        let url = try Self.documentURL(forDID: did, plcOrigin: plcOrigin)
        return try await documents.fetchJSON(from: url)
    }

    /// Pure, synchronous DID → document URL derivation, so the whole grammar is
    /// testable without a network.
    static func documentURL(forDID did: String, plcOrigin: URL) throws -> URL {
        guard did.utf8.count <= 512,
              did.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        if let identifier = did.dropPrefixIfPresent("did:plc:") {
            // PLC identifiers are lowercase base32-sortable. Anything else is
            // refused rather than concatenated into the directory's path.
            guard !identifier.isEmpty, identifier.utf8.count <= 64,
                  identifier.utf8.allSatisfy({
                      ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                          || ($0 >= UInt8(ascii: "2") && $0 <= UInt8(ascii: "7"))
                  }) else {
                throw SwanServiceResolutionFailure.unresolvableService
            }
            return try url(origin: plcOrigin, percentEncodedPath: "/\(did)")
        }
        if let methodSpecific = did.dropPrefixIfPresent("did:web:") {
            return try webDocumentURL(methodSpecificID: methodSpecific)
        }
        throw SwanServiceResolutionFailure.unresolvableService
    }

    /// `did:web:host` → `https://host/.well-known/did.json`;
    /// `did:web:host:a:b` → `https://host/a/b/did.json`.
    private static func webDocumentURL(methodSpecificID: String) throws -> URL {
        let segments = methodSpecificID.split(separator: ":", omittingEmptySubsequences: false)
        guard let rawHost = segments.first, !rawHost.isEmpty else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        // A port is the one place the method-specific id may carry a percent
        // escape (`%3A`). Nothing else is decoded: leaving other escapes
        // intact is what stops `..%2F` from climbing out of the path.
        let host = rawHost
            .replacingOccurrences(of: "%3A", with: ":")
            .replacingOccurrences(of: "%3a", with: ":")
        guard isValidWebAuthority(host) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        let pathSegments = segments.dropFirst().map(String.init)
        guard pathSegments.allSatisfy(isValidWebPathSegment) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        let path = pathSegments.isEmpty
            ? "/.well-known/did.json"
            : "/\(pathSegments.joined(separator: "/"))/did.json"
        guard let origin = URL(string: "https://\(host)") else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return try url(origin: origin, percentEncodedPath: path)
    }

    private static func isValidWebAuthority(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return false }
        let host = parts[0]
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasPrefix("."), !host.hasSuffix("."),
              !host.contains(".."),
              host.utf8.allSatisfy({
                  ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                      || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                      || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                      || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: ".")
              }) else {
            return false
        }
        guard parts.count == 2 else { return true }
        let port = parts[1]
        guard (1 ... 5).contains(port.utf8.count),
              port.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
              let value = Int(port), (1 ... 65_535).contains(value) else {
            return false
        }
        return true
    }

    /// Unreserved characters only. `%`, `/`, and `.`-only segments are refused,
    /// so no encoded traversal or empty segment can enter the path.
    private static func isValidWebPathSegment(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128, value != ".", value != ".." else {
            return false
        }
        return value.utf8.allSatisfy {
            ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: ".")
                || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: "~")
        }
    }

    private static func url(origin: URL, percentEncodedPath: String) throws -> URL {
        guard var components = URLComponents(url: origin, resolvingAgainstBaseURL: false) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        components.percentEncodedPath = percentEncodedPath
        components.percentEncodedQuery = nil
        components.fragment = nil
        guard let url = components.url else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return url
    }
}

private extension String {
    func dropPrefixIfPresent(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}
