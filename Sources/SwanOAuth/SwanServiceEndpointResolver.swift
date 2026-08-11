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
