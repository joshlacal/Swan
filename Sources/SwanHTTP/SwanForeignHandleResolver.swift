import Foundation
import SwanAccounts
import SwanCore

/// Answers `com.atproto.identity.resolveHandle` for handles this host does not
/// hold, using the same pinned TXT/`.well-known` resolver that verifies did:web
/// claims.
///
/// A reference PDS resolves foreign handles from its identity resolver — checked
/// against bsky.social, which answers a third-party handle with 200 and its DID.
/// Swan refused them, so every handle-to-DID lookup a client sent here failed
/// with `InvalidRequest`.
///
/// Two bounds beyond the verifier's own. The result is cached briefly, because
/// a client resolves the same handles repeatedly and the underlying TXT lookup
/// runs on a serial queue: without the cache a burst of lookups queues behind
/// one another. And failures are cached as failures for a shorter interval, so a
/// handle that does not resolve cannot be used to make an anonymous request
/// perform an outbound lookup on demand.
public actor SwanForeignHandleResolver: SwanForeignHandleResolving {
    private struct Entry {
        let did: String?
        let expiresAt: Date
    }

    private let verifier: ATProtocolHandleVerifier
    private let successTTL: TimeInterval
    private let failureTTL: TimeInterval
    private let maximumEntries: Int
    private let now: @Sendable () -> Date
    private var entries: [String: Entry] = [:]
    private var inFlight: [String: Task<String?, Never>] = [:]

    public init(
        verifier: ATProtocolHandleVerifier,
        successTTL: TimeInterval = 300,
        failureTTL: TimeInterval = 30,
        maximumEntries: Int = 1_024,
        now: @Sendable @escaping () -> Date = { Date() }
    ) throws {
        guard successTTL > 0, successTTL <= 3_600, successTTL.isFinite,
              failureTTL > 0, failureTTL <= successTTL, failureTTL.isFinite,
              (1 ... 65_536).contains(maximumEntries) else {
            throw SwanError.malformed("foreign handle resolver configuration is invalid")
        }
        self.verifier = verifier
        self.successTTL = successTTL
        self.failureTTL = failureTTL
        self.maximumEntries = maximumEntries
        self.now = now
    }

    public func resolve(handle: String) async throws -> String? {
        let moment = now()
        if let entry = entries[handle], entry.expiresAt > moment {
            return entry.did
        }
        entries.removeValue(forKey: handle)
        if let existing = inFlight[handle] {
            return await existing.value
        }
        let verifier = verifier
        let task = Task<String?, Never> {
            // A refusal and an unresolvable handle are the same answer here:
            // the route reports "not resolvable" either way, and distinguishing
            // them would tell an anonymous caller which handles exist.
            try? await verifier.resolve(handle: handle)
        }
        inFlight[handle] = task
        defer { inFlight.removeValue(forKey: handle) }
        let did = await task.value
        store(handle: handle, did: did, at: now())
        return did
    }

    private func store(handle: String, did: String?, at moment: Date) {
        entries[handle] = Entry(
            did: did,
            expiresAt: moment.addingTimeInterval(did == nil ? failureTTL : successTTL)
        )
        guard entries.count > maximumEntries else { return }
        entries = entries.filter { $0.value.expiresAt > moment }
        guard entries.count > maximumEntries else { return }
        let ordered = entries.sorted { $0.value.expiresAt < $1.value.expiresAt }
        for (handle, _) in ordered.prefix(entries.count - maximumEntries) {
            entries.removeValue(forKey: handle)
        }
    }
}
