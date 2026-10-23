import Dispatch
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanStorage

/// A generation-owned registry used by the PLC resolver's single-flight
/// implementation. Removal is compare-and-remove: a waiter holding an older
/// generation cannot clear a replacement installed for the same issuer.
struct PLCResolverFlightRegistry<Value: Sendable>: Sendable {
    struct Generation: Hashable, Sendable {
        fileprivate let id = UUID()
    }

    struct Entry: Sendable {
        let generation: Generation
        let value: Value
    }

    private var entries = [String: Entry]()

    var count: Int { entries.count }
    var issuers: Set<String> { Set(entries.keys) }

    func entry(for issuer: String) -> Entry? {
        entries[issuer]
    }

    @discardableResult
    mutating func install(
        _ value: Value,
        for issuer: String
    ) -> Generation {
        let generation = Generation()
        entries[issuer] = Entry(
            generation: generation,
            value: value
        )
        return generation
    }

    @discardableResult
    mutating func remove(
        for issuer: String,
        ifOwnedBy generation: Generation
    ) -> Value? {
        guard entries[issuer]?.generation == generation else {
            return nil
        }
        return entries.removeValue(forKey: issuer)?.value
    }
}

/// A process-wide hard cap prevents constructing multiple resolvers from
/// multiplying outbound PLC work. Per-resolver lower limits remain enforced
/// separately by each resolver's actor.
private actor PLCProcessLookupGate {
    static let shared = PLCProcessLookupGate(maximumActiveLookups: 8)

    private let maximumActiveLookups: Int
    private var activeLookups = 0

    private init(maximumActiveLookups: Int) {
        self.maximumActiveLookups = maximumActiveLookups
    }

    func acquire() -> PLCProcessLookupPermit? {
        guard activeLookups < maximumActiveLookups else {
            return nil
        }
        activeLookups += 1
        return PLCProcessLookupPermit(gate: self)
    }

    fileprivate func release() {
        precondition(activeLookups > 0)
        activeLookups -= 1
    }
}

/// The permit owns exactly one process-wide admission. Release is idempotent
/// so cancellation and error cleanup paths cannot underflow the shared gate.
private actor PLCProcessLookupPermit {
    private let gate: PLCProcessLookupGate
    private var released = false

    fileprivate init(gate: PLCProcessLookupGate) {
        self.gate = gate
    }

    func release() async {
        guard !released else { return }
        released = true
        await gate.release()
    }
}

/// PLC-backed discovery for remote space-credential and delegation
/// verification keys.
///
/// The resolver only speaks to a supplied ``PLCClient``. In particular, a
/// credential issuer is never treated as a URL and cannot trigger a DID-web,
/// DNS, PDS, or arbitrary HTTP lookup. ``PLCDirectoryClient`` authenticates a
/// state response against the PLC audit chain before this resolver consumes a
/// verification method. Cached state is used only until its short TTL ends;
/// an expired entry is never used if PLC refresh fails.
public actor PLCSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver,
    SpaceDelegationPublicKeyResolver
{
    /// Monotonic time source for cache and admission deadlines.
    ///
    /// Production uses process uptime. The public closure initializer exists
    /// so deterministic tests and embedders can supply an equivalent
    /// monotonic counter without coupling the resolver to wall-clock time.
    public struct MonotonicClock: Sendable {
        private let readNanoseconds: @Sendable () -> UInt64

        public init(
            nowNanoseconds: @escaping @Sendable () -> UInt64
        ) {
            readNanoseconds = nowNanoseconds
        }

        fileprivate static let continuous = MonotonicClock(
            nowNanoseconds: {
                DispatchTime.now().uptimeNanoseconds
            }
        )

        fileprivate func now() -> UInt64 {
            readNanoseconds()
        }
    }

    public struct CacheConfiguration: Sendable, Equatable {
        public static let standard = CacheConfiguration(
            lifetime: 60,
            maximumEntries: 256,
            negativeLifetime: 10,
            maximumConcurrentLookups: 8,
            maximumNewIssuerLookupsPerMinute: 64
        )

        public let lifetime: TimeInterval
        public let maximumEntries: Int
        public let negativeLifetime: TimeInterval
        public let maximumConcurrentLookups: Int
        public let maximumNewIssuerLookupsPerMinute: Int

        public init(
            lifetime: TimeInterval = 60,
            maximumEntries: Int = 256,
            negativeLifetime: TimeInterval = 10,
            maximumConcurrentLookups: Int = 8,
            maximumNewIssuerLookupsPerMinute: Int = 64
        ) {
            self.lifetime = lifetime
            self.maximumEntries = maximumEntries
            self.negativeLifetime = negativeLifetime
            self.maximumConcurrentLookups = maximumConcurrentLookups
            self.maximumNewIssuerLookupsPerMinute = maximumNewIssuerLookupsPerMinute
        }

        fileprivate func validate() throws {
            guard lifetime > 0, lifetime <= 300, lifetime.isFinite,
                  negativeLifetime > 0, negativeLifetime <= 60, negativeLifetime.isFinite,
                  (1 ... 1_024).contains(maximumEntries),
                  (1 ... 64).contains(maximumConcurrentLookups),
                  (1 ... 4_096).contains(maximumNewIssuerLookupsPerMinute) else {
                throw SwanError.malformed("PLC credential-key cache bounds are invalid")
            }
        }
    }

    private struct CacheEntry: Sendable {
        let state: PLCDocumentData
        let expiresAt: UInt64
    }

    private struct NegativeCacheEntry: Sendable {
        let expiresAt: UInt64
    }

    private struct RefreshedState: Sendable {
        let state: PLCDocumentData
        let continuityAdvance: PLCCredentialKeyContinuityAdvance
    }

    private enum RefreshResult: Sendable {
        case success(RefreshedState)
        case failure
    }

    private struct RefreshOutcome: Sendable {
        let result: RefreshResult
        let completedAt: UInt64
    }

    private let plc: any PLCClient
    private let continuityStore: any PLCCredentialKeyContinuityStore
    private let allowedIssuers: Set<String>?
    private let cacheConfiguration: CacheConfiguration
    private let monotonicClock: MonotonicClock
    private var cache: [String: CacheEntry] = [:]
    private var negativeCache: [String: NegativeCacheEntry] = [:]
    private var inFlight =
        PLCResolverFlightRegistry<Task<RefreshOutcome, Never>>()
    private var newIssuerWindowStartedAt: UInt64?
    private var newIssuerLookupsInWindow = 0

    public init(
        plc: any PLCClient,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard
    ) throws {
        try self.init(
            plc: plc,
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration,
            validatedMonotonicClock: .continuous
        )
    }

    public init(
        plc: any PLCClient,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard,
        monotonicClock: MonotonicClock
    ) throws {
        try self.init(
            plc: plc,
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration,
            validatedMonotonicClock: monotonicClock
        )
    }

    /// Source-compatible deterministic-clock initializer retained for
    /// existing callers. Its input is interpreted as a caller-owned logical
    /// monotonic instant. Production calls the no-clock initializer above,
    /// which uses process uptime rather than `Date`.
    public init(
        plc: any PLCClient,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard,
        clock: @escaping @Sendable () -> Date
    ) throws {
        try self.init(
            plc: plc,
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration,
            validatedMonotonicClock: MonotonicClock(
                nowNanoseconds: {
                    Self.nanoseconds(forLegacyLogicalDate: clock())
                }
            )
        )
    }

    private init(
        plc: any PLCClient,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>?,
        cacheConfiguration: CacheConfiguration,
        validatedMonotonicClock: MonotonicClock
    ) throws {
        try cacheConfiguration.validate()
        if let allowedIssuers {
            guard allowedIssuers.allSatisfy({
                $0.hasPrefix("did:plc:") &&
                    (try? AccountIdentifiers.validateDID($0)) != nil
            }) else {
                throw SwanError.malformed("PLC credential-key issuer allowlist is invalid")
            }
        }
        self.plc = plc
        self.continuityStore = continuityStore
        self.allowedIssuers = allowedIssuers
        self.cacheConfiguration = cacheConfiguration
        self.monotonicClock = validatedMonotonicClock
    }

    /// Builds the strict directory client from its already-validated
    /// configuration. Production versus laboratory/localhost policy remains
    /// entirely owned by ``PLCClientConfiguration``; this resolver accepts no
    /// independent remote origin or transport URL.
    public init(
        configuration: PLCClientConfiguration,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard
    ) throws {
        try self.init(
            plc: try PLCDirectoryClient(configuration: configuration),
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration
        )
    }

    public init(
        configuration: PLCClientConfiguration,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard,
        monotonicClock: MonotonicClock
    ) throws {
        try self.init(
            plc: try PLCDirectoryClient(configuration: configuration),
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration,
            monotonicClock: monotonicClock
        )
    }

    public init(
        configuration: PLCClientConfiguration,
        continuityStore: any PLCCredentialKeyContinuityStore,
        allowedIssuers: Set<String>? = nil,
        cacheConfiguration: CacheConfiguration = .standard,
        clock: @escaping @Sendable () -> Date
    ) throws {
        try self.init(
            plc: try PLCDirectoryClient(configuration: configuration),
            continuityStore: continuityStore,
            allowedIssuers: allowedIssuers,
            cacheConfiguration: cacheConfiguration,
            clock: clock
        )
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        guard (try? AccountIdentifiers.validateDID(issuer)) != nil,
              issuer.hasPrefix("did:plc:"),
              allowedIssuers.map({ $0.contains(issuer) }) ?? true,
              let methodNames = Self.methodNames(for: keyID) else {
            return nil
        }

        try Task.checkCancellation()
        let now = monotonicClock.now()
        let state = try await state(for: issuer, now: now)
        guard state.did == issuer else {
            return nil
        }

        // Current authorities (the reference implementation since
        // d7849741, and Swan) mint `kid: #atproto`, which resolves exactly.
        // Proposal 0016 also permits `kid: #atproto_space` with an
        // ordinary-account-key fallback, so for that kid try `#atproto` only
        // when the dedicated method is genuinely absent. A
        // present-but-malformed dedicated method remains fail-closed and
        // never silently downgrades to another key.
        for methodName in methodNames {
            guard let encodedKey = state.verificationMethods[methodName] else {
                continue
            }
            do {
                switch try PLCDIDKeyCodec.decode(encodedKey) {
                case let .p256(publicKey):
                    return .p256(publicKey)
                case let .secp256k1(publicKey):
                    return try .init(secp256k1PublicKey: publicKey)
                }
            } catch {
                // A malformed or unsupported method in an otherwise
                // authenticated PLC state is not a reason to try a second
                // network authority.
                return nil
            }
        }
        return nil
    }

    private func state(
        for issuer: String,
        now: UInt64
    ) async throws -> PLCDocumentData {
        if let entry = cache[issuer], entry.expiresAt > now {
            return entry.state
        }

        if let flight = inFlight.entry(for: issuer) {
            return try await finish(
                flight.value,
                issuer: issuer,
                generation: flight.generation
            )
        }

        if let negative = negativeCache[issuer], negative.expiresAt > now {
            throw SwanError.unavailable("PLC credential-key resolution is temporarily unavailable")
        }
        negativeCache.removeValue(forKey: issuer)

        try admitLookup(for: issuer, now: now)
        let plc = self.plc
        let continuityStore = self.continuityStore
        let monotonicClock = self.monotonicClock
        let priority = Task.currentPriority
        let task = Task.detached(priority: priority) {
            guard let permit = await PLCProcessLookupGate.shared.acquire() else {
                return RefreshOutcome(
                    result: .failure,
                    completedAt: monotonicClock.now()
                )
            }

            let result: RefreshResult
            do {
                let refreshed = try await Self.fetchVerifiedState(
                    plc: plc,
                    issuer: issuer
                )
                let committed = try await continuityStore
                    .advancePLCCredentialKeyContinuity(
                        refreshed.continuityAdvance
                    )
                guard committed ==
                    refreshed.continuityAdvance.checkpoint else {
                    throw PLCCredentialKeyContinuityStoreError.malformedRecord
                }
                result = .success(refreshed)
            } catch {
                result = .failure
            }
            await permit.release()
            return RefreshOutcome(
                result: result,
                completedAt: monotonicClock.now()
            )
        }
        let generation = inFlight.install(task, for: issuer)
        return try await finish(
            task,
            issuer: issuer,
            generation: generation
        )
    }

    private func finish(
        _ task: Task<RefreshOutcome, Never>,
        issuer: String,
        generation: PLCResolverFlightRegistry<
            Task<RefreshOutcome, Never>
        >.Generation
    ) async throws -> PLCDocumentData {
        let outcome = await task.value
        let ownsCurrentFlight =
            inFlight.remove(
                for: issuer,
                ifOwnedBy: generation
            ) != nil

        if ownsCurrentFlight {
            switch outcome.result {
            case let .success(refreshed):
                negativeCache.removeValue(forKey: issuer)
                cache[issuer] = CacheEntry(
                    state: refreshed.state,
                    expiresAt: Self.deadline(
                        after: outcome.completedAt,
                        interval: cacheConfiguration.lifetime
                    )
                )
            case .failure:
                // An expired authenticated state is never retained after a
                // failed refresh. A stale waiter cannot reach this branch for
                // a replacement generation.
                cache.removeValue(forKey: issuer)
                recordNegativeResult(
                    for: issuer,
                    completedAt: outcome.completedAt
                )
            }
        }

        // Cancellation is local to this waiter. The detached shared refresh
        // runs through permit release and populates (or negatively populates)
        // the cache before the cancelled caller observes cancellation.
        try Task.checkCancellation()
        switch outcome.result {
        case let .success(refreshed):
            return refreshed.state
        case .failure:
            throw SwanError.unavailable(
                "PLC credential-key resolution failed"
            )
        }
    }

    private static func fetchVerifiedState(
        plc: any PLCClient,
        issuer: String
    ) async throws -> RefreshedState {
        let state = try await plc.fetchState(did: issuer)
        let audit = try await plc.fetchAudit(did: issuer)
        guard state.did == issuer,
              !audit.isEmpty,
              audit.count <=
                PLCCredentialKeyContinuityAdvance.maximumAuditCIDCount,
              audit.allSatisfy({ $0.did == issuer }),
              let terminal = audit.last(where: { !$0.nullified }),
              let regular = terminal.operation.regular,
              state.rotationKeys == regular.rotationKeys,
              state.verificationMethods == regular.verificationMethods,
              state.alsoKnownAs == regular.alsoKnownAs,
              state.services == regular.services else {
            throw SwanError.unavailable("PLC credential-key identity or audit mismatch")
        }
        var auditCIDs = [String]()
        var seenAuditCIDs = Set<String>()
        var auditCIDBytes = 0
        for entry in audit {
            let byteCount = entry.cid.utf8.count
            guard byteCount <= 256,
                  auditCIDBytes <=
                    PLCCredentialKeyContinuityAdvance.maximumAuditCIDBytes -
                        byteCount,
                  try entry.operation.cid.string == entry.cid,
                  seenAuditCIDs.insert(entry.cid).inserted else {
                throw SwanError.unavailable("PLC credential-key audit CID is invalid")
            }
            auditCIDBytes += byteCount
            auditCIDs.append(entry.cid)
        }
        return RefreshedState(
            state: state,
            continuityAdvance: try PLCCredentialKeyContinuityAdvance(
                issuer: issuer,
                terminalCID: terminal.cid,
                auditCIDs: auditCIDs
            )
        )
    }

    private func admitLookup(for issuer: String, now: UInt64) throws {
        guard inFlight.count < cacheConfiguration.maximumConcurrentLookups else {
            throw SwanError.unavailable("PLC credential-key resolution capacity exhausted")
        }

        // Positive entries are a value-TTL cache, not the durable continuity
        // anchor. Once an entry expires it must release an issuer-capacity
        // slot; otherwise a bounded burst of distinct request issuers would
        // permanently deny every later issuer until process restart.
        let hadPositiveCacheEntry = cache[issuer] != nil
        pruneExpiredCacheEntries(now: now)
        pruneExpiredNegativeEntries(now: now)

        // Refreshes for a previously authenticated issuer do not consume the
        // new-issuer budget. An untrusted stream of distinct space authorities
        // therefore has a hard outbound-request ceiling as well as a
        // concurrency ceiling.
        guard hadPositiveCacheEntry || cache[issuer] == nil else { return }
        let retainedIssuers = Set(cache.keys)
            .union(negativeCache.keys)
            .union(inFlight.issuers)
        guard retainedIssuers.contains(issuer) ||
            retainedIssuers.count < cacheConfiguration.maximumEntries else {
            // Do not let request-selected input grow the process cache without
            // bound. Authenticated terminal CIDs live in the separate durable
            // continuity store and are not evicted with cached document data.
            throw SwanError.unavailable("PLC credential-key issuer capacity exhausted")
        }
        guard !hadPositiveCacheEntry else { return }
        if let startedAt = newIssuerWindowStartedAt {
            if now < startedAt ||
                now - startedAt >= Self.oneMinuteNanoseconds {
                newIssuerWindowStartedAt = now
                newIssuerLookupsInWindow = 0
            }
        } else {
            newIssuerWindowStartedAt = now
        }
        guard newIssuerLookupsInWindow <
            cacheConfiguration.maximumNewIssuerLookupsPerMinute else {
            throw SwanError.unavailable("PLC credential-key new-issuer budget exhausted")
        }
        newIssuerLookupsInWindow += 1
    }

    private func recordNegativeResult(
        for issuer: String,
        completedAt: UInt64
    ) {
        negativeCache[issuer] = NegativeCacheEntry(
            expiresAt: Self.deadline(
                after: completedAt,
                interval: cacheConfiguration.negativeLifetime
            )
        )
    }

    private func pruneExpiredNegativeEntries(now: UInt64) {
        let expired = negativeCache.compactMap { issuer, entry in
            entry.expiresAt <= now ? issuer : nil
        }
        for issuer in expired {
            negativeCache.removeValue(forKey: issuer)
        }
    }

    private func pruneExpiredCacheEntries(now: UInt64) {
        let expired = cache.compactMap { issuer, entry in
            entry.expiresAt <= now ? issuer : nil
        }
        for issuer in expired {
            cache.removeValue(forKey: issuer)
        }
    }

    private static let oneMinuteNanoseconds: UInt64 = 60_000_000_000

    private static func deadline(
        after instant: UInt64,
        interval: TimeInterval
    ) -> UInt64 {
        let duration = UInt64(
            (interval * 1_000_000_000).rounded(.up)
        )
        let (deadline, overflow) = instant.addingReportingOverflow(
            max(1, duration)
        )
        return overflow ? .max : deadline
    }

    private static func nanoseconds(
        forLegacyLogicalDate date: Date
    ) -> UInt64 {
        let seconds = date.timeIntervalSinceReferenceDate
        guard seconds.isFinite, seconds > 0 else { return 0 }
        let nanoseconds = seconds * 1_000_000_000
        guard nanoseconds < Double(UInt64.max) else { return .max }
        return UInt64(nanoseconds.rounded(.down))
    }

    private static func methodNames(for keyID: String) -> [String]? {
        keyID == "#atproto" ? ["atproto"] : nil
    }
}
