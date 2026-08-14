import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanPublicRepository
import SwanSQLite

/// The production `SwanLexiconResolving`: all fifteen steps of §5.7.4,
/// **including all six proofs**, plus the two caches.
///
/// **This is a port of `@atproto/lex-resolver`
/// (`packages/lex/lex-resolver/src/lex-resolver.ts`), not an approximation of
/// it.** An implementation that performs steps 1-7 and skips 8-13 is NOT a
/// partial implementation of this protocol; it is a different and unsafe
/// protocol wearing this one's name, and "we'll add proof verification in a
/// follow-up" is exactly the shortcut §5.7.4 exists to forbid. The reason is
/// concrete rather than stylistic: `com.atproto.repo.getRecord` — the endpoint
/// an earlier draft of this design used — is an application-layer XRPC call
/// with **no cryptographic linkage to the DID's repo state**, so a compromised,
/// misconfigured, MITM'd or simply dishonest PDS can return any JSON it likes
/// for `com.atproto.lexicon.schema/<nsid>`, including a permission set that
/// expands to a broader set of scopes than the DID's real signed repo declares.
/// Phase 2 feeds `include:` expansion directly into what an OAuth grant
/// materialises to. That is privilege escalation operated by lying in an HTTP
/// response, and only steps 8-13 detect it.
///
/// Trust flows: DID document → commit signature → MST membership → record bytes.
/// Never from "the server said so."
///
/// **What this type does NOT decide.** It classifies a proved document and stops
/// there. Whether a `.other` document is an error, whether an empty expansion is
/// acceptable, and whether a failure surfaces as `invalid_scope` or
/// `invalid_request` are all call-site decisions — §5.7.5 keeps upstream's
/// asymmetric codes for the same root cause deliberately, so the code cannot be
/// chosen here.
public struct SwanLexiconResolver: SwanLexiconResolving {
    /// Step 4. **Hardcoded, never caller-suppliable.** A caller-chosen
    /// collection would let a request point the proof machinery at an arbitrary
    /// record in the authority's repo and have the result treated as that
    /// authority's permission declaration.
    public static let lexiconCollection = "com.atproto.lexicon.schema"

    private let dns: any ATHandleDNSResolving
    private let authorities: any SwanLexiconAuthorityResolving
    private let fetcher: OAuthRemoteDocumentFetcher
    private let store: any OAuthLexiconDocumentStore
    private let authorityCache: SwanLexiconAuthorityCache
    private let limits: PublicRepositoryLimits
    private let now: @Sendable () -> Date
    private let diagnostics: (@Sendable (String, SwanLexiconResolverFailure) -> Void)?

    /// - Parameters:
    ///   - dns: a **new call site** on the existing bounded resolver, not new
    ///     DNS plumbing. `SystemATHandleDNSResolver` queries `_atproto.<handle>`
    ///     today over the same C wire-parser; this queries
    ///     `_lexicon.<authority>` over the same one.
    ///   - authorities: steps 5-6 (P2-C), accepting `did:plc:` and `did:web:`
    ///     under `allowedLexiconAuthorityDIDMethods` (§9-D22).
    ///   - fetcher: step 7. **Must** be an `OAuthRemoteDocumentFetcher`: its
    ///     `fetchBytes` shares one hardened core with `fetchJSON` — URL policy,
    ///     DNS resolution raced against the same deadline, the
    ///     public-address-only peer check, redirect policy, admission control
    ///     and the body cap. Constructing an `HTTPClient` here, or adding any
    ///     second fetch path, is the one refactor §5.7.4 forbids outright.
    ///   - store: the document-keyed cache (steps 7-15).
    ///   - limits: passed to the CAR parser and the MST walk. Defaults to
    ///     `.standard`, which is deliberately the **same** limits object the
    ///     full validators use: two MST budgets that can drift apart is a worse
    ///     outcome than either number.
    ///   - diagnostics: observes which check refused a resolution. A **cancelled**
    ///     resolution deliberately reports NOTHING here: cancellation is not a
    ///     resolver-class failure, so it leaves through `classify` before the
    ///     reporting site is reached. Read that silence as correctness, not as a
    ///     gap — this hook previously reported a cancelled fetch as
    ///     `.recordFetchFailed`, which was a confident false answer about an
    ///     NSID that never failed. If cancellation ever needs observing, it needs
    ///     its own channel; see `SwanLexiconResolverFailure` for why it must not
    ///     be added there.
    public init(
        dns: any ATHandleDNSResolving,
        authorities: any SwanLexiconAuthorityResolving,
        fetcher: OAuthRemoteDocumentFetcher,
        store: any OAuthLexiconDocumentStore,
        limits: PublicRepositoryLimits = .standard,
        now: @escaping @Sendable () -> Date = { Date() },
        diagnostics: (@Sendable (String, SwanLexiconResolverFailure) -> Void)? = nil
    ) throws {
        // The 256 KiB CAR cap is an anti-DoS control on MST-walk and
        // signature CPU, not a document-size preference, and the only thing
        // that actually enforces it is the fetcher's own body cap. Handing this
        // resolver a wider policy would silently remove the bound, so it is
        // refused at construction rather than checked per request.
        //
        // It cannot be expressed through `PublicRepositoryLimits` instead:
        // `maximumCARBytes` there is floored at the 256 MiB streaming
        // acceptance case (`PublicRepositoryLimits.swift:52-54`), so a
        // 256 KiB value is not constructible.
        guard fetcher.policy.maximumBodyBytes
            <= SwanLexiconResolutionBudget.maximumCARBytes else {
            throw SwanError.malformed(
                "lexicon resolver requires a fetch policy capped at 256 KiB or less"
            )
        }
        self.dns = dns
        self.authorities = authorities
        self.fetcher = fetcher
        self.store = store
        self.limits = limits
        self.now = now
        self.diagnostics = diagnostics
        authorityCache = SwanLexiconAuthorityCache()
    }

    // MARK: - Entry point

    /// Resolves one NSID through the cache, performing the fifteen steps only
    /// when the cached row is absent or stale.
    ///
    /// The outcomes are exactly §5.7.5's matrix:
    ///
    /// | condition | result |
    /// |---|---|
    /// | fresh positive row | `.resolved`, no I/O |
    /// | fresh negative row | `.unresolvable`, **no network I/O and no MST walk** |
    /// | stale / absent, resolves | `.resolved`, row written |
    /// | stale, fails, cache < 24 h | `.resolved` from cache (serve stale) |
    /// | stale, fails, no cache | `.unresolvable`, negative row written |
    /// | stale, fails, cache ≥ 24 h | `.unresolvable` (Swan's hard expiry) |
    ///
    /// Only `SwanLexiconResolverFailure` becomes `.unresolvable`. A cancellation,
    /// a storage fault, or any other error **propagates** — widening this to
    /// catch-all would convert a bug into a cached "this lexicon doesn't exist"
    /// for five minutes.
    public func resolve(_ nsid: String) async throws -> SwanLexiconResolution {
        let instant = now()
        let cached = try await store.findLexicon(nsid: nsid)

        if let cached, !cached.isStale(now: instant) {
            if let served = try Self.serve(cached, now: instant) { return served }
            // A fresh row that cannot be served is either a negative-cache row
            // or a positive one past the 24 h hard expiry. Both answer without a
            // network round trip, which is the point of writing the row at all.
            return .unresolvable
        }

        do {
            let outcome = try await performResolution(nsid)
            try await store.storeLexicon(
                OAuthLexiconDocumentRow(
                    nsid: nsid,
                    document: outcome.recordBytes,
                    sourceURI: outcome.sourceURI,
                    verifiedCID: outcome.verifiedCID,
                    createdAt: cached?.createdAt ?? instant,
                    updatedAt: instant,
                    lastSucceededAt: instant
                )
            )
            return .resolved(
                outcome.document,
                sourceURI: outcome.sourceURI,
                verifiedCID: outcome.verifiedCID
            )
        } catch let failure as SwanLexiconResolverFailure {
            diagnostics?(nsid, failure)
            // Serve-stale on failure: keep the previous document, its URI and
            // its CID, preserve `last_succeeded_at`, and bump `updated_at` so
            // `isStale` governs the next attempt — explicitly "to avoid
            // hammering the resolver" (`lexicon-getter.ts:19-40`).
            try await store.storeLexicon(
                OAuthLexiconDocumentRow(
                    nsid: nsid,
                    document: cached?.document,
                    sourceURI: cached?.sourceURI,
                    verifiedCID: cached?.verifiedCID,
                    createdAt: cached?.createdAt ?? instant,
                    updatedAt: instant,
                    lastSucceededAt: cached?.lastSucceededAt
                )
            )
            if let cached, let served = try Self.serve(cached, now: instant) {
                return served
            }
            return .unresolvable
        }
    }

    /// Decodes a cached row back into a resolution, or returns `nil` when the
    /// row cannot be served.
    ///
    /// The CID is **re-checked against the stored bytes**. That is why the row
    /// holds canonical DAG-CBOR rather than JSON: `verified_cid` is the content
    /// address the proof chain terminated at, and re-hashing here is what makes
    /// "a cached document can be shown to be the same document that was proved"
    /// an enforced property instead of an annotation. A row that fails it is
    /// treated as unservable rather than trusted — nothing vouches for those
    /// bytes any more.
    ///
    /// **Why this throws rather than folding every failure into `nil`.**
    /// `decodeDocument` routes its catch-all through `classify`, so it can raise
    /// `CancellationError`. Under the `try?` this function used to use, that
    /// cancellation would have been swallowed into `nil` and answered as
    /// `.unresolvable` — reintroducing the exact laundering `classify` exists to
    /// remove, on the one path that reaches it without any network I/O. `nil`
    /// still means "this row cannot be served"; cancellation now leaves by a
    /// different door.
    private static func serve(
        _ row: OAuthLexiconDocumentRow, now: Date
    ) throws -> SwanLexiconResolution? {
        guard let bytes = row.document,
              let sourceURI = row.sourceURI,
              let verifiedCID = row.verifiedCID,
              !row.isHardExpired(now: now) else { return nil }
        // `CID.parse` and `fromDAGCBOR` are pure and cannot be cancelled, so a
        // failure here is genuinely an unservable row.
        guard let cid = try? CID.parse(verifiedCID),
              CID.fromDAGCBOR(bytes) == cid else { return nil }
        let document: SwanLexiconDocument
        do {
            document = try decodeDocument(bytes, expectedNSID: row.nsid)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return nil
        }
        return .resolved(document, sourceURI: sourceURI, verifiedCID: verifiedCID)
    }

    // MARK: - The fifteen steps

    private struct ResolutionOutcome: Sendable {
        let document: SwanLexiconDocument
        let recordBytes: Data
        let sourceURI: String
        let verifiedCID: String
    }

    private func performResolution(_ nsid: String) async throws -> ResolutionOutcome {
        // Step 1 — NSID → reverse-DNS authority.
        let authority = try Self.authorityDomain(ofNSID: nsid)

        // Steps 2-6, domain-keyed. Four includes under one authority share one
        // DNS + DID resolution. This caches the resolved DID DOCUMENT (as the
        // key/endpoint pair it yields), never a proof result: the proof below is
        // re-verified on every resolution against whatever key the document
        // currently names. It is the same layer upstream caches at
        // (`DidResolverCached`, `create-did-resolver.ts:21-35`).
        let authorityRecord = try await resolveAuthority(domain: authority)
        let did = authorityRecord.did

        // Step 4 — the collection is hardcoded above.
        let path: PublicRepositoryPath
        do {
            path = try PublicRepositoryPath(
                collection: Self.lexiconCollection, recordKey: nsid
            )
        } catch {
            try Self.classify(error, as: .invalidNSID)
        }
        let sourceURI = "at://\(did)/\(Self.lexiconCollection)/\(nsid)"

        // Step 7 — against the RESOLVED PDS, never a caller-supplied host.
        let carBytes = try await fetchProofCAR(
            pds: authorityRecord.authority.pdsEndpoint,
            did: did,
            rkey: nsid
        )

        // Steps 8-13.
        let proof = try await verifyRecordProof(
            car: carBytes,
            did: did,
            path: path,
            verifier: authorityRecord.authority.commitVerifier
        )

        // Steps 14-15.
        let document = try Self.decodeDocument(proof.recordBytes, expectedNSID: nsid)

        return ResolutionOutcome(
            document: document,
            recordBytes: proof.recordBytes,
            sourceURI: sourceURI,
            verifiedCID: proof.recordCID.string
        )
    }

    // MARK: - Failure classification

    /// Turns a caught error into a resolver-class failure — **unless the task
    /// was cancelled**, in which case the cancellation is what actually
    /// happened and it must propagate.
    ///
    /// **Every catch-all on the resolution path routes through here — including
    /// the synchronous ones that cannot currently raise a cancellation at all.**
    /// That uniformity is the point: "the async catch-alls are covered" is an
    /// invariant a reader has to re-derive by checking which callee is async,
    /// and it silently stops holding the day someone makes one of the decoders
    /// streaming. "Every catch-all routes through `classify`" is checkable with
    /// a grep.
    ///
    /// `catch is CancellationError` alone is not sufficient anywhere on this
    /// path, and the reason is not obvious. A cancellation raised inside the
    /// fetcher is re-wrapped as `SwanError.unavailable("OAuth remote fetch
    /// failed")` before the resolver sees it (`OAuthRemoteFetch.swift:674-677`),
    /// and the same laundering is available to any injected DNS or DID-document
    /// resolver. Whether the bare `CancellationError` reaches this file at all
    /// then depends on which task in `SwanLexiconDeadline.run`'s group finishes
    /// first — the sleeper (which throws `CancellationError`) or the operation
    /// (which throws its laundered error). That race was measured at roughly
    /// 50/50 for a cancelled fetch.
    ///
    /// Losing it is not cosmetic. `resolveAll` cancels every in-flight sibling
    /// when the 10 s group deadline expires, so a laundered cancellation writes
    /// a **negative cache row for an NSID that never failed**, and the next five
    /// minutes of requests answer `.unresolvable` from that row without any I/O.
    /// An authority that is merely slow would then decide which of a user's
    /// other includes survive — the selective-corruption outcome §5.7.4's
    /// "a proof failure never degrades to a drop" rule exists to prevent,
    /// arriving through the cache instead of through the drop path.
    private static func classify(
        _ error: any Error, as failure: SwanLexiconResolverFailure
    ) throws -> Never {
        if error is CancellationError { throw CancellationError() }
        try Task.checkCancellation()
        throw failure
    }

    // MARK: Step 1

    /// The reverse-DNS authority of an NSID: every segment but the last,
    /// reversed — upstream `NSID.authority`. `com.example.foo.auth` →
    /// `foo.example.com`.
    public static func authorityDomain(ofNSID nsid: String) throws -> String {
        guard AtprotoSyntax.isValidNSID(nsid) else {
            throw SwanLexiconResolverFailure.invalidNSID
        }
        let segments = nsid.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else {
            // A valid NSID always has at least domain-authority + name, and
            // `isValidNSID` already enforces the segment floor; this is the
            // belt for a future grammar change rather than a reachable branch.
            throw SwanLexiconResolverFailure.invalidNSID
        }
        return segments.dropLast().reversed().joined(separator: ".")
    }

    // MARK: Steps 2-6

    private struct AuthorityRecord: Sendable {
        let did: String
        let authority: SwanLexiconAuthority
    }

    private func resolveAuthority(domain: String) async throws -> AuthorityRecord {
        if let cached = await authorityCache.value(for: domain, now: now()) {
            return AuthorityRecord(did: cached.did, authority: cached.authority)
        }
        let did = try await resolveAuthorityDID(domain: domain)
        let authority: SwanLexiconAuthority
        do {
            authority = try await SwanLexiconDeadline.run(
                seconds: SwanLexiconResolutionBudget.didDocumentDeadlineSeconds,
                onExpiry: SwanLexiconResolverFailure.authorityDocumentUnavailable
            ) { [authorities] in
                try await authorities.resolveAuthority(did: did)
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as SwanLexiconAuthorityResolutionError {
            // Steps 5 and 6 are separate rows of §5.7.5's matrix even though
            // they carry the same code, so the distinction is preserved rather
            // than flattened into one failure.
            switch error {
            case .missingSigningKey, .unsupportedSigningKey, .missingPDSEndpoint:
                try Self.classify(error, as: .authorityDocumentIncomplete)
            case .invalidAuthorityDID, .didMethodNotAllowed,
                 .documentUnavailable, .documentSubjectMismatch:
                try Self.classify(error, as: .authorityDocumentUnavailable)
            }
        } catch let failure as SwanLexiconResolverFailure {
            throw failure
        } catch {
            try Self.classify(error, as: .authorityDocumentUnavailable)
        }
        await authorityCache.store(
            domain: domain, did: did, authority: authority, now: now()
        )
        return AuthorityRecord(did: did, authority: authority)
    }

    /// Steps 2-3. `_lexicon.<authority>` TXT, then **exactly one** `did=` line.
    ///
    /// Zero is an error and more than one is an error; it is deliberately not
    /// "first wins" (`lex-resolver.ts:507-519`). Two `did=` lines is a state an
    /// attacker who can append a TXT record reaches, and under first-wins the
    /// winner is decided by DNS answer ordering — which the attacker also
    /// influences.
    ///
    /// Note the layering: chunk joining is already done for us. The C wire
    /// parser emits one entry per TXT RR with its character-strings
    /// concatenated, which is exactly upstream's `chunks.join('')`.
    private func resolveAuthorityDID(domain: String) async throws -> String {
        let records: [ATHandleTXTRecord]
        do {
            records = try await SwanLexiconDeadline.run(
                seconds: SwanLexiconResolutionBudget.dnsDeadlineSeconds,
                onExpiry: SwanLexiconResolverFailure.dnsUnavailable
            ) { [dns] in
                try await dns.txtRecords(name: "_lexicon.\(domain)")
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let failure as SwanLexiconResolverFailure {
            throw failure
        } catch {
            try Self.classify(error, as: .dnsUnavailable)
        }
        // The same answer-count bound `resolveTXT` applies to `_atproto`. An
        // unbounded answer set is work an attacker chooses the size of.
        guard records.count <= 128 else {
            throw SwanLexiconResolverFailure.dnsUnavailable
        }
        let prefix = Data("did=".utf8)
        var didLines: [String] = []
        for record in records where record.bytes.starts(with: prefix) {
            guard let text = String(data: record.bytes, encoding: .utf8) else {
                // A `did=`-prefixed record that is not UTF-8 still COUNTS as a
                // did line; discarding it would let an attacker add a
                // deliberately invalid second record to keep the count at one
                // and re-enable first-wins.
                throw SwanLexiconResolverFailure.invalidAuthorityDIDInTXT
            }
            didLines.append(String(text.dropFirst(prefix.count)))
        }
        guard didLines.count != 0 else {
            throw SwanLexiconResolverFailure.noAuthorityDIDInTXT
        }
        guard didLines.count == 1 else {
            throw SwanLexiconResolverFailure.multipleAuthorityDIDsInTXT
        }
        // Upstream's `assertDid` on the remainder. Two identical `did=` lines
        // are still two lines and are still refused above — deduplicating first
        // would be a quiet reintroduction of first-wins for the case where the
        // attacker can only replay the legitimate value.
        guard let did = try? AccountIdentifiers.validateDID(didLines[0]) else {
            throw SwanLexiconResolverFailure.invalidAuthorityDIDInTXT
        }
        return did
    }

    // MARK: Step 7

    /// `com.atproto.sync.getRecord` against the resolved PDS, returning raw CAR
    /// bytes.
    ///
    /// `sync.getRecord`, never `repo.getRecord`: the latter has no cryptographic
    /// linkage to repo state, which is the whole reason this design exists.
    private func fetchProofCAR(
        pds: URL, did: String, rkey: String
    ) async throws -> Data {
        guard var components = URLComponents(url: pds, resolvingAgainstBaseURL: false) else {
            throw SwanLexiconResolverFailure.authorityDocumentIncomplete
        }
        var path = components.percentEncodedPath
        if path.hasSuffix("/") { path.removeLast() }
        components.percentEncodedPath = path + "/xrpc/com.atproto.sync.getRecord"
        components.queryItems = [
            URLQueryItem(name: "did", value: did),
            URLQueryItem(name: "collection", value: Self.lexiconCollection),
            URLQueryItem(name: "rkey", value: rkey),
        ]
        guard let url = components.url else {
            throw SwanLexiconResolverFailure.authorityDocumentIncomplete
        }
        let bytes: Data
        do {
            bytes = try await SwanLexiconDeadline.run(
                seconds: SwanLexiconResolutionBudget.recordFetchDeadlineSeconds,
                onExpiry: SwanLexiconResolverFailure.recordFetchFailed
            ) { [fetcher] in
                try await fetcher.fetchBytes(from: url)
            }
        } catch {
            try Self.classify(error, as: .recordFetchFailed)
        }
        // The fetcher's policy cap already bounds this — the constructor refuses
        // a wider policy — but the CPU spent below is the thing being protected,
        // so the bound is also asserted where that spend begins.
        guard !bytes.isEmpty,
              bytes.count <= SwanLexiconResolutionBudget.maximumCARBytes else {
            throw SwanLexiconResolverFailure.recordFetchFailed
        }
        return bytes
    }

    // MARK: Steps 8-13 — the proofs

    private struct RecordProof: Sendable {
        let recordCID: CID
        let recordBytes: Data
    }

    /// Upstream's `verifyRecordProof` (`lex-resolver.ts:522-556`), step for step
    /// and **in upstream's order**.
    ///
    /// The order matters for one specific vector: `commit.did` is checked
    /// **before** the signature, so a cross-repo substitution is rejected by the
    /// DID equality itself rather than incidentally by a signature that happens
    /// not to verify. A resolver that resolved the key from the response would
    /// pass the signature check on such a CAR; only the equality catches it.
    private func verifyRecordProof(
        car: Data,
        did: String,
        path: PublicRepositoryPath,
        verifier: PermissionedDataPublicRepositoryCommitVerifier
    ) async throws -> RecordProof {
        // Step 8 — exactly one CAR root.
        //
        // This is structural in Swan rather than a separate count check: the
        // canonical one-root header is a single exact 58-byte schema
        // (`PublicRepositoryCAR.parseCanonicalHeader`), so a two-root header
        // fails to parse at all. An attacker-added second root cannot reach a
        // caller that would naively read `roots[0]`, because there is no
        // `roots[0]` to read.
        let sink = ProofCARSink()
        let parsed: PublicRepositoryCARParseResult
        do {
            parsed = try await PublicRepositoryCAR.parseIncrementally(
                from: ProofCARByteSource(bytes: car), to: sink, limits: limits
            )
        } catch {
            try Self.classify(error, as: .carRootCountInvalid)
        }
        let blocks = try await sink.blocks
        guard let commitBytes = try await blocks.block(for: parsed.rootCID) else {
            throw SwanLexiconResolverFailure.commitDecodeFailed
        }

        // Step 9 — the root block decodes as a repo-v3 `commit`. Structure
        // first, with no authenticity claim: CBOR that does not parse to the
        // exact commit schema is refused BEFORE any trust decision is taken on
        // its contents.
        let structural: StructurallyValidatedPublicRepositorySignedCommit
        do {
            structural = try PublicRepositoryCommitCodec.structurallyValidate(
                signedCommitBytes: commitBytes, expectedCommitCID: parsed.rootCID
            )
        } catch {
            try Self.classify(error, as: .commitDecodeFailed)
        }

        // Step 10 — `commit.did` is the RESOLVED did, not one the response
        // chose. Cross-repo substitution.
        guard structural.descriptor.did == did else {
            throw SwanLexiconResolverFailure.commitDIDMismatch
        }

        // Step 11 — the signature verifies against the key from the DID
        // DOCUMENT. The verifier arrives already bound to that key; nothing in
        // the response can influence which key is used.
        let verified: VerifiedPublicRepositorySignedCommit
        do {
            verified = try await PublicRepositoryCommitCodec.verify(
                signedCommitBytes: commitBytes,
                expectedCommitCID: parsed.rootCID,
                verifier: verifier
            )
        } catch {
            try Self.classify(error, as: .commitSignatureInvalid)
        }

        // Step 12 — MST membership from the SIGNATURE-VERIFIED `commit.data`.
        // Reachability, not presence: a record block sitting unlinked in the CAR
        // satisfies nothing here.
        //
        // `membership` returns nil ONLY for provable absence and throws when a
        // block is withheld. Both are refusals, and they are deliberately not
        // collapsed at the source — but they are the same answer HERE, because
        // an attacker who picks which blocks to omit must not be able to steer
        // the difference between "the authority does not declare this" and "I
        // withheld the evidence".
        let recordCID: CID?
        do {
            recordCID = try await RepositoryMSTProof.membership(
                rootCID: verified.descriptor.dataCID,
                path: path,
                blocks: blocks,
                limits: limits
            )
        } catch {
            try Self.classify(error, as: .recordNotInProof)
        }
        guard let recordCID, let recordBytes = try await blocks.block(for: recordCID) else {
            throw SwanLexiconResolverFailure.recordNotInProof
        }

        // Step 13 — the record's `$type` is the collection. Right MST key, wrong
        // lexicon type is type confusion, not a document. The CAR parser has
        // already proved `recordBytes` hashes to `recordCID`.
        let probe: RecordTypeProbe
        do {
            probe = try DAGCBOR.decode(recordBytes)
        } catch {
            try Self.classify(error, as: .recordTypeMismatch)
        }
        guard probe.type == Self.lexiconCollection else {
            throw SwanLexiconResolverFailure.recordTypeMismatch
        }
        return RecordProof(recordCID: recordCID, recordBytes: recordBytes)
    }

    // MARK: Steps 14-15

    /// Step 14 (lexicon-document schema) and step 15 (`lexicon.id == rkey`).
    ///
    /// Step 15 stops **same-repo record substitution**: a validly signed lexicon
    /// that describes a *different* NSID sitting at the expected rkey. Every
    /// proof above passes on such a record — it really is in the authority's
    /// signed repo at the key that was asked for — and only this check refuses
    /// it.
    static func decodeDocument(
        _ recordBytes: Data, expectedNSID nsid: String
    ) throws -> SwanLexiconDocument {
        let record: LexiconSchemaRecord
        do {
            record = try DAGCBOR.decode(recordBytes)
        } catch {
            try Self.classify(error, as: .documentSchemaInvalid)
        }
        // `lexiconDocumentSchema` (`lex-document/src/lexicon-document.ts:730`):
        // `lexicon` is the literal 1 and `id` is an NSID.
        guard record.lexicon == 1, AtprotoSyntax.isValidNSID(record.id) else {
            throw SwanLexiconResolverFailure.documentSchemaInvalid
        }
        guard record.id == nsid else {
            throw SwanLexiconResolverFailure.documentIDMismatch
        }
        switch record.defs.main {
        case let .permissionSet(set):
            return .permissionSet(set)
        case let .space(space):
            return .space(space)
        case .other, .none:
            // Proved and schema-valid, but `defs.main` is absent or names some
            // other definition type. A SUCCESS: the document was established as
            // the authority's. `lexicon-manager.ts:126-129` is where "not a
            // permission set" becomes an error, and that is a consumer decision.
            return .other
        }
    }
}

// MARK: - Record shapes

/// Step 13 reads `$type` alone, deliberately separately from the
/// document decode below. They are different rows of §5.7.5's matrix — a proof
/// failure and a schema failure — and a single combined decode would make them
/// indistinguishable, so a `$type` mismatch would be reported as a malformed
/// document rather than as the type confusion it is.
private struct RecordTypeProbe: Decodable, DAGCBORDecodable {
    let type: String

    private enum CodingKeys: String, CodingKey {
        case type = "$type"
    }
}

/// `lexiconDocumentSchema` (`lex-document/src/lexicon-document.ts:730`), narrowed
/// to what authorization needs: the version literal, the id, and `defs.main`.
///
/// Definitions other than `main` are accepted and ignored. They carry no
/// capability — `lexicon-manager.ts` reads `defs.main` and nothing else — and
/// validating the full `NAMED_LEXICON_SCHEMAS` union would make Swan reject
/// documents upstream's OAuth path accepts, for no authorization benefit.
private struct LexiconSchemaRecord: Decodable, DAGCBORDecodable {
    let lexicon: Int
    let id: String
    let defs: Defs

    struct Defs: Decodable {
        let main: MainDefinition?
    }

    /// `main` is decoded by its `type` discriminator, exactly as
    /// `l.discriminatedUnion('type', MAIN_LEXICON_SCHEMAS)` does. Anything that
    /// is not `permission-set` or `space` is `.other` rather than a decode
    /// failure: a lexicon document declaring, say, a `query` is a perfectly
    /// valid document that simply grants nothing.
    enum MainDefinition: Decodable {
        case permissionSet(LexiconPermissionSet)
        case space(LexiconSpace)
        case other

        private enum CodingKeys: String, CodingKey {
            case type
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            switch try container.decode(String.self, forKey: .type) {
            case "permission-set":
                self = .permissionSet(try LexiconPermissionSet(from: decoder))
            case "space":
                self = .space(try LexiconSpace(from: decoder))
            default:
                self = .other
            }
        }
    }
}

// MARK: - CAR plumbing

/// Feeds an already-bounded in-memory CAR to the streaming parser.
///
/// The bytes are in memory because the fetcher's 256 KiB cap put them there; the
/// parser is still the streaming one, so the framing rules — canonical varints,
/// the exact one-root header, per-block CID verification — are the same ones a
/// multi-gigabyte import goes through.
private actor ProofCARByteSource: PublicRepositoryCARByteSource {
    private let bytes: Data
    private var offset: Int

    init(bytes: Data) {
        self.bytes = bytes
        offset = bytes.startIndex
    }

    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < bytes.endIndex else { return nil }
        let end = min(bytes.endIndex, offset + max(1, maximumBytes))
        defer { offset = end }
        return Data(bytes[offset ..< end])
    }
}

/// Collects the CAR's blocks. Every block reaching `receiveBlock` has already
/// had its CID verified against its bytes by the parser, so the map is a set of
/// content-addressed blocks — which is what makes "reachable from `commit.data`"
/// a meaningful question to ask of it.
private actor ProofCARSink: PublicRepositoryCARFrameSink {
    private var collected: [PublicRepositoryBlock] = []
    private var cached: PublicRepositoryBlockMap?

    func receiveHeader(rootCID _: CID, receivedByteCount _: Int) async throws {}

    func receiveBlock(
        _ block: PublicRepositoryBlock,
        receivedByteCount _: Int,
        frameCount _: Int
    ) async throws {
        cached = nil
        collected.append(block)
    }

    var blocks: PublicRepositoryBlockMap {
        get async throws {
            if let cached { return cached }
            // Duplicate CIDs carrying different bytes cannot happen — the parser
            // verifies each block against its CID — so the map's
            // duplicate-conflict throw is unreachable here rather than tolerated.
            let map = try PublicRepositoryBlockMap(
                blocks: collected,
                maximumRelevantBytes: SwanLexiconResolutionBudget.maximumCARBytes
            )
            cached = map
            return map
        }
    }
}

// MARK: - Domain-keyed authority cache

/// Steps 1-6, keyed by **domain** rather than by NSID, so four includes under
/// one authority share one DNS + DID resolution (§5.7.4 budget).
///
/// It caches the DID document's *product* — the PDS endpoint and the bound
/// verifier — and never a proof result. The proof is re-run on every resolution
/// against whatever key this currently names, which is the property that makes
/// caching the document safe and caching the proof unsafe: a rotated key must
/// invalidate every conclusion drawn under the old one, and it does, because no
/// conclusion is stored.
private actor SwanLexiconAuthorityCache {
    struct Entry: Sendable {
        let did: String
        let authority: SwanLexiconAuthority
        let storedAt: Date
    }

    /// One entry per authority domain. Small because the population is
    /// per-request-capped at 4 includes + 8 space types, and because a stale
    /// entry costs one DNS + one DID fetch to rebuild.
    private static let capacity = 256

    private var entries: [String: Entry] = [:]

    func value(for domain: String, now: Date) -> Entry? {
        guard let entry = entries[domain] else { return nil }
        // The same 5-minute freshness the document cache uses. Sharing the
        // number is deliberate: an authority whose DNS or DID document changed
        // must not keep being reached through a cache that outlives the document
        // cache built on top of it.
        guard now.timeIntervalSince(entry.storedAt)
            < SwanLexiconResolutionBudget.refreshThresholdSeconds else {
            entries[domain] = nil
            return nil
        }
        return entry
    }

    func store(domain: String, did: String, authority: SwanLexiconAuthority, now: Date) {
        if entries[domain] == nil, entries.count >= Self.capacity {
            // Drop the oldest rather than refusing to cache: an attacker able to
            // name many authorities would otherwise turn the cache off for
            // everyone by filling it.
            if let oldest = entries.min(by: { $0.value.storedAt < $1.value.storedAt })?.key {
                entries[oldest] = nil
            }
        }
        entries[domain] = Entry(did: did, authority: authority, storedAt: now)
    }
}
