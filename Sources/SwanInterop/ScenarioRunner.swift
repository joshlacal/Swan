import Foundation
import SwanCore
import SwanSpacesWire

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct InteropScenarioFixtureArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let profileID: String
    public let scenarioCommit: String
    public let referenceImplementationCommit: String
    public let faultModes: [String]
    public let convergence: [EndpointConvergence]
    public let hostResults: [ScenarioHostResult]
    public let status: String
    public let summary: String
    public let startedAt: Date
    public let completedAt: Date
    public let fixturePolicy: String
    public let warnings: [String]

    public init(
        scenario: String,
        profileID: String,
        faultModes: [String],
        convergence: [EndpointConvergence],
        hostResults: [ScenarioHostResult],
        status: String,
        startedAt: Date,
        completedAt: Date,
        warnings: [String]
    ) {
        self.scenario = scenario
        self.profileID = profileID
        self.scenarioCommit = "119fa6b63476d30c2516846c714319046e0422f3"
        self.referenceImplementationCommit = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
        self.faultModes = faultModes
        self.convergence = convergence
        self.hostResults = hostResults
        self.status = status
        self.summary = hostResults.isEmpty ? "no endpoints executed" : "profile endpoint probes emitted"
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.fixturePolicy = "http-probe-only; json request/response summaries only"
        self.warnings = warnings
    }
}

public struct ScenarioHostResult: Codable, Sendable, Equatable {
    public let host: String
    public let baseURL: String
    public let endpointResults: [EndpointResult]

    public init(host: String, baseURL: String, endpointResults: [EndpointResult]) {
        self.host = host
        self.baseURL = baseURL
        self.endpointResults = endpointResults
    }
}

public struct EndpointResult: Codable, Sendable, Equatable {
    public let mode: String
    public let method: String
    public let path: String
    public let statusCode: Int
    public let requestSummary: [String: String]
    public let responseSummary: [String: String]
    public let expectedError: String?
    public let transportError: String?

    public init(
        mode: String,
        method: String,
        path: String,
        statusCode: Int,
        requestSummary: [String: String],
        responseSummary: [String: String],
        expectedError: String? = nil,
        transportError: String? = nil
    ) {
        self.mode = mode
        self.method = method
        self.path = path
        self.statusCode = statusCode
        self.requestSummary = requestSummary
        self.responseSummary = responseSummary
        self.expectedError = expectedError
        self.transportError = transportError
    }
}

public struct EndpointConvergence: Codable, Sendable, Equatable {
    public let mode: String
    public let method: String
    public let path: String
    public let swanProbeCount: Int
    public let referenceProbeCount: Int
    public let swanStatusCode: Int
    public let referenceStatusCode: Int
    public let swanTransportError: Bool
    public let referenceTransportError: Bool
    public let swanError: String?
    public let referenceError: String?
    public let firstProbeAligned: Bool
    public let allowedMismatch: Bool

    public init(
        mode: String,
        method: String,
        path: String,
        swanProbeCount: Int,
        referenceProbeCount: Int,
        swanStatusCode: Int,
        referenceStatusCode: Int,
        swanTransportError: Bool,
        referenceTransportError: Bool,
        swanError: String?,
        referenceError: String?,
        firstProbeAligned: Bool,
        allowedMismatch: Bool
    ) {
        self.mode = mode
        self.method = method
        self.path = path
        self.swanProbeCount = swanProbeCount
        self.referenceProbeCount = referenceProbeCount
        self.swanStatusCode = swanStatusCode
        self.referenceStatusCode = referenceStatusCode
        self.swanTransportError = swanTransportError
        self.referenceTransportError = referenceTransportError
        self.swanError = swanError
        self.referenceError = referenceError
        self.firstProbeAligned = firstProbeAligned
        self.allowedMismatch = allowedMismatch
    }
}

public enum InteropScenarioRunner {
    private struct ToxiproxyControl {
        static let proxyHostKey = "SWAN_INTEROP_TOXIPROXY_URL"
        static let proxyNameKey = "SWAN_INTEROP_TOXIPROXY_PROXY"
        static let referenceHostLabel = "reference-pds"

        static var baseURL: URL {
            if let configured = ProcessInfo.processInfo.environment[proxyHostKey],
               let parsed = URL(string: configured) {
                return parsed
            }
            return URL(string: "http://toxiproxy:8474")!
        }

        static var proxyName: String {
            ProcessInfo.processInfo.environment[proxyNameKey] ?? "reference-pds"
        }

        static func supports(hostLabel: String) -> Bool {
            hostLabel == referenceHostLabel
        }

        static var delayedToxicUpstreamName: String { "interop-delayed-upstream" }
        static var delayedToxicDownstreamName: String { "interop-delayed-downstream" }
        static var delayedLatencyMilliseconds: Int { 250 }
        static var delayedLatencyJitterMilliseconds: Int { 25 }
    }

    public struct RuntimeConfiguration: Sendable {
        public let swanBaseURL: URL
        public let referenceBaseURL: URL
        public let timeoutInterval: TimeInterval
        public let strictConvergence: Bool
        public let allowedConvergenceDivergences: Set<String>

        public init(
            swanBaseURL: URL = URL(string: "https://swan.test")!,
            referenceBaseURL: URL = URL(string: "https://pds.test")!,
            timeoutInterval: TimeInterval = 8,
            strictConvergence: Bool = false,
            allowedConvergenceDivergences: Set<String> = []
        ) {
            self.swanBaseURL = swanBaseURL
            self.referenceBaseURL = referenceBaseURL
            self.timeoutInterval = timeoutInterval
            self.strictConvergence = strictConvergence
            self.allowedConvergenceDivergences = allowedConvergenceDivergences
        }
    }

    public static func execute(
        scenario: String,
        faultModes: [FaultMode],
        runtime: RuntimeConfiguration = .init()
    ) async -> InteropScenarioFixtureArtifact {
        let startTime = Date()
        let normalizedScenario = scenario.trimmingCharacters(in: .whitespacesAndNewlines)

        let activeModes: [FaultMode] = faultModes
        let modeLabels = activeModes.map(\.rawValue)

        let targetInputs: [(label: String, baseURL: URL)] = [
            ("swan", runtime.swanBaseURL),
            ("reference-pds", runtime.referenceBaseURL),
        ]

        var hostResults: [ScenarioHostResult] = []
        var warnings: [String] = []
        var hasUnexpectedFailure = false
        var hasUnexpectedConvergenceFailure = false
        var hostEndpointBuckets: [String: [EndpointResultKey: [EndpointResult]]] = [:]
        let allowedConvergenceDivergences = Set(runtime.allowedConvergenceDivergences.map { $0.lowercased() })

        let executionModes = modeLabels.isEmpty ? ["normal"] : modeLabels
        let validatedTargets = targetInputs.map { target in
            (
                label: target.label,
                baseURL: target.baseURL,
                originLabel: sanitizedOriginLabel(for: target.baseURL)
            )
        }
        guard validatedTargets.allSatisfy({ $0.originLabel != nil }) else {
            hostResults = validatedTargets.map { target in
                ScenarioHostResult(
                    host: target.label,
                    baseURL: target.originLabel ?? "<invalid-origin>",
                    endpointResults: []
                )
            }
            return InteropScenarioFixtureArtifact(
                scenario: normalizedScenario,
                profileID: OfflineProtocolProfileVerifier.stableProfileID,
                faultModes: executionModes,
                convergence: [],
                hostResults: hostResults,
                status: "failed",
                startedAt: startTime,
                completedAt: Date(),
                warnings: ["invalid_endpoint_origin"]
            )
        }

        for target in validatedTargets {
            let hostLabel = target.label
            let baseURL = target.baseURL
            var endpointResults: [EndpointResult] = []

            for modeLabel in executionModes {
                let requestedModes = faultModeIfAny(modeLabel)

                if requestedModes.isEmpty {
                    let targetEndpointResults = await probeProfileEndpoints(
                        baseURL: baseURL,
                        faultMode: nil,
                        targetLabel: hostLabel,
                        timeoutInterval: runtime.timeoutInterval,
                        simulateDelayWhenUnavailable: false
                    )
                    endpointResults.append(contentsOf: targetEndpointResults)
                    if targetEndpointResults.contains(where: { isUnexpectedFailure($0, for: nil) }) {
                        hasUnexpectedFailure = true
                    }
                    continue
                }

                for mode in requestedModes {
                    let applied = await applyFaultMode(mode, forHost: hostLabel)
                    if !applied {
                        warnings.append("fault mode '\(modeLabel)' is best-effort for host '\(hostLabel)'")
                    }

                    let targetEndpointResults = await probeProfileEndpoints(
                        baseURL: baseURL,
                        faultMode: mode,
                        targetLabel: hostLabel,
                        timeoutInterval: runtime.timeoutInterval,
                        simulateDelayWhenUnavailable: !applied
                    )
                    endpointResults.append(contentsOf: targetEndpointResults)
                    if targetEndpointResults.contains(where: { isUnexpectedFailure($0, for: mode) }) {
                        hasUnexpectedFailure = true
                    }

                    await clearSimulatedFault(mode, forHost: hostLabel)
                }
            }

            hostResults.append(
                ScenarioHostResult(
                    host: hostLabel,
                    baseURL: target.originLabel!,
                    endpointResults: endpointResults
                )
            )
            hostEndpointBuckets[hostLabel] = bucketResults(endpointResults)
        }

        return InteropScenarioFixtureArtifact(
            scenario: normalizedScenario,
            profileID: OfflineProtocolProfileVerifier.stableProfileID,
            faultModes: executionModes,
            convergence: summarizeCrossHostConvergence(
                from: hostEndpointBuckets,
                strictConvergence: runtime.strictConvergence,
                allowedConvergenceDivergences: allowedConvergenceDivergences,
                hasUnexpectedFailure: &hasUnexpectedConvergenceFailure,
                warnings: &warnings
            ),
            hostResults: hostResults,
            status: hasUnexpectedFailure || hasUnexpectedConvergenceFailure ? "failed" : "passed",
            startedAt: startTime,
            completedAt: Date(),
            warnings: warnings
        )
    }

    private static func sanitizedOriginLabel(for url: URL) -> String? {
        let serialized = url.absoluteString
        guard !serialized.isEmpty,
              serialized.utf8.count <= 2_048,
              serialized.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              }),
              let components = URLComponents(
                  url: url,
                  resolvingAgainstBaseURL: false
              ),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              !components.percentEncodedPath.lowercased().contains("%00"),
              !components.path.contains("\\") else {
            return nil
        }

        var origin = URLComponents()
        origin.scheme = scheme
        origin.host = host.lowercased()
        origin.port = components.port
        return origin.string
    }

    private static func isUnexpectedFailure(_ result: EndpointResult, for faultMode: FaultMode?) -> Bool {
        if result.transportError != nil {
            return faultMode != .offline && faultMode != .disconnected
        }
        if result.statusCode == 503,
           let errorCode = result.responseSummary["error"],
           expectedBenign503ErrorCodes.contains(errorCode) {
            return false
        }
        if result.statusCode >= 500 {
            return true
        }
        if (300..<400).contains(result.statusCode) {
            return true
        }
        if (400..<500).contains(result.statusCode) {
            if let errorCode = result.responseSummary["error"] {
                return !expectedBenign4xxErrorCodes.contains(errorCode)
            }
            return true
        }
        return false
    }

    private static var expectedBenign4xxErrorCodes: Set<String> {
        [
            "AuthMissing",
            "InvalidRequest",
            "MissingCredential",
            "MissingJwt",
            "Unauthorized",
            "permissioned_data_pending",
            "permissioned_endpoint_unavailable",
            "temporarily_unavailable",
        ]
    }

    private static var expectedBenign503ErrorCodes: Set<String> {
        [
            "permissioned_data_pending",
            "permissioned_endpoint_unavailable",
        ]
    }

    struct EndpointResultKey: Hashable, Sendable {
        let mode: String
        let method: String
        let path: String
    }

    private static func bucketResults(_ results: [EndpointResult]) -> [EndpointResultKey: [EndpointResult]] {
        var buckets: [EndpointResultKey: [EndpointResult]] = [:]
        for result in results {
            let key = EndpointResultKey(mode: result.mode, method: result.method, path: result.path)
            buckets[key, default: []].append(result)
        }
        return buckets
    }

    static func summarizeCrossHostConvergence(
        from hostBuckets: [String: [EndpointResultKey: [EndpointResult]]],
        strictConvergence: Bool,
        allowedConvergenceDivergences: Set<String>,
        hasUnexpectedFailure: inout Bool,
        warnings: inout [String]
    ) -> [EndpointConvergence] {
        let normalizedAllowedConvergences = Set(allowedConvergenceDivergences.map { $0.lowercased() })
        let swanBuckets = hostBuckets["swan"] ?? [:]
        let referenceBuckets = hostBuckets["reference-pds"] ?? [:]
        let keys = Set(swanBuckets.keys).union(referenceBuckets.keys)

        guard !keys.isEmpty else {
            return []
        }

        var results: [EndpointConvergence] = []
        for key in keys.sorted(by: { lhs, rhs in
            if lhs.path != rhs.path {
                return lhs.path < rhs.path
            }
            if lhs.method != rhs.method {
                return lhs.method < rhs.method
            }
            return lhs.mode < rhs.mode
        }) {
            let swanProbeResults = swanBuckets[key] ?? []
            let referenceProbeResults = referenceBuckets[key] ?? []
            let swanFirst = swanProbeResults.first
            let referenceFirst = referenceProbeResults.first

            let swanStatusCode = swanFirst?.statusCode ?? 0
            let referenceStatusCode = referenceFirst?.statusCode ?? 0
            let swanTransportError = swanFirst?.transportError != nil
            let referenceTransportError = referenceFirst?.transportError != nil
            let swanError = swanFirst?.responseSummary["error"]
            let referenceError = referenceFirst?.responseSummary["error"]
            let firstProbeAligned = swanStatusCode == referenceStatusCode && swanTransportError == referenceTransportError
            let probeCountAligned = swanProbeResults.count == referenceProbeResults.count
            let errorAligned = swanError == referenceError
            let isAligned = firstProbeAligned && probeCountAligned && errorAligned
            let normalizedPath = key.path.lowercased()
            let normalizedMethodPath = "\(key.method) \(key.path)".lowercased()
            let normalizedModeMethodPath = "\(key.mode) \(key.method) \(key.path)".lowercased()

            let isAllowedMismatch = normalizedAllowedConvergences.contains(normalizedPath)
                || normalizedAllowedConvergences.contains(normalizedMethodPath)
                || normalizedAllowedConvergences.contains(normalizedModeMethodPath)
            if strictConvergence && !isAligned && !isAllowedMismatch {
                hasUnexpectedFailure = true
                warnings.append(
                    "cross-host divergence: mode=\(key.mode) method=\(key.method) path=\(key.path) " +
                    "swan(status=\(swanStatusCode), transport=\(swanTransportError), error=\(swanError ?? "<none>"), probes=\(swanProbeResults.count)) " +
                    "reference(status=\(referenceStatusCode), transport=\(referenceTransportError), error=\(referenceError ?? "<none>"), probes=\(referenceProbeResults.count))"
                )
            }

            results.append(
                EndpointConvergence(
                    mode: key.mode,
                    method: key.method,
                    path: key.path,
                    swanProbeCount: swanProbeResults.count,
                    referenceProbeCount: referenceProbeResults.count,
                    swanStatusCode: swanStatusCode,
                    referenceStatusCode: referenceStatusCode,
                    swanTransportError: swanTransportError,
                    referenceTransportError: referenceTransportError,
                    swanError: swanError,
                    referenceError: referenceError,
                    firstProbeAligned: firstProbeAligned,
                    allowedMismatch: isAllowedMismatch
                )
            )
        }

        return results
    }

    private static func probeProfileEndpoints(
        baseURL: URL,
        faultMode: FaultMode?,
        targetLabel: String,
        timeoutInterval: TimeInterval,
        simulateDelayWhenUnavailable: Bool
    ) async -> [EndpointResult] {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = timeoutInterval
        configuration.timeoutIntervalForResource = timeoutInterval
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        let modeLabel = faultMode?.rawValue ?? "normal"
        var requestPlan: [(method: String, path: String, request: URLRequest)] = []
        var endpointDefaults: [String: URLRequest] = [:]
        var endpointResults: [EndpointResult] = []

        let describeURL = baseURL.appendingPathComponent("xrpc/com.atproto.server.describeServer")
        var describeRequest = URLRequest(url: describeURL)
        describeRequest.httpMethod = "GET"
        describeRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        requestPlan.append(("GET", "/xrpc/com.atproto.server.describeServer", describeRequest))
        if faultMode == .corrupted {
            var describeCorrupt = describeRequest
            if var describeComponents = URLComponents(url: describeRequest.url!, resolvingAgainstBaseURL: true) {
                let existing = describeComponents.queryItems ?? []
                describeComponents.queryItems = existing + [URLQueryItem(name: "corrupted", value: "1")]
                describeCorrupt.url = describeComponents.url
            }
            describeCorrupt.setValue("text/plain", forHTTPHeaderField: "Content-Type")
            endpointDefaults["/xrpc/com.atproto.server.describeServer"] = describeCorrupt
        }

        for descriptor in PermissionedData0016.methods {
            let method = descriptor.httpMethod
            guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: true) else {
                endpointResults.append(
                    EndpointResult(
                        mode: modeLabel,
                        method: method,
                        path: "/xrpc/\(descriptor.nsid)",
                        statusCode: 0,
                        requestSummary: sanitizeSummary(["host": targetLabel, "nsid": descriptor.nsid]),
                        responseSummary: ["error": "InvalidResponse"],
                        expectedError: "InvalidResponse"
                    )
                )
                continue
            }
            components.path = components.path.appending("/xrpc/\(descriptor.nsid)")
            guard let endpointURL = components.url else {
                endpointResults.append(
                    EndpointResult(
                        mode: modeLabel,
                        method: method,
                        path: "/xrpc/\(descriptor.nsid)",
                        statusCode: 0,
                        requestSummary: sanitizeSummary(["host": targetLabel, "nsid": descriptor.nsid]),
                        responseSummary: ["error": "InvalidResponse"],
                        expectedError: "InvalidResponse"
                    )
                )
                continue
            }

            var request = URLRequest(url: endpointURL)
            request.httpMethod = method
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            if method == "POST" {
                request.httpBody = Data("{}".utf8)
            }
            if faultMode == .corrupted {
                var corrupted = request
                corrupted.httpMethod = method
                corrupted.setValue("text/plain", forHTTPHeaderField: "Content-Type")
                if method == "POST" {
                    corrupted.httpBody = Data("not-json".utf8)
                } else {
                    var components = URLComponents(url: endpointURL, resolvingAgainstBaseURL: true)
                    components?.queryItems = [URLQueryItem(name: "corrupted", value: "1")]
                    if let mutated = components?.url {
                        corrupted.url = mutated
                    }
                }
                endpointDefaults["/xrpc/\(descriptor.nsid)"] = corrupted
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            requestPlan.append((method, "/xrpc/\(descriptor.nsid)", request))
        }

        if (faultMode == .offline || faultMode == .disconnected) && simulateDelayWhenUnavailable {
            endpointResults.append(contentsOf: requestPlan.map { tuple in
                simulatedTransportFailure(
                    mode: modeLabel,
                    request: tuple.request,
                    pathOverride: tuple.path,
                    targetLabel: targetLabel,
                    transportError: "simulated-offline"
                )
            })
            return endpointResults
        }

        let shouldDelayLocally = faultMode == .delayed && simulateDelayWhenUnavailable
        let requestsToProbe: [(method: String, path: String, request: URLRequest)]
        if faultMode == .reordered {
            requestsToProbe = Array(requestPlan.reversed())
        } else {
            requestsToProbe = requestPlan
        }

        for tuple in requestsToProbe {
            let firstAttempt = await probe(
                request: tuple.request,
                path: tuple.path,
                mode: modeLabel,
                session: session,
                targetLabel: targetLabel,
                localDelayNanoseconds: shouldDelayLocally ? 75_000_000 : 0
            )
            endpointResults.append(firstAttempt)

            if faultMode == .duplicated {
                endpointResults.append(
                    await probe(
                        request: tuple.request,
                        path: tuple.path,
                        mode: modeLabel,
                        session: session,
                        targetLabel: targetLabel,
                        localDelayNanoseconds: shouldDelayLocally ? 75_000_000 : 0
                    )
                )
            }
            if faultMode == .corrupted, let defaultCorrupt = endpointDefaults[tuple.path] {
                endpointResults.append(
                    await probe(
                        request: defaultCorrupt,
                        path: tuple.path,
                        mode: modeLabel,
                        session: session,
                        targetLabel: targetLabel,
                        localDelayNanoseconds: shouldDelayLocally ? 75_000_000 : 0
                    )
                )
            }
        }

        return endpointResults
    }

    private static func probe(
        request: URLRequest,
        path: String,
        mode: String,
        session: URLSession,
        targetLabel: String,
        localDelayNanoseconds: UInt64
    ) async -> EndpointResult {
        if localDelayNanoseconds > 0 {
            _ = try? await Task.sleep(nanoseconds: localDelayNanoseconds)
        }

        let start = DispatchTime.now().uptimeNanoseconds
        do {
            let (data, response) = try await session.data(for: request)
            let latencyMs = Int((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
            guard let response = response as? HTTPURLResponse else {
                return EndpointResult(
                    mode: mode,
                    method: request.httpMethod ?? "UNKNOWN",
                    path: path,
                    statusCode: 0,
                    requestSummary: sanitizeSummary(
                        requestSummary(
                            for: request,
                            path: path,
                            label: targetLabel
                        )
                    ),
                    responseSummary: sanitizeSummary(["error": "InvalidResponse"])
                )
            }
            var summary = responseSummary(for: data, response: response)
            summary["latency-ms"] = String(latencyMs)
            return EndpointResult(
                mode: mode,
                method: request.httpMethod ?? "UNKNOWN",
                path: path,
                statusCode: response.statusCode,
                requestSummary: sanitizeSummary(
                    requestSummary(
                        for: request,
                        path: path,
                        label: targetLabel
                    )
                ),
                responseSummary: sanitizeSummary(summary)
            )
        } catch {
            return EndpointResult(
                mode: mode,
                method: request.httpMethod ?? "UNKNOWN",
                path: path,
                statusCode: 0,
                requestSummary: sanitizeSummary(
                    requestSummary(
                        for: request,
                        path: path,
                        label: targetLabel
                    )
                ),
                responseSummary: sanitizeSummary(["error": "TransportFailure"]),
                expectedError: nil,
                transportError: "network"
            )
        }
    }

    private static func simulatedTransportFailure(
        mode: String,
        request: URLRequest,
        pathOverride: String,
        targetLabel: String,
        transportError: String
    ) -> EndpointResult {
        EndpointResult(
            mode: mode,
            method: request.httpMethod ?? "UNKNOWN",
            path: pathOverride,
            statusCode: 0,
            requestSummary: sanitizeSummary(
                requestSummary(
                    for: request,
                    path: pathOverride,
                    label: targetLabel
                )
            ),
            responseSummary: sanitizeSummary(["error": transportError]),
            expectedError: nil,
            transportError: "network"
        )
    }

    private static func requestSummary(
        for request: URLRequest,
        path: String,
        label: String
    ) -> [String: String] {
        var output: [String: String] = [
            "host": label,
            "path": path,
            "method": request.httpMethod ?? "UNKNOWN",
        ]
        if let url = request.url,
           let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
           let queryItems = components.queryItems,
           !queryItems.isEmpty {
            output["request-query-keys"] = queryItems
                .map(\.name)
                .sorted()
                .joined(separator: ",")
        }
        if let body = request.httpBody {
            output["request-bytes"] = String(body.count)
        }
        if let contentType = request.value(forHTTPHeaderField: "Content-Type") {
            output["request-content-type"] = contentType
        }
        return output
    }

    private static func responseSummary(for data: Data, response: HTTPURLResponse) -> [String: String] {
        var output: [String: String] = [
            "response-bytes": String(data.count),
            "status": String(response.statusCode)
        ]
        if let contentType = response.value(forHTTPHeaderField: "Content-Type") {
            output["content-type"] = contentType
        }
        if let cacheControl = response.value(forHTTPHeaderField: "Cache-Control") {
            output["cache-control"] = cacheControl
        }
        guard let decoded = try? JSONSerialization.jsonObject(with: data) else {
            return output
        }
        if let payload = decoded as? [String: Any] {
            let keys = payload.keys.sorted()
            output["json-keys"] = String(keys.count)
            if let error = payload["error"] as? String,
               error.count <= 64,
               error.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }) {
                output["error"] = sanitizedScenarioErrorCode(error)
            }
            for (index, key) in keys.prefix(3).enumerated() {
                output["json-key-\(index)"] = forbiddenSummaryKey(key) ? "<redacted-key>" : key
            }
        } else if let payload = decoded as? [Any] {
            output["json-elements"] = String(payload.count)
        }
        return output
    }

    private static func sanitizeSummary(_ summary: [String: String]) -> [String: String] {
        return FixtureSanitizer.sanitize(summary)
    }

    private static func sanitizedScenarioErrorCode(_ rawValue: String) -> String {
        let sanitized = FixtureSanitizer.errorCode(rawValue)
        if sanitized != "<redacted>" {
            return sanitized
        }
        switch rawValue {
        case "permissioned_data_pending",
             "permissioned_endpoint_unavailable":
            return rawValue
        default:
            return "<redacted>"
        }
    }

    private static func forbiddenSummaryKey(_ key: String) -> Bool {
        let normalized = key.lowercased()
        return normalized.contains("access_token")
            || normalized.contains("authorization")
            || normalized.contains("refresh_token")
            || normalized.contains("password")
            || normalized.contains("dpop")
            || normalized.contains("private_key")
            || normalized.contains("ikm")
            || normalized.contains("token")
    }

    private static func faultModeIfAny(_ value: String) -> [FaultMode] {
        switch value {
        case "normal":
            return []
        case let rawValue where FaultMode(rawValue: rawValue) != nil:
            return [FaultMode(rawValue: rawValue)!]
        default:
            return []
        }
    }

    private static func applyFaultMode(_ mode: FaultMode, forHost hostLabel: String) async -> Bool {
        guard ToxiproxyControl.supports(hostLabel: hostLabel) else {
            return false
        }

        switch mode {
        case .offline, .disconnected:
            return await setProxy(enabled: false)
        case .delayed:
            return await addDelayToxics()
        case .duplicated, .reordered, .corrupted:
            return true
        }
    }

    private static func clearSimulatedFault(_ mode: FaultMode, forHost hostLabel: String) async {
        guard ToxiproxyControl.supports(hostLabel: hostLabel) else {
            return
        }

        switch mode {
        case .offline, .disconnected:
            _ = await setProxy(enabled: true)
            await removeToxic(name: ToxiproxyControl.delayedToxicUpstreamName)
            await removeToxic(name: ToxiproxyControl.delayedToxicDownstreamName)
        case .delayed:
            await removeToxic(name: ToxiproxyControl.delayedToxicUpstreamName)
            await removeToxic(name: ToxiproxyControl.delayedToxicDownstreamName)
            _ = await setProxy(enabled: true)
        case .duplicated, .reordered, .corrupted:
            return
        }
    }

    private static func setProxy(enabled: Bool) async -> Bool {
        return await sendToxiproxyRequest(
            path: "proxies/\(ToxiproxyControl.proxyName)",
            method: "POST",
            body: ["enabled": enabled]
        )
    }

    private static func addDelayToxics() async -> Bool {
        let upstream = await addToxic(
            name: ToxiproxyControl.delayedToxicUpstreamName,
            type: "latency",
            stream: "upstream",
            attributes: [
                "latency": ToxiproxyControl.delayedLatencyMilliseconds,
                "jitter": ToxiproxyControl.delayedLatencyJitterMilliseconds,
            ]
        )
        let downstream = await addToxic(
            name: ToxiproxyControl.delayedToxicDownstreamName,
            type: "latency",
            stream: "downstream",
            attributes: [
                "latency": ToxiproxyControl.delayedLatencyMilliseconds,
                "jitter": ToxiproxyControl.delayedLatencyJitterMilliseconds,
            ]
        )
        return upstream && downstream
    }

    private static func addToxic(name: String, type: String, stream: String, attributes: [String: Int]) async -> Bool {
        return await sendToxiproxyRequest(
            path: "proxies/\(ToxiproxyControl.proxyName)/toxics",
            method: "POST",
            body: [
                "name": name,
                "type": type,
                "stream": stream,
                "toxicity": 1.0,
                "attributes": attributes,
            ]
        )
    }

    private static func removeToxic(name: String) async {
        _ = await sendToxiproxyRequest(
            path: "proxies/\(ToxiproxyControl.proxyName)/toxics/\(name)",
            method: "DELETE"
        )
    }

    private static func sendToxiproxyRequest(
        path: String,
        method: String,
        body: [String: Any] = [:]
    ) async -> Bool {
        var components = URLComponents(url: ToxiproxyControl.baseURL, resolvingAgainstBaseURL: false)
        let pathPrefix = components?.path ?? ""
        components?.path = (pathPrefix as NSString).appendingPathComponent(path)
        guard let requestURL = components?.url else {
            return false
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = method
        request.timeoutInterval = 2
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if !body.isEmpty {
            if let data = try? JSONSerialization.data(withJSONObject: body, options: []) {
                request.httpBody = data
            } else {
                return false
            }
        }

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            guard let response = response as? HTTPURLResponse else {
                return false
            }
            return (200 ... 299).contains(response.statusCode)
        } catch {
            return false
        }
    }
}

private extension XRPCMethodDescriptor {
    var httpMethod: String {
        switch kind {
        case .query, .subscription:
            "GET"
        case .procedure:
            "POST"
        }
    }
}
