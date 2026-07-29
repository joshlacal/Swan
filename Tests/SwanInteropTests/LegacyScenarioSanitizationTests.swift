import Foundation
@testable import SwanInterop
import XCTest

final class LegacyScenarioSanitizationTests: XCTestCase, @unchecked Sendable {
    func testUnsafeEndpointURLsAreRejectedWithoutPersistingTheirComponents() async throws {
        let unsafeCases: [(url: URL, sentinels: [String])] = [
            (
                URL(string: "http://access_token:opaque-signed-secret@127.0.0.1:1")!,
                ["access_token", "opaque-signed-secret"]
            ),
            (
                URL(string: "http://127.0.0.1:1/?dpop=opaque.jwt.signature")!,
                ["dpop", "opaque.jwt.signature"]
            ),
            (
                URL(string: "http://127.0.0.1:1/#/Users/private/lab-fixture")!,
                ["/Users/private/lab-fixture", "lab-fixture"]
            ),
            (
                URL(string: "file:///Users/private/recoverable-person.json")!,
                ["/Users/private/recoverable-person.json", "recoverable-person"]
            ),
            (
                URL(string: "http:/Users/private/missing-host")!,
                ["/Users/private/missing-host", "missing-host"]
            ),
        ]

        for testCase in unsafeCases {
            let runtime = InteropScenarioRunner.RuntimeConfiguration(
                swanBaseURL: testCase.url,
                referenceBaseURL: URL(string: "http://127.0.0.1:1")!,
                timeoutInterval: 0.05
            )
            let artifact = await InteropScenarioRunner.execute(
                scenario: "unsafe-origin-rejection",
                faultModes: [],
                runtime: runtime
            )

            XCTAssertEqual(artifact.status, "failed")
            XCTAssertTrue(
                artifact.hostResults.allSatisfy(\.endpointResults.isEmpty),
                "URL validation must finish before any transport is built"
            )

            let serialized = try JSONSerialization.jsonObject(
                with: JSONEncoder().encode(artifact)
            )
            let strings = serializedStrings(in: serialized)
            for sentinel in testCase.sentinels {
                XCTAssertFalse(
                    strings.contains(where: { $0.contains(sentinel) }),
                    "serialized artifact leaked unsafe URL sentinel: \(sentinel)"
                )
            }
            XCTAssertTrue(strings.contains("<invalid-origin>"))
            XCTAssertTrue(strings.contains("invalid_endpoint_origin"))
        }
    }

    func testSafeLocalLabOriginIsReducedToOriginAndTransportErrorsAreAllowlisted() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "http://127.0.0.1:1/lab-prefix")!,
            referenceBaseURL: URL(string: "http://localhost:1/reference-prefix")!,
            timeoutInterval: 0.05
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "safe-local-origin",
            faultModes: [],
            runtime: runtime
        )

        XCTAssertEqual(
            artifact.hostResults.map(\.baseURL),
            ["http://127.0.0.1:1", "http://localhost:1"]
        )
        XCTAssertTrue(
            artifact.hostResults.allSatisfy { !$0.endpointResults.isEmpty }
        )

        let allowedTransportCodes: Set<String> = [
            "TransportFailure",
            "InvalidResponse",
        ]
        for result in artifact.hostResults.flatMap(\.endpointResults) {
            if let code = result.responseSummary["error"] {
                XCTAssertTrue(
                    allowedTransportCodes.contains(code),
                    "unexpected serialized transport detail: \(code)"
                )
            }
            XCTAssertTrue(result.transportError == nil || result.transportError == "network")
        }

        let serialized = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(artifact)
        )
        let strings = serializedStrings(in: serialized)
        for sentinel in [
            "lab-prefix",
            "reference-prefix",
            "NSURLError",
            "The operation couldn",
            "/Users/",
        ] {
            XCTAssertFalse(
                strings.contains(where: { $0.contains(sentinel) }),
                "serialized artifact leaked transport/origin detail: \(sentinel)"
            )
        }
    }

    private func serializedStrings(in value: Any) -> [String] {
        switch value {
        case let string as String:
            [string]
        case let array as [Any]:
            array.flatMap(serializedStrings(in:))
        case let dictionary as [String: Any]:
            dictionary.keys + dictionary.values.flatMap(serializedStrings(in:))
        default:
            []
        }
    }
}
