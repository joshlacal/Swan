import ArgumentParser
import Foundation
@testable import swan
import XCTest

final class PublicRelayVerifierCLIParseTests: XCTestCase {
  func testFirehoseVerifyRelayCaptureParsesRequiredEphemeralInputs() throws {
    let command = try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--manifest", "/tmp/relay-input.json",
      "--plc-origin", "https://plc.directory",
    ])
    XCTAssertTrue(String(describing: type(of: command)).contains("VerifyRelayCapture"))
  }

  func testFirehoseVerifyRelayCaptureRejectsMissingManifest() throws {
    XCTAssertThrowsError(try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--plc-origin", "https://plc.directory",
    ]))
  }

  func testRelayVerifierManifestRequiresExactOfflineRecoveryEvidence() throws {
    XCTAssertThrowsError(try RelayVerifierManifest.decode(manifestData(
      reconnects: [(12, 13)]
    )))
    XCTAssertThrowsError(try RelayVerifierManifest.decode(manifestData(
      reconnects: [], offlineStart: 13, offlineEnd: 17
    )))
    XCTAssertThrowsError(try RelayVerifierManifest.decode(manifestData(
      reconnects: [(12, 13)],
      offlineStart: 13,
      offlineEnd: 18
    )))

    let accepted = try RelayVerifierManifest.decode(manifestData(
      reconnects: [(12, 13)],
      offlineStart: 13,
      offlineEnd: 17
    ))
    XCTAssertEqual(accepted.offlineSequenceRange, 13 ... 17)
    XCTAssertEqual(accepted.reconnects.count, 1)
    XCTAssertEqual(accepted.reconnects[0].upstreamCursor, 12)
    XCTAssertEqual(accepted.reconnects[0].firstDeliveredRelaySequence, 13)

    let lagged = try RelayVerifierManifest.decode(manifestData(
      reconnects: [(900, 13)],
      offlineStart: 13,
      offlineEnd: 17
    ))
    XCTAssertEqual(lagged.reconnects[0].upstreamCursor, 900)

    XCTAssertThrowsError(try RelayVerifierManifest.decode(manifestData(
      reconnects: [(13, 12)],
      offlineStart: 13,
      offlineEnd: 17
    )))
  }

  func testRelayVerifierManifestRejectsReconnectUnrelatedToOfflineRecoveryRange() throws {
    XCTAssertThrowsError(try RelayVerifierManifest.decode(manifestData(
      frameFiles: (1 ... 17).map { "frame-\($0).cbor" },
      reconnects: [(5, 6)],
      offlineStart: 13,
      offlineEnd: 17
    )))
  }

  func testFirehoseVerifyRelayCaptureParsesExplicitLaboratoryPLCPolicy() throws {
    let command = try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--manifest", "/tmp/relay-input.json",
      "--plc-origin", "http://reference-plc:2582",
      "--plc-laboratory",
      "--plc-laboratory-allowlisted-host", "reference-plc",
    ])
    XCTAssertTrue(String(describing: type(of: command)).contains("VerifyRelayCapture"))
  }

  func testFirehoseVerifyRelayCaptureRejectsLaboratoryHostWithoutFlag() throws {
    XCTAssertThrowsError(try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--manifest", "/tmp/relay-input.json",
      "--plc-origin", "http://reference-plc:2582",
      "--plc-laboratory-allowlisted-host", "reference-plc",
    ])) { error in
      XCTAssertTrue(String(describing: error).contains(
        "--plc-laboratory-allowlisted-host requires --plc-laboratory"
      ))
    }
  }

  func testFirehoseVerifyRelayCaptureRejectsUnallowlistedReferencePLC() throws {
    XCTAssertThrowsError(try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--manifest", "/tmp/relay-input.json",
      "--plc-origin", "http://reference-plc:2582",
      "--plc-laboratory",
    ]))
  }

  func testFirehoseVerifyRelayCaptureRejectsHTTPOriginWithoutLaboratoryPolicy() throws {
    XCTAssertThrowsError(try SwanCommand.parseAsRoot([
      "firehose", "verify-relay-capture",
      "--manifest", "/tmp/relay-input.json",
      "--plc-origin", "http://reference-plc:2582",
    ]))
  }

  private func manifestData(
    frameFiles: [String] = ["frame-1.cbor"],
    reconnects: [(cursor: Int64, firstDeliveredSequence: Int64)],
    offlineStart: Int64? = nil,
    offlineEnd: Int64? = nil
  ) throws -> Data {
    var object: [String: Any] = [
      "did": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
      "frameFiles": frameFiles,
      "finalCARFile": "final.car",
      "finalRevision": "3jzfcijpj2z2a",
      "finalCommitCID": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "finalDataCID": "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "reconnects": reconnects.map {
        ["upstreamCursor": $0.cursor,
         "firstDeliveredRelaySequence": $0.firstDeliveredSequence]
      },
      "getRepo": [
        "mode": "cursor-only",
        "fullSnapshotAccepted": false,
        "exactFinalStateProven": false,
      ],
    ]
    if let offlineStart { object["offlineSequenceStart"] = offlineStart }
    if let offlineEnd { object["offlineSequenceEnd"] = offlineEnd }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }
}

/// The `serve` flags that select AppView proxying. Parsing is asserted here
/// because the composition itself needs a mounted KEK and a data directory,
/// which a parse-level test must not require.
final class ServeAppViewProxyCLIParseTests: XCTestCase {
  func testServeParsesAppViewProxyOptions() throws {
    let command = try SwanCommand.parseAsRoot([
      "serve",
      "--data-directory", "/tmp/swan-appview-proxy-parse",
      "--appview-did", "did:web:appview.example",
      "--appview-url", "https://appview.example",
      "--appview-service-fragment", "bsky_appview",
      "--appview-proxy-account-kek-file", "/tmp/kek",
    ])
    let serve = try XCTUnwrap(command as? SwanCommand.Serve)
    XCTAssertEqual(serve.appViewDID, "did:web:appview.example")
    XCTAssertEqual(serve.appViewURL, "https://appview.example")
    XCTAssertEqual(serve.appViewServiceFragment, "bsky_appview")
    XCTAssertEqual(serve.appViewProxyAccountKEKFile, "/tmp/kek")
    XCTAssertFalse(serve.disableAppViewProxy)
  }

  /// Proxying is on out of the box, so the flag that turns it off must exist
  /// and must default to false.
  func testServeDefaultsToProxyingEnabled() throws {
    let command = try SwanCommand.parseAsRoot([
      "serve", "--data-directory", "/tmp/swan-appview-proxy-parse",
    ])
    let serve = try XCTUnwrap(command as? SwanCommand.Serve)
    XCTAssertFalse(serve.disableAppViewProxy)
    XCTAssertNil(serve.appViewDID)

    let disabled = try SwanCommand.parseAsRoot([
      "serve",
      "--data-directory", "/tmp/swan-appview-proxy-parse",
      "--disable-appview-proxy",
    ])
    XCTAssertTrue(try XCTUnwrap(disabled as? SwanCommand.Serve).disableAppViewProxy)
  }
}
