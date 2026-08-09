import ArgumentParser
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
}
