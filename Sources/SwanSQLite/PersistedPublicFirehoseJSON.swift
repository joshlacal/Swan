import Foundation

/// Canonical JSON for material whose bytes participate in durable
/// public-firehose idempotency checks.
enum PersistedPublicFirehoseJSON {
  static func encode<Value: Encodable>(_ value: Value) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
  }
}
