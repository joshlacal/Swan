import Foundation

/// Test-only canonical CBOR value mirroring the strict reader in
/// `SwanPublicFirehoseTests.FirehoseFrameTestDecoder`. It validates shortest
/// integer encodings and canonical map-key order (length, then bytes) while
/// parsing; tag-42 CID links are consumed without CID validation (the reader
/// is for connection-control frames and stored-frame headers).
public indirect enum FirehoseStreamingTestCBORValue: Equatable, Sendable {
  case unsigned(UInt64)
  case signed(Int64)
  case text(String)
  case bytes(Data)
  case boolean(Bool)
  case null
  case array([FirehoseStreamingTestCBORValue])
  case map([FirehoseStreamingTestCBORMapEntry])
  case cidLink(Data)
}

public struct FirehoseStreamingTestCBORMapEntry: Equatable, Sendable {
  public let key: String
  public let value: FirehoseStreamingTestCBORValue

  public init(key: String, value: FirehoseStreamingTestCBORValue) {
    self.key = key
    self.value = value
  }
}

public enum FirehoseStreamingTestCBORError: Error, Equatable {
  case truncated
  case invalidEncoding
  case nonCanonicalInteger
  case nonCanonicalMapKeyOrder
  case trailingBytes
}

/// Minimal strict two-object CBOR reader for firehose frames: header and body
/// must be exactly two canonical values with no trailing bytes.
public struct FirehoseStreamingTestCBORReader {
  private let bytes: [UInt8]
  private var offset = 0

  public init(_ data: Data) {
    bytes = Array(data)
  }

  public var isAtEnd: Bool { offset == bytes.count }

  /// Parse exactly two canonical CBOR values and reject trailing bytes.
  public mutating func readFrame() throws -> (
    header: FirehoseStreamingTestCBORValue,
    body: FirehoseStreamingTestCBORValue
  ) {
    let header = try readNext()
    let body = try readNext()
    guard isAtEnd else { throw FirehoseStreamingTestCBORError.trailingBytes }
    return (header, body)
  }

  /// Header map convenience: the `op` value if the header is a map containing
  /// a signed or unsigned `op` entry.
  public func headerOp(_ header: FirehoseStreamingTestCBORValue) -> Int64? {
    guard case let .map(entries) = header,
          let entry = entries.first(where: { $0.key == "op" }) else {
      return nil
    }
    switch entry.value {
    case let .signed(value): return value
    case let .unsigned(value) where value <= UInt64(Int64.max):
      return Int64(value)
    default:
      return nil
    }
  }

  /// Header map convenience: the `t` value if the header is a map containing
  /// a text `t` entry.
  public func headerType(_ header: FirehoseStreamingTestCBORValue) -> String? {
    guard case let .map(entries) = header,
          let entry = entries.first(where: { $0.key == "t" }),
          case let .text(value) = entry.value else {
      return nil
    }
    return value
  }

  /// Body map convenience: the value for a text key, or `nil`.
  public func bodyValue(
    _ body: FirehoseStreamingTestCBORValue,
    key: String
  ) -> FirehoseStreamingTestCBORValue? {
    guard case let .map(entries) = body else { return nil }
    return entries.first(where: { $0.key == key })?.value
  }

  public mutating func readNext() throws -> FirehoseStreamingTestCBORValue {
    guard let initial = readByte() else {
      throw FirehoseStreamingTestCBORError.truncated
    }
    let major = initial >> 5
    let argument = try readArgument(expectedMajor: major, initial: initial)
    switch major {
    case 0:
      return .unsigned(argument)
    case 1:
      if argument == 1 << 63 {
        return .signed(Int64.min)
      }
      guard argument <= UInt64(Int64.max) else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      return .signed(-1 - Int64(argument))
    case 2:
      return .bytes(Data(try readPayload(length: argument)))
    case 3:
      let payload = try readPayload(length: argument)
      guard let text = String(data: Data(payload), encoding: .utf8) else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      return .text(text)
    case 4:
      guard argument <= UInt64(Int.max) else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      var values: [FirehoseStreamingTestCBORValue] = []
      values.reserveCapacity(Int(argument))
      for _ in 0 ..< argument {
        values.append(try readNext())
      }
      return .array(values)
    case 5:
      guard argument <= UInt64(Int.max) else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      var entries: [FirehoseStreamingTestCBORMapEntry] = []
      entries.reserveCapacity(Int(argument))
      var previousKey: (length: Int, bytes: [UInt8])?
      for _ in 0 ..< argument {
        guard case let .text(key) = try readNext() else {
          throw FirehoseStreamingTestCBORError.invalidEncoding
        }
        let keyBytes = Array(key.utf8)
        if let previousKey {
          if keyBytes.count < previousKey.length
            || (keyBytes.count == previousKey.length
              && keyBytes.lexicographicallyPrecedes(previousKey.bytes))
          {
            throw FirehoseStreamingTestCBORError.nonCanonicalMapKeyOrder
          }
        }
        previousKey = (keyBytes.count, keyBytes)
        entries.append(FirehoseStreamingTestCBORMapEntry(key: key, value: try readNext()))
      }
      return .map(entries)
    case 6:
      guard argument == 42 else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      guard case let .bytes(payload) = try readNext() else {
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
      return .cidLink(payload)
    case 7:
      switch argument {
      case 20:
        return .boolean(false)
      case 21:
        return .boolean(true)
      case 22:
        return .null
      default:
        throw FirehoseStreamingTestCBORError.invalidEncoding
      }
    default:
      throw FirehoseStreamingTestCBORError.invalidEncoding
    }
  }

  private mutating func readPayload(length: UInt64) throws -> [UInt8] {
    guard length <= UInt64(bytes.count - offset) else {
      throw FirehoseStreamingTestCBORError.truncated
    }
    let slice = bytes[offset ..< offset + Int(length)]
    offset += Int(length)
    return Array(slice)
  }

  private mutating func readArgument(expectedMajor: UInt8, initial: UInt8) throws -> UInt64 {
    guard initial >> 5 == expectedMajor else {
      throw FirehoseStreamingTestCBORError.invalidEncoding
    }
    switch initial & 0x1f {
    case 0 ... 23:
      return UInt64(initial & 0x1f)
    case 24:
      let value = try readFixed(1)
      guard value >= 24 else { throw FirehoseStreamingTestCBORError.nonCanonicalInteger }
      return value
    case 25:
      let value = try readFixed(2)
      guard value > UInt8.max else { throw FirehoseStreamingTestCBORError.nonCanonicalInteger }
      return value
    case 26:
      let value = try readFixed(4)
      guard value > UInt16.max else { throw FirehoseStreamingTestCBORError.nonCanonicalInteger }
      return value
    case 27:
      let value = try readFixed(8)
      guard value > UInt32.max else { throw FirehoseStreamingTestCBORError.nonCanonicalInteger }
      return value
    default:
      throw FirehoseStreamingTestCBORError.invalidEncoding
    }
  }

  private mutating func readFixed(_ count: Int) throws -> UInt64 {
    guard count <= bytes.count - offset else {
      throw FirehoseStreamingTestCBORError.truncated
    }
    var value: UInt64 = 0
    for byte in bytes[offset ..< offset + count] {
      value = (value << 8) | UInt64(byte)
    }
    offset += count
    return value
  }

  private mutating func readByte() -> UInt8? {
    guard offset < bytes.count else { return nil }
    defer { offset += 1 }
    return bytes[offset]
  }
}
