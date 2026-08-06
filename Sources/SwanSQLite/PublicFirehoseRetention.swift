import Foundation
import SwanCore
import SwanPublicFirehose

/// Bounded retention for the public firehose log. All three bounds are
/// enforced together inside a single prune transaction; the earliest violated
/// bound decides what is deleted and the retained cursor only ever advances.
public struct PublicFirehoseRetentionPolicy: Sendable, Equatable {
  public let maximumAge: Duration
  public let maximumRows: Int64
  public let maximumBytes: Int64

  /// The policy age converted to checked whole microseconds at init time.
  /// `PublicFirehoseTime.microseconds(_:)` rejects non-finite and negative
  /// timestamps, so a negative cutoff produced by `now - maximumAge` is never
  /// trusted to match against the non-negative `sequenced_at` column.
  let maximumAgeMicroseconds: Int64

  public static let standard = try! PublicFirehoseRetentionPolicy()

  public init(
    maximumAge: Duration = .seconds(259_200),
    maximumRows: Int64 = 1_000_000,
    maximumBytes: Int64 = 1_073_741_824
  ) throws {
    guard maximumAge > .zero else {
      throw SwanError.malformed("firehose retention age must be positive")
    }
    guard maximumRows >= 1 else {
      throw SwanError.malformed("firehose retention row budget must be positive")
    }
    // One valid maximum-sized frame must fit under the byte budget.
    guard maximumBytes >= Int64(FirehoseFrameLimits.maximumFrameBytes) else {
      throw SwanError.malformed(
        "firehose retention byte budget must be at least 5000000"
      )
    }
    let components = maximumAge.components
    let seconds = components.seconds.multipliedReportingOverflow(by: 1_000_000)
    let fraction = components.attoseconds / 1_000_000_000_000
    let micros = seconds.partialValue.addingReportingOverflow(fraction)
    guard !seconds.overflow, !micros.overflow, micros.partialValue > 0 else {
      throw SwanError.malformed("firehose retention age must be positive")
    }
    self.maximumAge = maximumAge
    self.maximumRows = maximumRows
    self.maximumBytes = maximumBytes
    self.maximumAgeMicroseconds = micros.partialValue
  }
}

public struct PublicFirehosePruneResult: Sendable, Equatable {
  public let deletedRows: Int64
  public let deletedBytes: Int64
  /// The retained boundary written by this prune, or `nil` when it did not
  /// advance. A no-op prune keeps the never-set state and reports `nil` here.
  public let retainedFromSeq: Int64?
  public let didAdvanceRetention: Bool
}
