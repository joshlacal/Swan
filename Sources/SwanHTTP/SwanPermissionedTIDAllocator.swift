import Foundation
import Petrel
import SwanCore

/// Process-local, serialized TID allocation for permissioned write requests.
///
/// Petrel's general generator combines a millisecond clock with a 10-bit
/// per-tick counter, which is suitable for ordinary client traffic but can
/// repeat after 1,024 allocations in one tick. Permissioned `applyWrites`
/// needs one valid TID per omitted rkey *and* a distinct commit revision, so
/// this allocator instead serializes the complete sortable TID integer and
/// advances it by one whenever wall time does not. It is intentionally owned
/// by SwanHTTP, not a process-global generator shared with unrelated work.
actor SwanPermissionedTIDAllocator {
    private static let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
    private var lastValue: UInt64 = 0

    func next() throws -> TID {
        let seconds = Date().timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw SwanError.unavailable("permissioned TID allocator is unavailable")
        }
        let microseconds = UInt64(seconds * 1_000_000)
        // TID reserves its low ten bits for clock/counter material. Retaining
        // that shape means our values interoperate with the pinned parser,
        // while `lastValue + 1` makes every serial allocation unique.
        guard microseconds <= (UInt64.max >> 10) else {
            throw SwanError.unavailable("permissioned TID allocator is unavailable")
        }
        let clockValue = microseconds << 10
        let value: UInt64
        if clockValue > lastValue {
            value = clockValue
        } else {
            guard lastValue < UInt64.max else {
                throw SwanError.unavailable("permissioned TID allocator is unavailable")
            }
            value = lastValue + 1
        }
        let encoded = Self.encode(value)
        let tid = try TID(tidString: encoded)
        lastValue = value
        return tid
    }

    private static func encode(_ value: UInt64) -> String {
        var remaining = value
        var output: [Character] = []
        repeat {
            output.append(alphabet[Int(remaining & 31)])
            remaining >>= 5
        } while remaining != 0
        while output.count < 13 { output.append("2") }
        return String(output.reversed())
    }
}
