import Darwin
import Foundation
import os

/// Process-level measurements the probe reports. Everything here is what jetsam
/// actually accounts (`phys_footprint`) plus the kernel's own statement of the
/// remaining budget (`os_proc_available_memory`), so the memory ceiling can be
/// measured instead of assumed.
enum ProcessMetrics {
    static let processStart = Date()

    static func footprintBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : 0
    }

    static func residentBytes() -> UInt64 {
        var info = mach_task_basic_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.resident_size : 0
    }

    /// Bytes the kernel says this process may still allocate before jetsam.
    /// footprint + available == the effective per-process limit.
    static func availableBytes() -> Int {
        os_proc_available_memory()
    }

    static func threadCount() -> Int {
        var list: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS, let list else { return -1 }
        for i in 0..<Int(count) { mach_port_deallocate(mach_task_self_, list[i]) }
        vm_deallocate(mach_task_self_, vm_address_t(bitPattern: list), vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.size))
        return Int(count)
    }

    /// CPU seconds consumed by this process (user + system).
    static func cpuSeconds() -> Double {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        func secs(_ t: timeval) -> Double { Double(t.tv_sec) + Double(t.tv_usec) / 1_000_000 }
        return secs(usage.ru_utime) + secs(usage.ru_stime)
    }

    /// IPv4/IPv6 addresses of every up interface, so a tester knows what to curl.
    static func interfaceAddresses() -> [String] {
        var result: [String] = []
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return result }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let addr = entry.pointee.ifa_addr, (entry.pointee.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }
            let family = addr.pointee.sa_family
            guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(family == UInt8(AF_INET) ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(addr, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let name = String(cString: entry.pointee.ifa_name)
            result.append("\(name)=\(String(cString: host))")
        }
        return result
    }

    static func snapshot(extra: [String: Any] = [:]) -> [String: Any] {
        var dict: [String: Any] = [
            "pid": Int(getpid()),
            "now": ISO8601DateFormatter().string(from: Date()),
            "processStart": ISO8601DateFormatter().string(from: processStart),
            "uptimeSeconds": Int(Date().timeIntervalSince(processStart)),
            "systemUptimeSeconds": Int(ProcessInfo.processInfo.systemUptime),
            "footprintBytes": footprintBytes(),
            "residentBytes": residentBytes(),
            "availableBytes": availableBytes(),
            "impliedLimitBytes": Int(footprintBytes()) + availableBytes(),
            "threads": threadCount(),
            "cpuSeconds": cpuSeconds(),
            "thermalState": ProcessInfo.processInfo.thermalState.rawValue,
            "lowPowerMode": ProcessInfo.processInfo.isLowPowerModeEnabled,
            "interfaces": interfaceAddresses(),
            "os": ProcessInfo.processInfo.operatingSystemVersionString,
        ]
        for (k, v) in extra { dict[k] = v }
        return dict
    }

    static func snapshotJSON(extra: [String: Any] = [:]) -> Data {
        (try? JSONSerialization.data(withJSONObject: snapshot(extra: extra), options: [.sortedKeys])) ?? Data("{}".utf8)
    }
}
