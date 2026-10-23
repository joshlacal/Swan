import Foundation
import NetworkExtension
import Observation

/// Owns the NETunnelProviderManager for the SwanTunnel extension. tvOS runs
/// the provider as a separate system process; this object only installs the
/// configuration, starts/stops it, and asks it for status.
@Observable
final class TunnelController {
    static let providerBundleID = "blue.catbird.SwanTV.SwanTunnel"
    static let groupID = "group.blue.catbird.SwanTV"

    private(set) var manager: NETunnelProviderManager?
    private(set) var status: NEVPNStatus = .invalid
    private(set) var onDemandEnabled = false
    private(set) var lastError: String?
    private(set) var providerStatusJSON = "(no status yet)"
    private(set) var heartbeatTail = "(no heartbeat log)"

    private var observer: NSObjectProtocol?

    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerBundleID }
            onDemandEnabled = manager?.isOnDemandEnabled ?? false
            refreshStatus()
        } catch {
            lastError = "load: \(error.localizedDescription)"
        }
    }

    /// Creates or updates the tunnel configuration. `onDemand` installs a
    /// connect-always rule so the system restarts the tunnel after reboot and
    /// network changes without the app being launched (probe T1 step 8).
    func install(onDemand: Bool) async {
        let target = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = "swan-probe-overlay"
        target.protocolConfiguration = proto
        target.localizedDescription = "SwanTV Probe Tunnel"
        target.isEnabled = true
        target.isOnDemandEnabled = onDemand
        target.onDemandRules = onDemand ? [NEOnDemandRuleConnect()] : nil
        do {
            try await target.saveToPreferences()
            // Apple requires a reload after save before the manager can start.
            try await target.loadFromPreferences()
            manager = target
            onDemandEnabled = onDemand
            lastError = nil
            refreshStatus()
        } catch {
            lastError = "save: \(error.localizedDescription)"
        }
    }

    func start() {
        guard let manager else { lastError = "no configuration installed"; return }
        do {
            try manager.connection.startVPNTunnel()
            lastError = nil
        } catch {
            lastError = "start: \(error.localizedDescription)"
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    func remove() async {
        do {
            try await manager?.removeFromPreferences()
            manager = nil
            refreshStatus()
        } catch {
            lastError = "remove: \(error.localizedDescription)"
        }
    }

    func refreshStatus() {
        status = manager?.connection.status ?? .invalid
        heartbeatTail = Self.readHeartbeatTail()
    }

    /// Round-trips a message to the running provider; a reply proves the
    /// extension process is alive and answering, independent of `status`.
    func queryProvider(_ command: String = "status") async {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            providerStatusJSON = "(no session)"; return
        }
        do {
            let reply: Data? = try await withCheckedThrowingContinuation { continuation in
                do {
                    try session.sendProviderMessage(Data(command.utf8)) { continuation.resume(returning: $0) }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            providerStatusJSON = reply.map { String(decoding: $0, as: UTF8.self) } ?? "(empty reply)"
            heartbeatTail = Self.readHeartbeatTail()
        } catch {
            providerStatusJSON = "(provider message failed: \(error.localizedDescription))"
        }
    }

    static func readHeartbeatTail(lines: Int = 30) -> String {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID)?
            .appendingPathComponent("swantv-heartbeat.log"),
            let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8)
        else { return "(no heartbeat log)" }
        return text.split(separator: "\n").suffix(lines).joined(separator: "\n")
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "invalid (no configuration)"
        case .disconnected: "disconnected"
        case .connecting: "connecting"
        case .connected: "connected"
        case .reasserting: "reasserting"
        case .disconnecting: "disconnecting"
        @unknown default: "unknown(\(rawValue))"
        }
    }
}
