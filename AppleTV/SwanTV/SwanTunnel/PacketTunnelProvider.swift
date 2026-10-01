import Foundation
import NetworkExtension

/// Probe T0/T1/T2 provider.
///
/// RESEARCH BUILD. This provider brings up a real utun with a private overlay
/// prefix (10.77.0.0/24) and drains packets routed to it, but it does not yet
/// carry them anywhere: it exists to measure extension lifetime, memory ceiling,
/// and listener reachability on tvOS hardware. Milestone M2 replaces the packet
/// loop with a WireGuard peer so the overlay becomes a genuine VPN function;
/// see docs/apple-tv-pds/NETWORKING.md. Do not ship this loop.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    static let overlayAddress = "10.77.0.2"
    static let overlayPeer = "10.77.0.1"
    static let httpPort: UInt16 = 8080

    private var probe: ProbeServer?
    private var heartbeat: Timer?
    private var packetsIn = 0
    private var bytesIn = 0
    private var packetLoopActive = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        ProbeLog.shared.event("tunnel.start", "options=\(options?.keys.sorted() ?? [])")

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.overlayPeer)
        let ipv4 = NEIPv4Settings(addresses: [Self.overlayAddress], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.77.0.0", subnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4
        settings.mtu = 1280

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                ProbeLog.shared.event("tunnel.settings.failed", "\(error)")
                completionHandler(error)
                return
            }
            ProbeLog.shared.event("tunnel.settings.applied", "overlay=\(Self.overlayAddress)")
            do {
                let server = try ProbeServer(port: Self.httpPort)
                server.packetCounters = { [weak self] in
                    ["packetsIn": self?.packetsIn ?? 0, "bytesIn": self?.bytesIn ?? 0, "loopActive": self?.packetLoopActive ?? false]
                }
                server.start()
                probe = server
            } catch {
                ProbeLog.shared.event("http.listener.failed", "\(error)")
                completionHandler(error)
                return
            }
            startHeartbeat()
            packetLoopActive = true
            drainPackets()
            ProbeLog.shared.event("tunnel.ready", "http=:\(Self.httpPort)")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        ProbeLog.shared.event("tunnel.stop", "reason=\(reason.rawValue)")
        packetLoopActive = false
        heartbeat?.invalidate()
        heartbeat = nil
        probe?.stop()
        probe = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let command = String(decoding: messageData, as: UTF8.self)
        switch command {
        case "log":
            completionHandler?(Data(ProbeLog.shared.tail(lines: 60).utf8))
        default:
            completionHandler?(ProcessMetrics.snapshotJSON(extra: [
                "packetsIn": packetsIn, "bytesIn": bytesIn, "overlay": Self.overlayAddress,
            ]))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        ProbeLog.shared.event("tunnel.sleep")
        completionHandler()
    }

    override func wake() {
        ProbeLog.shared.event("tunnel.wake")
    }

    private func startHeartbeat() {
        ProbeLog.shared.event("heartbeat.start")
        DispatchQueue.main.async { [weak self] in
            let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
                ProbeLog.shared.event("heartbeat", "packetsIn=\(self?.packetsIn ?? 0)")
            }
            RunLoop.main.add(timer, forMode: .common)
            self?.heartbeat = timer
        }
    }

    /// Packets routed to 10.77.0.0/24 arrive here. Counted and dropped until
    /// M2 wires a WireGuard peer; the loop exists so the utun stays healthy and
    /// so T3 can confirm packets really reach the provider.
    private func drainPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, packetLoopActive else { return }
            packetsIn += packets.count
            bytesIn += packets.reduce(0) { $0 + $1.count }
            drainPackets()
        }
    }
}
