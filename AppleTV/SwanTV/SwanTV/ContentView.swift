import SwiftUI

struct ContentView: View {
    @State private var tunnel = TunnelController()
    @State private var onDemand = true

    var body: some View {
        HStack(alignment: .top, spacing: 40) {
            VStack(alignment: .leading, spacing: 18) {
                Text("SwanTV Probe").font(.title)
                Text("Tunnel: \(tunnel.status.label)")
                Text("On-demand: \(tunnel.onDemandEnabled ? "enabled" : "off")")
                if let error = tunnel.lastError {
                    Text(error).foregroundStyle(.red).font(.caption)
                }
                Toggle("Install with on-demand (auto-start after reboot)", isOn: $onDemand)
                Button("Install / Update Configuration") { Task { await tunnel.install(onDemand: onDemand) } }
                Button("Start Tunnel") { tunnel.start() }
                Button("Stop Tunnel") { tunnel.stop() }
                Button("Query Provider") { Task { await tunnel.queryProvider() } }
                Button("Refresh Heartbeat Log") { tunnel.refreshStatus() }
                Button("Remove Configuration") { Task { await tunnel.remove() } }
                Text("curl http://<apple-tv-lan-ip>:8080/health").font(.caption).foregroundStyle(.secondary)
            }
            .frame(width: 620)

            VStack(alignment: .leading, spacing: 12) {
                Text("Provider status").font(.headline)
                ScrollView {
                    Text(tunnel.providerStatusJSON)
                        .font(.system(size: 20, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 380)
                Text("Heartbeat log (App Group)").font(.headline)
                ScrollView {
                    Text(tunnel.heartbeatTail)
                        .font(.system(size: 18, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(40)
        .task {
            await tunnel.load()
            await tunnel.queryProvider()
        }
    }
}

#Preview {
    ContentView()
}
