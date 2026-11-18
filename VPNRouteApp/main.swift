import SwiftUI
import AppKit

extension Notification.Name { static let showHelp = Notification.Name("showHelp") }

// MARK: - Helpers

let defaultIPs: [String] = []

func isValidIPv4(_ s: String) -> Bool {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { p in
        guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(p) else { return false }
        return n <= 255
    }
}

func isValidDomain(_ s: String) -> Bool {
    s.count <= 253 && s.range(of: #"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"#, options: .regularExpression) != nil
}

func isValidEntry(_ s: String) -> Bool { isValidIPv4(s) || isValidDomain(s) }

/// Resolve a domain to a list of IPv4 addresses (an IP resolves to itself).
func resolveIPv4(_ host: String) -> [String] {
    if isValidIPv4(host) { return [host] }
    var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
    defer { freeaddrinfo(res) }
    var out: [String] = []
    var cur: UnsafeMutablePointer<addrinfo>? = first
    while let ai = cur {
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        ai.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
            var addr = sin.pointee.sin_addr
            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
        }
        let ip = String(cString: buf)
        if !out.contains(ip) { out.append(ip) }
        cur = ai.pointee.ai_next
    }
    return out
}

func isValidIface(_ s: String) -> Bool {
    s.range(of: #"^[A-Za-z0-9]{1,16}$"#, options: .regularExpression) != nil
}

/// Run a command without privileges and return its output.
func run(_ path: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run() } catch { return "Error: \(error.localizedDescription)" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(data: data, encoding: .utf8) ?? ""
}

/// Run a shell command with admin rights (a single macOS password prompt).
func runAdmin(_ shell: String) -> (ok: Bool, output: String) {
    let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\")
                       .replacingOccurrences(of: "\"", with: "\\\"")
    let src = "do shell script \"\(escaped)\" with administrator privileges"
    var err: NSDictionary?
    guard let script = NSAppleScript(source: src) else { return (false, "Could not create AppleScript") }
    let result = script.executeAndReturnError(&err)
    if let err = err {
        let msg = err[NSAppleScript.errorMessage] as? String ?? "\(err)"
        return (false, msg)
    }
    return (true, result.stringValue ?? "")
}

// MARK: - Model

@MainActor
final class Model: ObservableObject {
    @Published var ips: [String] = []
    @Published var iface: String = "utun4"
    @Published var interfaces: [String] = []
    @Published var ifaceIPs: [String: String] = [:]   // utunX -> IPv4 (has IPv4 = most likely a VPN)
    @Published var newIP: String = ""
    @Published var log: String = ""
    @Published var routes: String = ""
    @Published var busy = false
    @Published var showHelp = false

    private let fileURL: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VPNRoute")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("ips.txt")
    }()

    init() {
        if let text = try? String(contentsOf: fileURL, encoding: .utf8) {
            ips = text.split(whereSeparator: \.isNewline).map { String($0).trimmingCharacters(in: .whitespaces).lowercased() }.filter(isValidEntry)
        } else {
            ips = defaultIPs
            save()
        }
        refreshInterfaces()
        refreshRoutes()
    }

    func save() {
        try? ips.joined(separator: "\n").write(to: fileURL, atomically: true, encoding: .utf8)
    }

    func addIP() {
        var ip = newIP.trimmingCharacters(in: .whitespaces).lowercased()
        // accept pasted URLs: strip scheme and path
        if let r = ip.range(of: "://") { ip = String(ip[r.upperBound...]) }
        if let slash = ip.firstIndex(of: "/") { ip = String(ip[..<slash]) }
        guard isValidEntry(ip) else { append("✗ Invalid IP/domain: \(ip)"); return }
        guard !ips.contains(ip) else { append("• Already in the list: \(ip)"); return }
        ips.append(ip); newIP = ""; save()
    }

    func remove(_ ip: String) { ips.removeAll { $0 == ip }; save() }

    /// A VPN is usually a utunX interface with an IPv4 address; system utun interfaces (iCloud, etc.) have none.
    var vpnCandidates: [String] { interfaces.filter { ifaceIPs[$0] != nil } }
    var vpnDetected: Bool { ifaceIPs[iface] != nil }

    func refreshInterfaces() {
        let list = run("/sbin/ifconfig", ["-l"]).split(whereSeparator: \.isWhitespace).map(String.init).filter { $0.hasPrefix("utun") }
        interfaces = list.sorted { (Int($0.dropFirst(4)) ?? 0) < (Int($1.dropFirst(4)) ?? 0) }
        var ips: [String: String] = [:]
        for name in interfaces {
            let out = run("/sbin/ifconfig", [name])
            for line in out.split(separator: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("inet "), let ip = t.split(separator: " ").dropFirst().first { ips[name] = String(ip); break }
            }
        }
        ifaceIPs = ips
        if interfaces.isEmpty { return }
        // Auto-select: keep the current choice if it is still a VPN, otherwise pick the latest interface with an IPv4
        if ips[iface] == nil {
            if let vpn = vpnCandidates.last { iface = vpn }
            else if !interfaces.contains(iface) { iface = interfaces.last! }
        }
    }

    func refreshRoutes() {
        let entries = ips
        Task.detached {
            let resolved = entries.flatMap(resolveIPv4)
            let out = run("/usr/sbin/netstat", ["-rn", "-f", "inet"])
            let lines = out.split(separator: "\n").map(String.init)
            var hits = lines.filter { l in resolved.contains { l.hasPrefix($0 + " ") || l.hasPrefix($0 + "/") } }
            if let header = lines.first(where: { $0.hasPrefix("Destination") }) { hits.insert(header, at: 0) }
            let text = hits.count > 1 ? hits.joined(separator: "\n") : "(no routes yet for the IPs/domains in the list)"
            await MainActor.run { self.routes = text }
        }
    }

    func append(_ s: String) { log += (log.isEmpty ? "" : "\n") + s }

    func apply(add: Bool) {
        guard isValidIface(iface) else { append("✗ Invalid interface: \(iface)"); return }
        let entries = ips.filter(isValidEntry)
        guard !entries.isEmpty else { append("• The list is empty"); return }
        let verb = add ? "add" : "delete"
        let iface = self.iface
        busy = true
        append("▶ \(add ? "Add" : "Delete") \(entries.count) entries via \(iface)")
        Task.detached {
            var notes: [String] = []
            var targets: [String] = []
            for e in entries {
                let r = resolveIPv4(e)
                if r.isEmpty { notes.append("✗ Could not resolve: \(e)"); continue }
                if e != r.first { notes.append("• \(e) → \(r.joined(separator: ", "))") }
                for ip in r where !targets.contains(ip) { targets.append(ip) }
            }
            guard !targets.isEmpty else {
                await MainActor.run { self.append(notes.joined(separator: "\n")); self.busy = false }
                return
            }
            let cmds = targets.map { ip -> String in
                let tail = add ? " -interface \(iface)" : ""
                return "echo '== \(verb) \(ip)'; /sbin/route -n \(verb) -host \(ip)\(tail) 2>&1"
            }.joined(separator: "; ")
            let r = runAdmin(cmds)
            await MainActor.run {
                if !notes.isEmpty { self.append(notes.joined(separator: "\n")) }
                self.append(r.ok ? r.output.replacingOccurrences(of: "\r", with: "\n") : "✗ \(r.output)")
                self.busy = false
                self.refreshRoutes()
            }
        }
    }
}

// MARK: - UI

struct HelpView: View {
    @Environment(\.dismiss) private var dismiss

    private func section(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            Text(body).fixedSize(horizontal: false, vertical: true)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Draytek Custom Route — Guide").font(.title2).bold()
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
            }.padding([.horizontal, .top], 20).padding(.bottom, 10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    section("What does this app do?",
                            "When connected to a VPN (Draytek), only some traffic goes through the VPN by default. This app forces specific IPs or domains through the VPN network interface (utunX) by adding static routes on your Mac, instead of typing `sudo route` commands by hand.")
                    section("Quick start",
                            "1. Connect to the VPN first.\n2. Open the app: it finds the VPN interface automatically (a utunX with an IP address) and shows a green \"VPN found\" line. You do not need to know what utun is. If the orange line says no VPN was found, turn on the VPN and click ⟳.\n3. Type an IP or domain in the list field and click + (or press Enter).\n4. Click Add routes and enter your Mac password when macOS asks.\n5. Check the \"Current routes\" section to confirm the routes were added.")
                    section("Features",
                            "• VPN interface: detected automatically. A VPN is a utun interface with an IP address (shown as \"VPN 10.x.x.x\"); utun entries marked \"(system)\" are not VPNs. It is re-detected every time you return to the app window. If several VPNs are active, pick one manually in the dropdown. To check yourself: run `ifconfig | grep -A3 utun` in Terminal and look for a utun with an `inet` line.\n• IP / domain list: enter an IPv4 address (8.8.8.8) or a domain (github.com). Pasting a full URL works too; the app extracts the domain. The list is saved automatically and is still there next time.\n• Add routes: adds routes via the selected interface for the whole list, asking for the password only once.\n• Delete routes: removes those routes; use it when disconnecting the VPN or to restore the original state.\n• Current routes: shows the routing-table entries matching your list. Click ⟳ to refresh.\n• Log: the result of each command, including errors and the IPs a domain resolved to.")
                    section("About domains",
                            "Routes are attached to IPs, not hostnames. The app resolves a domain to IPs at the moment you click Add/Delete. If a domain uses a CDN or changes IP often, click Add routes again when needed. Routes for an old IP do not disappear on their own if the IP has changed.")
                    section("Notes",
                            "• Static routes are lost when you restart the Mac or disconnect the VPN; just click Add routes again.\n• \"route already in table\" means the route already exists; it is not a serious error.\n• \"not in table\" on Delete means the route was never added.\n• If the password dialog is cancelled, no routes are changed.\n• The list is stored at ~/Library/Application Support/VPNRoute/ips.txt (one entry per line, editable by hand).")
                }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: 560, height: 540)
    }
}

struct ContentView: View {
    @StateObject private var m = Model()
    @AppStorage("helpShown") private var helpShown = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("VPN interface").font(.headline)
                if m.interfaces.isEmpty {
                    TextField("utun4", text: $m.iface).frame(width: 100)
                } else {
                    Picker("", selection: $m.iface) {
                        ForEach(m.interfaces, id: \.self) { n in Text(m.ifaceIPs[n].map { "\(n)  ·  VPN \($0)" } ?? "\(n)  (system)").tag(n) }
                    }.labelsHidden().frame(width: 220)
                }
                Button { m.refreshInterfaces() } label: { Image(systemName: "arrow.clockwise") }.help("Re-detect VPN interface")
                Spacer()
                Button("Add routes") { m.apply(add: true) }.keyboardShortcut(.defaultAction)
                Button("Delete routes") { m.apply(add: false) }
                if m.busy { ProgressView().controlSize(.small) }
                Button { m.showHelp = true } label: { Image(systemName: "questionmark.circle") }
                    .help("User guide")
            }.disabled(m.busy)

            HStack(spacing: 6) {
                Image(systemName: m.vpnDetected ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundColor(m.vpnDetected ? .green : .orange)
                Text(m.vpnDetected
                     ? "VPN found: \(m.iface) (\(m.ifaceIPs[m.iface] ?? ""))"
                     : "No active VPN found. Turn on the VPN, then click ⟳ to re-detect; adding routes now may send traffic the wrong way.")
                    .font(.callout)
                Spacer()
            }
            GroupBox("IP / domain list") {
                VStack(alignment: .leading) {
                    HStack {
                        TextField("Enter an IP or domain, e.g. github.com", text: $m.newIP).onSubmit { m.addIP() }
                        Button { m.addIP() } label: { Image(systemName: "plus") }
                    }
                    List {
                        ForEach(m.ips, id: \.self) { ip in
                            HStack {
                                Text(ip).font(.system(.body, design: .monospaced))
                                Spacer()
                                Button { m.remove(ip) } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                            }
                        }
                    }.frame(minHeight: 110)
                }.padding(4)
            }

            GroupBox {
                VStack(alignment: .leading) {
                    HStack { Text("Current routes").font(.headline); Spacer()
                        Button { m.refreshRoutes() } label: { Image(systemName: "arrow.clockwise") } }
                    ScrollView { Text(m.routes).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled) }
                        .frame(height: 80)
                }.padding(4)
            }

            GroupBox {
                VStack(alignment: .leading) {
                    HStack { Text("Log").font(.headline); Spacer(); Button("Clear") { m.log = "" } }
                    ScrollView { Text(m.log).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled) }
                        .frame(height: 100)
                }.padding(4)
            }
        }
        .padding(16)
        .frame(minWidth: 520, minHeight: 560)
        .sheet(isPresented: $m.showHelp) { HelpView() }
        .onAppear { if !helpShown { helpShown = true; m.showHelp = true } }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in m.refreshInterfaces(); m.refreshRoutes() }
        .onReceive(NotificationCenter.default.publisher(for: .showHelp)) { _ in m.showHelp = true }
    }
}

@main
struct VPNRouteApp: App {
    var body: some Scene {
        WindowGroup("Draytek Custom Route") { ContentView() }
            .commands {
                CommandGroup(replacing: .help) {
                    Button("User Guide") {
                        NotificationCenter.default.post(name: .showHelp, object: nil)
                    }.keyboardShortcut("?")
                }
            }
    }
}
