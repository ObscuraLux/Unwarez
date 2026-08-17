import SwiftUI
import AppKit
import UnwarezCore

struct ScanView: View {
    @ObservedObject var engine: ScanEngine
    @Binding var selection: SidebarItem?
    @State private var selectedTarget: ScanTarget = .downloads
    @State private var customPath: String = ""
    @State private var showingFullSystemConfirm = false
    @State private var showingNoKeysConfirm = false
    @State private var hasFullDiskAccess: Bool = FullDiskAccess.isGranted()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Scan")
                .font(.largeTitle.bold())

            Text("Checks known-hash databases only. Not a substitute for macOS's built-in protections or a dedicated antivirus product.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if hasFullDiskAccess {
                Label("Full Disk Access is enabled - scans can see protected folders.", systemImage: "checkmark.shield")
                    .font(.caption)
                    .foregroundStyle(.green)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HStack(alignment: .top, spacing: 8) {
                    Label("Full Disk Access is recommended for complete results - without it, scans may silently skip protected folders.", systemImage: "exclamationmark.shield")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Open Settings…") {
                        FullDiskAccess.openPrivacySettings()
                    }
                    .font(.caption)
                }
            }

            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(ScanTarget.allCases, id: \.self) { target in
                        Button {
                            selectedTarget = target
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: selectedTarget == target ? "largecircle.fill.circle" : "circle")
                                    .foregroundStyle(selectedTarget == target ? Color.accentColor : Color.secondary)
                                Text(target.label)
                                    .foregroundStyle(.primary)
                                Spacer()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .disabled(engine.isScanning)

                liveCategoryCounts
                    .frame(width: 160)
            }

            if selectedTarget == .customDirectory {
                HStack {
                    TextField("Folder path", text: $customPath)
                        .textFieldStyle(.roundedBorder)
                    Button("Choose…") { chooseFolder() }
                }
            } else if selectedTarget == .customFile {
                HStack {
                    TextField("File path", text: $customPath)
                        .textFieldStyle(.roundedBorder)
                    Button("Choose…") { chooseFile() }
                }
            }

            HStack {
                if engine.isScanning {
                    Button {
                        if engine.isPaused {
                            engine.resumeScan()
                        } else {
                            engine.pauseScan()
                        }
                    } label: {
                        Label(
                            engine.isPaused ? "Resume" : "Pause",
                            systemImage: engine.isPaused ? "play.fill" : "pause.fill"
                        )
                    }

                    Button(role: .destructive) {
                        engine.cancelScan()
                    } label: {
                        Label("Cancel Scan", systemImage: "xmark.circle")
                    }
                } else {
                    Button {
                        requestStartScan()
                    } label: {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                }

                if engine.isScanning && !engine.isPaused {
                    ProgressView()
                        .controlSize(.small)
                        .padding(.leading, 4)
                }

                if engine.isPaused {
                    Label("Paused", systemImage: "pause.circle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption)
                        .padding(.leading, 4)
                }
            }

            if let error = engine.lastError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            if let status = engine.statusMessage {
                HStack(spacing: 6) {
                    if !engine.isPaused {
                        ProgressView().controlSize(.small)
                    }
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if engine.isScanning || engine.totalFiles > 0 {
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(
                        value: Double(engine.scannedCount),
                        total: Double(max(engine.totalFiles, 1))
                    )
                    Text("\(engine.scannedCount) / \(engine.totalFiles) files")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            // A plain List rather than Table: Table needs macOS 12+.
            // No selection binding is used (matching this app's
            // established workaround for the List(selection:) bug in
            // DEVELOPER_NOTES.md), so a plain List works identically
            // back to 10.15's original SwiftUI release.
            VStack(spacing: 0) {
                HStack {
                    Text("File").frame(maxWidth: .infinity, alignment: .leading)
                    Text("Status").frame(width: 120, alignment: .leading)
                    Text("Size (KB)").frame(width: 80, alignment: .leading)
                    Text("Detail").frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption.bold())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)

                List(engine.results) { result in
                    HStack {
                        Text(result.name)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        statusBadge(result.status)
                            .frame(width: 120, alignment: .leading)
                        Text("\(result.sizeKB)")
                            .frame(width: 80, alignment: .leading)
                        Text(result.detail)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .frame(minHeight: 240)

            if let summary = engine.summary {
                summaryCard(summary)
                Text("\"Clean\" means not found in these specific databases — not a guarantee this system is free of malware.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                if engine.results.contains(where: { $0.status == .pup }) {
                    Text("PUP = Potentially Unwanted Program. Flagged by some antivirus engines - typically for a bundled toolbar, adware installer, or similar - but not confirmed as actual malware. Still quarantined for your review, but shown separately from a confirmed threat.")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }

                if !engine.isScanning, summary.detected > 0, !flaggedPaths.isEmpty {
                    Button {
                        engine.rescanFlagged(paths: flaggedPaths)
                    } label: {
                        Label("Re-scan Flagged Files Only", systemImage: "arrow.clockwise.circle")
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding()
        .confirmationDialog(
            "Full system scan can take a long time. Continue?",
            isPresented: $showingFullSystemConfirm
        ) {
            Button("Scan Entire System", role: .destructive) {
                engine.startScan(target: .fullSystem)
            }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog(
            "No VirusTotal or MalwareBazaar API key is configured. Scans still check ReleaseSeal, CIRCL, the built-in threat-intel list, and ClamAV, but skip these two extra sources without a key.",
            isPresented: $showingNoKeysConfirm
        ) {
            Button("Add a Key Now") {
                selection = .settings
            }
            Button("Scan Without a Key") {
                proceedToScan()
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Scan Complete", isPresented: $engine.showCompletionAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Remember to scan all files before use - this only checks the files included in this scan.")
        }
        .onAppear { hasFullDiskAccess = FullDiskAccess.isGranted() }
        // Granting Full Disk Access happens in System Settings, outside
        // the app - re-check whenever the user comes back to it instead
        // of leaving the stale "not granted" warning up after they've
        // already approved it.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            hasFullDiskAccess = FullDiskAccess.isGranted()
        }
    }

    /// Live per-category tally, next to the scan-target list - unlike
    /// `summaryCard` below, this reads `engine.results` directly (rather
    /// than waiting for `engine.summary`, only set once the scan
    /// finishes) so the counts climb in real time as files come in.
    private var liveCategoryCounts: some View {
        VStack(alignment: .leading, spacing: 8) {
            categoryCountRow("VERIFIED", count(.verified), .green)
            categoryCountRow("MALICIOUS", count(.malicious), .red)
            categoryCountRow("PUP", count(.pup), .orange)
            categoryCountRow("UNVERIFIED", count(.unverified), .yellow)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.25)))
    }

    private func count(_ status: FileStatus) -> Int {
        engine.results.filter { $0.status == status }.count
    }

    private func categoryCountRow(_ label: String, _ value: Int, _ color: Color) -> some View {
        HStack {
            Text(label)
                .font(.caption.bold())
                .foregroundStyle(color)
            Spacer()
            Text("\(value)")
                .font(.caption.bold())
                .foregroundStyle(color)
        }
    }

    private var flaggedPaths: [String] {
        engine.results.filter { ($0.status == .malicious || $0.status == .pup) && !$0.path.isEmpty }.map { $0.path }
    }

    /// Entry point for the Start Scan button - asks about API keys first
    /// (if neither is configured) before falling through to the existing
    /// full-system confirmation/direct-start flow in `proceedToScan()`.
    private func requestStartScan() {
        guard ConfigStore.virusTotalKey() == nil, ConfigStore.malwareBazaarKey() == nil else {
            proceedToScan()
            return
        }
        showingNoKeysConfirm = true
    }

    private func proceedToScan() {
        if selectedTarget == .fullSystem {
            showingFullSystemConfirm = true
        } else {
            engine.startScan(target: selectedTarget, customPath: customPath)
        }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            customPath = url.path
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            customPath = url.path
        }
    }

    @ViewBuilder
    private func statusBadge(_ status: FileStatus) -> some View {
        switch status {
        case .malicious:
            Label("Malicious", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        case .pup:
            // Potentially Unwanted Program - flagged by some antivirus
            // engines (typically for bundled adware/toolbars) but not
            // confirmed as actual malware. Orange, distinct from the
            // red used for a confirmed MALICIOUS verdict.
            Label("PUP", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
        case .verified:
            Label("Verified", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .unverified:
            Label("Unverified", systemImage: "questionmark.circle.fill")
                .foregroundStyle(.yellow)
        }
    }

    @ViewBuilder
    private func summaryCard(_ summary: ScanSummary) -> some View {
        HStack(spacing: 32) {
            statPill("Scanned", "\(summary.scanned)", .primary)
            statPill("Threats", "\(summary.detected)", summary.detected > 0 ? .red : .secondary)
            statPill("Unverified", "\(summary.unverified)", .yellow)
            statPill("Quarantined", "\(summary.quarantined)", .secondary)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 10))
    }

    private func statPill(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title2.bold()).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}
