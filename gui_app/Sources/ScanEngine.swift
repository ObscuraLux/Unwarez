import Foundation
import Combine

/// Drives the existing, already-tested bash scanner in `--gui` mode and
/// parses its structured output (lines prefixed "GUI\x1f...") into
/// SwiftUI-observable state. All actual hashing / VirusTotal / ReleaseSeal /
/// threat-intel logic stays in the shell script - this class only shells
/// out to it and reads its output, it does not reimplement any scanning.
final class ScanEngine: ObservableObject {
    @Published var results: [ScanResult] = []
    @Published var totalFiles: Int = 0
    @Published var scannedCount: Int = 0
    @Published var isScanning: Bool = false
    @Published var summary: ScanSummary?
    @Published var lastError: String?
    @Published var statusMessage: String?
    @Published var showCompletionAlert: Bool = false

    private var process: Process?
    private var lineBuffer = Data()
    private var watchdogTimer: Timer?
    private var scanStartedAt: Date?

    /// Absolute ceiling on a single scan's wall-clock time, comfortably
    /// longer than the bash script's own 30-minute clamscan timeout plus
    /// the rest of the pipeline. Pure safety net: if the backend process
    /// is ever still running past this, something is stuck in a way its
    /// own internal timeouts didn't catch, and the app recovers on its
    /// own instead of requiring the user to notice and manually
    /// `pkill -f clamscan` to get scanning moving again.
    private static let watchdogTimeout: TimeInterval = 45 * 60

    /// Path to the bundled scanner script, copied into Contents/Resources
    /// at build time by build_app.sh.
    private var scriptPath: String? {
        Bundle.main.path(forResource: "WolfCare", ofType: nil)
    }

    func startScan(target: ScanTarget, customPath: String = "") {
        guard let scriptPath = scriptPath else {
            lastError = "Could not find the bundled scanner script inside the app."
            return
        }
        guard !isScanning else { return }

        // Defensive cleanup: if the app was previously quit or relaunched
        // mid-scan, a background clamscan process from that old run can be
        // orphaned - it keeps running with nothing left to stop it, and a
        // fresh scan would then start a second one competing for CPU.
        ScanEngine.killOrphanedClamscan()

        results = []
        totalFiles = 0
        scannedCount = 0
        summary = nil
        lastError = nil
        showCompletionAlert = false
        statusMessage = "Starting…"
        lineBuffer = Data()
        isScanning = true

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")

        var args = [scriptPath, "--gui", "--target=\(target.rawValue)"]
        if (target == .customDirectory || target == .customFile), !customPath.isEmpty {
            args.append("--path=\(customPath)")
        }
        task.arguments = args

        let outPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = Pipe() // discard human-readable/colored noise

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.consume(data)
        }

        task.terminationHandler = { [weak self] terminatedProcess in
            DispatchQueue.main.async {
                outPipe.fileHandleForReading.readabilityHandler = nil
                guard let self = self else { return }
                self.stopWatchdog()
                // Don't clobber a more specific explanation (e.g. the
                // watchdog's "took too long" message) already set for
                // why this process is no longer running.
                if self.summary == nil && self.lastError == nil && terminatedProcess.terminationStatus != 0 {
                    self.lastError = "Scan process ended unexpectedly (exit code \(terminatedProcess.terminationStatus))."
                }
                self.statusMessage = nil
                self.isScanning = false
            }
        }

        self.process = task
        do {
            try task.run()
            scanStartedAt = Date()
            startWatchdog()
        } catch {
            isScanning = false
            lastError = "Could not start scan: \(error.localizedDescription)"
        }
    }

    func cancelScan() {
        stopWatchdog()
        process?.terminate()
        process = nil
        isScanning = false
        // Terminating the bash process doesn't guarantee clamscan (its
        // child) receives the signal too - clean it up explicitly so
        // Cancel actually stops all the work, not just the visible part.
        ScanEngine.killOrphanedClamscan()
    }

    /// Wall-clock safety net independent of the bash script's own
    /// internal timeouts (clamscan's 30-minute one, the 30-60s ones on
    /// unzip/hdiutil/pkgutil/unar): if the whole backend process is ever
    /// still running past `watchdogTimeout`, something hung in a way
    /// none of those caught, and the scan is force-stopped automatically
    /// rather than leaving the user staring at a frozen progress bar
    /// with no way to recover short of a manual `pkill`.
    private func startWatchdog() {
        stopWatchdog()
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.checkWatchdog()
        }
    }

    private func stopWatchdog() {
        watchdogTimer?.invalidate()
        watchdogTimer = nil
        scanStartedAt = nil
    }

    private func checkWatchdog() {
        guard let startedAt = scanStartedAt,
              Date().timeIntervalSince(startedAt) > ScanEngine.watchdogTimeout else { return }
        stopWatchdog()
        process?.terminate()
        process = nil
        ScanEngine.killOrphanedClamscan()
        isScanning = false
        statusMessage = nil
        lastError = "Scan was taking far longer than expected and was stopped automatically. Try again with a smaller target."
    }

    /// Kills any leftover clamscan process this app may have started in a
    /// previous run. Uses pkill -f matching our specific invocation
    /// pattern (--file-list=, which only this app's scans use) rather
    /// than a bare "clamscan" match, so it won't touch a clamscan the
    /// user might be running for something unrelated. Sends SIGKILL
    /// (-9), not the default SIGTERM, since the whole point of this call
    /// is recovering a process that's already stuck/unresponsive rather
    /// than asking it nicely. Static so it can also be called from
    /// app-termination code, which doesn't have a live ScanEngine
    /// instance to call into.
    static func killOrphanedClamscan() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-9", "-f", "clamscan.*--file-list="]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
        task.waitUntilExit()
    }

    // MARK: - Output parsing

    private func consume(_ data: Data) {
        lineBuffer.append(data)
        let newline = UInt8(ascii: "\n")
        while let idx = lineBuffer.firstIndex(of: newline) {
            let lineData = lineBuffer.subdata(in: lineBuffer.startIndex..<idx)
            lineBuffer.removeSubrange(lineBuffer.startIndex...idx)
            if let line = String(data: lineData, encoding: .utf8) {
                handle(line: line)
            }
        }
    }

    private func handle(line: String) {
        let sep = "\u{1F}"
        guard line.hasPrefix("GUI\(sep)") else { return }
        let fields = line.components(separatedBy: sep)
        guard fields.count >= 2 else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            switch fields[1] {
            case "STATUS":
                if fields.count >= 3 {
                    self.statusMessage = fields[2]
                }
            case "TOTAL":
                if fields.count >= 3, let n = Int(fields[2]) {
                    self.totalFiles = n
                    self.statusMessage = nil
                }
            case "FILE":
                guard fields.count >= 7 else { return }
                let idx = Int(fields[2]) ?? (self.results.count + 1)
                let status = FileStatus(rawValue: fields[3]) ?? .unverified
                let name = fields[4]
                let sha = fields[5]
                let sizeKB = Int(fields[6]) ?? 0
                let detail = fields.count > 7 ? fields[7] : ""
                self.results.append(
                    ScanResult(id: idx, name: name, sha256: sha, sizeKB: sizeKB, status: status, detail: detail)
                )
                self.scannedCount = idx
                self.statusMessage = nil
            case "DONE":
                guard fields.count >= 6 else { return }
                self.summary = ScanSummary(
                    scanned: Int(fields[2]) ?? 0,
                    detected: Int(fields[3]) ?? 0,
                    unverified: Int(fields[4]) ?? 0,
                    quarantined: Int(fields[5]) ?? 0
                )
                self.statusMessage = nil
                self.showCompletionAlert = true
            default:
                break
            }
        }
    }
}
