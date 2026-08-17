import Foundation
import Combine
import UnwarezCore

/// Drives `UnwarezCore.ScanPipeline` in-process and republishes its
/// `ScanEvent` stream as SwiftUI-observable state. Replaces the previous
/// version, which shelled out to a bundled bash script in `--gui` mode
/// and parsed a `GUI\x1f...`-prefixed stdout protocol - there's no
/// subprocess or wire protocol anymore, just a Swift `AsyncStream`.
@MainActor
final class ScanEngine: ObservableObject {
    @Published var results: [ScanResult] = []
    @Published var totalFiles: Int = 0
    @Published var scannedCount: Int = 0
    @Published var isScanning: Bool = false
    @Published var isPaused: Bool = false
    @Published var summary: ScanSummary?
    @Published var lastError: String?
    @Published var statusMessage: String?
    @Published var showCompletionAlert: Bool = false

    private let pipeline = ScanPipeline()
    private var consumerTask: Task<Void, Never>?
    private var scanStartedAt: Date?
    private var watchdogTimer: Timer?

    /// Absolute ceiling on a single scan's wall-clock time, comfortably
    /// longer than ClamAV's own 30-minute timeout plus the rest of the
    /// pipeline. Pure safety net: if a scan is ever still running past
    /// this, something hung in a way the pipeline's own internal
    /// timeouts didn't catch.
    private static let watchdogTimeout: TimeInterval = 45 * 60

    func startScan(target: ScanTarget, customPath: String = "") {
        let options = ScanOptions(target: target, customPath: customPath.isEmpty ? nil : customPath)
        launch(options: options)
    }

    /// Re-scans exactly the given paths (e.g. "scan again just the files
    /// flagged malicious last time") instead of walking a directory.
    func rescanFlagged(paths: [String]) {
        guard !paths.isEmpty else { return }
        let listPath = NSTemporaryDirectory() + "obscuralux_unwarez_rescan_\(UUID().uuidString).txt"
        do {
            try (paths.joined(separator: "\n") + "\n").write(toFile: listPath, atomically: true, encoding: .utf8)
        } catch {
            lastError = "Could not prepare the file list to re-scan: \(error.localizedDescription)"
            return
        }
        launch(options: ScanOptions(target: .rescanList, fileListPath: listPath), cleanupPath: listPath)
    }

    private func launch(options: ScanOptions, cleanupPath: String? = nil) {
        guard !isScanning else { return }

        results = []
        totalFiles = 0
        scannedCount = 0
        summary = nil
        lastError = nil
        showCompletionAlert = false
        statusMessage = "Starting…"
        isScanning = true
        isPaused = false

        consumerTask = Task { [weak self, pipeline] in
            let stream = await pipeline.run(options: options)
            for await event in stream {
                guard let self else { return }
                self.handle(event)
            }
            if let cleanupPath {
                try? FileManager.default.removeItem(atPath: cleanupPath)
            }
            guard let self else { return }
            self.stopWatchdog()
            self.statusMessage = nil
            self.isScanning = false
            self.isPaused = false
        }
        scanStartedAt = Date()
        startWatchdog()
    }

    private func handle(_ event: ScanEvent) {
        switch event {
        case .status(let message):
            statusMessage = message
        case .total(let total):
            totalFiles = total
            statusMessage = nil
        case .file(let result):
            results.append(result)
            scannedCount = result.id
            statusMessage = nil
        case .done(let scanSummary):
            summary = scanSummary
            statusMessage = nil
            showCompletionAlert = true
        }
    }

    func pauseScan() {
        guard isScanning, !isPaused else { return }
        Task { await pipeline.pause() }
        isPaused = true
        watchdogTimer?.invalidate()
        watchdogTimer = nil
    }

    func resumeScan() {
        guard isScanning, isPaused else { return }
        Task { await pipeline.resume() }
        isPaused = false
        scanStartedAt = Date()
        startWatchdog()
    }

    func cancelScan() {
        stopWatchdog()
        isPaused = false
        isScanning = false
        consumerTask?.cancel()
        Task { await pipeline.cancel() }
    }

    private func startWatchdog() {
        stopWatchdog()
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkWatchdog() }
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
        consumerTask?.cancel()
        Task { await pipeline.cancel() }
        isScanning = false
        isPaused = false
        statusMessage = nil
        lastError = "Scan was taking far longer than expected and was stopped automatically. Try again with a smaller target."
    }

    /// Called from `applicationWillTerminate` - if the app quits while a
    /// scan's ClamAV pass is running, the pipeline's own cancellation
    /// won't run (the process is exiting), so this is a direct,
    /// synchronous last-resort cleanup matching the same pattern the
    /// pipeline itself uses to identify "our" clamscan invocations.
    nonisolated static func killOrphanedClamscan() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-9", "-f", "clamscan.*--file-list="]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
        task.waitUntilExit()
    }
}
