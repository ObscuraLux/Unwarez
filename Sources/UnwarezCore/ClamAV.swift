import Foundation

public enum ClamAVOutcome: Sendable, Equatable {
    case unavailable
    case timedOut
    case error(String)
    case completed(hits: Int)
}

/// ClamAV integration - the only content-based (not hash-based) check.
/// Runs once against the full file list per scan (not per-file), bounded
/// at 30 minutes like every other external tool this app orchestrates.
public actor ClamAVScanner {
    private(set) public var available = false
    private var infectedByPath: [String: String] = [:]

    public init() {}

    public static func findBinary() -> String? {
        for candidate in ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"] {
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        guard let pathEnv = ProcessInfo.processInfo.environment["PATH"] else { return nil }
        for dir in pathEnv.split(separator: ":") {
            let candidate = "\(dir)/clamscan"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    public func run(filePaths: [String], cancellationToken: ProcessCancellationToken? = nil) async -> ClamAVOutcome {
        guard let binary = Self.findBinary(), !filePaths.isEmpty else { return .unavailable }

        let listURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("obscuralux_unwarez_clamav_filelist_\(UUID().uuidString).txt")
        do {
            try (filePaths.joined(separator: "\n") + "\n").write(to: listURL, atomically: true, encoding: .utf8)
        } catch {
            return .error("Could not write ClamAV file list: \(error.localizedDescription)")
        }
        defer { try? FileManager.default.removeItem(at: listURL) }

        guard let result = try? await ProcessRunner.run(
            binary, arguments: ["--no-summary", "--infected", "--file-list=\(listURL.path)"],
            timeout: 1800, cancellationToken: cancellationToken
        ) else {
            return .error("Failed to launch clamscan")
        }

        if result.timedOut {
            // Matches the bash backend's fallback cleanup: clamscan is a
            // grandchild process, so terminating just the runner doesn't
            // guarantee it dies - explicitly pattern-kill it too.
            _ = try? await ProcessRunner.run("/usr/bin/pkill", arguments: ["-9", "-f", "clamscan.*--file-list="], timeout: 5)
            return .timedOut
        }
        if result.exitCode == 2 {
            let firstLine = result.standardErrorString.split(separator: "\n", maxSplits: 1).first.map(String.init) ?? ""
            return .error(firstLine)
        }

        var index: [String: String] = [:]
        for line in result.standardOutputString.split(separator: "\n") {
            guard let range = line.range(of: ": ") else { continue }
            let path = String(line[line.startIndex..<range.lowerBound])
            var signature = String(line[range.upperBound...])
            if signature.hasSuffix(" FOUND") { signature.removeLast(" FOUND".count) }
            index[path] = signature
        }
        infectedByPath = index
        available = true
        return .completed(hits: index.count)
    }

    /// nil = not scanned/unavailable (SKIPPED); empty is not a valid
    /// signature so callers distinguish "clean" from "skipped" via `available`.
    public func infectionSignature(forPath path: String) -> String? {
        infectedByPath[path]
    }
}
