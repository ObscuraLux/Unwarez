import Foundation

/// Incremental, append-as-you-go writers for the two on-disk artifacts
/// every scan produces - matches the bash backend's format exactly so
/// existing report/hash-log files remain readable, and so a scan that's
/// interrupted partway still leaves whatever it wrote so far on disk.
final class LineAppender {
    private let handle: FileHandle

    /// Always (re)creates the file with `initialContent` - both the report
    /// and hash log are meant to be fresh per scan, matching the bash
    /// backend's `>` (truncating) redirects at the start of `run_scan`.
    init?(url: URL, initialContent: String) {
        guard FileManager.default.createFile(atPath: url.path, contents: Data(initialContent.utf8)) else { return nil }
        guard let handle = try? FileHandle(forWritingTo: url) else { return nil }
        handle.seekToEndOfFile()
        self.handle = handle
    }

    func appendLine(_ line: String) {
        handle.write(Data((line + "\n").utf8))
    }

    func close() {
        try? handle.close()
    }
}

enum ScanReport {
    static func makeHashLog() -> LineAppender? {
        LineAppender(url: UnwarezPaths.hashLogPath, initialContent: "SHA256|MD5|FILENAME|SIZE|STATUS\n")
    }

    static func makeReport(startedAt: Date) -> (writer: LineAppender?, path: URL) {
        let path = UnwarezPaths.reportPath(for: startedAt)
        let formatter = DateFormatter()
        formatter.dateStyle = .full
        formatter.timeStyle = .medium
        let writer = LineAppender(url: path, initialContent: "Scan Report - \(formatter.string(from: startedAt))\n")
        return (writer, path)
    }

    static let footer = """

    NOTE: This checks known-hash databases only (ReleaseSeal,
    VirusTotal, MalwareBazaar, CIRCL, and a local list tied to
    two documented campaigns). A clean result here is NOT a
    guarantee this system is free of malware - it does not
    replace macOS's built-in protections or a dedicated
    antivirus product.
    """
}
