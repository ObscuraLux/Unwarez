import Foundation
import Combine

struct QuarantineEntry: Identifiable {
    let id = UUID()
    let timestamp: String
    let originalPath: String
    let quarantinedName: String
    let sha256: String
    let reason: String
}

/// Reads and writes the exact same quarantine manifest file the bash
/// backend uses, so restore/delete here works on the same quarantined
/// copies the CLI/app version created.
final class QuarantineStore: ObservableObject {
    @Published var entries: [QuarantineEntry] = []
    @Published var message: String?

    private var quarantineDir: String {
        NSHomeDirectory() + "/.local/share/wolfcare_quarantine"
    }
    private var manifestPath: String {
        quarantineDir + "/hashes/quarantine_manifest.txt"
    }
    private var filesDir: String {
        quarantineDir + "/files"
    }
    private var allowlistPath: String {
        quarantineDir + "/allowlist.txt"
    }

    init() {
        load()
    }

    func load() {
        entries = []
        guard let content = try? String(contentsOfFile: manifestPath, encoding: .utf8) else { return }
        for rawLine in content.split(separator: "\n", omittingEmptySubsequences: true) {
            let parts = rawLine.components(separatedBy: "|")
            guard parts.count >= 5 else { continue }
            entries.append(
                QuarantineEntry(
                    timestamp: parts[0],
                    originalPath: parts[1],
                    quarantinedName: parts[2],
                    sha256: parts[3],
                    reason: parts[4]
                )
            )
        }
    }

    func restore(_ entry: QuarantineEntry) {
        let quarantinedPath = filesDir + "/" + entry.quarantinedName
        guard FileManager.default.fileExists(atPath: quarantinedPath) else {
            message = "Quarantined copy is missing on disk - cannot restore."
            return
        }
        if FileManager.default.fileExists(atPath: entry.originalPath) {
            message = "A file already exists at the original path - not overwriting. Restored copy is still safely in quarantine."
            return
        }
        do {
            let originalDir = (entry.originalPath as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(
                atPath: originalDir, withIntermediateDirectories: true
            )
            try FileManager.default.copyItem(atPath: quarantinedPath, toPath: entry.originalPath)
            message = "Restored to \(entry.originalPath)"
        } catch {
            message = "Restore failed: \(error.localizedDescription)"
        }
    }

    /// Path to the quarantined copy - the file that actually still
    /// exists in every case (originals are copied, not moved, into
    /// quarantine, but may since have been deleted/moved by the user).
    func quarantinedPath(for entry: QuarantineEntry) -> String {
        filesDir + "/" + entry.quarantinedName
    }

    /// Removes an entry from the quarantine list WITHOUT deleting the
    /// quarantined copy, and - unlike just deleting the manifest line -
    /// adds the hash to a persistent allowlist the bash backend checks
    /// before every other detection layer, so this exact file is never
    /// re-flagged on a future scan. For a confirmed false positive
    /// (e.g. a PUP - potentially unwanted, but not actually malicious).
    func markSafe(_ entry: QuarantineEntry) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let label = "marked safe by user on \(formatter.string(from: Date())) (was: \(entry.reason))"
        let line = "\(entry.sha256)|\(label)\n"
        do {
            try FileManager.default.createDirectory(atPath: quarantineDir, withIntermediateDirectories: true)
            if let handle = FileHandle(forWritingAtPath: allowlistPath) {
                handle.seekToEndOfFile()
                handle.write(line.data(using: .utf8) ?? Data())
                handle.closeFile()
            } else {
                try line.write(toFile: allowlistPath, atomically: true, encoding: .utf8)
            }
            removeFromManifest(entry)
            load()
            message = "Marked safe - won't be flagged again, and the quarantined copy was kept (not deleted)."
        } catch {
            message = "Could not update the allowlist: \(error.localizedDescription)"
        }
    }

    func delete(_ entry: QuarantineEntry) {
        let quarantinedPath = filesDir + "/" + entry.quarantinedName
        try? FileManager.default.removeItem(atPath: quarantinedPath)
        removeFromManifest(entry)
        load()
        message = "Deleted"
    }

    private func removeFromManifest(_ entry: QuarantineEntry) {
        guard let content = try? String(contentsOfFile: manifestPath, encoding: .utf8) else { return }
        let lineToRemove = "\(entry.timestamp)|\(entry.originalPath)|\(entry.quarantinedName)|\(entry.sha256)|\(entry.reason)"
        let remaining = content
            .split(separator: "\n", omittingEmptySubsequences: true)
            .filter { $0.trimmingCharacters(in: .whitespaces) != lineToRemove }
            .joined(separator: "\n")
        try? (remaining + "\n").write(toFile: manifestPath, atomically: true, encoding: .utf8)
    }
}
