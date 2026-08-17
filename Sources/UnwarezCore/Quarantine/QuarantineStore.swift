import Foundation

/// Reads/writes the pipe-delimited quarantine manifest and manages
/// quarantined file copies. Pure `FileManager` - no subprocess. Shared by
/// the scan pipeline (which only appends), the GUI's quarantine tab, and
/// the CLI (both of which list/restore/delete).
public enum QuarantineStore {
    public static func append(_ entry: QuarantineEntry) {
        _ = try? UnwarezPaths.ensureDirectoriesExist()
        let line = entry.manifestLine + "\n"
        let path = UnwarezPaths.manifestPath.path
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        if let handle = try? FileHandle(forWritingTo: UnwarezPaths.manifestPath) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        }
    }

    public static func loadEntries() -> [QuarantineEntry] {
        guard let text = try? String(contentsOf: UnwarezPaths.manifestPath, encoding: .utf8) else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: true).compactMap {
            QuarantineEntry(manifestLine: String($0))
        }
    }

    public static func quarantinedFileURL(for entry: QuarantineEntry) -> URL {
        UnwarezPaths.filesDir.appendingPathComponent(entry.quarantinedName)
    }

    public enum ActionError: Error, CustomStringConvertible {
        case missingQuarantinedCopy
        case originalAlreadyExists
        case underlying(String)

        public var description: String {
            switch self {
            case .missingQuarantinedCopy: return "Quarantined copy is missing."
            case .originalAlreadyExists: return "A file already exists at the original location."
            case .underlying(let message): return message
            }
        }
    }

    /// Copies (not moves) the quarantined file back to its original
    /// location. Never overwrites an existing file there.
    public static func restore(_ entry: QuarantineEntry) -> Result<Void, ActionError> {
        let source = quarantinedFileURL(for: entry)
        guard FileManager.default.fileExists(atPath: source.path) else { return .failure(.missingQuarantinedCopy) }
        guard !FileManager.default.fileExists(atPath: entry.originalPath) else { return .failure(.originalAlreadyExists) }
        let destination = URL(fileURLWithPath: entry.originalPath)
        do {
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: source, to: destination)
            return .success(())
        } catch {
            return .failure(.underlying(error.localizedDescription))
        }
    }

    /// Removes the manifest entry only - does not delete the quarantined
    /// copy and does not exempt the file from future detection (a future
    /// scan re-evaluates it fresh).
    public static func markSafe(_ entry: QuarantineEntry) {
        removeFromManifest(entry)
    }

    public static func delete(_ entry: QuarantineEntry) {
        try? FileManager.default.removeItem(at: quarantinedFileURL(for: entry))
        removeFromManifest(entry)
    }

    private static func removeFromManifest(_ entry: QuarantineEntry) {
        guard let text = try? String(contentsOf: UnwarezPaths.manifestPath, encoding: .utf8) else { return }
        let targetLine = entry.manifestLine
        let remaining = text.split(separator: "\n", omittingEmptySubsequences: true)
            .filter { $0.trimmingCharacters(in: .whitespaces) != targetLine }
            .joined(separator: "\n")
        try? (remaining.isEmpty ? "" : remaining + "\n").write(to: UnwarezPaths.manifestPath, atomically: true, encoding: .utf8)
    }
}
