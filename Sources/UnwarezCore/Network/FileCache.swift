import Foundation

/// Shared 24h-TTL disk-cache helper used by ReleaseSeal and the badfiles.txt
/// feed - both follow the identical "download, cache for a day, fall back
/// to whatever's on disk if offline" pattern from the bash backend.
enum FileCache {
    static let ttl: TimeInterval = 86400

    static func isFresh(timestampPath: URL, dataPath: URL) -> Bool {
        guard FileManager.default.fileExists(atPath: dataPath.path),
              let tsString = try? String(contentsOf: timestampPath, encoding: .utf8),
              let ts = TimeInterval(tsString.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return false
        }
        return Date().timeIntervalSince1970 - ts < ttl
    }

    static func markFresh(timestampPath: URL) {
        let ts = String(Int(Date().timeIntervalSince1970))
        try? ts.write(to: timestampPath, atomically: true, encoding: .utf8)
    }
}
