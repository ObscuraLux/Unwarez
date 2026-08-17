import Foundation

/// Shared helpers for the four deep inspectors. Every external tool
/// invocation here goes through `Process`'s `arguments` array (never a
/// shell string), so - unlike the bash backend's one historical
/// vulnerability (a `bash -c "...'$path'..."` interpolation that let an
/// attacker-controlled archive-internal path break out and inject shell
/// commands) - there is no shell in the loop at all for these calls, and
/// no quoting-escape class of bug is possible here by construction.
enum DeepInspectionSupport {
    static func fileSize(at path: String) -> Int {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int ?? 0
    }

    static func directorySizeKB(_ url: URL) -> Int {
        guard let enumerator = FileManager.default.enumerator(
            at: url, includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]
        ) else { return 0 }
        var totalBytes = 0
        for case let fileURL as URL in enumerator {
            if let size = try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize {
                totalBytes += size
            }
        }
        return totalBytes / 1024
    }

    /// Lazily enumerates regular files under `dir`, stopping at `limit`
    /// (mirrors the bash inspectors' hard inner-file-count caps).
    static func regularFiles(under dir: URL, limit: Int) -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: dir, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]
        ) else { return [] }
        var results: [URL] = []
        for case let fileURL as URL in enumerator {
            guard (try? fileURL.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true else { continue }
            results.append(fileURL)
            if results.count >= limit { break }
        }
        return results
    }

    static func makeTempDirectory() -> URL? {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("obscuralux_unwarez_\(UUID().uuidString)")
        guard (try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)) != nil else { return nil }
        return dir
    }

    static func removeQuietly(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    /// `find $dir -maxdepth N \( -type f|d \) -iname "*.ext"` equivalent -
    /// unlike `regularFiles(under:limit:)` this respects a depth cap and
    /// name-extension filter instead of walking unbounded and capping only
    /// by count, matching the specific `find` invocations the dmg/pkg
    /// inspectors use for their loose-script/nested-container/app-bundle
    /// scans. `depth` counts the same way `find -maxdepth` does: direct
    /// children of `dir` are depth 1.
    static func find(under dir: URL, maxDepth: Int, wantDirectories: Bool, match: (URL) -> Bool) -> [URL] {
        var results: [URL] = []
        func walk(_ current: URL, depth: Int) {
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: current, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]
            ) else { return }
            for item in items {
                let isDir = (try? item.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false
                if isDir == wantDirectories, match(item) {
                    results.append(item)
                }
                if isDir, depth < maxDepth {
                    walk(item, depth: depth + 1)
                }
            }
        }
        walk(dir, depth: 1)
        return results
    }

    /// Convenience overload for the common `-iname "*.ext"` case (case-
    /// insensitive extension matching, as the bash backend's `-iname` did).
    static func find(under dir: URL, maxDepth: Int, wantDirectories: Bool, extensions: Set<String>) -> [URL] {
        find(under: dir, maxDepth: maxDepth, wantDirectories: wantDirectories) {
            extensions.contains($0.pathExtension.lowercased())
        }
    }

    /// Gatekeeper-disable / quarantine-strip pattern checks, shared by the
    /// dmg and pkg inspectors' loose-helper-script scanning.
    static func scriptWarnings(contentsOf text: String) -> [String] {
        var warnings: [String] = []
        let gatekeeperDisable = try! NSRegularExpression(
            pattern: #"(^|[;&|\s])(sudo\s+)?(/usr/sbin/)?spctl\s+--(master|global)-disable"#
        )
        let quarantineStrip = try! NSRegularExpression(pattern: #"xattr\s+.*com\.apple\.quarantine"#)
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        if gatekeeperDisable.firstMatch(in: text, range: range) != nil {
            warnings.append("disables Gatekeeper")
        }
        if quarantineStrip.firstMatch(in: text, range: range) != nil {
            warnings.append("strips quarantine attribute")
        }
        return warnings
    }
}
