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

    /// Hashes an inner file found during extraction, checks it against
    /// `checker` (local lists + budget-limited VT/MalwareBazaar), and -
    /// if that comes back clean and the file is itself archive-shaped
    /// (a zip inside a zip, a .pkg inside a .dmg, etc.) - recurses into
    /// it via `recurse`, the enclosing `DeepInspector.inspect(path:
    /// depth:)`. Centralizing this (rather than duplicating hash-check-
    /// then-maybe-recurse in each of the four inspectors' inner loops)
    /// is what makes recursion "just work" everywhere inner files get
    /// examined, with one place to get the depth right.
    ///
    /// Returns the nested result's label as-is, unwrapped - each
    /// inspector's own call site already appends its own "(inside X)"
    /// as the result bubbles back up one level at a time, so by the time
    /// a 3-deep match reaches the top it reads as a full chain (e.g.
    /// "... (inside malicious.bin in package payload) (inside
    /// payload.pkg) (inside wrapper.zip)") without this helper doubling
    /// any one level's annotation.
    static func checkInner(
        _ file: URL, checker: any InnerHashChecking, depth: Int,
        recurse: @Sendable (String, Int) async -> DeepInspectionResult
    ) async -> DeepInspectionResult {
        guard let sha = Hashing.sha256(ofFileAt: file) else { return .clean }
        let md5 = Hashing.md5(ofFileAt: file) ?? ""
        if case .malicious(let label) = await checker.check(sha256: sha, md5: md5, path: file.path) {
            return .malicious(label)
        }
        guard DeepInspector.isArchiveLike(file.path) else { return .clean }
        return await recurse(file.path, depth + 1)
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
