import Foundation

/// Walks a scan target and returns candidate file paths, mirroring the
/// bash backend's `find` invocations (same extension filter, same
/// exclusion pruning, same `-maxdepth 10`).
public enum FileEnumerator {
    static let scannableExtensions: Set<String> = [
        "dmg", "zip", "pkg", "app", "rar", "7z", "tar", "tgz", "tbz2", "txz", "gz", "bz2", "xz", "iso",
    ]
    private static let maxDepth = 10

    public static func enumerate(target: ScanTarget, customPath: String?, fileListPath: String?) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        switch target {
        case .downloads:
            return walk("\(home)/Downloads", excluding: [UnwarezPaths.quarantineRoot.path])
        case .desktop:
            return walk("\(home)/Desktop", excluding: [UnwarezPaths.quarantineRoot.path])
        case .home:
            return walk(home, excluding: [UnwarezPaths.quarantineRoot.path])
        case .customDirectory:
            guard let customPath, !customPath.isEmpty else { return [] }
            return walk(customPath, excluding: [UnwarezPaths.quarantineRoot.path])
        case .customFile:
            guard let customPath, !customPath.isEmpty else { return [] }
            return [customPath]
        case .fullSystem:
            return walk("/", excluding: ["/System", "/Library", "/.Trash", UnwarezPaths.quarantineRoot.path], matchTrashAnywhere: true)
        case .rescanList:
            guard let fileListPath, let text = try? String(contentsOfFile: fileListPath, encoding: .utf8) else { return [] }
            return text.split(separator: "\n").map { String($0) }.filter { !$0.isEmpty }
        }
    }

    /// `excluding` entries are matched as path prefixes, mirroring the
    /// bash backend's `-path "$EXCLUDE" -prune`. `matchTrashAnywhere`
    /// mirrors the full-system scan's `*/.Trash*` glob (matches at any
    /// depth, not just as a root-level prefix).
    private static func walk(_ root: String, excluding: [String], matchTrashAnywhere: Bool = false) -> [String] {
        guard let enumerator = FileManager.default.enumerator(
            at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var results: [String] = []
        while let item = enumerator.nextObject() as? URL {
            let path = item.path
            let depth = enumerator.level
            if depth > maxDepth {
                enumerator.skipDescendants()
                continue
            }
            if excluding.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) {
                enumerator.skipDescendants()
                continue
            }
            if matchTrashAnywhere, path.contains("/.Trash") {
                enumerator.skipDescendants()
                continue
            }
            let isRegularFile = (try? item.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile ?? false
            guard isRegularFile else { continue }
            if scannableExtensions.contains(item.pathExtension.lowercased()) {
                results.append(path)
            }
        }
        return results
    }
}
