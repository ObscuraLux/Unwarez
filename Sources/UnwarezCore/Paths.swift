import Foundation

/// Single source of truth for every path the app reads or writes.
/// The bash-backed version had this knowledge duplicated across five
/// different Swift files (each re-deriving `~/.local/share/obscuralux_unwarez_quarantine/...`
/// independently); centralizing it here means there's exactly one place
/// to change if the layout ever moves.
///
/// Kept byte-identical to the bash backend's layout so existing installs'
/// quarantine data, config, and caches keep working with no migration.
public enum UnwarezPaths {
    public static let quarantineRoot: URL = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/share/obscuralux_unwarez_quarantine")
    }()

    public static var filesDir: URL { quarantineRoot.appendingPathComponent("files") }
    public static var hashesDir: URL { quarantineRoot.appendingPathComponent("hashes") }
    public static var reportsDir: URL { quarantineRoot.appendingPathComponent("reports") }

    public static var manifestPath: URL { hashesDir.appendingPathComponent("quarantine_manifest.txt") }
    public static var hashLogPath: URL { hashesDir.appendingPathComponent("hashes.txt") }
    public static var configPath: URL { quarantineRoot.appendingPathComponent(".obscuralux_unwarez_config") }

    public static var releaseSealCachePath: URL { quarantineRoot.appendingPathComponent("releaseseal_cache.json") }
    public static var releaseSealTimestampPath: URL { quarantineRoot.appendingPathComponent(".releaseseal_timestamp") }
    public static var badfilesCachePath: URL { quarantineRoot.appendingPathComponent("badfiles_cache.txt") }
    public static var badfilesTimestampPath: URL { quarantineRoot.appendingPathComponent(".badfiles_timestamp") }

    public static func reportPath(for date: Date = Date()) -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        return reportsDir.appendingPathComponent("report_\(formatter.string(from: date)).txt")
    }

    @discardableResult
    public static func ensureDirectoriesExist() throws -> Bool {
        var created = false
        for dir in [quarantineRoot, filesDir, hashesDir, reportsDir] {
            if !FileManager.default.fileExists(atPath: dir.path) {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                created = true
            }
        }
        return created
    }
}
