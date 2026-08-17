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

    /// Locates a bundled resource (ThreatIntel.json, ReleaseSealDatabase.json)
    /// without relying solely on SwiftPM's generated `Bundle.module`.
    ///
    /// `Bundle.module`'s generated accessor resolves relative to
    /// `Bundle.main.bundleURL` (a real .app's *root*, sibling to
    /// `Contents/`) with a hardcoded-at-build-time absolute fallback into
    /// this machine's own `.build/` directory - both fail on every other
    /// machine once packaged into a real .app, where `codesign --deep`
    /// refuses to seal anything outside `Contents/` in the first place
    /// (confirmed: placing the resource bundle at the bundle root, even
    /// as a symlink, makes codesign fail with "unsealed contents present
    /// in the bundle root"). The result was `Bundle.module`'s lazy
    /// initializer calling `fatalError()` the instant any packaged build
    /// touched it - crashing on the very first scan.
    ///
    /// This checks the *correct*, signable location for a real .app
    /// (`Bundle.main.resourceURL`, i.e. `Contents/Resources/`, where
    /// `build_app.sh` actually copies the resource bundle) first, and
    /// only falls back to `Bundle.module` for `swift run`/`swift test`
    /// dev contexts, where there's no real .app wrapper and the
    /// generated accessor resolves correctly on its own.
    public static func bundledResourceURL(named name: String, withExtension ext: String) -> URL? {
        let bundleDirName = "Unwarez_UnwarezCore.bundle"
        if let resourceURL = Bundle.main.resourceURL {
            let candidate = resourceURL
                .appendingPathComponent(bundleDirName)
                .appendingPathComponent("\(name).\(ext)")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return Bundle.module.url(forResource: name, withExtension: ext)
    }
}
