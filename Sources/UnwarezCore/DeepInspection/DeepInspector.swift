import Foundation

/// Looks INSIDE .zip/.dmg/.pkg/archive containers rather than only hashing
/// the outer file - without this, a malicious file repackaged inside a
/// new/different wrapper evades every hash check, since the outer hash
/// changes even when the payload inside is identical to something already
/// known. Dispatches by extension, mirroring `inspect_deep_contents`.
///
/// Recurses into archives found *inside* other archives (a zip containing
/// a .pkg containing a .dmg, etc.) - each inspector's inner-file loop
/// calls back into `inspect(path:depth:)` via `DeepInspectionSupport.
/// checkInner` for any inner file that's itself archive-shaped, not just
/// hash-checking it. `maxRecursionDepth` bounds how deep that chases, so
/// a maliciously deep nesting chain built purely to exhaust time/disk
/// can't run away.
///
/// A `final class` (not a struct) specifically so `inspect(path:depth:)`
/// can pass itself (`self.inspect`) as the recursion closure to each
/// sub-inspector - a struct can't reference `self` while its own stored
/// properties are still being initialized, and these sub-inspectors need
/// that reference to call back up into dispatch.
public final class DeepInspector: @unchecked Sendable {
    /// Real installer chains are rarely nested more than 1-2 levels deep
    /// (e.g. a .dmg containing a .pkg). This exists purely to bound the
    /// resource cost of an adversarial nesting chain, not to accommodate
    /// legitimate structures.
    static let maxRecursionDepth = 5

    private static let archiveSuffixes = [
        ".zip", ".dmg", ".pkg", ".rar", ".7z", ".tar", ".tar.gz", ".tgz",
        ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz", ".iso",
    ]

    /// Whether `path` looks like something `inspect` would actually do
    /// work for - used by `DeepInspectionSupport.checkInner` to decide
    /// whether an inner file found during extraction is itself worth
    /// recursing into, rather than attempting (and no-op'ing on) every
    /// single extracted file regardless of type.
    static func isArchiveLike(_ path: String) -> Bool {
        let lower = path.lowercased()
        return archiveSuffixes.contains { lower.hasSuffix($0) }
    }

    private let zip: ZipInspector
    private let dmg: DMGInspector
    private let pkg: PKGInspector
    private let archive: ArchiveInspector

    /// `vtKey`/`mbKey` and the fresh 15-lookup-per-scan budget are
    /// captured once here - construct a new `DeepInspector` at the start
    /// of each scan (not once for a whole app's lifetime) so a changed
    /// API key or a fresh budget actually takes effect.
    public init(releaseSeal: ReleaseSealClient, badFiles: BadFilesClient, virusTotal: VirusTotalClient, vtKey: String?, mbKey: String?) {
        let checker = InnerHashChecker(releaseSeal: releaseSeal, badFiles: badFiles, virusTotal: virusTotal, vtKey: vtKey, mbKey: mbKey)
        self.zip = ZipInspector(innerHashChecker: checker)
        self.dmg = DMGInspector(innerHashChecker: checker, releaseSeal: releaseSeal)
        self.pkg = PKGInspector(innerHashChecker: checker)
        self.archive = ArchiveInspector(innerHashChecker: checker)
    }

    /// Injects a custom hash checker instead of the real threat-intel/
    /// ReleaseSeal sources. Exists for testing: a real malware hash can't
    /// be reverse-engineered into fixture content, but the extraction/
    /// traversal/gating/cleanup mechanism each inspector implements can
    /// still be exercised end-to-end this way, against a planted file
    /// whose hash the test controls.
    public init(innerHashChecker: any InnerHashChecking, releaseSeal: ReleaseSealClient = ReleaseSealClient()) {
        self.zip = ZipInspector(innerHashChecker: innerHashChecker)
        self.dmg = DMGInspector(innerHashChecker: innerHashChecker, releaseSeal: releaseSeal)
        self.pkg = PKGInspector(innerHashChecker: innerHashChecker)
        self.archive = ArchiveInspector(innerHashChecker: innerHashChecker)
    }

    public func inspect(path: String) async -> DeepInspectionResult {
        await inspect(path: path, depth: 0)
    }

    func inspect(path: String, depth: Int) async -> DeepInspectionResult {
        guard depth <= Self.maxRecursionDepth else { return .clean }
        let lower = path.lowercased()
        if lower.hasSuffix(".zip") { return await zip.inspect(path: path, depth: depth, recurse: inspect) }
        if lower.hasSuffix(".dmg") { return await dmg.inspect(path: path, depth: depth, recurse: inspect) }
        if lower.hasSuffix(".pkg") { return await pkg.inspect(path: path, depth: depth, recurse: inspect) }
        if Self.archiveSuffixes.contains(where: { lower.hasSuffix($0) }) {
            return await archive.inspect(path: path, depth: depth, recurse: inspect)
        }
        return .clean
    }
}
