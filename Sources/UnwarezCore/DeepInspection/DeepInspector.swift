import Foundation

/// Looks INSIDE .zip/.dmg/.pkg/archive containers rather than only hashing
/// the outer file - without this, a malicious file repackaged inside a
/// new/different wrapper evades every hash check, since the outer hash
/// changes even when the payload inside is identical to something already
/// known. Dispatches by extension, mirroring `inspect_deep_contents`.
public struct DeepInspector {
    private let zip: ZipInspector
    private let dmg: DMGInspector
    private let pkg: PKGInspector
    private let archive: ArchiveInspector

    public init(releaseSeal: ReleaseSealClient) {
        let innerHashChecker = InnerHashChecker(releaseSeal: releaseSeal)
        self.zip = ZipInspector(innerHashChecker: innerHashChecker)
        self.dmg = DMGInspector(innerHashChecker: innerHashChecker, releaseSeal: releaseSeal)
        self.pkg = PKGInspector(innerHashChecker: innerHashChecker)
        self.archive = ArchiveInspector(innerHashChecker: innerHashChecker)
    }

    public func inspect(path: String) async -> DeepInspectionResult {
        let lower = path.lowercased()
        if lower.hasSuffix(".zip") { return await zip.inspect(path: path) }
        if lower.hasSuffix(".dmg") { return await dmg.inspect(path: path) }
        if lower.hasSuffix(".pkg") { return await pkg.inspect(path: path) }

        let archiveSuffixes = [".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz", ".iso"]
        if archiveSuffixes.contains(where: { lower.hasSuffix($0) }) {
            return await archive.inspect(path: path)
        }
        return .clean
    }
}
