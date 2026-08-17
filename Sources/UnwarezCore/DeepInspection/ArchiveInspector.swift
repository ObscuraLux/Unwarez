import Foundation

/// Handles every archive/compression format beyond zip/dmg/pkg through
/// `unar`'s single interface: rar, 7z, tar, tar.gz/.tgz, tar.bz2/.tbz2,
/// tar.xz/.txz, gz, bz2, xz, and iso. `unrar` was removed from Homebrew
/// (license policy); `unar` (`brew install unar`) is the actively
/// maintained replacement.
struct ArchiveInspector {
    let innerHashChecker: any InnerHashChecking

    func inspect(path: String, depth: Int, recurse: @Sendable (String, Int) async -> DeepInspectionResult) async -> DeepInspectionResult {
        guard let unarPath = Self.findUnar() else { return .clean }
        guard DeepInspectionSupport.fileSize(at: path) <= 536_870_912 else { return .clean }

        guard let workdir = DeepInspectionSupport.makeTempDirectory() else { return .clean }
        defer { DeepInspectionSupport.removeQuietly(workdir) }

        guard let unarResult = try? await ProcessRunner.run(
            unarPath, arguments: ["-f", "-q", "-o", workdir.path, path], timeout: 30
        ), !unarResult.timedOut, unarResult.exitCode == 0 else {
            return .clean
        }

        guard DeepInspectionSupport.directorySizeKB(workdir) <= 1_048_576 else { return .clean }

        for inner in DeepInspectionSupport.regularFiles(under: workdir, limit: 200) {
            let result = await DeepInspectionSupport.checkInner(inner, checker: innerHashChecker, depth: depth, recurse: recurse)
            if case .malicious(let label) = result {
                return .malicious("\(label) (inside \(inner.lastPathComponent))")
            }
        }
        return .clean
    }

    private static func findUnar() -> String? {
        for candidate in ["/opt/homebrew/bin/unar", "/usr/local/bin/unar"] {
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        guard let pathEnv = ProcessInfo.processInfo.environment["PATH"] else { return nil }
        for dir in pathEnv.split(separator: ":") {
            let candidate = "\(dir)/unar"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }
}
