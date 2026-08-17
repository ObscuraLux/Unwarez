import Foundation

struct ZipInspector {
    let innerHashChecker: any InnerHashChecking

    func inspect(path: String, depth: Int, recurse: @Sendable (String, Int) async -> DeepInspectionResult) async -> DeepInspectionResult {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/unzip") else { return .clean }
        guard DeepInspectionSupport.fileSize(at: path) <= 536_870_912 else { return .clean } // skip >512MB

        guard let workdir = DeepInspectionSupport.makeTempDirectory() else { return .clean }
        defer { DeepInspectionSupport.removeQuietly(workdir) }

        guard let unzipResult = try? await ProcessRunner.run(
            "/usr/bin/unzip", arguments: ["-q", "-o", path, "-d", workdir.path], timeout: 30
        ), !unzipResult.timedOut, unzipResult.exitCode == 0 else {
            return .clean
        }

        // Zip-bomb guard: bail rather than hash potentially thousands of files.
        guard DeepInspectionSupport.directorySizeKB(workdir) <= 1_048_576 else { return .clean }

        for inner in DeepInspectionSupport.regularFiles(under: workdir, limit: 200) {
            let result = await DeepInspectionSupport.checkInner(inner, checker: innerHashChecker, depth: depth, recurse: recurse)
            if case .malicious(let label) = result {
                return .malicious("\(label) (inside \(inner.lastPathComponent))")
            }
        }
        return .clean
    }
}
