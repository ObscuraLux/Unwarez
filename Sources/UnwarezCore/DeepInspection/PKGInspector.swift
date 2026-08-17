import Foundation

struct PKGInspector {
    let innerHashChecker: any InnerHashChecking

    func inspect(path: String, depth: Int, recurse: @Sendable (String, Int) async -> DeepInspectionResult) async -> DeepInspectionResult {
        guard FileManager.default.isExecutableFile(atPath: "/usr/sbin/pkgutil") else { return .clean }
        guard DeepInspectionSupport.fileSize(at: path) <= 1_073_741_824 else { return .clean } // skip >1GB

        // pkgutil --expand requires the target path not exist yet.
        guard let placeholder = DeepInspectionSupport.makeTempDirectory() else { return .clean }
        DeepInspectionSupport.removeQuietly(placeholder)
        let workdir = placeholder

        guard let expandResult = try? await ProcessRunner.run(
            "/usr/sbin/pkgutil", arguments: ["--expand", path, workdir.path], timeout: 60
        ), !expandResult.timedOut, expandResult.exitCode == 0 else {
            DeepInspectionSupport.removeQuietly(workdir)
            return .clean
        }
        defer { DeepInspectionSupport.removeQuietly(workdir) }

        // Installer script check - INFORMATIONAL ONLY. Pattern-matching
        // scripts is exactly the kind of heuristic that produced a real
        // false positive earlier in this tool's history.
        var warnScripts: [String] = []
        let scripts = DeepInspectionSupport.find(under: workdir, maxDepth: .max, wantDirectories: false) {
            $0.lastPathComponent == "preinstall" || $0.lastPathComponent == "postinstall"
        }
        for script in scripts {
            guard let text = try? String(contentsOf: script, encoding: .utf8) else { continue }
            for warning in DeepInspectionSupport.scriptWarnings(contentsOf: text) where !warnScripts.contains(warning) {
                warnScripts.append(warning)
            }
        }

        // Payload contents - a pkg Payload is gzip-compressed cpio, not tar.
        var maliciousResult: String?
        var innerCount = 0
        for payloadFile in findPayloads(under: workdir) {
            guard let expandedPayload = DeepInspectionSupport.makeTempDirectory() else { continue }
            defer { DeepInspectionSupport.removeQuietly(expandedPayload) }

            let ok = await decompressPayload(payloadFile, into: expandedPayload)
            if ok {
                // Zip-bomb guard, matching the other inspectors - a hostile
                // payload could otherwise expand unbounded within the time budget.
                guard DeepInspectionSupport.directorySizeKB(expandedPayload) <= 1_048_576 else { continue }

                for inner in DeepInspectionSupport.regularFiles(under: expandedPayload, limit: 100) {
                    innerCount += 1
                    if innerCount > 100 { break }
                    let result = await DeepInspectionSupport.checkInner(inner, checker: innerHashChecker, depth: depth, recurse: recurse)
                    if case .malicious(let label) = result {
                        maliciousResult = "\(label) (inside \(inner.lastPathComponent) in package payload)"
                        break
                    }
                }
            }
            if maliciousResult != nil || innerCount > 100 { break }
        }

        if let maliciousResult { return .malicious(maliciousResult) }
        if !warnScripts.isEmpty { return .suspiciousScript(warnScripts.joined(separator: "; ")) }
        return .clean
    }

    private func findPayloads(under workdir: URL) -> [URL] {
        DeepInspectionSupport.find(under: workdir, maxDepth: 2, wantDirectories: false) {
            $0.lastPathComponent == "Payload"
        }
    }

    /// `gunzip -dc payload | cpio -i` with no shell in the loop - two
    /// `Process`es connected by a native `Pipe`. This is the exact call
    /// site where the bash backend used to interpolate an attacker-
    /// influenced path into a `bash -c "...'$path'..."` string (fixed
    /// separately in the bash script, but structurally impossible here:
    /// `Process.arguments` never passes through a shell, so there's no
    /// quoting boundary for a crafted component name to break out of).
    private func decompressPayload(_ payloadFile: URL, into destination: URL) async -> Bool {
        let gunzip = Process()
        gunzip.executableURL = URL(fileURLWithPath: "/usr/bin/gunzip")
        gunzip.arguments = ["-dc", payloadFile.path]
        gunzip.standardError = Pipe()

        let cpio = Process()
        cpio.executableURL = URL(fileURLWithPath: "/usr/bin/cpio")
        cpio.arguments = ["-i", "--quiet"]
        cpio.currentDirectoryURL = destination
        cpio.standardError = Pipe()

        let pipe = Pipe()
        gunzip.standardOutput = pipe
        cpio.standardInput = pipe

        do {
            try cpio.run()
            try gunzip.run()
        } catch {
            return false
        }

        let watchdog = Task.detached(priority: .utility) { () -> Bool in
            try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
            var timedOut = false
            if gunzip.isRunning { timedOut = true; kill(gunzip.processIdentifier, SIGKILL) }
            if cpio.isRunning { timedOut = true; kill(cpio.processIdentifier, SIGKILL) }
            return timedOut
        }

        gunzip.waitUntilExit()
        cpio.waitUntilExit()
        watchdog.cancel()

        return gunzip.terminationStatus == 0 && cpio.terminationStatus == 0
    }
}
