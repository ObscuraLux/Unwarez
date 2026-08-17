import Foundation

struct DMGInspector {
    let innerHashChecker: InnerHashChecker
    let releaseSeal: ReleaseSealClient

    func inspect(path: String) async -> DeepInspectionResult {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/hdiutil") else { return .clean }
        guard DeepInspectionSupport.fileSize(at: path) <= 1_073_741_824 else { return .clean } // skip >1GB

        guard let mountDir = DeepInspectionSupport.makeTempDirectory() else { return .clean }

        guard let attachResult = try? await ProcessRunner.run(
            "/usr/bin/hdiutil",
            arguments: ["attach", "-readonly", "-nobrowse", "-noautoopen", "-owners", "off", "-noverify", "-mountpoint", mountDir.path, path],
            timeout: 30
        ), !attachResult.timedOut, attachResult.exitCode == 0 else {
            // A timeout-killed attach can leave a partial mount behind even
            // though it reported failure - always try to detach before
            // removing the directory, or the mount point leaks permanently.
            await detach(mountDir)
            return .clean
        }

        // Loose top-level helper scripts - release groups commonly ship an
        // "open me first" / Gatekeeper-bypass script loose next to the .app
        // rather than inside a .pkg's pre/postinstall. Informational only;
        // a cataloged ReleaseSeal helper (filename+hash match) suppresses
        // the warning for that specific known entry only.
        var warnScripts: [String] = []
        for script in DeepInspectionSupport.find(under: mountDir, maxDepth: 2, wantDirectories: false, extensions: ["command", "sh", "tool"]) {
            let sha = Hashing.sha256(ofFileAt: script) ?? ""
            if await releaseSeal.checkHelper(fileName: script.lastPathComponent, sha256: sha) != nil { continue }
            guard let text = try? String(contentsOf: script, encoding: .utf8) else { continue }
            for warning in DeepInspectionSupport.scriptWarnings(contentsOf: text) where !warnScripts.contains(warning) {
                warnScripts.append(warning)
            }
        }

        let outerName = (path as NSString).lastPathComponent
        var maliciousResult: String?

        // Nested .pkg / .dmg files - hash the container itself.
        var count = 0
        for inner in DeepInspectionSupport.find(under: mountDir, maxDepth: 4, wantDirectories: false, extensions: ["pkg", "dmg"]) {
            count += 1
            if count > 30 { break }
            guard let sha = Hashing.sha256(ofFileAt: inner) else { continue }
            if case .malicious(let label) = await innerHashChecker.check(sha256: sha) {
                maliciousResult = "\(label) (inside \(inner.lastPathComponent), found in \(outerName))"
                break
            }
        }

        // .app bundles - hash the main executable specifically (found via
        // Info.plist's CFBundleExecutable), since hashing a directory isn't
        // meaningful and the app's actual code is what matters.
        var certEvidence: String?
        if maliciousResult == nil {
            count = 0
            for app in DeepInspectionSupport.find(under: mountDir, maxDepth: 3, wantDirectories: true, extensions: ["app"]) {
                count += 1
                if count > 30 { break }
                guard let execName = await plistBuddyExecutableName(for: app),
                      !execName.contains("/"), execName != ".", execName != ".." else { continue }
                let bin = app.appendingPathComponent("Contents/MacOS/\(execName)")
                guard FileManager.default.fileExists(atPath: bin.path), let sha = Hashing.sha256(ofFileAt: bin) else { continue }
                if case .malicious(let label) = await innerHashChecker.check(sha256: sha) {
                    maliciousResult = "\(label) (inside \(app.lastPathComponent)'s main executable, found in \(outerName))"
                    break
                }
                if certEvidence == nil {
                    certEvidence = await CodeSigningEvidence.checkCertificateLabel(forFileAt: app.path, releaseSeal: releaseSeal)
                }
            }
        }

        await detach(mountDir)

        if let maliciousResult { return .malicious(maliciousResult) }
        if !warnScripts.isEmpty { return .suspiciousScript(warnScripts.joined(separator: "; ")) }
        if let certEvidence { return .certificateEvidence(certEvidence) }
        return .clean
    }

    private func plistBuddyExecutableName(for app: URL) async -> String? {
        guard let result = try? await ProcessRunner.run(
            "/usr/libexec/PlistBuddy",
            arguments: ["-c", "Print :CFBundleExecutable", app.appendingPathComponent("Contents/Info.plist").path],
            timeout: 10
        ), result.exitCode == 0 else { return nil }
        let value = result.standardOutputString.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private func detach(_ mountDir: URL) async {
        let plain = try? await ProcessRunner.run("/usr/bin/hdiutil", arguments: ["detach", mountDir.path], timeout: 15)
        if plain == nil || plain?.exitCode != 0 {
            _ = try? await ProcessRunner.run("/usr/bin/hdiutil", arguments: ["detach", mountDir.path, "-force"], timeout: 15)
        }
        DeepInspectionSupport.removeQuietly(mountDir)
    }
}
