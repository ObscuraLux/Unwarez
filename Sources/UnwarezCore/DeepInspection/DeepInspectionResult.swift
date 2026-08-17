import Foundation

/// Result of looking inside a container (.zip/.dmg/.pkg/rar/7z/tar family
/// via unar). Only `.malicious` ever affects a scan verdict - the other
/// two cases are informational/advisory only, surfaced as extra detail on
/// an otherwise UNVERIFIED result, never upgrading or downgrading it.
public enum DeepInspectionResult: Sendable, Equatable {
    case malicious(String)
    case suspiciousScript(String)
    case certificateEvidence(String)
    case clean
}

/// Evidence-only code-signing certificate lookup, shared by any inspector
/// that wants to surface "this app was signed with a cert ReleaseSeal has
/// seen before" context. Never upgrades a verdict - self-signed certs are
/// trivially reproducible.
enum CodeSigningEvidence {
    static func checkCertificateLabel(forFileAt path: String, releaseSeal: ReleaseSealClient) async -> String? {
        let lower = path.lowercased()
        guard lower.hasSuffix(".app") || lower.hasSuffix(".pkg") else { return nil }
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign"),
              FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else { return nil }

        guard let certDir = DeepInspectionSupport.makeTempDirectory() else { return nil }
        defer { DeepInspectionSupport.removeQuietly(certDir) }

        _ = try? await ProcessRunner.run(
            "/usr/bin/codesign", arguments: ["-dvvv", "--extract-certificates", path],
            timeout: 15, currentDirectory: certDir
        )

        guard let items = try? FileManager.default.contentsOfDirectory(atPath: certDir.path) else { return nil }
        for item in items.sorted() where item.hasPrefix("codesign") {
            let certPath = certDir.appendingPathComponent(item).path
            guard let opensslResult = try? await ProcessRunner.run(
                "/usr/bin/openssl", arguments: ["x509", "-inform", "DER", "-in", certPath, "-outform", "DER"], timeout: 10
            ), opensslResult.exitCode == 0, !opensslResult.standardOutput.isEmpty else { continue }
            let certHash = Hashing.sha256(of: opensslResult.standardOutput)
            if let label = await releaseSeal.checkCertificate(hash: certHash) {
                return label
            }
        }
        return nil
    }
}
