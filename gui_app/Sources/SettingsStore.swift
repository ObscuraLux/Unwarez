import Foundation
import Combine

/// Reads and writes the exact same config file the bash backend
/// (WolfCare.sh) already uses - so a key set here is immediately
/// picked up by scans, and the CLI/app version stays in sync too.
final class SettingsStore: ObservableObject {
    @Published var vtApiKey: String = ""
    @Published var mbApiKey: String = ""
    @Published var alertEmail: String = ""
    @Published var saveMessage: String?

    // Preserved as-is even though the GUI doesn't use it, so we
    // never clobber a theme preference set via the CLI version.
    private var theme: String = "dark"

    private var configDir: String {
        NSHomeDirectory() + "/.local/share/wolfcare_quarantine"
    }
    private var configPath: String {
        configDir + "/.wolfcare_config"
    }

    init() {
        load()
    }

    func load() {
        guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { return }
        for rawLine in content.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let eqIndex = line.firstIndex(of: "=") else { continue }
            let key = String(line[line.startIndex..<eqIndex]).trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
                value = String(value.dropFirst().dropLast())
            }
            switch key {
            case "VT_API_KEY": vtApiKey = value
            case "MB_API_KEY": mbApiKey = value
            case "ALERT_EMAIL": alertEmail = value
            case "THEME": theme = value
            default: break
            }
        }
    }

    func save() {
        // Defensive sanitization: strip any embedded newlines/control
        // characters before writing. A config file is parsed line-by-line
        // (both here and in the bash backend), so a value containing a
        // literal newline - e.g. from an accidental Terminal-output paste
        // instead of an actual key - would corrupt the file's structure
        // rather than just being a "wrong" key.
        vtApiKey = sanitize(vtApiKey)
        mbApiKey = sanitize(mbApiKey)
        alertEmail = sanitize(alertEmail)

        var warnings: [String] = []
        if !vtApiKey.isEmpty && !looksLikeVTKey(vtApiKey) {
            warnings.append("VirusTotal key doesn't look right (should be 64 hex characters) - double check what was pasted.")
        }

        do {
            try FileManager.default.createDirectory(
                atPath: configDir, withIntermediateDirectories: true
            )
            let content = """
            THEME="\(theme)"
            VT_API_KEY="\(vtApiKey)"
            MB_API_KEY="\(mbApiKey)"
            ALERT_EMAIL="\(alertEmail)"

            """
            try content.write(toFile: configPath, atomically: true, encoding: .utf8)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: configPath
            )
            saveMessage = warnings.isEmpty ? "Saved" : "Saved, but: " + warnings.joined(separator: " ")
        } catch {
            saveMessage = "Could not save: \(error.localizedDescription)"
        }
    }

    private func sanitize(_ value: String) -> String {
        value.components(separatedBy: .newlines)
            .joined()
            .trimmingCharacters(in: .whitespaces)
    }

    private func looksLikeVTKey(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit }
    }
}
