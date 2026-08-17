import Foundation
import Combine

/// Reads/writes the same config file the bash backend (WolfCare.sh)
/// uses for THEME/ALERT_EMAIL, and the same Keychain entries (via the
/// `security` CLI, exactly as the bash backend does) for the API keys -
/// so a key set here is immediately visible to scans, and the CLI/app
/// version stays in sync too. Shelling out to `security` rather than
/// using the Security framework directly keeps this identical to the
/// bash side's mechanism instead of a second implementation that could
/// silently drift from it.
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
    // Matches the bash backend's KEYCHAIN_SERVICE="${CONFIG_FILE##*/}"
    // exactly, so both land on the same Keychain entries.
    private var keychainService: String {
        (configPath as NSString).lastPathComponent
    }

    // Deliberately does NOT load in init(). load() spawns a subprocess
    // (`security`) synchronously, and an @StateObject's init() runs
    // during the view's first layout pass - doing blocking subprocess
    // work there corrupts SwiftUI's AttributeGraph and crashes with
    // SIGABRT (AG::Graph::value_set precondition failure), reproduced
    // via a real crash log. CronStore has the same shape (crontab -l is
    // also a subprocess) and avoids this the same way: load from the
    // view's .onAppear, after layout has settled, not from init().

    func load() {
        var legacyVT = ""
        var legacyMB = ""
        if let content = try? String(contentsOfFile: configPath, encoding: .utf8) {
            for rawLine in content.split(separator: "\n", omittingEmptySubsequences: true) {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                guard let eqIndex = line.firstIndex(of: "=") else { continue }
                let key = String(line[line.startIndex..<eqIndex]).trimmingCharacters(in: .whitespaces)
                var value = String(line[line.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)
                if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
                    value = String(value.dropFirst().dropLast())
                }
                switch key {
                // Only read here for one-time migration below - a
                // pre-Keychain config file is the sole remaining source
                // for these two once migrated, they're never written
                // back to the file.
                case "VT_API_KEY": legacyVT = value
                case "MB_API_KEY": legacyMB = value
                case "ALERT_EMAIL": alertEmail = value
                case "THEME": theme = value
                default: break
                }
            }
        }

        vtApiKey = keychainGet(account: "virustotal_api_key")
        mbApiKey = keychainGet(account: "malwarebazaar_api_key")

        // One-time migration, matching what the bash backend does on
        // its own first load - covers a GUI-only user who never ran a
        // scan (which is what would otherwise trigger the bash side's
        // migration first).
        if vtApiKey.isEmpty, !legacyVT.isEmpty {
            keychainSet(account: "virustotal_api_key", value: legacyVT)
            vtApiKey = legacyVT
        }
        if mbApiKey.isEmpty, !legacyMB.isEmpty {
            keychainSet(account: "malwarebazaar_api_key", value: legacyMB)
            mbApiKey = legacyMB
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
            ALERT_EMAIL="\(alertEmail)"

            """
            try content.write(toFile: configPath, atomically: true, encoding: .utf8)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: configPath
            )
            if let err = keychainSet(account: "virustotal_api_key", value: vtApiKey) {
                warnings.append("VirusTotal key: \(err)")
            }
            if let err = keychainSet(account: "malwarebazaar_api_key", value: mbApiKey) {
                warnings.append("MalwareBazaar key: \(err)")
            }
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

    // MARK: - Keychain

    private func keychainGet(account: String) -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["find-generic-password", "-a", account, "-s", keychainService, "-w"]
        let outPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = Pipe()
        do {
            try task.run()
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return "" }
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .newlines) ?? ""
        } catch {
            return ""
        }
    }

    /// Returns an error description on failure, nil on success -
    /// including the "value is empty, item deleted or already absent"
    /// case, which isn't a real failure.
    @discardableResult
    private func keychainSet(account: String, value: String) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        if value.isEmpty {
            task.arguments = ["delete-generic-password", "-a", account, "-s", keychainService]
        } else {
            task.arguments = ["add-generic-password", "-a", account, "-s", keychainService, "-w", value, "-U"]
        }
        let errPipe = Pipe()
        task.standardOutput = Pipe()
        task.standardError = errPipe
        do {
            try task.run()
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            if value.isEmpty { return nil }
            guard task.terminationStatus != 0 else { return nil }
            let text = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return (text?.isEmpty == false) ? text : "could not save to Keychain"
        } catch {
            return value.isEmpty ? nil : error.localizedDescription
        }
    }
}
