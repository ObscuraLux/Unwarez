import Foundation
import Combine
import UnwarezCore

/// Reads/writes the same config file and Keychain entries
/// `UnwarezCore.ConfigStore`/`KeychainStore` use - shared with the CLI and
/// the scan pipeline, so a key set here is immediately visible to scans.
@MainActor
final class SettingsStore: ObservableObject {
    @Published var vtApiKey: String = ""
    @Published var mbApiKey: String = ""
    @Published var alertEmail: String = ""
    @Published var saveMessage: String?
    @Published var vtKeychainAccessDenied: Bool = false
    @Published var mbKeychainAccessDenied: Bool = false

    // Preserved as-is even though the GUI doesn't expose it, so we never
    // clobber a theme preference set via the CLI version.
    private var theme: String = "dark"

    // Deliberately does NOT load in init(). Even though this no longer
    // shells out to `security`, `SecItemCopyMatching` is still a
    // synchronous call, and an @StateObject's init() runs during the
    // view's first layout pass - the established pattern in this app
    // (see ScheduleStore too) is to load from .onAppear instead, after
    // layout has settled, to stay clear of the AttributeGraph crash this
    // caused once when the subprocess version did the same thing.
    func load() {
        let config = ConfigStore.load()
        theme = config.theme
        alertEmail = config.alertEmail

        switch ConfigStore.virusTotalKeyStatus() {
        case .found(let value): vtApiKey = value; vtKeychainAccessDenied = false
        case .notFound: vtApiKey = ""; vtKeychainAccessDenied = false
        case .accessDenied: vtApiKey = ""; vtKeychainAccessDenied = true
        }
        switch ConfigStore.malwareBazaarKeyStatus() {
        case .found(let value): mbApiKey = value; mbKeychainAccessDenied = false
        case .notFound: mbApiKey = ""; mbKeychainAccessDenied = false
        case .accessDenied: mbApiKey = ""; mbKeychainAccessDenied = true
        }
    }

    func save() {
        // Defensive sanitization: strip any embedded newlines/control
        // characters before writing - a config value containing a literal
        // newline (e.g. an accidental Terminal-output paste) would
        // corrupt the file's line-based structure rather than just being
        // a "wrong" key.
        vtApiKey = sanitize(vtApiKey)
        mbApiKey = sanitize(mbApiKey)
        alertEmail = sanitize(alertEmail)

        var warnings: [String] = []
        if !vtApiKey.isEmpty, !looksLikeVTKey(vtApiKey) {
            warnings.append("VirusTotal key doesn't look right (should be 64 hex characters) - double check what was pasted.")
        }

        do {
            try ConfigStore.save(AppConfig(theme: theme, alertEmail: alertEmail))
        } catch {
            saveMessage = "Could not save: \(error.localizedDescription)"
            return
        }

        if case .failure(let error) = ConfigStore.setVirusTotalKey(vtApiKey) {
            warnings.append("VirusTotal key: \(error)")
        }
        if case .failure(let error) = ConfigStore.setMalwareBazaarKey(mbApiKey) {
            warnings.append("MalwareBazaar key: \(error)")
        }
        saveMessage = warnings.isEmpty ? "Saved" : "Saved, but: " + warnings.joined(separator: " ")
    }

    private func sanitize(_ value: String) -> String {
        value.components(separatedBy: .newlines).joined().trimmingCharacters(in: .whitespaces)
    }

    private func looksLikeVTKey(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit }
    }
}
