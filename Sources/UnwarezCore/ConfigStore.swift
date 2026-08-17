import Foundation

public struct AppConfig: Equatable, Sendable {
    public var theme: String
    public var alertEmail: String

    public init(theme: String = "dark", alertEmail: String = "") {
        self.theme = theme
        self.alertEmail = alertEmail
    }
}

/// Plaintext config (theme + alert email only) plus the Keychain-backed API
/// keys. Mirrors the bash backend's split: `.obscuralux_unwarez_config`
/// never stores secrets, `KeychainStore` does.
public enum ConfigStore {
    public static let virusTotalAccount = "virustotal_api_key"
    public static let malwareBazaarAccount = "malwarebazaar_api_key"

    public static func load() -> AppConfig {
        _ = try? UnwarezPaths.ensureDirectoriesExist()
        var config = AppConfig()

        guard let text = try? String(contentsOf: UnwarezPaths.configPath, encoding: .utf8) else {
            return config
        }

        var legacyVT = ""
        var legacyMB = ""
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[line.startIndex..<eq])
            let value = String(line[line.index(after: eq)...])
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            switch key {
            case "THEME": config.theme = value
            case "ALERT_EMAIL": config.alertEmail = value
            // Legacy pre-Keychain installs may still have these sitting in
            // plaintext; `save` below never writes them back out, so this
            // migration path naturally stops firing once the file is rewritten.
            case "VT_API_KEY": legacyVT = value
            case "MB_API_KEY": legacyMB = value
            default: break
            }
        }

        if KeychainStore.get(account: virusTotalAccount) == nil, !legacyVT.isEmpty {
            KeychainStore.set(account: virusTotalAccount, value: legacyVT)
        }
        if KeychainStore.get(account: malwareBazaarAccount) == nil, !legacyMB.isEmpty {
            KeychainStore.set(account: malwareBazaarAccount, value: legacyMB)
        }

        return config
    }

    public static func save(_ config: AppConfig) throws {
        try UnwarezPaths.ensureDirectoriesExist()
        let text = "THEME=\"\(config.theme)\"\nALERT_EMAIL=\"\(config.alertEmail)\"\n"
        try text.write(to: UnwarezPaths.configPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: UnwarezPaths.configPath.path)
    }

    public static func virusTotalKey() -> String? { KeychainStore.get(account: virusTotalAccount) }
    public static func malwareBazaarKey() -> String? { KeychainStore.get(account: malwareBazaarAccount) }

    public static func virusTotalKeyStatus() -> KeychainReadResult { KeychainStore.getResult(account: virusTotalAccount) }
    public static func malwareBazaarKeyStatus() -> KeychainReadResult { KeychainStore.getResult(account: malwareBazaarAccount) }

    @discardableResult
    public static func setVirusTotalKey(_ value: String) -> Result<Void, KeychainError> {
        KeychainStore.set(account: virusTotalAccount, value: value)
    }

    @discardableResult
    public static func setMalwareBazaarKey(_ value: String) -> Result<Void, KeychainError> {
        KeychainStore.set(account: malwareBazaarAccount, value: value)
    }
}
