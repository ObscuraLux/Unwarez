import Foundation
import Security

/// Native `Security` framework Keychain access, replacing both the bash
/// backend's `security` CLI shell-outs and the GUI's (also shelled-out)
/// `SettingsStore.keychainGet/keychainSet`. Service name and account names
/// are kept byte-identical to the old scheme so existing installs' saved
/// API keys are found without any migration.
public enum KeychainStore {
    /// Matches the bash backend's `KEYCHAIN_SERVICE="${CONFIG_FILE##*/}"`,
    /// which evaluated to the literal basename of the config file.
    public static let serviceName = ".obscuralux_unwarez_config"

    public static func get(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Empty `value` deletes the entry, matching the bash backend's
    /// `keychain_set` (called with an empty value to clear a key).
    @discardableResult
    public static func set(account: String, value: String) -> Result<Void, KeychainError> {
        guard !value.isEmpty else { return delete(account: account) }

        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        let data = Data(value.utf8)

        let updateStatus = SecItemUpdate(identity as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecSuccess {
            return .success(())
        }
        guard updateStatus == errSecItemNotFound else {
            return .failure(KeychainError(status: updateStatus))
        }

        var addQuery = identity
        addQuery[kSecValueData as String] = data
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            return .failure(KeychainError(status: addStatus))
        }
        return .success(())
    }

    @discardableResult
    public static func delete(account: String) -> Result<Void, KeychainError> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            return .failure(KeychainError(status: status))
        }
        return .success(())
    }
}

public struct KeychainError: Error, CustomStringConvertible, Sendable {
    public let status: OSStatus
    public var description: String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)"
    }
}
