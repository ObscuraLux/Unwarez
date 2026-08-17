import Foundation
import UnwarezCore

/// Flags specific, test-controlled hashes as malicious instead of
/// consulting the real threat-intel/ReleaseSeal sources - see
/// `InnerHashChecking`'s doc comment for why this exists.
actor MockInnerHashChecker: InnerHashChecking {
    private var flagged: [String: String] = [:]

    func flag(sha256: String, label: String) {
        flagged[sha256.lowercased()] = label
    }

    func check(sha256: String) async -> InnerHashResult {
        if let label = flagged[sha256.lowercased()] {
            return .malicious(label)
        }
        return .clean
    }
}
