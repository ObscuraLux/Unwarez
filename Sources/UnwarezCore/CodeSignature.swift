import Foundation

public enum CodeSignatureStatus: String, Sendable {
    case signedNotarized = "SIGNED_NOTARIZED"
    case signedUnnotarized = "SIGNED_UNNOTARIZED"
    case unsignedOrRejected = "UNSIGNED_OR_REJECTED"
    case notApplicable = "N/A"
}

/// Gatekeeper's own assessment via `spctl`. INFORMATIONAL ONLY - never
/// affects MALICIOUS/VERIFIED/UNVERIFIED classification. Being unsigned is
/// common for entirely legitimate software (including this app itself),
/// so treating "unsigned" as a threat signal would reintroduce exactly the
/// false-positive problem this tool already fixed once (see the UNVERIFIED
/// design principle). Only meaningful for .app/.pkg.
public enum CodeSignature {
    public static func check(fileAt path: String) async -> CodeSignatureStatus {
        let lower = path.lowercased()
        let spctlType: String
        if lower.hasSuffix(".app") {
            spctlType = "execute"
        } else if lower.hasSuffix(".pkg") {
            spctlType = "install"
        } else {
            return .notApplicable
        }

        guard let result = try? await ProcessRunner.run("/usr/sbin/spctl", arguments: ["-a", "-vv", "-t", spctlType, path], timeout: 15) else {
            return .notApplicable
        }
        let combined = (result.standardOutputString + result.standardErrorString).lowercased()
        if combined.contains("accepted") {
            return combined.contains("notarized") ? .signedNotarized : .signedUnnotarized
        }
        if combined.contains("rejected") {
            return .unsignedOrRejected
        }
        return .notApplicable
    }
}
