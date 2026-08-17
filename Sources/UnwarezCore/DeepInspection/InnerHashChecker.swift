import Foundation

public enum InnerHashResult: Sendable, Equatable {
    case malicious(String)
    case clean
}

/// The single funnel every deep inspector uses for inner-file verdicts.
/// Deliberately restricted to local/free/no-rate-limit sources only
/// (embedded threat-intel + ReleaseSeal) - an archive can contain
/// hundreds of files, and checking each against VirusTotal/MalwareBazaar
/// could exhaust a whole scan's rate-limit quota on one archive.
public struct InnerHashChecker {
    let releaseSeal: ReleaseSealClient

    public init(releaseSeal: ReleaseSealClient) {
        self.releaseSeal = releaseSeal
    }

    public func check(sha256: String) async -> InnerHashResult {
        if let label = ThreatIntel.checkKnownBad(sha256: sha256) {
            return .malicious(label)
        }
        if await releaseSeal.checkHash(sha256: sha256) == .compromised {
            return .malicious("ReleaseSeal")
        }
        return .clean
    }
}
