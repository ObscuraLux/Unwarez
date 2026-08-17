import Foundation

public enum InnerHashResult: Sendable, Equatable {
    case malicious(String)
    case clean
}

/// The seam every deep inspector uses for inner-file verdicts, as a
/// protocol rather than a concrete type specifically so tests can inject
/// a fake "this exact hash is malicious" checker - real malware hashes
/// can't be reverse-engineered into test fixture content, but the
/// extraction/traversal/gating/cleanup mechanism each inspector
/// implements can still be exercised end-to-end this way, against a
/// planted file whose hash the test controls.
public protocol InnerHashChecking: Sendable {
    func check(sha256: String) async -> InnerHashResult
}

/// The production implementation, deliberately restricted to local/free/
/// no-rate-limit sources only (embedded threat-intel + ReleaseSeal) - an
/// archive can contain hundreds of files, and checking each against
/// VirusTotal/MalwareBazaar could exhaust a whole scan's rate-limit
/// quota on one archive.
public struct InnerHashChecker: InnerHashChecking {
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
