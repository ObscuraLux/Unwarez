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
///
/// Takes both SHA256 and MD5 - MD5-keyed sources (the embedded list's
/// MD5 half, badfiles.txt) are meaningless without it. An earlier
/// version of this checker (both here and in the bash tool this was
/// ported from) only ever computed/passed SHA256 for inner files, so
/// the MD5-keyed sources could never match anything found inside an
/// archive - "scans but doesn't flag" for exactly that reason, fixed
/// upstream and ported here.
public protocol InnerHashChecking: Sendable {
    func check(sha256: String, md5: String, path: String) async -> InnerHashResult
}

/// The production implementation. Local/free sources (embedded list,
/// badfiles.txt, ReleaseSeal) are checked unconditionally. VirusTotal/
/// MalwareBazaar are also now reachable for archive contents - previously
/// local-sources-only to protect quota - but only for a capped number of
/// "plausible payload" files per scan (executable bit set, or a
/// .pkg/.dmg/.command/.sh extension), so a zip full of resource files
/// can't burn the budget.
public actor InnerHashChecker: InnerHashChecking {
    /// Caps how many archive-inner files get a VT/MalwareBazaar lookup
    /// for the whole scan - VT throttles to 1 call/15s, so unrestricted
    /// use here could turn a single archive full of executables into a
    /// multi-minute scan.
    private static let vtBudgetPerScan = 15

    private let releaseSeal: ReleaseSealClient
    private let badFiles: BadFilesClient
    private let virusTotal: VirusTotalClient
    private let vtKey: String?
    private let mbKey: String?
    private var remainingVTBudget = InnerHashChecker.vtBudgetPerScan

    public init(releaseSeal: ReleaseSealClient, badFiles: BadFilesClient, virusTotal: VirusTotalClient, vtKey: String?, mbKey: String?) {
        self.releaseSeal = releaseSeal
        self.badFiles = badFiles
        self.virusTotal = virusTotal
        self.vtKey = vtKey
        self.mbKey = mbKey
    }

    public func check(sha256: String, md5: String, path: String) async -> InnerHashResult {
        if let label = ThreatIntel.checkKnownBad(sha256: sha256, md5: md5) {
            return .malicious(label)
        }
        if let label = await badFiles.check(md5: md5) {
            return .malicious(label)
        }
        if await releaseSeal.checkHash(sha256: sha256, md5: md5) == .compromised {
            return .malicious("ReleaseSeal")
        }

        guard remainingVTBudget > 0, isPlausiblePayload(path) else {
            return .clean
        }
        remainingVTBudget -= 1

        if let vtKey, !vtKey.isEmpty {
            if case .malicious(let count) = await virusTotal.check(sha256: sha256, apiKey: vtKey) {
                return .malicious("VirusTotal (\(count) engines)")
            }
        }
        if let mbKey, !mbKey.isEmpty {
            if case .malicious(let family) = await MalwareBazaarClient.check(sha256: sha256, apiKey: mbKey) {
                return .malicious("MalwareBazaar (\(family))")
            }
        }
        return .clean
    }

    private func isPlausiblePayload(_ path: String) -> Bool {
        if FileManager.default.isExecutableFile(atPath: path) { return true }
        let lower = path.lowercased()
        return lower.hasSuffix(".pkg") || lower.hasSuffix(".dmg") || lower.hasSuffix(".command") || lower.hasSuffix(".sh")
    }
}
