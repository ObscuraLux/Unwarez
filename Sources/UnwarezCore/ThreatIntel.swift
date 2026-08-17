import Foundation

/// Embedded local threat-intel: known-bad hashes plus the persistence/
/// network-threat signals used to check for already-installed infections
/// (not just files being scanned). Loaded from `ThreatIntel.json`, a
/// resource mechanically extracted from the bash backend's embedded
/// `KNOWN_BAD_*` arrays (54 SHA256 + 113 MD5 entries covering the
/// "xdivcmp" fake-installer backdoor and "OGF" infostealer-bundle
/// campaigns) rather than hand-transcribed, to guarantee the hash data
/// itself carried over byte-for-byte.
public struct HashEntry: Codable, Sendable {
    public let hash: String
    public let label: String
}

public struct ThreatIntelDatabase: Codable, Sendable {
    public let sha256: [HashEntry]
    public let md5: [HashEntry]
    public let launchdLabels: [String]
    public let launchdPaths: [String]
    public let stagingApps: [String]
    public let ips: [String]
    public let domains: [String]
}

public enum ThreatIntel {
    public static let database: ThreatIntelDatabase = {
        guard let url = Bundle.module.url(forResource: "ThreatIntel", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let db = try? JSONDecoder().decode(ThreatIntelDatabase.self, from: data) else {
            return ThreatIntelDatabase(sha256: [], md5: [], launchdLabels: [], launchdPaths: [], stagingApps: [], ips: [], domains: [])
        }
        return db
    }()

    private static let sha256Index: [String: String] = Dictionary(
        database.sha256.map { ($0.hash.lowercased(), $0.label) }, uniquingKeysWith: { first, _ in first }
    )
    private static let md5Index: [String: String] = Dictionary(
        database.md5.map { ($0.hash.lowercased(), $0.label) }, uniquingKeysWith: { first, _ in first }
    )

    /// Exact match against the embedded lists. SHA256 is always checked;
    /// MD5 only if a non-empty value is supplied - mirrors the bash
    /// backend's `check_known_bad_hash`.
    public static func checkKnownBad(sha256: String, md5: String? = nil) -> String? {
        if let label = sha256Index[sha256.lowercased()] { return label }
        if let md5, !md5.isEmpty, let label = md5Index[md5.lowercased()] { return label }
        return nil
    }

    /// Scans real LaunchDaemon/LaunchAgent plists plus known malware
    /// staging-app paths for exact known-bad matches - i.e. checks for an
    /// already-installed infection, not a file being actively scanned.
    /// Mirrors `check_persistence_threats`.
    public static func checkPersistenceThreats() -> [String] {
        var findings: [String] = []
        let fm = FileManager.default

        for path in database.launchdPaths where fm.fileExists(atPath: path) {
            findings.append("Known-malicious LaunchDaemon present: \(path)")
        }

        let launchDirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents").path,
        ]
        for dir in launchDirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for item in items where item.hasSuffix(".plist") {
                let fullPath = (dir as NSString).appendingPathComponent(item)
                guard let contents = try? String(contentsOfFile: fullPath, encoding: .utf8) else { continue }
                for label in database.launchdLabels where contents.contains(label) {
                    findings.append("Known-malicious launchd label '\(label)' found in \(fullPath)")
                }
            }
        }

        for appPath in database.stagingApps where fm.fileExists(atPath: appPath) {
            findings.append("Known malware staging app present: \(appPath)")
        }

        return findings
    }

    /// Checks live outbound network connections against known C2 IPs via
    /// `lsof -i -n -P`. Mirrors `check_network_threats`.
    public static func checkNetworkThreats() async -> [String] {
        guard let result = try? await ProcessRunner.run("/usr/sbin/lsof", arguments: ["-i", "-n", "-P"], timeout: 10) else {
            return []
        }
        var findings: [String] = []
        for line in result.standardOutputString.split(separator: "\n") {
            for ip in database.ips where line.contains(ip) {
                findings.append("Active connection to known-malicious IP \(ip): \(line.trimmingCharacters(in: .whitespaces))")
            }
        }
        return findings
    }

    /// Filename-only, informational-only match for "Open Gatekeeper
    /// Friendly"-style bait names in Desktop/Downloads. Never affects a
    /// scan verdict - mirrors `check_ogf_filenames`.
    public static func checkOGFFilenames() -> [String] {
        let fm = FileManager.default
        let dirs = [
            fm.homeDirectoryForCurrentUser.appendingPathComponent("Desktop"),
            fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads"),
        ]
        var findings: [String] = []
        for dir in dirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir.path) else { continue }
            for item in items where item.lowercased().hasPrefix("open gatekeeper friendly") {
                findings.append(dir.appendingPathComponent(item).path)
            }
        }
        return findings
    }
}
