import Foundation

public enum FileStatus: String, Codable, Sendable {
    case malicious = "MALICIOUS"
    case pup = "PUP"
    case verified = "VERIFIED"
    case unverified = "UNVERIFIED"
}

public struct ScanResult: Identifiable, Sendable, Codable {
    public let id: Int
    public let name: String
    public let sha256: String
    public let sizeKB: Int
    public let status: FileStatus
    public let detail: String
    public let path: String

    public init(id: Int, name: String, sha256: String, sizeKB: Int, status: FileStatus, detail: String, path: String) {
        self.id = id
        self.name = name
        self.sha256 = sha256
        self.sizeKB = sizeKB
        self.status = status
        self.detail = detail
        self.path = path
    }
}

public struct ScanSummary: Sendable, Codable {
    public let scanned: Int
    public let detected: Int
    public let unverified: Int
    public let quarantined: Int

    public init(scanned: Int, detected: Int, unverified: Int, quarantined: Int) {
        self.scanned = scanned
        self.detected = detected
        self.unverified = unverified
        self.quarantined = quarantined
    }
}

/// Mirrors the bash backend's scan-target menu (1-6), plus the GUI-only
/// "rescan an explicit file list" mode which used to be an undocumented
/// raw `--target=8` with no corresponding case anywhere.
public enum ScanTarget: Int, CaseIterable, Sendable, Codable {
    case downloads = 1
    case desktop = 2
    case home = 3
    case customDirectory = 4
    case customFile = 5
    case fullSystem = 6
    case rescanList = 8

    /// `.rescanList` is a programmatic-only mode (triggered by "Re-scan
    /// Flagged Files"), never a picker choice - excluded here so
    /// synthesized `CaseIterable` doesn't offer it as one.
    public static var allCases: [ScanTarget] {
        [.downloads, .desktop, .home, .customDirectory, .customFile, .fullSystem]
    }

    public var label: String {
        switch self {
        case .downloads: return "Downloads Folder"
        case .desktop: return "Desktop"
        case .home: return "Home Folder"
        case .customDirectory: return "Custom Directory"
        case .customFile: return "Custom File"
        case .fullSystem: return "Full System"
        case .rescanList: return "Rescan Flagged Files"
        }
    }
}

/// Replaces the bash backend's `GUI\x1f...` stdout protocol. Consumed
/// in-process by both the GUI and CLI targets via an AsyncStream instead
/// of being parsed line-by-line out of a subprocess's stdout.
public enum ScanEvent: Sendable {
    case status(String)
    case total(Int)
    case file(ScanResult)
    case done(ScanSummary)
}

public struct QuarantineEntry: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let timestamp: String
    public let originalPath: String
    public let quarantinedName: String
    public let sha256: String
    public let reason: String

    public init(id: UUID = UUID(), timestamp: String, originalPath: String, quarantinedName: String, sha256: String, reason: String) {
        self.id = id
        self.timestamp = timestamp
        self.originalPath = originalPath
        self.quarantinedName = quarantinedName
        self.sha256 = sha256
        self.reason = reason
    }

    /// `timestamp|originalPath|quarantinedName|sha256|reason` - matches the
    /// on-disk manifest format written by the original bash backend, kept
    /// unchanged so existing quarantine data doesn't need migrating.
    public var manifestLine: String {
        "\(timestamp)|\(originalPath)|\(quarantinedName)|\(sha256)|\(reason)"
    }

    public init?(manifestLine line: String) {
        let parts = line.components(separatedBy: "|")
        guard parts.count >= 5 else { return nil }
        self.init(timestamp: parts[0], originalPath: parts[1], quarantinedName: parts[2], sha256: parts[3], reason: parts[4])
    }
}

public struct LogEntry: Identifiable, Sendable {
    public let id: UUID
    public let filename: String
    public let path: String
    public let date: Date

    public init(id: UUID = UUID(), filename: String, path: String, date: Date) {
        self.id = id
        self.filename = filename
        self.path = path
        self.date = date
    }
}
