import Foundation

enum FileStatus: String {
    case malicious = "MALICIOUS"
    case verified = "VERIFIED"
    case unverified = "UNVERIFIED"
}

struct ScanResult: Identifiable {
    let id: Int
    let name: String
    let sha256: String
    let sizeKB: Int
    let status: FileStatus
    let detail: String
}

struct ScanSummary {
    let scanned: Int
    let detected: Int
    let unverified: Int
    let quarantined: Int
}

enum ScanTarget: Int, CaseIterable {
    case downloads = 1
    case desktop = 2
    case home = 3
    case customDirectory = 4
    case fullSystem = 6

    var label: String {
        switch self {
        case .downloads: return "Downloads folder"
        case .desktop: return "Desktop folder"
        case .home: return "Entire home directory"
        case .customDirectory: return "Custom directory"
        case .fullSystem: return "Full system scan"
        }
    }
}
