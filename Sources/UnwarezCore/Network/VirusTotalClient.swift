import Foundation

public enum VirusTotalResult: Sendable, Equatable, CustomStringConvertible {
    case malicious(Int)
    case pup(Int)
    case clean
    case unknown
    case rateLimited
    case badKey
    case noKey

    public var description: String {
        switch self {
        case .malicious(let n): return "MALICIOUS:\(n)"
        case .pup(let n): return "PUP:\(n)"
        case .clean: return "CLEAN"
        case .unknown: return "UNKNOWN"
        case .rateLimited: return "RATE_LIMITED"
        case .badKey: return "BADKEY"
        case .noKey: return "NOKEY"
        }
    }
}

/// VirusTotal v3 file-hash lookup. Self-throttles to respect the free
/// tier's ~4/min limit and permanently disables itself for the rest of a
/// scan session on 429/401/403 - state is per-instance (one instance per
/// scan run), not global, unlike the bash backend's script-lifetime globals.
public actor VirusTotalClient {
    private var disabledForSession = false
    private var lastCallAt: Date?

    public init() {}

    public func check(sha256: String, apiKey: String?) async -> VirusTotalResult {
        guard let apiKey, !apiKey.isEmpty else { return .noKey }
        guard !disabledForSession else { return .rateLimited }

        if let lastCallAt {
            let elapsed = Date().timeIntervalSince(lastCallAt)
            if elapsed < 15 {
                try? await Task.sleep(nanoseconds: UInt64((15 - elapsed) * 1_000_000_000))
            }
        }
        lastCallAt = Date()

        var request = URLRequest(url: URL(string: "https://www.virustotal.com/api/v3/files/\(sha256)")!)
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        request.timeoutInterval = 15

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse else {
            return .unknown
        }

        switch http.statusCode {
        case 429:
            disabledForSession = true
            return .rateLimited
        case 401, 403:
            disabledForSession = true
            return .badKey
        case 404:
            return .unknown
        case 200:
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let dataObj = json["data"] as? [String: Any],
                  let attributes = dataObj["attributes"] as? [String: Any],
                  let stats = attributes["last_analysis_stats"] as? [String: Any] else {
                return .unknown
            }
            let malicious = stats["malicious"] as? Int ?? 0
            guard malicious > 0 else { return .clean }

            // PUP vs real malware: if every engine that flagged this used a
            // PUP/PUA/"unwanted"-style signature name, it's a bundled/adware
            // -style flag, not confirmed malware. Any non-PUP-looking name
            // keeps this as full MALICIOUS - conservative on purpose.
            let results = attributes["last_analysis_results"] as? [String: Any] ?? [:]
            let flaggedSignatures: [String] = results.values.compactMap { entry in
                guard let entry = entry as? [String: Any],
                      (entry["category"] as? String) == "malicious" else { return nil }
                return entry["result"] as? String
            }
            let isPUP = !flaggedSignatures.isEmpty && flaggedSignatures.allSatisfy { sig in
                let lower = sig.lowercased()
                return lower.contains("pup") || lower.contains("pua") || lower.contains("unwanted")
            }
            return isPUP ? .pup(malicious) : .malicious(malicious)
        default:
            return .unknown
        }
    }
}
