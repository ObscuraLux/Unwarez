import Foundation

public enum ReleaseSealStatus: Sendable, Equatable, CustomStringConvertible {
    case verified
    case compromised
    case unknown
    case offline

    public var description: String {
        switch self {
        case .verified: return "VERIFIED"
        case .compromised: return "COMPROMISED"
        case .unknown: return "UNKNOWN"
        case .offline: return "OFFLINE"
        }
    }
}

struct ReleaseSealDB: Codable {
    struct HashEntry: Codable { let hash: String; let label: String? }
    struct Helper: Codable { let fileName: String; let sha256: [String]; let label: String }
    struct Certificate: Codable { let hash: String; let label: String }

    let trustedCertificates: [Certificate]
    let trustedHelpers: [Helper]
    let verifiedArtifacts: [HashEntry]
    let compromised: [HashEntry]
}

/// GitHub-hosted hash-reputation database, cached 24h. Replaces
/// `download_releaseseal_db`/`check_releaseseal_hash`/
/// `check_releaseseal_helper`/`check_releaseseal_cert`.
public actor ReleaseSealClient {
    private static let apiURL = URL(string: "https://api.github.com/repos/SEALTEAMWORLDWIDE/ReleaseSeal/releases/latest")!
    private static let fallbackAssetURL = URL(string: "https://github.com/SEALTEAMWORLDWIDE/ReleaseSeal/releases/latest/download/evidence.json")!

    private var db: ReleaseSealDB?
    private var verifiedIndex: [String: Bool] = [:]
    private var compromisedIndex: [String: Bool] = [:]

    public init() {}

    public func ensureLoaded() async {
        guard db == nil else { return }

        if FileCache.isFresh(timestampPath: UnwarezPaths.releaseSealTimestampPath, dataPath: UnwarezPaths.releaseSealCachePath),
           let cached = try? Data(contentsOf: UnwarezPaths.releaseSealCachePath),
           let parsed = try? JSONDecoder().decode(ReleaseSealDB.self, from: cached) {
            install(parsed)
            return
        }

        if let downloaded = await download() {
            _ = try? UnwarezPaths.ensureDirectoriesExist()
            try? downloaded.write(to: UnwarezPaths.releaseSealCachePath)
            if let parsed = try? JSONDecoder().decode(ReleaseSealDB.self, from: downloaded) {
                FileCache.markFresh(timestampPath: UnwarezPaths.releaseSealTimestampPath)
                install(parsed)
                return
            }
        }

        // Offline or download failed - fall back to the bundled seed
        // database rather than running with no ReleaseSeal coverage.
        if let seedURL = UnwarezPaths.bundledResourceURL(named: "ReleaseSealDatabase", withExtension: "json"),
           let seedData = try? Data(contentsOf: seedURL),
           let parsed = try? JSONDecoder().decode(ReleaseSealDB.self, from: seedData) {
            install(parsed)
        }
    }

    private func install(_ parsed: ReleaseSealDB) {
        db = parsed
        verifiedIndex = Dictionary(uniqueKeysWithValues: parsed.verifiedArtifacts.map { ($0.hash.lowercased(), true) })
        compromisedIndex = Dictionary(uniqueKeysWithValues: parsed.compromised.map { ($0.hash.lowercased(), true) })
    }

    private func download() async -> Data? {
        var assetURL: URL?
        if let (apiData, _) = try? await URLSession.shared.data(for: makeRequest(Self.apiURL, timeout: 15)),
           let json = try? JSONSerialization.jsonObject(with: apiData) as? [String: Any],
           let assets = json["assets"] as? [[String: Any]] {
            for asset in assets {
                if let name = asset["name"] as? String, name.contains("evidence.json"),
                   let urlString = asset["browser_download_url"] as? String {
                    assetURL = URL(string: urlString)
                    break
                }
            }
        }

        if let assetURL, let (data, response) = try? await URLSession.shared.data(for: makeRequest(assetURL, timeout: 20)),
           (response as? HTTPURLResponse)?.statusCode == 200, !data.isEmpty {
            return data
        }

        if let (data, response) = try? await URLSession.shared.data(for: makeRequest(Self.fallbackAssetURL, timeout: 20)),
           (response as? HTTPURLResponse)?.statusCode == 200, !data.isEmpty {
            return data
        }

        return nil
    }

    private func makeRequest(_ url: URL, timeout: TimeInterval) -> URLRequest {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        return request
    }

    /// SHA256 is always checked; MD5 only if supplied (used for the
    /// `compromised` list, which was seeded from MD5-only samples).
    public func checkHash(sha256: String, md5: String? = nil) -> ReleaseSealStatus {
        guard db != nil else { return .offline }
        if verifiedIndex[sha256.lowercased()] == true { return .verified }
        if compromisedIndex[sha256.lowercased()] == true { return .compromised }
        if let md5, !md5.isEmpty, compromisedIndex[md5.lowercased()] == true { return .compromised }
        return .unknown
    }

    /// Suppresses the Gatekeeper-bypass-script warning only for helper
    /// scripts specifically cataloged by filename + hash - an unrecognized
    /// script matching the same pattern still gets flagged.
    public func checkHelper(fileName: String, sha256: String) -> String? {
        guard let db else { return nil }
        let lowerName = fileName.lowercased()
        let lowerHash = sha256.lowercased()
        for helper in db.trustedHelpers {
            guard helper.fileName.lowercased() == lowerName else { continue }
            if helper.sha256.contains(where: { $0.lowercased() == lowerHash }) {
                return helper.label
            }
        }
        return nil
    }

    /// Evidence-only certificate lookup - never upgrades a verdict.
    public func checkCertificate(hash: String) -> String? {
        guard let db else { return nil }
        let lowerHash = hash.lowercased()
        return db.trustedCertificates.first { $0.hash.lowercased() == lowerHash }?.label
    }
}
