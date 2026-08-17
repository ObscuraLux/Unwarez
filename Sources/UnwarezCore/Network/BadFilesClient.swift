import Foundation

/// Community-maintained MD5 corpus of known-malicious warez/cracked-
/// installer repacks, same shape/caching as ReleaseSeal but a plain
/// `<md5> <label...>` text feed rather than JSON. Independent free/local
/// source, checked alongside the embedded `ThreatIntel` list.
public actor BadFilesClient {
    private static let url = URL(string: "https://brokenstones.is/static/scripts/badfiles.txt")!

    private var index: [String: String] = [:]
    private var loaded = false

    public init() {}

    public func ensureLoaded() async {
        guard !loaded else { return }
        defer { loaded = true }

        if FileCache.isFresh(timestampPath: UnwarezPaths.badfilesTimestampPath, dataPath: UnwarezPaths.badfilesCachePath),
           let cached = try? String(contentsOf: UnwarezPaths.badfilesCachePath, encoding: .utf8) {
            install(cached)
            return
        }

        var request = URLRequest(url: Self.url)
        request.timeoutInterval = 20
        if let (data, response) = try? await URLSession.shared.data(for: request),
           (response as? HTTPURLResponse)?.statusCode == 200, !data.isEmpty,
           let text = String(data: data, encoding: .utf8) {
            _ = try? UnwarezPaths.ensureDirectoriesExist()
            try? text.write(to: UnwarezPaths.badfilesCachePath, atomically: true, encoding: .utf8)
            FileCache.markFresh(timestampPath: UnwarezPaths.badfilesTimestampPath)
            install(text)
            return
        }

        // Offline/download failed - fall back to whatever's cached on disk, if anything.
        if let cached = try? String(contentsOf: UnwarezPaths.badfilesCachePath, encoding: .utf8) {
            install(cached)
        }
    }

    private func install(_ text: String) {
        var built: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            guard let spaceIndex = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" }) else { continue }
            let md5 = String(trimmed[trimmed.startIndex..<spaceIndex]).lowercased()
            let label = trimmed[trimmed.index(after: spaceIndex)...].trimmingCharacters(in: .whitespaces)
            built[md5] = label
        }
        index = built
    }

    public func check(md5: String) -> String? {
        guard !md5.isEmpty, let label = index[md5.lowercased()] else { return nil }
        return "brokenstones.is: \(label)"
    }
}
