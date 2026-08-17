import Foundation

public enum CIRCLResult: Sendable, Equatable {
    case knownGood
    case unknown
}

/// CIRCL hashlookup - a known-GOOD file database (NSRL + Linux package
/// repos + common OS builds). Opposite polarity from every other check: a
/// match means the file is a recognized legitimate file, not malware.
/// Free, no API key, always runs.
public enum CIRCLClient {
    public static func check(sha256: String) async -> CIRCLResult {
        var request = URLRequest(url: URL(string: "https://hashlookup.circl.lu/lookup/sha256/\(sha256)")!)
        request.timeoutInterval = 15
        guard let (_, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200 else {
            return .unknown
        }
        return .knownGood
    }
}
