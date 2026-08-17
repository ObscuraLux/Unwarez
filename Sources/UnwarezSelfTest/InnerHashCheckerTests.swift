import Foundation
import UnwarezCore

/// Directly exercises the production `InnerHashChecker` (not a mock) -
/// this is the regression test for the real bug fixed upstream: inner
/// (archive-content) files never had their MD5 computed/checked, so the
/// MD5-keyed embedded list and badfiles.txt could never match anything
/// found inside a zip/dmg/pkg/archive, only the outer container's own
/// hash. `DeepInspectionTests` proves the mechanism finds and hashes
/// inner files at all; this proves the checker itself actually consults
/// MD5 once handed one.
enum InnerHashCheckerTests {
    static func run() async {
        await TestKit.shared.suite("InnerHashChecker (MD5 threading regression test)")

        let checker = InnerHashChecker(
            releaseSeal: ReleaseSealClient(),
            badFiles: BadFilesClient(),
            virusTotal: VirusTotalClient(),
            vtKey: nil,
            mbKey: nil
        )

        // A real embedded-list MD5 entry (same one ThreatIntelTests uses
        // directly) - deliberately paired with a SHA256 that does NOT
        // match anything, so this only passes if MD5 is actually consulted.
        let result = await checker.check(
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            md5: "0041b628e66c59e25f2dac8a95405931",
            path: "/tmp/irrelevant-path-for-this-test"
        )
        if case .malicious(let label) = result {
            await TestKit.shared.expect(label == "OGF-infected release: zBrush 2024.0.2.dmg", "inner-file MD5 match found the correct label (got: \(label))")
        } else {
            await TestKit.shared.expect(false, "inner-file check with a known-bad MD5 (and unrelated SHA256) should return .malicious, got \(result)")
        }

        // Neither hash matches anything - must come back clean.
        let cleanResult = await checker.check(
            sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            md5: "22222222222222222222222222222222",
            path: "/tmp/irrelevant-path-for-this-test"
        )
        await TestKit.shared.expectEqual(cleanResult, .clean, "unrelated SHA256+MD5 pair comes back clean")
    }
}
