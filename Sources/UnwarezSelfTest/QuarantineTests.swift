import Foundation
import UnwarezCore

/// Pure round-trip test (no file I/O against the real quarantine
/// directory - that's live user data, not something a test should touch).
enum QuarantineTests {
    static func run() async {
        await TestKit.shared.suite("QuarantineEntry (manifest line encode/decode)")

        let entry = QuarantineEntry(
            timestamp: "20260817_213009",
            originalPath: "/Users/test/Downloads/evil.dmg",
            quarantinedName: "abc123456789_evil.dmg",
            sha256: "abc123456789def",
            reason: "MALICIOUS"
        )
        let line = entry.manifestLine
        await TestKit.shared.expectEqual(
            line, "20260817_213009|/Users/test/Downloads/evil.dmg|abc123456789_evil.dmg|abc123456789def|MALICIOUS",
            "manifestLine produces the expected pipe-delimited format"
        )

        guard let decoded = QuarantineEntry(manifestLine: line) else {
            await TestKit.shared.expect(false, "round-trip: decoding the encoded line failed")
            return
        }
        await TestKit.shared.expectEqual(decoded.timestamp, entry.timestamp, "round-trip preserves timestamp")
        await TestKit.shared.expectEqual(decoded.originalPath, entry.originalPath, "round-trip preserves originalPath")
        await TestKit.shared.expectEqual(decoded.quarantinedName, entry.quarantinedName, "round-trip preserves quarantinedName")
        await TestKit.shared.expectEqual(decoded.sha256, entry.sha256, "round-trip preserves sha256")
        await TestKit.shared.expectEqual(decoded.reason, entry.reason, "round-trip preserves reason")

        await TestKit.shared.expect(QuarantineEntry(manifestLine: "too|few|fields") == nil, "malformed line (too few fields) fails to decode rather than crashing")
    }
}
