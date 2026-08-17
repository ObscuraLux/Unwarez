import Foundation
import UnwarezCore

enum ThreatIntelTests {
    static func run() async {
        await TestKit.shared.suite("ThreatIntel (embedded local database)")

        // Mechanically extracted from the original bash arrays during the
        // port - these two entries were spot-checked against the source
        // script at extraction time.
        let sha = ThreatIntel.checkKnownBad(sha256: "4ccb76cedc3508e40f041694efcb7996067ef6a3ccba2dd917354cc971c23f89")
        await TestKit.shared.expectEqual(sha, "xdivcmp: fake Microsoft_365_and_Office_16.112.26081010.dmg", "known SHA256 matches with the correct label")

        let md5 = ThreatIntel.checkKnownBad(sha256: "irrelevant", md5: "0041b628e66c59e25f2dac8a95405931")
        await TestKit.shared.expectEqual(md5, "OGF-infected release: zBrush 2024.0.2.dmg", "known MD5 matches with the correct label")

        let clean = ThreatIntel.checkKnownBad(sha256: "0000000000000000000000000000000000000000000000000000000000000000")
        await TestKit.shared.expect(clean == nil, "unrelated hash does not match")

        await TestKit.shared.expectEqual(ThreatIntel.database.sha256.count, 54, "embedded SHA256 list has the expected entry count")
        await TestKit.shared.expectEqual(ThreatIntel.database.md5.count, 113, "embedded MD5 list has the expected entry count")
    }
}
