import Foundation
import UnwarezCore

enum ReleaseSealTests {
    static func run() async {
        await TestKit.shared.suite("ReleaseSealClient (live network + bundled seed fallback)")

        let client = ReleaseSealClient()
        await client.ensureLoaded()

        let verified = await client.checkHash(sha256: "aa7d1ce13666885acd3747b7219e7093624b43ecba27ef0c32421bc4f6a1e30b")
        await TestKit.shared.expectEqual(verified, .verified, "a known verifiedArtifacts hash resolves to .verified")

        let compromised = await client.checkHash(sha256: "irrelevant", md5: "0041b628e66c59e25f2dac8a95405931")
        await TestKit.shared.expectEqual(compromised, .compromised, "a known compromised MD5 resolves to .compromised")

        let unknown = await client.checkHash(sha256: "0000000000000000000000000000000000000000000000000000000000000000")
        await TestKit.shared.expectEqual(unknown, .unknown, "an unrelated hash resolves to .unknown")
    }
}
