import Foundation
import UnwarezCore

enum HashingTests {
    static func run() async {
        await TestKit.shared.suite("Hashing (known test vectors)")

        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_hash_\(UUID().uuidString)")
        try? "abc".write(to: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Standard published test vectors for SHA256("abc") / MD5("abc").
        await TestKit.shared.expectEqual(
            Hashing.sha256(ofFileAt: tmp), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA256(\"abc\") matches the published test vector"
        )
        await TestKit.shared.expectEqual(
            Hashing.md5(ofFileAt: tmp), "900150983cd24fb0d6963f7d28e17f72",
            "MD5(\"abc\") matches the published test vector"
        )

        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_hash_empty_\(UUID().uuidString)")
        FileManager.default.createFile(atPath: empty.path, contents: Data())
        defer { try? FileManager.default.removeItem(at: empty) }
        await TestKit.shared.expectEqual(
            Hashing.sha256(ofFileAt: empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA256(\"\") matches the published test vector"
        )
    }
}
