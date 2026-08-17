import Foundation
import UnwarezCore

/// Exercises the deep-inspection mechanism (extraction/mounting,
/// traversal, size/count caps, cleanup) against real container fixtures
/// with a planted file, using an injected `MockInnerHashChecker` instead
/// of real threat-intel data (a real malware hash can't be
/// reverse-engineered into fixture content - see `InnerHashChecking`).
/// This is what actually answers "does deep inspection work," since the
/// hash-matching logic itself is already covered by `ThreatIntelTests`/
/// `ReleaseSealTests`.
enum DeepInspectionTests {
    static func run() async {
        await TestKit.shared.suite("Deep inspection (real zip/dmg/pkg fixtures)")
        await testZip()
        await testDMG()
        await testPKG()
        await testUnarArchive()
        await testNestedArchiveRecursion()
    }

    private static func testZip() async {
        let plantedContent = Data("planted malicious content for zip test".utf8)
        let plantedHash = UnwarezCore.Hashing.sha256(of: plantedContent)

        guard let zipURL = try? Fixtures.makeZip(plantedFilename: "malicious.bin", content: plantedContent) else {
            await TestKit.shared.expect(false, "zip fixture: could not build test .zip")
            return
        }
        defer { try? FileManager.default.removeItem(at: zipURL) }

        let checker = MockInnerHashChecker()
        await checker.flag(sha256: plantedHash, label: "test-malware")
        let inspector = DeepInspector(innerHashChecker: checker)

        let result = await inspector.inspect(path: zipURL.path)
        if case .malicious(let detail) = result {
            await TestKit.shared.expect(detail.contains("test-malware"), "zip: planted file inside .zip is detected as malicious (detail: \(detail))")
        } else {
            await TestKit.shared.expect(false, "zip: expected .malicious, got \(result)")
        }

        // Same archive, but nothing planted-hash matches - must come back clean.
        let cleanChecker = MockInnerHashChecker()
        let cleanInspector = DeepInspector(innerHashChecker: cleanChecker)
        let cleanResult = await cleanInspector.inspect(path: zipURL.path)
        await TestKit.shared.expectEqual(cleanResult, .clean, "zip: same archive with no flagged hash comes back clean (no false positive)")
    }

    private static func testDMG() async {
        let plantedContent = Data("planted malicious executable for dmg test".utf8)
        let plantedHash = UnwarezCore.Hashing.sha256(of: plantedContent)

        guard let dmgURL = try? Fixtures.makeDMGWithApp(execContent: plantedContent) else {
            await TestKit.shared.expect(false, "dmg fixture: could not build test .dmg")
            return
        }
        defer { try? FileManager.default.removeItem(at: dmgURL) }

        let checker = MockInnerHashChecker()
        await checker.flag(sha256: plantedHash, label: "test-malware")
        let inspector = DeepInspector(innerHashChecker: checker)

        let result = await inspector.inspect(path: dmgURL.path)
        if case .malicious(let detail) = result {
            await TestKit.shared.expect(detail.contains("test-malware"), "dmg: planted .app main executable is detected as malicious (detail: \(detail))")
        } else {
            await TestKit.shared.expect(false, "dmg: expected .malicious, got \(result)")
        }
    }

    private static func testPKG() async {
        let plantedContent = Data("planted malicious payload for pkg test".utf8)
        let plantedHash = UnwarezCore.Hashing.sha256(of: plantedContent)

        guard let pkgURL = try? Fixtures.makePKG(plantedFilename: "malicious.bin", content: plantedContent) else {
            await TestKit.shared.expect(false, "pkg fixture: could not build test .pkg")
            return
        }
        defer { try? FileManager.default.removeItem(at: pkgURL) }

        let checker = MockInnerHashChecker()
        await checker.flag(sha256: plantedHash, label: "test-malware")
        let inspector = DeepInspector(innerHashChecker: checker)

        // Also confirms the gunzip|cpio pipeline (the exact call site of
        // the earlier command-injection fix) still decompresses correctly.
        let result = await inspector.inspect(path: pkgURL.path)
        if case .malicious(let detail) = result {
            await TestKit.shared.expect(detail.contains("test-malware"), "pkg: planted payload file is detected as malicious (detail: \(detail))")
        } else {
            await TestKit.shared.expect(false, "pkg: expected .malicious, got \(result)")
        }
    }

    private static func testUnarArchive() async {
        guard Fixtures.findUnar() != nil else {
            await TestKit.shared.skip("archive (.tar via unar): unar is not installed (brew install unar) - skipping")
            return
        }

        let plantedContent = Data("planted malicious content for archive test".utf8)
        let plantedHash = UnwarezCore.Hashing.sha256(of: plantedContent)

        guard let tarURL = try? Fixtures.makeUnarArchive(plantedFilename: "malicious.bin", content: plantedContent) else {
            await TestKit.shared.expect(false, "archive fixture: could not build test .tar")
            return
        }
        defer { try? FileManager.default.removeItem(at: tarURL) }

        let checker = MockInnerHashChecker()
        await checker.flag(sha256: plantedHash, label: "test-malware")
        let inspector = DeepInspector(innerHashChecker: checker)

        let result = await inspector.inspect(path: tarURL.path)
        if case .malicious(let detail) = result {
            await TestKit.shared.expect(detail.contains("test-malware"), "archive: planted file inside .tar (via unar) is detected as malicious (detail: \(detail))")
        } else {
            await TestKit.shared.expect(false, "archive: expected .malicious, got \(result)")
        }
    }

    /// A zip containing a zip containing a pkg containing the planted
    /// file - proves inspection actually recurses through nested
    /// containers rather than only hash-checking the outer wrapper of
    /// each nested file (which would never match, since only the
    /// innermost payload's hash is in the threat-intel list).
    private static func testNestedArchiveRecursion() async {
        let plantedContent = Data("planted malicious payload for nested-archive test".utf8)
        let plantedHash = UnwarezCore.Hashing.sha256(of: plantedContent)

        guard let pkgURL = try? Fixtures.makePKG(plantedFilename: "malicious.bin", content: plantedContent) else {
            await TestKit.shared.expect(false, "nested: could not build innermost .pkg fixture")
            return
        }
        defer { try? FileManager.default.removeItem(at: pkgURL) }

        guard let pkgData = try? Data(contentsOf: pkgURL),
              let innerZipURL = try? Fixtures.makeZip(plantedFilename: "payload.pkg", content: pkgData) else {
            await TestKit.shared.expect(false, "nested: could not build middle .zip fixture")
            return
        }
        defer { try? FileManager.default.removeItem(at: innerZipURL) }

        guard let innerZipData = try? Data(contentsOf: innerZipURL),
              let outerZipURL = try? Fixtures.makeZip(plantedFilename: "wrapper.zip", content: innerZipData) else {
            await TestKit.shared.expect(false, "nested: could not build outer .zip fixture")
            return
        }
        defer { try? FileManager.default.removeItem(at: outerZipURL) }

        let checker = MockInnerHashChecker()
        await checker.flag(sha256: plantedHash, label: "test-malware")
        let inspector = DeepInspector(innerHashChecker: checker)

        let result = await inspector.inspect(path: outerZipURL.path)
        if case .malicious(let detail) = result {
            await TestKit.shared.expect(detail.contains("test-malware"), "nested: zip>zip>pkg planted file found through 3 levels of recursion (detail: \(detail))")
        } else {
            await TestKit.shared.expect(false, "nested: expected .malicious from 3-level-deep recursion, got \(result)")
        }

        // Same nesting shape, nothing planted-hash matches - must come
        // back clean rather than false-flagging on the recursion itself.
        let cleanChecker = MockInnerHashChecker()
        let cleanInspector = DeepInspector(innerHashChecker: cleanChecker)
        let cleanResult = await cleanInspector.inspect(path: outerZipURL.path)
        await TestKit.shared.expectEqual(cleanResult, .clean, "nested: same 3-level nesting with no flagged hash comes back clean (no false positive)")
    }
}
