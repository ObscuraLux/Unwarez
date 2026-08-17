import Foundation

/// Builds real container fixtures (via the same system tools the app
/// itself uses to read them: zip, hdiutil, pkgbuild, unar) with a planted
/// file of known content, so deep-inspection tests exercise real
/// extraction/mounting rather than a hand-rolled stand-in for it.
enum Fixtures {
    struct BuildError: Error { let message: String }

    static func tempDir(_ label: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("unwarez_selftest_\(label)_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @discardableResult
    private static func run(_ executable: String, _ arguments: [String]) throws -> Int32 {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try task.run()
        task.waitUntilExit()
        return task.terminationStatus
    }

    /// A .zip containing one planted file with the given content.
    static func makeZip(plantedFilename: String, content: Data) throws -> URL {
        let workDir = try tempDir("zipsrc")
        defer { try? FileManager.default.removeItem(at: workDir) }
        let innerFile = workDir.appendingPathComponent(plantedFilename)
        try content.write(to: innerFile)

        let zipURL = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_\(UUID().uuidString).zip")
        let status = try run("/usr/bin/zip", ["-q", "-j", zipURL.path, innerFile.path])
        guard status == 0 else { throw BuildError(message: "zip exited \(status)") }
        return zipURL
    }

    /// A .dmg containing a minimal fake .app bundle whose main executable
    /// has the given content - the shape DMGInspector actually looks for
    /// (it hashes an .app's `Contents/MacOS/<CFBundleExecutable>`, not
    /// arbitrary loose files on the volume).
    static func makeDMGWithApp(execContent: Data) throws -> URL {
        let srcDir = try tempDir("dmgsrc")
        defer { try? FileManager.default.removeItem(at: srcDir) }
        let appDir = srcDir.appendingPathComponent("TestApp.app")
        let macOSDir = appDir.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macOSDir, withIntermediateDirectories: true)

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleExecutable</key>
            <string>TestExec</string>
        </dict>
        </plist>
        """
        try plist.write(to: appDir.appendingPathComponent("Contents/Info.plist"), atomically: true, encoding: .utf8)
        try content_write(execContent, to: macOSDir.appendingPathComponent("TestExec"))

        let dmgURL = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_\(UUID().uuidString).dmg")
        let status = try run("/usr/bin/hdiutil", ["create", "-volname", "SelfTestVol", "-srcfolder", srcDir.path, "-ov", "-format", "UDZO", dmgURL.path])
        guard status == 0 else { throw BuildError(message: "hdiutil create exited \(status)") }
        return dmgURL
    }

    /// A .pkg whose payload contains one planted file with the given
    /// content - exercises the exact gunzip|cpio pipeline that was the
    /// site of the command-injection fix earlier in this project.
    static func makePKG(plantedFilename: String, content: Data) throws -> URL {
        let rootDir = try tempDir("pkgroot")
        defer { try? FileManager.default.removeItem(at: rootDir) }
        try content_write(content, to: rootDir.appendingPathComponent(plantedFilename))

        let pkgURL = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_\(UUID().uuidString).pkg")
        let status = try run("/usr/bin/pkgbuild", [
            "--root", rootDir.path,
            "--identifier", "com.obscuralux.unwarez.selftest",
            "--version", "1.0",
            "--install-location", "/tmp/unwarez_selftest_install",
            pkgURL.path,
        ])
        guard status == 0 else { throw BuildError(message: "pkgbuild exited \(status)") }
        return pkgURL
    }

    /// A .tar (handled via `unar`, the same as rar/7z/etc) containing one
    /// planted file. Building the .tar itself only needs the system
    /// `tar`, not `unar` - callers should check `findUnar() != nil`
    /// first and skip the test if it's absent, matching the app's own
    /// graceful "tool not present" degradation.
    static func makeUnarArchive(plantedFilename: String, content: Data) throws -> URL {
        let workDir = try tempDir("tarsrc")
        defer { try? FileManager.default.removeItem(at: workDir) }
        let innerFile = workDir.appendingPathComponent(plantedFilename)
        try content_write(content, to: innerFile)

        let tarURL = FileManager.default.temporaryDirectory.appendingPathComponent("selftest_\(UUID().uuidString).tar")
        let status = try run("/usr/bin/tar", ["-cf", tarURL.path, "-C", workDir.path, plantedFilename])
        guard status == 0 else { throw BuildError(message: "tar exited \(status)") }
        return tarURL
    }

    static func findUnar() -> String? {
        for candidate in ["/opt/homebrew/bin/unar", "/usr/local/bin/unar"] {
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    private static func content_write(_ data: Data, to url: URL) throws {
        try data.write(to: url)
    }
}
