import Foundation

/// A dependency-free test runner for UnwarezCore.
///
/// Why this exists instead of XCTest or swift-testing: this project is
/// deliberately buildable with Xcode Command Line Tools alone (no full
/// Xcode, no `.xcodeproj`) - `packaging/build_app.sh` has never needed
/// more than that, and end users rebuilding from source shouldn't need
/// it either. Both XCTest and swift-testing's `Testing` module require
/// full Xcode to resolve (`import XCTest`/`import Testing` fail to
/// type-check under Command Line Tools alone, confirmed directly while
/// setting this up) - `swift test` doesn't work here. This target is a
/// plain executable with a tiny assertion helper (`TestKit.swift`), so
/// `swift run unwarez-selftest` works in exactly the same environment
/// `swift build` already does, with no additional toolchain requirement.
///
/// Covers: local threat-intel matching against the real embedded data,
/// hashing correctness against published SHA256/MD5 test vectors, a live
/// network round-trip against the real ReleaseSeal database, quarantine
/// manifest-line encode/decode, and - most importantly - deep inspection
/// (zip/dmg/pkg/archive) exercised against real fixtures built with the
/// same system tools the app uses to read them (zip, hdiutil, pkgbuild,
/// unar), using an injected mock hash-checker since a real malware hash
/// can't be reverse-engineered into fixture content.
///
/// If a machine with full Xcode is available, consider also adding a
/// proper `XCTest`/`swift-testing` target back - this doesn't replace
/// that, it fills the gap in an environment where that's not an option.
@main
struct UnwarezSelfTestEntry {
    static func main() async {
        await ThreatIntelTests.run()
        await HashingTests.run()
        await QuarantineTests.run()
        await DeepInspectionTests.run()
        await ReleaseSealTests.run() // last: needs network, slowest suite

        let allPassed = await TestKit.shared.summary()
        exit(allPassed ? 0 : 1)
    }
}
