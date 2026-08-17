// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Unwarez",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "UnwarezCore", targets: ["UnwarezCore"]),
        .executable(name: "unwarez-cli", targets: ["UnwarezCLI"]),
        .executable(name: "ObscuraLuxUnwarezGUI", targets: ["UnwarezGUI"]),
        .executable(name: "unwarez-selftest", targets: ["UnwarezSelfTest"]),
    ],
    targets: [
        .target(
            name: "UnwarezCore",
            resources: [
                .copy("Resources/ThreatIntel.json"),
                .copy("Resources/ReleaseSealDatabase.json"),
            ]
        ),
        .executableTarget(
            name: "UnwarezCLI",
            dependencies: ["UnwarezCore"]
        ),
        .executableTarget(
            name: "UnwarezGUI",
            dependencies: ["UnwarezCore"]
        ),
        // A dependency-free, no-XCTest test runner: this environment
        // (and, per docs/DEVELOPER_NOTES.md, potentially end users'
        // environments too) has Command Line Tools but not full Xcode,
        // and neither XCTest nor swift-testing's `Testing` module
        // resolves without it. `swift run unwarez-selftest` works
        // anywhere `swift build` does. See its README doc comment in
        // Entry.swift for what it covers.
        .executableTarget(
            name: "UnwarezSelfTest",
            dependencies: ["UnwarezCore"]
        ),
    ]
)
