// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Unwarez",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "UnwarezCore", targets: ["UnwarezCore"]),
        .executable(name: "unwarez-cli", targets: ["UnwarezCLI"]),
        .executable(name: "ObscuraLuxUnwarezGUI", targets: ["UnwarezGUI"]),
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
    ]
)
