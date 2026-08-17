import Foundation
import UnwarezCore

/// Drives `ScanPipeline` and prints its event stream to the terminal.
/// Shared between `--auto` (cron/launchd) mode and the interactive menu.
enum ScanRunner {
    @discardableResult
    static func run(options: ScanOptions, verbose: Bool) async -> ScanSummary? {
        let pipeline = ScanPipeline()
        let stream = await pipeline.run(options: options)
        var summary: ScanSummary?
        var count = 0
        var total = 0

        for await event in stream {
            switch event {
            case .status(let message):
                if verbose { print("\(Terminal.blue)[*] \(message)\(Terminal.reset)") }
            case .total(let value):
                total = value
                if verbose { print("\(Terminal.blue)[*] \(total) file(s) to scan\(Terminal.reset)") }
            case .file(let result):
                count += 1
                if verbose { printResult(result, count: count, total: total) }
            case .done(let value):
                summary = value
            }
        }
        return summary
    }

    private static func printResult(_ result: ScanResult, count: Int, total: Int) {
        let prefix = "[\(count)/\(total)] \(result.name)"
        switch result.status {
        case .malicious:
            print("\(Terminal.red)[!] MALICIOUS: \(prefix) - \(result.detail)\(Terminal.reset)")
        case .pup:
            print("\(Terminal.orange)[!] PUP: \(prefix) - \(result.detail)\(Terminal.reset)")
        case .verified:
            print("\(Terminal.green)[v] VERIFIED: \(prefix)\(Terminal.reset)")
        case .unverified:
            print("\(Terminal.yellow)[?] UNVERIFIED: \(prefix) - \(result.detail)\(Terminal.reset)")
        }
    }

    static func printSummary(_ summary: ScanSummary) {
        print("")
        print(String(repeating: "=", count: 40))
        print("        SCAN COMPLETE")
        print(String(repeating: "=", count: 40))
        print("  Files Scanned:   \(summary.scanned)")
        print("  Threats Found:   \(summary.detected)")
        print("  Unverified:      \(summary.unverified) (no ReleaseSeal/VirusTotal match either way)")
        print("  Auto-Quarantine: \(summary.quarantined) files moved")
        if summary.detected == 0 {
            print("  Status:          \(Terminal.green)CLEAN\(Terminal.reset)")
        } else {
            print("  Status:          \(Terminal.red)THREATS DETECTED\(Terminal.reset)")
        }
        print(String(repeating: "=", count: 40))
        print("\(Terminal.yellow)Note: this checks known-hash databases only. \"Clean\" means")
        print("\"not found in these sources\" - not a guarantee this system")
        print("is free of malware. Not a substitute for macOS's built-in")
        print("protections or a dedicated antivirus product.\(Terminal.reset)")
        print("")
        print("Report saved to: \(UnwarezPaths.reportsDir.path)")
        print("Hash log: \(UnwarezPaths.hashLogPath.path)")
        print("Quarantine folder: \(UnwarezPaths.filesDir.path)")
    }
}
