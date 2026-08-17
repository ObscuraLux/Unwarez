import Foundation
import UnwarezCore

enum InteractiveMenu {
    static func run() async {
        showDisclaimer()
        while true {
            Terminal.banner()
            print("")
            print("  [1] Run Scan")
            print("  [2] Quarantined Files")
            print("  [3] Manage Scheduled Scans")
            print("  [4] Settings")
            print("  [5] Exit")
            print("")
            switch Terminal.prompt("Selection: ") {
            case "1": await runScanMenu()
            case "2": await quarantineMenu()
            case "3": await scheduleMenu()
            case "4": await settingsMenu()
            case "5": return
            default:
                print("\(Terminal.yellow)Invalid selection\(Terminal.reset)")
                Terminal.pause()
            }
        }
    }

    private static func showDisclaimer() {
        Terminal.banner()
        print("")
        print("\(Terminal.yellow)IMPORTANT - PLEASE READ\(Terminal.reset)")
        print("This tool is NOT a complete security solution.")
        print("")
        print("It fills one specific gap: checking files against a handful")
        print("of hash-reputation databases (ReleaseSeal, VirusTotal,")
        print("MalwareBazaar, CIRCL) and a small list of indicators tied to")
        print("two documented campaigns. It does NOT replace macOS's own")
        print("built-in protections, a real-time antivirus product, or")
        print("common sense about what you download and run.")
        print("")
        Terminal.pause()
    }

    // MARK: - Scan

    private static func runScanMenu() async {
        Terminal.banner()
        print("")
        print("Choose scan target:")
        print("  [1] Downloads folder only")
        print("  [2] Desktop folder only")
        print("  [3] Entire home directory (~)")
        print("  [4] Custom directory")
        print("  [5] Custom file")
        print("  [6] Full system scan (excludes system folders)")
        print("  [7] Back to main menu")
        print("")
        let choice = Terminal.prompt("Selection: ")

        var target: ScanTarget?
        var customPath: String?

        switch choice {
        case "1": target = .downloads
        case "2": target = .desktop
        case "3": target = .home
        case "4":
            customPath = Terminal.prompt("Enter directory path: ")
            target = .customDirectory
        case "5":
            customPath = Terminal.prompt("Enter file path: ")
            target = .customFile
        case "6":
            print("")
            print("\(Terminal.yellow)Full system scan will walk the entire drive and can take a long time.\(Terminal.reset)")
            guard Terminal.prompt("Type YES to confirm: ") == "YES" else {
                print("Cancelled.")
                Terminal.pause()
                return
            }
            target = .fullSystem
        case "7":
            return
        default:
            print("\(Terminal.yellow)Invalid selection\(Terminal.reset)")
            Terminal.pause()
            return
        }

        guard let target else { return }

        if ConfigStore.virusTotalKey() == nil, ConfigStore.malwareBazaarKey() == nil {
            print("")
            print("\(Terminal.yellow)No VirusTotal or MalwareBazaar API key is configured.\(Terminal.reset)")
            print("Scans still check ReleaseSeal, CIRCL, the built-in threat-intel list, and ClamAV,")
            print("but skip these two extra sources without a key.")
            if Terminal.prompt("Add a key now instead of scanning? [y/N]: ").lowercased().hasPrefix("y") {
                await settingsMenu()
                return
            }
        }

        print("")
        print("\(Terminal.blue)[*] Initializing scan...\(Terminal.reset)")
        let options = ScanOptions(target: target, customPath: customPath, isAutoMode: false)
        if let summary = await ScanRunner.run(options: options, verbose: true) {
            ScanRunner.printSummary(summary)
            ReportExport.promptAndExport(reportPath: summary.reportPath)
        }
        Terminal.pause()
    }

    // MARK: - Quarantine

    private static func quarantineMenu() async {
        while true {
            Terminal.banner()
            print("Quarantined Files")
            print(String(repeating: "=", count: 40))

            let entries = UnwarezCore.QuarantineStore.loadEntries()
            if entries.isEmpty {
                print("  (no quarantined files on record)")
                print("")
                Terminal.pause("Press ENTER to go back...")
                return
            }

            for (index, entry) in entries.enumerated() {
                let exists = FileManager.default.fileExists(atPath: UnwarezCore.QuarantineStore.quarantinedFileURL(for: entry).path)
                let status = exists ? "present" : "MISSING FROM DISK"
                print(String(format: "  [%d] %-10s %-40s (%@, %@)", index + 1, entry.reason, entry.originalPath, entry.timestamp, status))
            }

            print("")
            print("  [R] Restore an item by number")
            print("  [D] Permanently delete an item by number")
            print("  [B] Back to main menu")
            print("")

            switch Terminal.prompt("Selection: ").uppercased() {
            case "R":
                guard let entry = pickEntry(entries) else { continue }
                print("Original location: \(entry.originalPath)")
                if Terminal.prompt("Restore to this path? [y/N]: ").lowercased().hasPrefix("y") {
                    switch UnwarezCore.QuarantineStore.restore(entry) {
                    case .success:
                        print("\(Terminal.green)[v] Restored to \(entry.originalPath)\(Terminal.reset)")
                    case .failure(let error):
                        print("\(Terminal.red)[!] \(error.description)\(Terminal.reset)")
                    }
                } else {
                    print("Cancelled.")
                }
                Terminal.pause()
            case "D":
                guard let entry = pickEntry(entries) else { continue }
                if Terminal.prompt("Permanently delete quarantined copy of '\(entry.originalPath)'? [y/N]: ").lowercased().hasPrefix("y") {
                    UnwarezCore.QuarantineStore.delete(entry)
                    print("\(Terminal.green)[v] Deleted\(Terminal.reset)")
                } else {
                    print("Cancelled.")
                }
                Terminal.pause()
            case "B":
                return
            default:
                print("\(Terminal.yellow)Invalid selection\(Terminal.reset)")
                Terminal.pause()
            }
        }
    }

    private static func pickEntry(_ entries: [QuarantineEntry]) -> QuarantineEntry? {
        guard let num = Int(Terminal.prompt("Enter item number: ")), num >= 1, num <= entries.count else {
            print("\(Terminal.yellow)Invalid item number\(Terminal.reset)")
            Terminal.pause()
            return nil
        }
        return entries[num - 1]
    }

    // MARK: - Scheduled scans

    private static func scheduleMenu() async {
        let store = LaunchAgentStore()
        while true {
            Terminal.banner()
            print("Manage Scheduled Scans")
            print(String(repeating: "=", count: 40))
            if let schedule = await store.currentSchedule() {
                let frequency = schedule.frequency == .daily ? "Daily, 9:00 AM" : "Weekly, Sundays 9:00 AM"
                print("  Current: \(frequency) — \(schedule.target.label)")
            } else {
                print("  No scheduled scans set up.")
            }
            print("")
            print("  [1] Add daily scan (Downloads, 9am)")
            print("  [2] Add weekly scan (Home, Sunday 9am)")
            print("  [3] Remove all scheduled scans")
            print("  [4] Back to main menu")
            print("")

            switch Terminal.prompt("Selection: ") {
            case "1":
                await scheduleAction { await store.schedule(frequency: .daily, cliExecutablePath: CommandLine.arguments[0]) }
            case "2":
                await scheduleAction { await store.schedule(frequency: .weekly, cliExecutablePath: CommandLine.arguments[0]) }
            case "3":
                let removed = await store.removeExisting()
                print(removed ? "\(Terminal.green)[v] Scheduled scans removed\(Terminal.reset)" : "\(Terminal.red)[!] Could not remove the scheduled scan\(Terminal.reset)")
                Terminal.pause()
            case "4":
                return
            default:
                print("\(Terminal.yellow)Invalid selection\(Terminal.reset)")
                Terminal.pause()
            }
        }
    }

    private static func scheduleAction(_ action: () async -> Result<Void, ScheduleError>) async {
        switch await action() {
        case .success:
            print("\(Terminal.green)[v] Scheduled\(Terminal.reset)")
        case .failure(let error):
            print("\(Terminal.red)[!] \(error.description)\(Terminal.reset)")
        }
        Terminal.pause()
    }

    // MARK: - Settings

    private static func settingsMenu() async {
        while true {
            Terminal.banner()
            print("Settings")
            print(String(repeating: "=", count: 40))
            let config = ConfigStore.load()
            print("  VirusTotal API key:    \(keyStatusDescription(ConfigStore.virusTotalKeyStatus()))")
            print("  MalwareBazaar API key: \(keyStatusDescription(ConfigStore.malwareBazaarKeyStatus()))")
            print("  Alert email:           \(config.alertEmail.isEmpty ? "(not set)" : config.alertEmail)")
            print("  ClamAV:                \(ClamAVScanner.findBinary() != nil ? "installed" : "not installed (brew install clamav)")")
            print("")
            print("  [1] Set VirusTotal API key")
            print("  [2] Clear VirusTotal API key")
            print("  [3] Set MalwareBazaar API key")
            print("  [4] Clear MalwareBazaar API key")
            print("  [5] Set alert email")
            print("  [6] Clear alert email")
            print("  [7] Back to main menu")
            print("")

            switch Terminal.prompt("Selection: ") {
            case "1":
                let value = Terminal.prompt("Enter VirusTotal API key: ")
                report(ConfigStore.setVirusTotalKey(value))
            case "2":
                report(ConfigStore.setVirusTotalKey(""))
            case "3":
                let value = Terminal.prompt("Enter MalwareBazaar API key: ")
                report(ConfigStore.setMalwareBazaarKey(value))
            case "4":
                report(ConfigStore.setMalwareBazaarKey(""))
            case "5":
                let email = Terminal.prompt("Enter alert email: ")
                try? ConfigStore.save(AppConfig(theme: config.theme, alertEmail: email))
                print("\(Terminal.green)[v] Saved\(Terminal.reset)")
                Terminal.pause()
            case "6":
                try? ConfigStore.save(AppConfig(theme: config.theme, alertEmail: ""))
                print("\(Terminal.green)[v] Cleared\(Terminal.reset)")
                Terminal.pause()
            case "7":
                return
            default:
                print("\(Terminal.yellow)Invalid selection\(Terminal.reset)")
                Terminal.pause()
            }
        }
    }

    /// Distinguishes "never set" from "saved, but this build can't read it
    /// back" (most likely an ad-hoc signature mismatch after a rebuild -
    /// ad-hoc signatures aren't stable across builds the way a real
    /// Developer ID is, so macOS can refuse silent access to an item
    /// created under a previous build's signature) - these need different
    /// fixes, so collapsing both to "(not set)" would be misleading.
    private static func keyStatusDescription(_ status: KeychainReadResult) -> String {
        switch status {
        case .found(let value): return "set (\(value.count) chars)"
        case .notFound: return "(not set)"
        case .accessDenied: return "\(Terminal.red)saved, but can't be read back (Keychain access denied - re-enter it)\(Terminal.reset)"
        }
    }

    private static func report(_ result: Result<Void, KeychainError>) {
        switch result {
        case .success:
            print("\(Terminal.green)[v] Saved\(Terminal.reset)")
        case .failure(let error):
            print("\(Terminal.red)[!] Could not save to Keychain: \(error.description)\(Terminal.reset)")
        }
        Terminal.pause()
    }
}
