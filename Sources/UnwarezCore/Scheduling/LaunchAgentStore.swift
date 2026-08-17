import Foundation

public enum ScheduleFrequency: Sendable, Equatable {
    case daily
    case weekly
}

public struct ScheduledScanInfo: Sendable, Equatable {
    public let frequency: ScheduleFrequency
    public let target: ScanTarget
}

public struct ScheduleError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public var description: String { message }
}

/// Replaces the bash backend's crontab-based scheduling with a real
/// LaunchAgent - the actual Mac-native mechanism, and one that survives
/// reboots cleanly without shelling out to `crontab` to parse/rewrite the
/// user's whole crontab. A fixed reverse-DNS `Label` identifies "our"
/// entry instead of the old scheme (a crontab line matching the running
/// script's absolute path as a substring).
public actor LaunchAgentStore {
    public static let label = "com.obscuralux.unwarez.scheduledscan"

    public static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    public init() {}

    public func currentSchedule() -> ScheduledScanInfo? {
        guard let data = try? Data(contentsOf: Self.plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let args = plist["ProgramArguments"] as? [String] else { return nil }

        var targetValue: Int?
        for arg in args where arg.hasPrefix("--target=") {
            targetValue = Int(arg.dropFirst("--target=".count))
        }
        guard let targetValue, let target = ScanTarget(rawValue: targetValue) else { return nil }

        let interval = plist["StartCalendarInterval"] as? [String: Int]
        let frequency: ScheduleFrequency = interval?["Weekday"] != nil ? .weekly : .daily
        return ScheduledScanInfo(frequency: frequency, target: target)
    }

    @discardableResult
    public func schedule(frequency: ScheduleFrequency, cliExecutablePath: String) async -> Result<Void, ScheduleError> {
        await removeExisting()
        await Self.migrateLegacyCronEntries()

        // Matches the bash backend's fixed choices: daily @ 9am scans
        // Downloads, weekly @ Sunday 9am scans Home.
        let target: ScanTarget = frequency == .daily ? .downloads : .home
        var calendarInterval: [String: Int] = ["Hour": 9, "Minute": 0]
        if frequency == .weekly { calendarInterval["Weekday"] = 0 }

        let plist: [String: Any] = [
            "Label": Self.label,
            "ProgramArguments": [cliExecutablePath, "--auto", "--target=\(target.rawValue)"],
            "StartCalendarInterval": calendarInterval,
            "RunAtLoad": false,
        ]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) else {
            return .failure(ScheduleError(message: "Could not encode the LaunchAgent plist."))
        }

        do {
            try FileManager.default.createDirectory(at: Self.plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: Self.plistURL)
        } catch {
            return .failure(ScheduleError(message: "Could not write the LaunchAgent plist: \(error.localizedDescription)"))
        }

        let runResult = try? await ProcessRunner.run("/bin/launchctl", arguments: ["load", "-w", Self.plistURL.path], timeout: 10)
        guard let runResult, runResult.exitCode == 0 else {
            let detail = runResult?.standardErrorString.trimmingCharacters(in: .whitespacesAndNewlines)
            return .failure(ScheduleError(message: "Could not activate the scheduled scan" + (detail?.isEmpty == false ? ": \(detail!)" : ".")))
        }
        return .success(())
    }

    @discardableResult
    public func removeExisting() async -> Bool {
        guard FileManager.default.fileExists(atPath: Self.plistURL.path) else { return true }
        _ = try? await ProcessRunner.run("/bin/launchctl", arguments: ["unload", Self.plistURL.path], timeout: 10)
        return (try? FileManager.default.removeItem(at: Self.plistURL)) != nil
    }

    /// One-time compatibility nicety: pre-rewrite installs may still have
    /// a crontab entry pointing at the old bash script. Strips any line
    /// containing the old script names so the two scheduling mechanisms
    /// don't both fire.
    public static func migrateLegacyCronEntries() async {
        guard let listResult = try? await ProcessRunner.run("/usr/bin/crontab", arguments: ["-l"], timeout: 10),
              listResult.exitCode == 0 else { return }
        let lines = listResult.standardOutputString.split(separator: "\n", omittingEmptySubsequences: false)
        let filtered = lines.filter { !$0.contains("ObscuraLuxUnwarez.sh") && !$0.contains("Unwarez v1.1.sh") }
        guard filtered.count != lines.count else { return }
        let newContent = filtered.joined(separator: "\n")
        _ = try? await ProcessRunner.run("/usr/bin/crontab", arguments: ["-"], timeout: 10, standardInput: Data(newContent.utf8))
    }
}
