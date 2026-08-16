import Foundation
import Combine

/// Manages crontab entries for scheduled scans, matching the exact
/// command format the CLI/app version already uses (--auto --target=N),
/// so scheduled runs behave identically regardless of which version
/// set them up.
final class CronStore: ObservableObject {
    @Published var currentEntries: [String] = []
    @Published var message: String?

    private var scriptPath: String? {
        Bundle.main.path(forResource: "WolfCare", ofType: nil)
    }

    func refresh() {
        guard let scriptPath = scriptPath else { return }
        let output = runCrontab(args: ["-l"]) ?? ""
        currentEntries = output
            .split(separator: "\n")
            .map(String.init)
            .filter { $0.contains(scriptPath) }
    }

    func addDaily() {
        guard let scriptPath = scriptPath else {
            message = "Could not find the bundled scanner script."
            return
        }
        let line = "0 9 * * * \"\(scriptPath)\" --auto --target=1"
        writeCrontab(replacingLinesContaining: scriptPath, adding: line)
        message = "Daily scan scheduled for 9:00 AM"
    }

    func addWeekly() {
        guard let scriptPath = scriptPath else {
            message = "Could not find the bundled scanner script."
            return
        }
        let line = "0 9 * * 0 \"\(scriptPath)\" --auto --target=3"
        writeCrontab(replacingLinesContaining: scriptPath, adding: line)
        message = "Weekly scan scheduled for Sundays, 9:00 AM"
    }

    func removeAll() {
        guard let scriptPath = scriptPath else { return }
        writeCrontab(replacingLinesContaining: scriptPath, adding: nil)
        message = "Scheduled scans removed"
    }

    private func writeCrontab(replacingLinesContaining marker: String, adding newLine: String?) {
        let existing = runCrontab(args: ["-l"]) ?? ""
        var lines = existing
            .split(separator: "\n")
            .map(String.init)
            .filter { !$0.contains(marker) }
        if let newLine {
            lines.append(newLine)
        }
        let newContent = lines.joined(separator: "\n") + "\n"

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/crontab")
        task.arguments = ["-"]
        let inPipe = Pipe()
        task.standardInput = inPipe
        do {
            try task.run()
            inPipe.fileHandleForWriting.write(newContent.data(using: .utf8) ?? Data())
            inPipe.fileHandleForWriting.closeFile()
            task.waitUntilExit()
        } catch {
            message = "Could not update crontab: \(error.localizedDescription)"
        }
        refresh()
    }

    private func runCrontab(args: [String]) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/crontab")
        task.arguments = args
        let outPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = Pipe()
        do {
            try task.run()
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}
