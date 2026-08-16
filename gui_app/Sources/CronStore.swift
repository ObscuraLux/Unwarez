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
        if writeCrontab(replacingLinesContaining: scriptPath, adding: line) {
            message = "Daily scan scheduled for 9:00 AM"
        }
    }

    func addWeekly() {
        guard let scriptPath = scriptPath else {
            message = "Could not find the bundled scanner script."
            return
        }
        let line = "0 9 * * 0 \"\(scriptPath)\" --auto --target=3"
        if writeCrontab(replacingLinesContaining: scriptPath, adding: line) {
            message = "Weekly scan scheduled for Sundays, 9:00 AM"
        }
    }

    func removeAll() {
        guard let scriptPath = scriptPath else { return }
        if writeCrontab(replacingLinesContaining: scriptPath, adding: nil) {
            message = "Scheduled scans removed"
        }
    }

    /// Returns whether the write actually succeeded. `crontab -` rejects
    /// malformed input (verified: it leaves the existing crontab
    /// untouched and exits non-zero rather than installing anything) -
    /// without checking that, a failed write here would still show the
    /// "scheduled" success message despite nothing having changed.
    @discardableResult
    private func writeCrontab(replacingLinesContaining marker: String, adding newLine: String?) -> Bool {
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
        let errPipe = Pipe()
        task.standardInput = inPipe
        task.standardError = errPipe
        var succeeded = false
        do {
            try task.run()
            inPipe.fileHandleForWriting.write(newContent.data(using: .utf8) ?? Data())
            inPipe.fileHandleForWriting.closeFile()
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            if task.terminationStatus == 0 {
                succeeded = true
            } else {
                let errText = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                message = "Could not update crontab" + (errText?.isEmpty == false ? ": \(errText!)" : ".")
            }
        } catch {
            message = "Could not update crontab: \(error.localizedDescription)"
        }
        refresh()
        return succeeded
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
