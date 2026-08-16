import Foundation
import Combine

struct LogEntry: Identifiable {
    let id = UUID()
    let filename: String
    let path: String
    let date: Date
}

/// Reads the same per-scan report files the bash backend writes to
/// `$QUARANTINE/reports/` (one timestamped .txt per scan, listing every
/// file checked - not just detections) - so scans run from the CLI show
/// up here too, not just ones run from the GUI.
final class LogsStore: ObservableObject {
    @Published var entries: [LogEntry] = []

    var reportsDirPath: String {
        NSHomeDirectory() + "/.local/share/wolfcare_quarantine/reports"
    }

    init() {
        load()
    }

    func load() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: reportsDirPath) else {
            entries = []
            return
        }
        entries = files
            .filter { $0.hasSuffix(".txt") }
            .map { name -> LogEntry in
                let path = reportsDirPath + "/" + name
                let attrs = try? fm.attributesOfItem(atPath: path)
                let date = (attrs?[.modificationDate] as? Date) ?? Date.distantPast
                return LogEntry(filename: name, path: path, date: date)
            }
            .sorted { $0.date > $1.date }
    }

    func content(for entry: LogEntry) -> String {
        (try? String(contentsOfFile: entry.path, encoding: .utf8)) ?? "Could not read this report - it may have been moved or deleted."
    }

    func delete(_ entry: LogEntry) {
        try? FileManager.default.removeItem(atPath: entry.path)
        load()
    }
}
