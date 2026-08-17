import Foundation
import UnwarezCore

/// CSV/PDF export of a completed scan's results - interactive-CLI-only,
/// matching the bash backend's `export_report` (which was likewise never
/// offered from `--gui`/`--auto` mode, only the interactive menu).
enum ReportExport {
    static func promptAndExport(reportPath: String) {
        print("")
        print("Export results:")
        print("  [1] CSV")
        print("  [2] PDF")
        print("  [3] Both")
        print("  [4] Skip")
        switch Terminal.prompt("Selection: ") {
        case "1": exportCSV(reportPath: reportPath)
        case "2": exportPDF(reportPath: reportPath)
        case "3": exportCSV(reportPath: reportPath); exportPDF(reportPath: reportPath)
        default: break
        }
    }

    private static func csvPath(forReportPath reportPath: String) -> String {
        (reportPath as NSString).deletingPathExtension + ".csv"
    }

    private static func pdfPath(forReportPath reportPath: String) -> String {
        (reportPath as NSString).deletingPathExtension + ".pdf"
    }

    /// `hashes.txt` is pipe-delimited with a header row
    /// (`SHA256|MD5|FILENAME|SIZE|STATUS`) - reformats every row after
    /// that into quoted CSV fields.
    private static func exportCSV(reportPath: String) {
        guard let content = try? String(contentsOf: UnwarezPaths.hashLogPath, encoding: .utf8) else {
            print("\(Terminal.yellow)[!] Could not read \(UnwarezPaths.hashLogPath.path)\(Terminal.reset)")
            return
        }
        var lines = content.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        if !lines.isEmpty { lines.removeFirst() } // drop the pipe-delimited header; CSV gets its own below

        var csv = "SHA256,MD5,Filename,SizeBytes,Status\n"
        for line in lines {
            let fields = line.components(separatedBy: "|")
            guard fields.count >= 5 else { continue }
            csv += fields.prefix(5).map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: ",") + "\n"
        }

        let outPath = csvPath(forReportPath: reportPath)
        do {
            try csv.write(toFile: outPath, atomically: true, encoding: .utf8)
            print("\(Terminal.green)[v] CSV saved to \(outPath)\(Terminal.reset)")
        } catch {
            print("\(Terminal.yellow)[!] Could not write CSV: \(error.localizedDescription)\(Terminal.reset)")
        }
    }

    private static func exportPDF(reportPath: String) {
        guard let text = try? String(contentsOfFile: reportPath, encoding: .utf8) else {
            print("\(Terminal.yellow)[!] Could not read \(reportPath)\(Terminal.reset)")
            return
        }
        let outPath = pdfPath(forReportPath: reportPath)
        if PDFExport.render(text: text, to: URL(fileURLWithPath: outPath)) {
            print("\(Terminal.green)[v] PDF saved to \(outPath)\(Terminal.reset)")
        } else {
            print("\(Terminal.yellow)[!] PDF conversion failed\(Terminal.reset)")
        }
    }
}
