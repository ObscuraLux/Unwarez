import Foundation

enum Terminal {
    static let red = "\u{001B}[0;31m"
    static let green = "\u{001B}[0;32m"
    static let yellow = "\u{001B}[0;33m"
    static let orange = "\u{001B}[38;5;208m"
    static let blue = "\u{001B}[0;34m"
    static let cyan = "\u{001B}[0;36m"
    static let bold = "\u{001B}[1m"
    static let reset = "\u{001B}[0m"

    static func clearScreen() {
        print("\u{001B}[2J\u{001B}[H", terminator: "")
    }

    /// `readLine()` returns `nil` on EOF (stdin closed/redirected from an
    /// exhausted source, e.g. `/dev/null` or a script that ran out of
    /// input) - treating that as an empty string would make every
    /// interactive menu loop spin forever re-prompting into a menu that
    /// can never match "", pegging a CPU core with no way out short of
    /// being killed externally. Exiting is the only sane response: there
    /// is no more input to interact with.
    static func prompt(_ text: String) -> String {
        print(text, terminator: "")
        guard let line = readLine() else {
            print("\n\(yellow)No more input on stdin - exiting.\(reset)")
            exit(1)
        }
        return line.trimmingCharacters(in: .whitespaces)
    }

    static func banner() {
        clearScreen()
        print("\(bold)\(cyan)ObscuraLux Unwarez\(reset)")
        print(String(repeating: "=", count: 40))
    }

    static func pause(_ message: String = "Press ENTER to continue...") {
        _ = prompt(message)
    }
}
