import Foundation

/// Minimal, dependency-free assertion/reporting helper - see Entry.swift
/// for why this exists instead of XCTest/swift-testing.
actor TestKit {
    static let shared = TestKit()

    private var passed = 0
    private var failed = 0
    private var skipped = 0
    private var currentSuite = ""

    func suite(_ name: String) {
        currentSuite = name
        print("\n\(Terminal.bold)\(name)\(Terminal.reset)")
    }

    func expect(_ condition: Bool, _ message: String, file: String = #file, line: Int = #line) {
        if condition {
            passed += 1
            print("  \(Terminal.green)ok\(Terminal.reset)  \(message)")
        } else {
            failed += 1
            print("  \(Terminal.red)FAIL\(Terminal.reset) \(message)  (\((file as NSString).lastPathComponent):\(line))")
        }
    }

    func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String, file: String = #file, line: Int = #line) {
        expect(actual == expected, "\(message) (got \(actual), expected \(expected))", file: file, line: line)
    }

    func skip(_ message: String) {
        skipped += 1
        print("  \(Terminal.yellow)skip\(Terminal.reset) \(message)")
    }

    func summary() -> Bool {
        print("\n\(String(repeating: "=", count: 40))")
        print("\(passed) passed, \(failed) failed, \(skipped) skipped")
        print(String(repeating: "=", count: 40))
        return failed == 0
    }
}

enum Terminal {
    static let red = "\u{001B}[0;31m"
    static let green = "\u{001B}[0;32m"
    static let yellow = "\u{001B}[0;33m"
    static let bold = "\u{001B}[1m"
    static let reset = "\u{001B}[0m"
}
