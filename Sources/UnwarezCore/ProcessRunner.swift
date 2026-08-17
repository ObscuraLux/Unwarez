import Foundation

/// Replaces the bash backend's `run_timeout` wrapper. That wrapper existed
/// only because `timeout`/`gtimeout` aren't part of stock macOS (a real
/// production bug found the hard way - see DEVELOPER_NOTES.md) and bash
/// itself has no native timeout primitive, forcing a pure-bash
/// background-job-plus-watcher fallback. None of that applies here:
/// `Process` + `Task.sleep` gives a real, always-available timeout with no
/// portability dance. On timeout this kills with SIGKILL immediately
/// (matching the bash fallback's behavior, which - since real `timeout`
/// binaries are absent on stock installs - was the actually-exercised path
/// in practice; unlike GNU `timeout`'s default SIGTERM, immediate SIGKILL
/// is appropriate here since a timeout only fires after a generous budget
/// on tools inspecting untrusted, potentially adversarial input).
public struct ProcessResult: Sendable {
    public let exitCode: Int32
    public let standardOutput: Data
    public let standardError: Data
    public let timedOut: Bool

    public var standardOutputString: String { String(data: standardOutput, encoding: .utf8) ?? "" }
    public var standardErrorString: String { String(data: standardError, encoding: .utf8) ?? "" }
}

/// Lets a caller kill a long-running `ProcessRunner.run` call on demand
/// (e.g. a user-initiated Cancel) instead of only ever timing out. Needed
/// specifically for ClamAV, which can legitimately run for up to 30
/// minutes - every other external tool this app calls already has a
/// short (30-60s) timeout, so worst-case cancel latency there is bounded
/// even without wiring this through.
public actor ProcessCancellationToken {
    private var pid: pid_t?
    private var cancelled = false

    public init() {}

    func register(pid: pid_t) {
        self.pid = pid
        if cancelled { kill(pid, SIGKILL) }
    }

    public func cancel() {
        cancelled = true
        if let pid { kill(pid, SIGKILL) }
    }
}

public enum ProcessRunner {
    @discardableResult
    public static func run(
        _ executable: String,
        arguments: [String],
        timeout: TimeInterval? = nil,
        currentDirectory: URL? = nil,
        standardInput: Data? = nil,
        cancellationToken: ProcessCancellationToken? = nil
    ) async throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let currentDirectory {
            process.currentDirectoryURL = currentDirectory
        }

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        var inPipe: Pipe?
        if standardInput != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inPipe = pipe
        }

        try process.run()
        if let cancellationToken {
            await cancellationToken.register(pid: process.processIdentifier)
        }

        if let standardInput, let inPipe {
            inPipe.fileHandleForWriting.write(standardInput)
            try? inPipe.fileHandleForWriting.close()
        }

        let timedOutBox = TimedOutBox()
        let watchdog: Task<Void, Never>?
        if let timeout {
            let pid = process.processIdentifier
            watchdog = Task.detached(priority: .utility) {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                guard !Task.isCancelled, process.isRunning else { return }
                await timedOutBox.markTimedOut()
                kill(pid, SIGKILL)
            }
        } else {
            watchdog = nil
        }

        // Both pipes must be drained concurrently, not sequentially - if
        // the child writes enough to stderr while we're still blocked
        // reading stdout to EOF (or vice versa), the unread pipe's 64KB
        // kernel buffer fills and the child deadlocks writing to it.
        async let outData = Self.readAll(outPipe.fileHandleForReading)
        async let errData = Self.readAll(errPipe.fileHandleForReading)
        let (stdout, stderrData) = await (outData, errData)

        process.waitUntilExit()
        watchdog?.cancel()

        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: stdout,
            standardError: stderrData,
            timedOut: await timedOutBox.value
        )
    }

    private static func readAll(_ handle: FileHandle) async -> Data {
        await Task.detached(priority: .utility) {
            handle.readDataToEndOfFile()
        }.value
    }

    private actor TimedOutBox {
        private(set) var value = false
        func markTimedOut() { value = true }
    }
}
