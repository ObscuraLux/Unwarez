import Foundation

private enum ClamAVFileStatus: Equatable, CustomStringConvertible {
    case skipped
    case clean
    case infected(String)
    var isInfected: Bool { if case .infected = self { return true }; return false }
    var description: String {
        switch self {
        case .skipped: return "SKIPPED"
        case .clean: return "CLEAN"
        case .infected(let sig): return "INFECTED:\(sig)"
        }
    }
}

private extension VirusTotalResult {
    var isMaliciousPrefix: Bool { if case .malicious = self { return true }; return false }
    var isPUPPrefix: Bool { if case .pup = self { return true }; return false }
    var isMaliciousOrPUP: Bool { isMaliciousPrefix || isPUPPrefix }
    var isClean: Bool { self == .clean }
}

private extension MalwareBazaarResult {
    var isMalicious: Bool { if case .malicious = self { return true }; return false }
}

private extension DeepInspectionResult {
    var isMalicious: Bool { if case .malicious = self { return true }; return false }
}

public struct ScanOptions: Sendable {
    public var target: ScanTarget
    public var customPath: String?
    public var fileListPath: String?
    public var isAutoMode: Bool

    public init(target: ScanTarget, customPath: String? = nil, fileListPath: String? = nil, isAutoMode: Bool = false) {
        self.target = target
        self.customPath = customPath
        self.fileListPath = fileListPath
        self.isAutoMode = isAutoMode
    }
}

/// The core per-file detection pipeline and orchestration - the direct
/// native replacement for the bash backend's `run_scan`. Runs entirely
/// in-process; progress/results are delivered via an `AsyncStream` of
/// `ScanEvent` instead of a subprocess's parsed stdout protocol.
public actor ScanPipeline {
    private let releaseSeal = ReleaseSealClient()
    private let badFiles = BadFilesClient()
    private let virusTotal = VirusTotalClient()
    private let clamAV = ClamAVScanner()
    private let clamAVCancellationToken = ProcessCancellationToken()

    private var runningTask: Task<Void, Never>?
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func run(options: ScanOptions) -> AsyncStream<ScanEvent> {
        AsyncStream { continuation in
            let task = Task {
                await execute(options: options, continuation: continuation)
                continuation.finish()
            }
            self.runningTask = task
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Cooperative pause: the per-file loop checks this between files
    /// (there's no OS process to SIGSTOP anymore - the whole pipeline
    /// runs in-process). Network/hash work already in flight for the
    /// current file finishes before the pause takes effect.
    public func pause() {
        isPaused = true
    }

    public func resume() {
        isPaused = false
        let waiters = pauseWaiters
        pauseWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
    }

    /// Cancels the scan loop (checked between files, and immediately for
    /// any in-flight `await`) and, since it can otherwise block for up to
    /// 30 minutes, force-kills a ClamAV run in progress.
    public func cancel() async {
        runningTask?.cancel()
        resume() // release anything blocked in waitWhilePaused() so cancellation is observed promptly
        await clamAVCancellationToken.cancel()
    }

    private func waitWhilePaused() async {
        while isPaused {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                pauseWaiters.append(continuation)
            }
        }
    }

    private func execute(options: ScanOptions, continuation: AsyncStream<ScanEvent>.Continuation) async {
        _ = try? UnwarezPaths.ensureDirectoriesExist()
        let config = ConfigStore.load()
        let vtKey = ConfigStore.virusTotalKey()
        let mbKey = ConfigStore.malwareBazaarKey()

        continuation.yield(.status("Checking ReleaseSeal database..."))
        await releaseSeal.ensureLoaded()
        continuation.yield(.status("Checking known bad files list..."))
        await badFiles.ensureLoaded()

        continuation.yield(.status("Checking for known threats..."))
        _ = ThreatIntel.checkPersistenceThreats()
        _ = await ThreatIntel.checkNetworkThreats()
        _ = ThreatIntel.checkOGFFilenames()

        continuation.yield(.status("Finding files to scan..."))
        let filePaths = FileEnumerator.prioritizingPlainFiles(
            FileEnumerator.enumerate(target: options.target, customPath: options.customPath, fileListPath: options.fileListPath)
        )

        // Constructed fresh per scan (not once for the pipeline's whole
        // lifetime) so the current API keys and a full 15-lookup budget
        // are always in effect.
        let deepInspector = DeepInspector(releaseSeal: releaseSeal, badFiles: badFiles, virusTotal: virusTotal, vtKey: vtKey, mbKey: mbKey)

        guard let hashLog = ScanReport.makeHashLog() else { return }
        defer { hashLog.close() }
        let (reportWriter, reportPath) = ScanReport.makeReport(startedAt: Date())
        defer { reportWriter?.close() }

        let totalFiles = max(filePaths.count, 1)
        continuation.yield(.total(totalFiles))

        continuation.yield(.status("Running ClamAV content scan (this may take a while)..."))
        _ = await clamAV.run(filePaths: filePaths, cancellationToken: clamAVCancellationToken)

        var scanCount = 0
        var detected = 0
        var quarantined = 0
        var unverified = 0

        for path in filePaths {
            if Task.isCancelled { break }
            await waitWhilePaused()
            if Task.isCancelled { break }
            guard FileManager.default.fileExists(atPath: path) else { continue }
            scanCount += 1

            let url = URL(fileURLWithPath: path)
            let name = url.lastPathComponent
            guard let sha = Hashing.sha256(ofFileAt: url) else { continue }
            let md5 = Hashing.md5(ofFileAt: url) ?? "N/A"
            let sizeBytes = DeepInspectionSupport.fileSize(at: path)
            let sizeKB = sizeBytes / 1024

            // Free/local sources first, ahead of the rate-limited VT/MB lookups.
            let rsStatus = await releaseSeal.checkHash(sha256: sha, md5: md5)
            var kbMatch = ThreatIntel.checkKnownBad(sha256: sha, md5: md5)
            if kbMatch == nil { kbMatch = await badFiles.check(md5: md5) }
            let clamavStatus: ClamAVFileStatus = await clamAV.available
                ? (await clamAV.infectionSignature(forPath: path)).map { .infected($0) } ?? .clean
                : .skipped
            let vtStatus = await virusTotal.check(sha256: sha, apiKey: vtKey)
            let mbStatus = await MalwareBazaarClient.check(sha256: sha, apiKey: mbKey)
            let circlStatus = await CIRCLClient.check(sha256: sha)
            let sigStatus = await CodeSignature.check(fileAt: path)
            let rsCert = await CodeSigningEvidence.checkCertificateLabel(forFileAt: path, releaseSeal: releaseSeal)

            // Deep inspection is real overhead (unzipping/mounting/expanding),
            // so it only runs when nothing else already has a verdict -
            // exactly the case where a repackaged/bundled payload would
            // otherwise slip through as UNVERIFIED with the outer hash unrecognized.
            let deepGateAllowed = rsStatus != .compromised
                && !vtStatus.isMaliciousPrefix
                && kbMatch == nil
                && !mbStatus.isMalicious
                && !clamavStatus.isInfected
                && rsStatus != .verified
                && !vtStatus.isClean
                && circlStatus != .knownGood
            let deepResult: DeepInspectionResult = deepGateAllowed ? await deepInspector.inspect(path: path) : .clean

            // PUP only when VirusTotal's PUP-style flag is the SOLE reason -
            // any other independent source keeps the full MALICIOUS verdict.
            var verdictLabel: FileStatus = .malicious
            if vtStatus.isPUPPrefix, rsStatus != .compromised, kbMatch == nil,
               !mbStatus.isMalicious, !clamavStatus.isInfected, !deepResult.isMalicious {
                verdictLabel = .pup
            }

            let isThreat = rsStatus == .compromised || vtStatus.isMaliciousOrPUP || kbMatch != nil
                || mbStatus.isMalicious || clamavStatus.isInfected || deepResult.isMalicious

            if isThreat {
                let qname = "\(sha.prefix(12))_\(name)"
                try? FileManager.default.copyItem(atPath: path, toPath: UnwarezPaths.filesDir.appendingPathComponent(qname).path)
                let timestamp = ScanPipeline.timestampFormatter.string(from: Date())
                let entry = QuarantineEntry(timestamp: timestamp, originalPath: path, quarantinedName: qname, sha256: sha, reason: verdictLabel.rawValue)
                QuarantineStore.append(entry)
                hashLog.appendLine("\(sha)|\(md5)|\(name)|\(sizeBytes)|\(verdictLabel.rawValue)")
                detected += 1
                quarantined += 1

                let detail = maliciousDetail(kbMatch: kbMatch, mbStatus: mbStatus, clamavStatus: clamavStatus, deepResult: deepResult, rsStatus: rsStatus, vtStatus: vtStatus)
                reportWriter?.appendLine("  [!] \(verdictLabel.rawValue): \(path) | \(sha) | RS=\(rsStatus) VT=\(vtStatus) MB=\(mbStatus) CLAMAV=\(clamavStatus)\(deepSuffix(deepResult))\(kbMatch.map { " THREAT-INTEL=\($0)" } ?? "")")
                continuation.yield(.file(ScanResult(id: scanCount, name: name, sha256: sha, sizeKB: sizeKB, status: verdictLabel, detail: detail, path: path)))
            } else if rsStatus == .verified || vtStatus.isClean || circlStatus == .knownGood {
                hashLog.appendLine("\(sha)|\(md5)|\(name)|\(sizeBytes)|VERIFIED")
                reportWriter?.appendLine("  [v] VERIFIED: \(path) | SIG=\(sigStatus.rawValue)\(rsCert.map { " | RS_CERT=\($0)" } ?? "")")
                var detail = "\(rsStatus)/\(vtStatus)/\(circlStatus)"
                if let rsCert { detail += " | Known release: \(rsCert)" }
                continuation.yield(.file(ScanResult(id: scanCount, name: name, sha256: sha, sizeKB: sizeKB, status: .verified, detail: detail, path: path)))
            } else {
                unverified += 1
                hashLog.appendLine("\(sha)|\(md5)|\(name)|\(sizeBytes)|UNVERIFIED")
                reportWriter?.appendLine("  [?] UNVERIFIED: \(path) | \(sha) | SIG=\(sigStatus.rawValue)\(rsCert.map { " | RS_CERT=\($0)" } ?? "")\(deepSuffix(deepResult))")

                var detail = sigStatus == .notApplicable ? "no match" : sigStatus.rawValue
                if case .suspiciousScript(let reasons) = deepResult {
                    detail += " | Script warning: \(reasons)"
                } else if case .certificateEvidence(let label) = deepResult {
                    detail += " | Known release: \(label)"
                }
                if let rsCert { detail += " | Known release: \(rsCert)" }
                continuation.yield(.file(ScanResult(id: scanCount, name: name, sha256: sha, sizeKB: sizeKB, status: .unverified, detail: detail, path: path)))
            }
        }

        // A cancelled scan just stops - matches the bash backend's Cancel
        // behavior (terminating the process), which never got to print a
        // completion summary either.
        guard !Task.isCancelled else { return }

        reportWriter?.appendLine("")
        reportWriter?.appendLine("Files scanned: \(scanCount)")
        reportWriter?.appendLine("Threats found: \(detected)")
        reportWriter?.appendLine("Unverified: \(unverified)")
        reportWriter?.appendLine("Auto-quarantined: \(quarantined)")
        reportWriter?.appendLine(ScanReport.footer)

        if detected > 0, !config.alertEmail.isEmpty {
            EmailAlert.send(
                subject: "ObscuraLux Unwarez: \(detected) threat(s) detected",
                body: "ObscuraLux Unwarez scanned \(scanCount) files and quarantined \(quarantined).\nFull report: \(reportPath.path)",
                to: config.alertEmail
            )
        }

        continuation.yield(.done(ScanSummary(scanned: scanCount, detected: detected, unverified: unverified, quarantined: quarantined, reportPath: reportPath.path)))
    }

    private func maliciousDetail(
        kbMatch: String?, mbStatus: MalwareBazaarResult, clamavStatus: ClamAVFileStatus,
        deepResult: DeepInspectionResult, rsStatus: ReleaseSealStatus, vtStatus: VirusTotalResult
    ) -> String {
        if let kbMatch { return kbMatch }
        if case .malicious(let family) = mbStatus { return "MalwareBazaar: \(family)" }
        if case .infected(let sig) = clamavStatus { return "ClamAV: \(sig)" }
        if case .malicious(let label) = deepResult { return "Deep scan: \(label)" }
        if rsStatus == .compromised { return "ReleaseSeal: compromised" }
        if case .pup(let n) = vtStatus { return "VirusTotal (PUP): \(n)" }
        if case .malicious(let n) = vtStatus { return "VirusTotal: \(n)" }
        return "flagged malicious"
    }

    private func deepSuffix(_ result: DeepInspectionResult) -> String {
        switch result {
        case .malicious(let label): return " DEEP=MALICIOUS:\(label)"
        case .suspiciousScript(let reasons): return " DEEP=SUSPICIOUS_SCRIPT:\(reasons)"
        case .certificateEvidence(let label): return " DEEP=RS_CERT:\(label)"
        case .clean: return ""
        }
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        return formatter
    }()
}
