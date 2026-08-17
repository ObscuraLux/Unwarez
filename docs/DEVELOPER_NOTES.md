# ObscuraLux Unwarez — Developer Notes

A snapshot for further development. This covers architecture, what's
actually been verified vs. what hasn't, and the known open work.

**Rebrand note:** this project was previously "WolfCare" (and, before
that, also shipped a separately-branded "Broken Stones" CLI variant of
the identical scanner). Renamed throughout - scripts, Swift sources,
bundle IDs, the quarantine data path, docs.

**Rewrite note (this pass):** the entire bash-script backend (previously
`gui_app/ObscuraLuxUnwarez.sh` and `cli_scripts/ObscuraLux Unwarez v1.1.sh`
— ~1800 and ~1760 lines respectively, kept in manual sync) has been
ported to native Swift and both bash scripts removed. There is no shell
script anywhere in this project anymore. See "Architecture" below for
what replaced it.

---

## Repository layout

```
Package.swift              SwiftPM manifest - one package, three targets

Sources/
  UnwarezCore/              Shared library: the entire detection engine
    Resources/
      ThreatIntel.json       Embedded local threat-intel (54 SHA256 +
                              113 MD5 hashes, launchd/staging/IP/domain
                              indicators) - mechanically extracted from
                              the old bash arrays, not hand-transcribed
      ReleaseSealDatabase.json  Bundled fallback seed for the ReleaseSeal
                                 hash-reputation database
    Network/                ReleaseSeal, VirusTotal, MalwareBazaar,
                             CIRCL, badfiles.txt clients (URLSession)
    DeepInspection/          zip/dmg/pkg/archive(unar) container inspectors
    Scanning/                FileEnumerator, ScanPipeline, ScanReport
    Quarantine/              QuarantineStore (manifest read/write/restore)
    Scheduling/              LaunchAgentStore (replaces crontab)
    Models.swift, Paths.swift, Hashing.swift, ProcessRunner.swift,
    KeychainStore.swift, ConfigStore.swift, ThreatIntel.swift,
    ClamAV.swift, CodeSignature.swift, EmailAlert.swift

  UnwarezCLI/                Terminal executable ("unwarez-cli") -
                              interactive menu + --auto/--target=/--path=/
                              --files= non-interactive mode for launchd

  UnwarezGUI/                Native macOS SwiftUI app ("ObscuraLuxUnwarezGUI")

packaging/                  Everything needed to produce a distributable
                             .app + DMG (not part of the Swift package)
  Info.plist, AppIcon.icns, dmg_readme.txt
  build_app.sh                Compiles both targets, both architectures,
                               assembles + ad-hoc signs the .app
  build_dmg.sh                 Packages the .app into a DMG
```

### The two variants, now

Both the GUI and CLI depend on the same `UnwarezCore` library target -
there is exactly one implementation of every detection check, hashing
routine, network client, and piece of on-disk-format knowledge. There is
**no manual-sync problem anymore**: the old split (a bash script bundled
as the GUI's backend, plus a second, separately-maintained CLI copy of
the same script, diffed and patched in parallel) is gone. Changes to
scan logic only ever touch one place.

| | Bundle ID | Quarantine path |
|---|---|---|
| ObscuraLux Unwarez CLI (`unwarez-cli`) | n/a (no bundle ID; runs as a bundled Resources binary or standalone) | `~/.local/share/obscuralux_unwarez_quarantine` |
| ObscuraLux Unwarez GUI | `com.obscuralux.unwarez.gui` | `~/.local/share/obscuralux_unwarez_quarantine` (shared with CLI) |

All on-disk formats (quarantine manifest, hash log, report files, config
file, Keychain service/account names) were kept byte-identical to the
bash-era layout specifically so existing installs' data and saved API
keys keep working with zero migration.

---

## Architecture

### GUI/CLI ↔ engine: no protocol anymore

The old GUI shelled out to the bash script in `--gui` mode and parsed a
custom `GUI\x1f...`-delimited stdout protocol line by line. That's gone.
`ScanPipeline.run(options:)` (in `UnwarezCore/Scanning/ScanPipeline.swift`)
runs the whole scan in-process and returns an `AsyncStream<ScanEvent>`
(`.status`, `.total`, `.file`, `.done`) that both the GUI's `ScanEngine`
and the CLI's `ScanRunner` consume directly with `for await`. No
subprocess, no wire format, no line-buffering/partial-read handling.

### Pause/cancel, now that there's no subprocess to signal

The old GUI paused a scan with `SIGSTOP`/`SIGCONT` on the bash process
and cancelled it with `SIGTERM`. There's no OS process to signal anymore
- `ScanPipeline` implements **cooperative** pause/cancel instead:
- `pause()`/`resume()`: an actor-isolated flag the per-file loop awaits
  on between files (`waitWhilePaused()`), backed by `CheckedContinuation`.
- `cancel()`: cancels the underlying `Task` (checked at the top of every
  loop iteration and at any `await` point) and separately force-kills
  ClamAV if one is in flight via `ProcessCancellationToken` - the one
  external call that can legitimately run for up to 30 minutes. Every
  *other* external tool call (`unzip`/`hdiutil`/`pkgutil`/`unar`) already
  has its own short (30-60s) timeout, so cancel latency there is bounded
  even without separately wiring a kill-switch through each one - a
  deliberate scope cut, not an oversight.

### Detection layers

Unchanged from the bash era, just native now. Checked per file, in
order (free/local sources first). Only the first four can mark
something `MALICIOUS`:

1. **Local threat-intel list** — `ThreatIntel.swift`, loaded from the
   bundled `ThreatIntel.json` resource (167 hashes: xdivcmp campaign +
   OGF piracy-bundle stealer)
2. **ReleaseSeal** — `Network/ReleaseSealClient.swift`, GitHub-hosted
   hash reputation, cached 24h, falls back to the bundled seed JSON offline
3. **VirusTotal** — `Network/VirusTotalClient.swift`, optional key,
   self-throttled (actor-isolated per-scan state, not a global)
4. **MalwareBazaar** — `Network/MalwareBazaarClient.swift`, optional key
5. **CIRCL hashlookup** — `Network/CIRCLClient.swift`, free, identifies known-GOOD files
6. **ClamAV** — `ClamAV.swift`, optional (`brew install clamav`), the
   only content-based (not hash-based) check
7. **Deep inspection** — `DeepInspection/`, looks inside archives

Plus two informational-only signals that never trigger quarantine:
code signature (`CodeSignature.swift`, via `spctl`) and installer-script
warnings (`SUSPICIOUS_SCRIPT`, pkg/dmg loose-helper-script scanning).

### Design principle worth preserving

`UNVERIFIED` means "not found in these databases" — **not**
"suspicious." Deep-inspection findings only ever ADD to `MALICIOUS`.
Inner-file checks (`InnerHashChecker.swift`) use only local/free sources
(embedded list + ReleaseSeal), never the rate-limited APIs - preserved
exactly from the bash version's design, including one thing worth
knowing: the old code's *comment* claimed CIRCL was also used for
inner-file checks, but the actual bash code never called it there -
`InnerHashChecker` here matches what the code actually did (list +
ReleaseSeal only), not what the stale comment claimed.

### No more shell-outs to `security`/`crontab`/GNU `timeout`

- **Keychain**: `KeychainStore.swift` uses the `Security` framework
  (`SecItemAdd`/`SecItemCopyMatching`/`SecItemUpdate`/`SecItemDelete`)
  directly - no `/usr/bin/security` subprocess. Same service name
  (`.obscuralux_unwarez_config`) and account names
  (`virustotal_api_key`/`malwarebazaar_api_key`) as before, so existing
  saved keys are found without migration.
- **Scheduling**: `Scheduling/LaunchAgentStore.swift` writes a real
  LaunchAgent plist (`~/Library/LaunchAgents/com.obscuralux.unwarez.scheduledscan.plist`)
  and drives it via `launchctl load -w`/`unload`, replacing crontab
  entirely. The old "marker = script's absolute path as a crontab-line
  substring" scheme is replaced by a fixed `Label`. `LaunchAgentStore.migrateLegacyCronEntries()`
  strips any leftover pre-rewrite crontab line on first schedule, so the
  two mechanisms can't both fire for someone upgrading from an old install.
- **Process timeouts**: `ProcessRunner.swift` replaces `run_timeout` (the
  bash wrapper that existed *only* because `timeout`/`gtimeout` aren't
  part of stock macOS - a real bug found the hard way, see below). Native
  `Process` + `Task.sleep` needs no such portability dance; it's a plain
  parameter (`timeout:`) with immediate `SIGKILL` on expiry.
- **External tools still shelled out to via `Process`** (by design, not
  oversight - see the security note below): `unzip`, `hdiutil`,
  `pkgutil`, `gunzip`/`cpio`, `unar`, `clamscan`, `spctl`, `codesign`,
  `openssl`, `/usr/libexec/PlistBuddy`, `launchctl`. macOS has no public
  Swift API for DMG mounting, PKG expansion, or these archive formats -
  going "native" here means calling them directly via `Process.arguments`
  from Swift, never through an intermediate shell script.

### A security note worth keeping in mind for any future subprocess code

The bash version had one real vulnerability, found and fixed during this
project: `inspect_pkg_contents` decompressed a PKG's Payload via
`bash -c "gunzip -dc '$payload_file' | ..."` - string-interpolating a
path that (inside a maliciously crafted `.pkg`, which is exactly the
threat model this tool exists for) could contain a single quote and
inject arbitrary shell commands. The Swift port doesn't just fix that
call site (`DeepInspection/PKGInspector.swift` connects two `Process`es
with a native `Pipe`, no shell string at all) - the entire class of bug
is structurally impossible everywhere in this codebase now, since
`Process.arguments` takes an array and never passes through `/bin/sh`.
If you ever add a new external-tool call, keep it that way; don't
introduce a `Process(["/bin/bash", "-c", "... \(untrustedValue) ..."])`
anywhere.

---

## Testing status — read this before trusting anything

### Verified

- **Whole package builds clean** (`swift build`), all three targets,
  zero warnings beyond a since-resolved SwiftPM test-target path notice
- **Local threat-intel matching** — verified at runtime (not just
  compile-checked) against the real embedded data: known SHA256 and MD5
  entries match with the correct label, an unrelated hash correctly
  returns no match, and the loaded counts (54 SHA256 / 113 MD5) match
  the source data exactly
- **ReleaseSeal, live** — verified at runtime against the real
  GitHub-hosted database: both a known-verified-artifact hash and a
  known-compromised hash resolve correctly, meaning the download, 24h
  cache, JSON parsing, and matching logic all work end-to-end over a
  real network call, not just against the bundled offline seed
- **CLI end-to-end** — `unwarez-cli --auto --target=4 --path=...` against
  a real directory containing a `.zip`: file enumeration, hashing, zip
  deep-inspection (extract, size-cap check, inner-file hashing), and
  report/hash-log writing all ran and produced correct output and exit
  code 0
- **GUI app** — builds as a real, ad-hoc-signed, universal (arm64 +
  x86_64) `.app` via `packaging/build_app.sh`; launches and stays running
  (verified via `open` + process check + crash-log check) without
  crashing on startup
- **Command-injection class of bug structurally eliminated** — see the
  security note above

### Not yet verified / open follow-ups

- **DMG/PKG deep inspection with a real planted malicious hash** — the
  zip path was exercised end-to-end with real detection; dmg/pkg
  inspection compiles and follows the same code shape (verified
  line-by-line against the original bash logic during the port) but
  hasn't been exercised against a real crafted `.dmg`/`.pkg` fixture the
  way the bash version's testing notes describe. Same caveat applies to
  the RAR/7z/tar-family paths via `unar`.
- **GUI interactive flows** (Settings save round-trip through the real
  Keychain, Scheduled Scans tab writing a real LaunchAgent, Quarantine
  restore/delete, Pause/Resume mid-scan) — the underlying store logic is
  either unit-verified indirectly (Keychain/config share the exact code
  path the CLI's runtime-tested settings menu uses) or type-checks
  against the same `UnwarezCore` APIs the CLI already exercised, but
  none of the SwiftUI views themselves have been clicked through in a
  running window.
- **`XCTest` is unavailable in this environment** (Command Line Tools
  only, no full Xcode - `xcrun --find xctest` fails) - there is
  currently no automated test target. Verification so far has been via
  real runtime execution (the CLI, and a temporary self-test harness
  removed after confirming results) rather than `swift test`. If a
  machine with full Xcode is available, adding an `XCTest` target back
  (a `.testTarget` in `Package.swift`) is worth doing.
- **CSV/PDF report export** (`export_report` in the old bash version)
  was not ported to `unwarez-cli` - the CLI writes the same `.txt`
  report/hash-log files, but doesn't offer an interactive export step.
- **Deep-inspection subprocess cancellation** - per above, Cancel is
  wired through Task cancellation + a kill-switch for ClamAV
  specifically, not through every individual `unzip`/`hdiutil`/`pkgutil`/
  `unar` call. Worst case, Cancel during deep inspection of one file
  takes up to that tool's own timeout (30-60s) to actually stop, not
  instant.
- **A preserved-as-is quirk, not introduced by this rewrite**: both the
  old bash `find` file-enumeration filter and the new
  `FileEnumerator.swift` match `.app` only via `-type f` (a regular
  file) / `isRegularFile`. Real `.app` bundles are directories, so this
  glob effectively never matches a loose `.app` on disk during directory
  enumeration - `.app` bundles are still inspected when they turn up
  *inside* a mounted `.dmg` (via `DMGInspector`'s separate `.app`-bundle
  walk), just not when sitting loose in a scanned folder. Worth deciding
  whether this was ever intentional.
- Domains list (`KNOWN_BAD_DOMAINS`, 5 entries in `ThreatIntel.json`) is
  loaded but still not checked against anything (same as the bash
  version - dead data, carried over as-is rather than silently wired up
  or dropped during the port).

---

## Bugs found the hard way (don't reintroduce these)

Carried over from the bash era - the underlying lessons still apply even
though the specific code they were about no longer exists:

**SwiftUI selection bindings.** `List(selection:)` and
`Picker`+`.tag()` both silently failed to update state on click —
only the default-selected value ever worked. Both were replaced with
plain `Button`s setting `@State` directly (still true in the ported
`ContentView`/`ScanView`). If you reintroduce either pattern, test every
option, not just the default.

**Hit testing.** Decorative background views need
`.allowsHitTesting(false)` - SwiftUI views are clickable across their
whole frame regardless of visual opacity.

**Orphaned processes.** `clamscan` is a grandchild process. Terminating
a parent doesn't propagate to it. `ScanEngine.killOrphanedClamscan()`
(GUI, called from `applicationWillTerminate`) and
`ProcessCancellationToken`/the pattern-`pkill` fallback in
`ClamAV.swift` both still exist for this reason.

**Doing subprocess/synchronous work in a `@StateObject`'s `init()`
crashes SwiftUI's AttributeGraph** (`SIGABRT`). Every store that does
non-trivial work on load (`SettingsStore`, `ScheduleStore`) loads from
`.onAppear`, never `init()` - preserved in the rewrite even though the
specific *subprocess* aspect that originally caused this (shelling out
to `security`) is gone; the safest posture is to keep the same pattern
for any non-trivial synchronous work, in-process or not.

**`find` operator precedence / exclusion pruning.** The bash version's
`\( -path EXCLUDE -prune \) -o \( ... -print \)` pattern was easy to get
subtly wrong. `FileEnumerator.swift`'s Swift port uses explicit
prefix-matching against an exclusion list instead, which is more
directly readable but should still be tested empirically if you change it.

---

## Build & distribution

```bash
bash packaging/build_app.sh                    # needs Xcode CLT
open "build/ObscuraLux Unwarez.app"
```

Two architectures are built as **separate single-arch `swift build -c
release --arch <arch>` invocations, then `lipo -create`d together** -
not a single `swift build --arch arm64 --arch x86_64` call. That
combined form needs XCBuild, which only ships with full Xcode, not
Command Line Tools alone (confirmed by testing both in this environment).
This mirrors what the pre-rewrite `build_app.sh` did with raw `swiftc`
calls, just via `swift build` instead.

Ad-hoc signing is **mandatory**, not optional — Apple Silicon refuses
to run any compiled Mach-O with no signature at all, separate from (and
stricter than) the "unidentified developer" Gatekeeper warning.
`build_app.sh` handles it.

Deployment target is 12.0 (`Package.swift`'s `platforms: [.macOS(.v12)]`,
matching `Info.plist`'s `LSMinimumSystemVersion`) - unchanged from the
bash-era constraint (`NavigationSplitView`/`Table`/`.defaultSize` all
need 13+; `@StateObject`/SF Symbols need 11+; `.foregroundStyle` needs
12+). Unlike the old CLI (plain bash, no version floor at all), the new
`unwarez-cli` shares this 12.0 floor since it's compiled from the same
package - see the DMG readme for how that's communicated to end users.

`unwarez-cli` is bundled into the `.app` at `Contents/Resources/unwarez-cli`
specifically so `LaunchAgentStore`-scheduled scans can run without the
GUI app being open - the LaunchAgent's `ProgramArguments` points at that
bundled binary.
