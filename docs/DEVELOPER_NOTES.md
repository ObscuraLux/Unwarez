# WolfCare / Broken Stones Malware Scanner — Developer Notes

A snapshot for further development. This covers architecture, what's
actually been verified vs. what hasn't, and the known open work.

---

## Repository layout

```
gui_app/                  Native macOS SwiftUI app (v1.5)
  Sources/*.swift         UI + logic (12 files)
  WolfCare.sh             The bash scanner, bundled as the backend
  build_app.sh            Compiles + assembles + ad-hoc signs the .app
  Info.plist              Bundle metadata
  icon.icns               App icon
  dmg_readme.txt          End-user setup guide (ships inside the DMG)
  README.txt              Build/changelog notes

cli_scripts/              Standalone terminal versions (v1.1)
  Wolfcare Malware Scanner v1.1.sh
  Broken Stones Malware Scanner v1.1.sh
```

### The three variants

All three share the same scanning engine. The GUI app is a Swift
frontend that shells out to the same bash script the CLI versions
run directly.

| | Bundle ID | Quarantine path |
|---|---|---|
| WolfCare CLI | `com.wolfcare.malwarescanner` | `~/.local/share/wolfcare_quarantine` |
| Broken Stones CLI | `com.brokenstones.malwarescanner` | `~/.local/share/brokenstones_quarantine` |
| WolfCare GUI | `com.wolfcare.malwarescanner.gui` | `~/.local/share/wolfcare_quarantine` (shared with CLI) |

**Important for development:** the three bash scripts are separate
files that must be kept in sync manually. Changes to scan logic need
applying to all three. Past sessions did this with Python patch
scripts using unique anchor strings + assertions — recommended, since
a silent partial propagation already caused one real bug (a function
was left behind, producing a runtime `command not found` that only
showed up in a full end-to-end test, not a syntax check).

---

## Architecture

### GUI ↔ backend protocol

The Swift app runs `WolfCare.sh --gui --target=N [--path=...]` and
parses structured lines from stdout. Fields are separated by ASCII
unit separator (`\x1f`, shown as `<US>` below):

```
GUI<US>STATUS<US>{message}
GUI<US>TOTAL<US>{count}
GUI<US>FILE<US>{index}<US>{MALICIOUS|VERIFIED|UNVERIFIED}<US>{name}<US>{sha256}<US>{sizeKB}<US>{detail}
GUI<US>DONE<US>{scanned}<US>{detected}<US>{unverified}<US>{quarantined}
```

Human-readable/colored output goes to stderr and is discarded by the
GUI. `--auto` mode (used by cron) emits neither and never blocks on
prompts.

### Detection layers

Checked per file, in order. Only the first four can mark something
`MALICIOUS`:

1. **Local threat-intel list** — 167 hashes (xdivcmp campaign + OGF
   piracy-bundle stealer), embedded in the script
2. **ReleaseSeal** — GitHub-hosted hash reputation, cached 24h
3. **VirusTotal** — optional, needs free API key, self-throttled to
   respect the 4/min free tier
4. **MalwareBazaar** — optional, needs free key from abuse.ch
5. **CIRCL hashlookup** — free, no key, identifies known-GOOD files
6. **ClamAV** — optional (`brew install clamav`); the only
   content-based (not hash-based) check
7. **Deep inspection** — looks inside archives (see below)

Plus two informational-only signals that never trigger quarantine:
- **Code signature** (`spctl`) — unsigned is common and legitimate,
  so this is context, not a verdict
- **Installer script warnings** (pkg only) — flags scripts that
  disable Gatekeeper or strip quarantine attributes

### Design principle worth preserving

An earlier version had a naive keyword grep that produced a real
false positive (flagged Dropbox). It was removed and replaced with
the honest `UNVERIFIED` status. The lesson stuck and shapes the
current design:

- `UNVERIFIED` means "not found in these databases" — **not**
  "suspicious." It's the expected result for most files.
- Deep-inspection findings only ever ADD to `MALICIOUS`. A clean
  file inside an archive never upgrades anything to `VERIFIED`.
- Inner-file checks use only local/free sources, never the
  rate-limited APIs — one archive could contain hundreds of files
  and exhaust a daily quota.

---

## Testing status — read this before trusting anything

Early testing happened in a Linux sandbox with no macOS/Swift
toolchain; a later session ran with a real Mac (Apple Silicon, Swift
6.1, Xcode CLT) and used it to close out everything that sandbox
couldn't touch. Be skeptical of anything not listed below as verified.

### Verified end-to-end (real tests, real detections)

- **ZIP/RAR deep inspection** — clean archive → no match; injected
  payload → correctly detected; 250-file archive → capped without
  hanging; temp dirs cleaned up; full pipeline runs on both the GUI
  backend and a propagated CLI script
- **7z/tar/tar.gz/.tgz/tar.bz2/.tbz2/tar.xz/.txz/gz/bz2/xz/iso deep
  inspection** (real hardware) — all nine additional `unar`-handled
  formats verified with real fixtures and a planted malicious hash,
  in both the real-`timeout`-binary code path and the pure-bash
  fallback path (see the `timeout` bug below - this matters)
- **DMG deep inspection** (real hardware, `hdiutil`) — nested
  `.pkg`/`.dmg` container hashing and `.app` main-executable hashing
  (via `PlistBuddy`/`CFBundleExecutable`) both verified with real
  `hdiutil create` fixtures; mount count before/after confirmed equal
  (no leaked volumes) across both a clean run and a detection run
- **PKG deep inspection** (real hardware, `pkgutil`) — payload
  (gzip+cpio) hash matching verified with a real `pkgbuild` fixture;
  the informational `SUSPICIOUS_SCRIPT` signal verified against a real
  postinstall script disabling Gatekeeper and stripping the quarantine
  attribute
- **ClamAV integration** — tested against a faithful stub
  replicating real `clamscan` I/O (flags, output format, exit codes),
  then confirmed on real hardware with a genuine EICAR detection
- **Scan target exclusions** — verified `/System`, `/Library`, and
  the quarantine folder are correctly pruned
- **Config round-trip** — Swift-written config verified to parse
  correctly via bash `source`
- **Keychain round-trip** (real hardware, via `security` CLI) —
  legacy-plaintext migration, save, key rotation, and clearing a key
  all verified against a real (throwaway) Keychain entry; GUI and CLI
  confirmed to resolve to the same Keychain service name
- **Scheduled-scan crontab logic** (real hardware) — add
  daily/weekly, replace, and remove-all verified against a real
  (backed-up-and-restored) crontab using a marker script path; also
  confirmed `crontab -` fails loudly (non-zero exit, old crontab left
  untouched) on malformed input rather than silently doing nothing
- **GUI build** — compiles clean with zero warnings as a universal
  binary (arm64 + x86_64), ad-hoc signed

### Still not verified

- Full Disk Access live-check UX (`FullDiskAccess.swift`) and the
  Scheduled Scans tab's SwiftUI layer haven't been clicked through in
  a running app window - the underlying mechanisms they call
  (TCC probe, crontab read/write) are verified directly per above, but
  the view layer itself hasn't been exercised interactively.

---

## Bugs found the hard way (don't reintroduce these)

**SwiftUI selection bindings.** `List(selection:)` and
`Picker`+`.tag()` both silently failed to update state on click —
only the default-selected value ever worked. Both were replaced with
plain `Button`s setting `@State` directly. If you reintroduce either
pattern, test every option, not just the default.

**Hit testing.** A decorative background image at 22% opacity
silently swallowed clicks meant for the nav underneath. SwiftUI views
are clickable across their whole frame regardless of visual opacity —
decorative layers need `.allowsHitTesting(false)`.

**Orphaned processes.** `clamscan` is a grandchild process (app →
bash → clamscan). Terminating the bash child doesn't propagate, so
quitting mid-scan orphaned a CPU-pegged `clamscan` that then competed
with the next scan. Now cleaned up in three places: before each new
scan, on Cancel, and in `applicationWillTerminate`.

**Missing network timeout.** One `curl` call (the first of every
scan) lacked `--connect-timeout`, which could hang indefinitely with
no visible error. All network calls now have both `--connect-timeout`
and `--max-time`.

**`find` operator precedence.** The original prune logic was subtly
wrong and wasn't actually excluding `/System` or `/Library` — it also
printed raw directories. Correct pattern:
`find PATH \( -path EXCLUDE -prune \) -o \( -type f ... -print \)`.
Test any change to this empirically; it's easy to get wrong.

**`timeout` isn't part of stock macOS.** The single biggest finding
from real-hardware testing: `timeout` is a GNU coreutils command, not
BSD userland, so it doesn't exist on a Mac without Homebrew coreutils
installed. Every deep-inspection call site (`unzip`, `hdiutil`,
`pkgutil`, `unar`) used it directly - on a real end-user machine that
was silently "command not found", meaning deep inspection had likely
never actually run despite the earlier sandbox testing showing it
working (Linux ships `timeout` standard, which is exactly how this
got missed). Fixed with a `run_timeout()` wrapper that prefers a real
`timeout`/`gtimeout` binary and falls back to a pure-bash equivalent
(same exit-code-124 convention either way) - verified in both code
paths. If you add a new external/slow call, use `run_timeout`, not
`timeout` directly.

**clamscan had no timeout at all.** Root cause of scans getting stuck
mid-run and needing a manual `pkill -f clamscan` - every *other* slow
operation in the script had one, this was the exception. Now bounded
at 30 minutes via `run_timeout`, with a 45-minute GUI-side watchdog as
a second safety net, and cleanup sends `SIGKILL` (`-9`) rather than
the default `SIGTERM` since the whole point is recovering something
already unresponsive.

**Crontab writes weren't checked for success.** `crontab -` can fail
(verified: bad input → non-zero exit, old crontab left untouched) but
`CronStore.swift` showed the "scheduled" success message unconditionally.
Now checks `terminationStatus` and surfaces `security`/`crontab`'s own
stderr on failure instead.

---

## Open work

Nothing currently tracked here. See "Resolved this session" below for
what was just closed out, and "Bugs found the hard way" for traps not
to reintroduce.

### Resolved this session (kept here briefly for context, not re-open)

- Multi-format archive support, Keychain-backed API keys, and the
  Scheduled Scans tab's underlying crontab logic - see Testing status
  above for what was verified and "Bugs found the hard way" for what
  broke along the way (notably the `timeout` portability bug, found
  while doing the archive work).
- **Logo.** The earlier "sidebar logo" attempts were stuck on an asset
  with a black background that resisted automated cutout. A
  user-provided, already-correctly-cut-out transparent PNG
  (`wolf_logo.png`) is now placed in the window's title bar via
  `.toolbar { ToolbarItem(placement: .primaryAction) { ... } }`.
  Verified against the real installed app: clicked through all 5
  sidebar tabs with it present, no missed clicks, no crash.
- **Settings tab crash.** `SettingsStore.init()` called `load()`,
  which - after the Keychain migration - spawns a subprocess
  synchronously. An `@StateObject`'s `init()` runs during the view's
  first layout pass, and blocking subprocess work there crashes
  SwiftUI's AttributeGraph (`SIGABRT`, confirmed via real crash logs).
  Fixed by loading from `.onAppear` instead, matching the pattern
  `CronStore`/`ScheduleView` already used for the same reason.
- **Logs tab.** Per-scan reports (`$QUARANTINE/reports/*.txt`) were
  already written by the bash backend but only reachable via Finder.
  Added a Logs tab (`LogsStore`/`LogsView`) to browse, view, and reveal
  them from the GUI.
- **Scan-complete alert.** `ScanEngine` now flags completion; `ScanView`
  shows a modal alert before the already-visible results table.
- **Individual file scanning.** The bash backend has supported
  `--target=5` (single file) from before this repo's history starts,
  but the Swift `ScanTarget` enum never included it, so the option
  never appeared in the GUI. Restored.

---

## Build & distribution

```bash
cd gui_app
bash build_app.sh                              # needs Xcode CLT
open "build/WolfCare Malware Scanner v1.5.app"
```

Ad-hoc signing is **mandatory**, not optional — Apple Silicon refuses
to run any compiled Mach-O with no signature at all. This is separate
from (and stricter than) the "unidentified developer" Gatekeeper
warning. `build_app.sh` handles it.

The build produces a universal binary (arm64 + x86_64 via two
`swiftc -target` passes + `lipo -create`), so one build serves both
Intel and Apple Silicon Macs. Deployment target is 12.0, matching
`Info.plist`'s `LSMinimumSystemVersion` (verified: `minos 12.0` in
both slices via `otool -l`).

Was 13.0 until `NavigationSplitView` (needs 13+) was swapped for
`NavigationView`, and `Table` (ScanView's results grid, needs 12+) for
a plain `List` - both verified with `swiftc -target
arm64/x86_64-apple-macos12.0 -typecheck`, which is the reliable way to
check this empirically rather than guessing at API availability from
memory (surfaced two more floor-raising APIs that weren't obvious
up front: `Scene.defaultSize` needs 13+, dropped entirely since
`.frame(minWidth:minHeight:)` already keeps the window a sane size).

**12.0 is the practical floor without a much bigger change.** Going
below it (down toward SwiftUI's own hard floor of 10.15) would also
require: reworking every `@StateObject` (needs 11.0, used in every
view), replacing every SF Symbol icon (`Image(systemName:)`/
`Label(systemImage:)`, needs 11.0, used throughout), and replacing
every `.foregroundStyle` call (needs 12.0, ~40+ call sites) with
`.foregroundColor`. True 10.10 support isn't reachable at all without
dropping SwiftUI for AppKit entirely. The `cli_scripts/` have no
version floor regardless - they're plain bash and run on essentially
any macOS version, including 10.10.

End users don't need Xcode — distribute the compiled `.app` in a DMG
and Swift runtime libs ship with macOS. Only the build machine needs
the toolchain.

The CLI scripts are self-locating via `${BASH_SOURCE[0]}` and run
from anywhere with no build step.
