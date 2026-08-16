# WolfCare / Broken Stones Malware Scanner — Developer Notes

A snapshot for further development. This covers architecture, what's
actually been verified vs. what hasn't, and the known open work.

---

## Repository layout

```
gui_app/                  Native macOS SwiftUI app (v1.5)
  Sources/*.swift         UI + logic (11 files)
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

Testing happened in a Linux sandbox, so anything macOS-specific
could not be executed. Be skeptical accordingly.

### Verified end-to-end (real tests, real detections)

- **ZIP deep inspection** — clean archive → no match; injected
  payload → correctly detected; 250-file archive → capped without
  hanging; temp dirs cleaned up; full pipeline runs on both the GUI
  backend and a propagated CLI script
- **RAR deep inspection** — same battery, using real `.rar` archives
  built with the actual `rar` compressor
- **ClamAV integration** — tested against a faithful stub
  replicating real `clamscan` I/O (flags, output format, exit codes),
  then confirmed on real hardware with a genuine EICAR detection
- **Scan target exclusions** — verified `/System`, `/Library`, and
  the quarantine folder are correctly pruned
- **Config round-trip** — Swift-written config verified to parse
  correctly via bash `source`

### NOT verified — needs testing on real hardware

- **DMG deep inspection** (`hdiutil`) — unavailable in sandbox
- **PKG deep inspection** (`pkgutil`) — unavailable in sandbox
- **All Swift code** — no Swift toolchain in sandbox. Three genuine
  bugs were found only when compiled/run on a real Mac (see below).

To verify DMG/PKG: `hdiutil create` and `pkgbuild` can build real
test cases containing a payload whose hash you've added to
`KNOWN_BAD_SHA256`.

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

---

## Open work

**Multi-format archive support (in progress, not started in code).**
`unar` was verified to handle 7z, tar, tar.gz, tar.bz2, tar.xz, gz,
bz2, xz, and iso — all nine tested working through the same interface
already used for RAR. The remaining work is a generic handler routing
these through `inspect_rar_contents`-style logic, plus adding the
extensions to the `find` patterns in `run_scan()` (three places, all
three scripts). Note `unrar` is NOT an option — removed from Homebrew
over licensing, and the fallback cask is disabled as of 2026-09-01.

**Keychain for API keys.** Currently plaintext in
`~/.local/share/*_quarantine/.wolfcare_config` (chmod 600). Moving to
Keychain via the Security framework would be better hygiene. Deferred
previously because a Keychain bug fails silently rather than loudly —
worth doing as its own focused change with real testing.

**GUI Scheduled Scans tab.** Built and wired to `crontab`, but never
clicked through by a user. Lower risk than it sounds (same patterns
as the tested tabs) but genuinely unverified.

**Sidebar logo.** Attempted twice, removed both times — first
invisible, then overlapping the nav text. The asset has a black
background that resists automated cutout because the wolf silhouette
and background are both near-black and intertwined. Would need a
manually prepared transparent PNG.

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

End users don't need Xcode — distribute the compiled `.app` in a DMG
and Swift runtime libs ship with macOS. Only the build machine needs
the toolchain.

The CLI scripts are self-locating via `${BASH_SOURCE[0]}` and run
from anywhere with no build step.
