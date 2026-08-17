WolfCare Malware Scanner - Native GUI (v1.6.3)
==========================================================

WHAT'S NEW IN THIS PASS
------------------------
- Deep inspection (zip/dmg/pkg/rar/7z/tar/tar.gz/tar.bz2/tar.xz/gz/
  bz2/xz/iso) was silently a no-op on real end-user Macs: `timeout` is
  a GNU coreutils command, not part of stock macOS. Added a
  run_timeout() wrapper (real binary when present, pure-bash fallback
  otherwise) and generalized RAR's unar-based inspector to cover the
  other nine archive formats.
- clamscan had no timeout at all - the root cause of scans getting
  stuck and needing a manual `pkill -f clamscan`. Now bounded at 30
  minutes, plus a 45-minute GUI-side watchdog as a second safety net.
- Fixed a real MalwareBazaar false-positive bug: any network failure,
  timeout, or malformed API response was silently treated as a
  detection instead of "unknown" (deny-list logic instead of
  allow-list). Confirmed live against a real false positive.
- Added a PUP (Potentially Unwanted Program) classification, distinct
  from MALICIOUS and shown in orange - VirusTotal hits where every
  flagging engine used a PUP/PUA-style signature name are downgraded
  from a red "confirmed threat" to an orange "potentially unwanted,"
  same as antivirus vendors themselves distinguish it. Still
  auto-quarantined for review either way.
- API keys (VirusTotal, MalwareBazaar) moved from a plaintext config
  file to the macOS Keychain, via the same `security` CLI mechanism
  used by the CLI scripts, the bundled backend, and this app's
  Settings tab.
- New Logs tab: browse, view, and reveal the per-scan report files
  the backend already wrote, previously only reachable via Finder.
- New Quarantine actions: re-scan a single entry or all of them
  (against the still-existing quarantined copy, not the possibly-gone
  original), and "Mark as Safe" - removes an entry from the list
  without deleting the quarantined copy, with no permanent exemption
  from future detection (it's evaluated completely fresh next time).
- Restored "Individual file" as a scan target - the bash backend
  supported it long before this GUI did, the Swift target list just
  never included it.
- Full Disk Access notice is now a live check (a real TCC probe,
  rechecked when the app regains focus) instead of a static hint.
- Fixed a crash on opening Settings: an @StateObject's init() ran
  Keychain access (a subprocess) during the view's first layout pass,
  corrupting SwiftUI's AttributeGraph. Now loads from .onAppear.
- Scan-complete alert, wolf/moon logo in the title bar, GUI now builds
  as a universal binary (arm64 + x86_64), deployment target dropped
  from 13.0 to 12.0 (NavigationSplitView -> NavigationView, Table ->
  List).
- New build_dmg.sh packages a "fancy" installer DMG (app / Applications
  alias / setup guide, 96x96 icons, compressed read-only).

REQUIREMENTS
------------
Xcode Command Line Tools (free, no full Xcode needed):
    xcode-select --install

HOW TO BUILD
------------
    cd gui_app
    bash build_app.sh
    open "build/WolfCare Malware Scanner.app"

To also package a distributable DMG (requires `pip3 install dmgbuild`):
    bash build_dmg.sh

Ad-hoc signed, not notarized - expect one Gatekeeper prompt the
first time (right-click, Open).

PROJECT LAYOUT
---------------
Sources/
  WolfCareApp.swift      App entry point
  ContentView.swift      Sidebar (Buttons, not List) + routing, title
                           bar logo
  ScanView.swift          Scan tab (target selector also Buttons)
  ScanEngine.swift        Shells out to WolfCare.sh, parses --gui
                           output, cleans up orphaned clamscan
                           processes, re-scan-specific-files support
  SettingsView.swift      Settings tab UI
  SettingsStore.swift     Reads/writes .wolfcare_config (theme/email)
                           and Keychain (API keys)
  QuarantineView.swift    Quarantine tab UI - restore/delete/re-scan/
                           mark as safe
  QuarantineStore.swift   Reads/writes quarantine_manifest.txt
  LogsView.swift          Logs tab UI - browse/view/reveal reports
  LogsStore.swift         Reads $QUARANTINE/reports/*.txt
  ScheduleView.swift      Scheduled Scans tab UI
  CronStore.swift         Shells out to crontab
  FullDiskAccess.swift    Live TCC probe + Privacy Settings deep link
  Models.swift            Data types
Info.plist              App bundle metadata
WolfCare.sh              The bash scanner (bundled as the backend)
icon.icns                App icon
wolf_logo.png            Title bar logo
dmg_readme.txt           End-user setup guide (ships inside the DMG)
build_app.sh             Compiles everything into
                           build/WolfCare Malware Scanner.app
build_dmg.sh             Packages that .app into a distributable DMG
