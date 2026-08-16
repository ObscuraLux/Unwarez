WolfCare Malware Scanner - Native GUI (v2.4)
==========================================================

WHAT'S NEW IN THIS PASS
------------------------
- Fixed a real process-leak bug found via live testing: if the app
  gets quit or relaunched while a scan is mid-flight, the background
  clamscan process (a grandchild of the app, spawned via the bash
  backend) becomes orphaned - terminating the app's direct bash
  child doesn't propagate to clamscan, so it just keeps running
  invisibly. A fresh scan afterward would then start a second
  clamscan on top of the orphaned one, both competing for CPU.
  Confirmed via `ps aux` showing two simultaneous clamscan processes
  during a real 430-file scan. Now cleaned up defensively both when
  Cancel is clicked and automatically before every new scan starts,
  so this can't accumulate regardless of how the app got into that
  state. Uses a specific pattern match (--file-list=, unique to this
  app's invocations) rather than a bare "clamscan" match, so it
  won't touch an unrelated clamscan process if you're running one.
- Added an app-quit hook (NSApplicationDelegateAdaptor +
  applicationWillTerminate): the same clamscan cleanup now also runs
  automatically if you quit the app entirely while a scan is
  running, not just on Cancel or before a new scan. Previously,
  quitting mid-scan was still a way to orphan clamscan even with the
  fix above in place.
- Added a GUI status message for the ClamAV batch-scan phase
  specifically, which previously had none - the app would show a
  frozen 0/N progress bar with no explanation while ClamAV worked
  through the file list, which could look identical to a genuine
  hang on a scan with many files.

REQUIREMENTS
------------
Xcode Command Line Tools (free, no full Xcode needed):
    xcode-select --install

HOW TO BUILD
------------
    cd wolfcare_gui
    bash build_app.sh
    open "build/WolfCare Malware Scanner.app"

Ad-hoc signed, not notarized - expect one Gatekeeper prompt the
first time (right-click, Open).

PROJECT LAYOUT
---------------
Sources/
  WolfCareApp.swift    App entry point
  ContentView.swift    Sidebar (Buttons, not List) + routing
  ScanView.swift        Scan tab (target selector also Buttons)
  ScanEngine.swift       Shells out to WolfCare.sh, parses --gui output,
                          cleans up orphaned clamscan processes
  SettingsView.swift     Settings tab UI
  SettingsStore.swift    Reads/writes .wolfcare_config, sanitizes input
  QuarantineView.swift   Quarantine tab UI
  QuarantineStore.swift  Reads/writes quarantine_manifest.txt
  ScheduleView.swift     Scheduled Scans tab UI
  CronStore.swift        Shells out to crontab
  Models.swift           Data types
Info.plist            App bundle metadata
WolfCare.sh            The bash scanner (bundled as the backend)
icon.icns              App icon
build_app.sh           Compiles everything into build/WolfCare Malware Scanner.app



