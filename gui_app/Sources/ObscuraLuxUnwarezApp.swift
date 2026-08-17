import SwiftUI
import AppKit

/// Ensures a scan's background clamscan process gets cleaned up if the
/// app itself is quit while a scan is still running - without this,
/// quitting mid-scan orphans clamscan exactly the same way a stale
/// build (from before this fix existed) could.
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        ScanEngine.killOrphanedClamscan()
    }
}

@main
struct ObscuraLuxUnwarezApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    // CFBundleName/CFBundleDisplayName in Info.plist are deliberately
    // versionless - that's what drives the system menu bar's app name
    // (top of screen, next to the Apple logo), which shouldn't need
    // updating every version bump. The window's own title bar is set
    // explicitly here instead, reading CFBundleShortVersionString so
    // there's still only one place (Info.plist) to update per release.
    private var windowTitle: String {
        guard let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
              !version.isEmpty else {
            return "ObscuraLux Unwarez"
        }
        return "ObscuraLux Unwarez v\(version)"
    }

    var body: some Scene {
        // .defaultSize needs macOS 13+ and was dropped for the 12.0
        // floor - .frame's minWidth/minHeight (10.15+) still keeps the
        // window at a sane size, just without a specific larger
        // preferred initial size.
        WindowGroup(windowTitle) {
            ContentView()
                .frame(minWidth: 850, minHeight: 550)
        }
    }
}
