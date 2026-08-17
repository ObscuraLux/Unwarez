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
struct WolfCareApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // .defaultSize needs macOS 13+ and was dropped for the 12.0
        // floor - .frame's minWidth/minHeight (10.15+) still keeps the
        // window at a sane size, just without a specific larger
        // preferred initial size.
        WindowGroup {
            ContentView()
                .frame(minWidth: 850, minHeight: 550)
        }
    }
}
