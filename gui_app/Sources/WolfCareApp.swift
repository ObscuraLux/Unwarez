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
        WindowGroup {
            ContentView()
                .frame(minWidth: 850, minHeight: 550)
        }
        .defaultSize(width: 950, height: 620)
    }
}
