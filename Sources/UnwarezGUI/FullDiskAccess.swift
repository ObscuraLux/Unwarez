import Foundation
import AppKit

/// Checks whether this app actually has Full Disk Access, instead of
/// just always showing a static "you probably want this" hint. TCC
/// (the macOS privacy subsystem) gates access at the syscall level, not
/// via POSIX permission bits, so a plain `FileManager.isReadableFile`
/// check against a normal path can't detect it - reading a path that's
/// unconditionally FDA-gated is the reliable way to actually know.
enum FullDiskAccess {
    /// Every Mac has this file, and reading it (regardless of POSIX
    /// permissions) is only possible with Full Disk Access - it's the
    /// standard TCC probe path.
    private static let probePath = "/Library/Application Support/com.apple.TCC/TCC.db"

    static func isGranted() -> Bool {
        guard let handle = FileHandle(forReadingAtPath: probePath) else { return false }
        handle.closeFile()
        return true
    }

    static func openPrivacySettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") else { return }
        NSWorkspace.shared.open(url)
    }
}
