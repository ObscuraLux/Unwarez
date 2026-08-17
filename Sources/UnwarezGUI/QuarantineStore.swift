import Foundation
import Combine
import UnwarezCore

/// Thin `ObservableObject` wrapper around `UnwarezCore.QuarantineStore` -
/// all the actual manifest/file logic lives there now (shared with the
/// CLI), this just republishes it for SwiftUI.
@MainActor
final class GUIQuarantineStore: ObservableObject {
    @Published var entries: [QuarantineEntry] = []
    @Published var message: String?

    init() {
        load()
    }

    func load() {
        entries = UnwarezCore.QuarantineStore.loadEntries()
    }

    func restore(_ entry: QuarantineEntry) {
        switch UnwarezCore.QuarantineStore.restore(entry) {
        case .success:
            message = "Restored to \(entry.originalPath)"
        case .failure(let error):
            message = error.description
        }
    }

    func quarantinedPath(for entry: QuarantineEntry) -> String {
        UnwarezCore.QuarantineStore.quarantinedFileURL(for: entry).path
    }

    func markSafe(_ entry: QuarantineEntry) {
        UnwarezCore.QuarantineStore.markSafe(entry)
        load()
        message = "Removed from the quarantine list. The quarantined copy was kept (not deleted), and it'll be evaluated normally on any future scan."
    }

    func delete(_ entry: QuarantineEntry) {
        UnwarezCore.QuarantineStore.delete(entry)
        load()
        message = "Deleted"
    }
}
