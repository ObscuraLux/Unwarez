import SwiftUI
import UnwarezCore

struct QuarantineView: View {
    @ObservedObject var engine: ScanEngine
    @Binding var selection: SidebarItem?
    @StateObject private var store = GUIQuarantineStore()
    @State private var pendingDelete: QuarantineEntry?
    @State private var pendingMarkSafe: QuarantineEntry?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Quarantine")
                    .font(.largeTitle.bold())
                Spacer()
                Button {
                    store.load()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                Button {
                    rescanAll()
                } label: {
                    Label("Re-scan All", systemImage: "arrow.clockwise.circle")
                }
                .disabled(store.entries.isEmpty || engine.isScanning)
            }

            Text("Re-scanning checks the quarantined copies again against current results - useful after a detection source is fixed or its data updates, to confirm something quarantined earlier is still (or no longer) flagged.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let message = store.message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if store.entries.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("No quarantined files")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(store.entries) { entry in
                            quarantineRow(entry)
                        }
                    }
                }
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .confirmationDialog(
            "Permanently delete this quarantined copy?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )
        ) {
            Button("Delete", role: .destructive) {
                if let entry = pendingDelete {
                    store.delete(entry)
                }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) {
                pendingDelete = nil
            }
        }
        .confirmationDialog(
            "Are you sure this is safe?",
            isPresented: Binding(
                get: { pendingMarkSafe != nil },
                set: { if !$0 { pendingMarkSafe = nil } }
            )
        ) {
            Button("Yes") {
                if let entry = pendingMarkSafe {
                    store.markSafe(entry)
                }
                pendingMarkSafe = nil
            }
            Button("No", role: .cancel) {
                pendingMarkSafe = nil
            }
        } message: {
            if let entry = pendingMarkSafe {
                Text("\((entry.originalPath as NSString).lastPathComponent) will be removed from this list, but the quarantined copy is kept - not deleted. It'll still be scanned and evaluated normally the next time you scan it - this doesn't exempt it from future detection. Only do this for files you've personally verified, like a PUP (potentially unwanted, but not necessarily malicious) you've decided to keep.")
            }
        }
    }

    private func quarantineRow(_ entry: QuarantineEntry) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text((entry.originalPath as NSString).lastPathComponent)
                    .font(.system(size: 13, weight: .medium))
                Text(entry.originalPath)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(entry.reason) · \(entry.timestamp)")
                    .font(.caption2)
                    .foregroundStyle(entry.reason == "PUP" ? Color.orange : Color.secondary)
            }

            Spacer()

            Button("Re-scan") {
                rescan(entry)
            }
            .buttonStyle(.bordered)
            .disabled(engine.isScanning)

            Button("Restore") {
                store.restore(entry)
            }
            .buttonStyle(.bordered)

            Button("Mark as Safe") {
                pendingMarkSafe = entry
            }
            .buttonStyle(.bordered)
            .tint(.green)

            Button("Delete") {
                pendingDelete = entry
            }
            .buttonStyle(.bordered)
            .tint(.red)
        }
        .padding(10)
        .background(Color.gray.opacity(0.08))
        .cornerRadius(8)
    }

    private func rescan(_ entry: QuarantineEntry) {
        selection = .scan
        engine.rescanFlagged(paths: [store.quarantinedPath(for: entry)])
    }

    private func rescanAll() {
        guard !store.entries.isEmpty else { return }
        selection = .scan
        engine.rescanFlagged(paths: store.entries.map { store.quarantinedPath(for: $0) })
    }
}
