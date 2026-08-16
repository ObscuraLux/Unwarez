import SwiftUI
import AppKit

struct LogsView: View {
    @StateObject private var store = LogsStore()
    @State private var selected: LogEntry?
    @State private var pendingDelete: LogEntry?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Logs")
                    .font(.largeTitle.bold())
                Spacer()
                Button {
                    store.load()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                Button {
                    revealFolder()
                } label: {
                    Label("Open Reports Folder", systemImage: "folder")
                }
            }

            Text("Every scan (from the app, the CLI, or a scheduled run) saves a full report here - every file checked, not just detections.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if store.entries.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("No scan reports yet")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(store.entries) { entry in
                                logRow(entry)
                            }
                        }
                    }
                    .frame(width: 260)

                    Group {
                        if let selected {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(selected.filename)
                                        .font(.subheadline.bold())
                                    Spacer()
                                    Button("Reveal in Finder") { reveal(selected) }
                                        .font(.caption)
                                }
                                ScrollView {
                                    Text(store.content(for: selected))
                                        .font(.system(size: 11, design: .monospaced))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .textSelection(.enabled)
                                        .padding(8)
                                }
                                .background(Color.gray.opacity(0.06))
                                .cornerRadius(8)
                            }
                        } else {
                            Text("Select a report to view it")
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
                        }
                    }
                }
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { store.load() }
        .confirmationDialog(
            "Delete this report?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )
        ) {
            Button("Delete", role: .destructive) {
                if let entry = pendingDelete {
                    if selected?.id == entry.id { selected = nil }
                    store.delete(entry)
                }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        }
    }

    private func logRow(_ entry: LogEntry) -> some View {
        Button {
            selected = entry
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(displayDate(entry.date))
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                    Text(entry.filename)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    pendingDelete = entry
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.red)
            }
            .padding(8)
            .background(
                selected?.id == entry.id
                    ? Color.accentColor.opacity(0.18)
                    : Color.gray.opacity(0.08)
            )
            .cornerRadius(6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func displayDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private func reveal(_ entry: LogEntry) {
        NSWorkspace.shared.selectFile(entry.path, inFileViewerRootedAtPath: store.reportsDirPath)
    }

    private func revealFolder() {
        try? FileManager.default.createDirectory(atPath: store.reportsDirPath, withIntermediateDirectories: true)
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: store.reportsDirPath)
    }
}
