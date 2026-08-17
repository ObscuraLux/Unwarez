import SwiftUI
import AppKit
import UnwarezCore

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case scan = "Scan"
    case quarantine = "Quarantine"
    case logs = "Logs"
    case settings = "Settings"
    case schedule = "Scheduled Scans"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .scan: return "magnifyingglass.circle"
        case .quarantine: return "lock.shield"
        case .logs: return "doc.text.magnifyingglass"
        case .settings: return "gearshape"
        case .schedule: return "clock"
        }
    }
}

struct ContentView: View {
    @State private var selection: SidebarItem? = .scan
    @StateObject private var scanEngine = ScanEngine()

    var body: some View {
        // NavigationView rather than NavigationSplitView: the latter
        // needs macOS 13+, NavigationView gives the same two-pane
        // sidebar/detail layout on macOS back to 10.15. No selection
        // binding is used here (plain Buttons + @State, matching the
        // rest of this app's established workaround for the List/Picker
        // selection-binding bug in DEVELOPER_NOTES.md), so nothing about
        // that switch is version-sensitive.
        NavigationView {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(SidebarItem.allCases) { item in
                    Button {
                        selection = item
                    } label: {
                        HStack {
                            Label(item.rawValue, systemImage: item.icon)
                            Spacer()
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 10)
                        .background(
                            selection == item
                                ? Color.accentColor.opacity(0.18)
                                : Color.clear
                        )
                        .cornerRadius(6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                Spacer()
            }
            .padding(8)
            .navigationTitle("ObscuraLux Unwarez")

            Group {
                switch selection {
                case .scan:
                    ScanView(engine: scanEngine, selection: $selection)
                case .quarantine:
                    QuarantineView(engine: scanEngine, selection: $selection)
                case .logs:
                    LogsView()
                case .settings:
                    SettingsView()
                case .schedule:
                    ScheduleView()
                case .none:
                    Text("Select a section")
                        .foregroundStyle(.secondary)
                }
            }
            .frame(minWidth: 500, minHeight: 400)
        }
    }
}

struct PlaceholderView: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "hammer.circle")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text(title).font(.title2.bold())
            Text(subtitle)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
