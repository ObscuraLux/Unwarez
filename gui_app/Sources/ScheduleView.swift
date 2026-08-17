import SwiftUI

struct ScheduleView: View {
    @StateObject private var store = CronStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Scheduled scans")
                .font(.largeTitle.bold())

            Text("Current schedule")
                .font(.subheadline.bold())

            if store.currentEntries.isEmpty {
                Text("No scheduled scans set up.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(store.currentEntries, id: \.self) { entry in
                        Text(entry)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(10)
                .background(Color.gray.opacity(0.08))
                .cornerRadius(8)
            }

            HStack(spacing: 10) {
                Button("Add daily scan (Downloads, 9am)") {
                    store.addDaily()
                }
                .buttonStyle(.bordered)

                Button("Add weekly scan (Home, Sunday 9am)") {
                    store.addWeekly()
                }
                .buttonStyle(.bordered)

                Button("Remove all") {
                    store.removeAll()
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }

            if let message = store.message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text("Scheduled scans run in the background using the same target folders as the CLI menu, with no window popping up. Results save to the usual report folder - check Quarantine or the report files afterward.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            store.refresh()
        }
    }
}
