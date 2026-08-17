import SwiftUI
import UnwarezCore

struct ScheduleView: View {
    @StateObject private var store = ScheduleStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Scheduled scans")
                .font(.largeTitle.bold())

            Text("Current schedule")
                .font(.subheadline.bold())

            if let schedule = store.currentSchedule {
                VStack(alignment: .leading, spacing: 4) {
                    Text(description(for: schedule))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.gray.opacity(0.08))
                .cornerRadius(8)
            } else {
                Text("No scheduled scans set up.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

            Text("Scheduled scans run in the background via a LaunchAgent, with no window popping up. Results save to the usual report folder - check Quarantine or the report files afterward.")
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

    private func description(for schedule: ScheduledScanInfo) -> String {
        let frequency = schedule.frequency == .daily ? "Daily, 9:00 AM" : "Weekly, Sundays 9:00 AM"
        return "\(frequency) — \(schedule.target.label)"
    }
}
