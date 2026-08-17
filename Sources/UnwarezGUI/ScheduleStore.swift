import Foundation
import Combine
import UnwarezCore

/// Wraps `UnwarezCore.LaunchAgentStore` - replaces the old crontab-based
/// `CronStore`. A scheduled scan needs to run even when the GUI app
/// itself isn't open, so the LaunchAgent invokes the bundled `unwarez-cli`
/// executable (Contents/Resources/unwarez-cli) rather than the GUI binary.
@MainActor
final class ScheduleStore: ObservableObject {
    @Published var currentSchedule: ScheduledScanInfo?
    @Published var message: String?

    private let store = LaunchAgentStore()

    private var cliPath: String? {
        Bundle.main.path(forResource: "unwarez-cli", ofType: nil)
    }

    // Deliberately not loaded in init() - see SettingsStore for why.
    func refresh() {
        Task {
            let schedule = await store.currentSchedule()
            currentSchedule = schedule
        }
    }

    func addDaily() {
        guard let cliPath else {
            message = "Could not find the bundled unwarez-cli executable."
            return
        }
        Task {
            switch await store.schedule(frequency: .daily, cliExecutablePath: cliPath) {
            case .success:
                message = "Daily scan scheduled for 9:00 AM"
            case .failure(let error):
                message = error.description
            }
            refresh()
        }
    }

    func addWeekly() {
        guard let cliPath else {
            message = "Could not find the bundled unwarez-cli executable."
            return
        }
        Task {
            switch await store.schedule(frequency: .weekly, cliExecutablePath: cliPath) {
            case .success:
                message = "Weekly scan scheduled for Sundays, 9:00 AM"
            case .failure(let error):
                message = error.description
            }
            refresh()
        }
    }

    func removeAll() {
        Task {
            let removed = await store.removeExisting()
            message = removed ? "Scheduled scans removed" : "Could not remove the scheduled scan."
            refresh()
        }
    }
}
