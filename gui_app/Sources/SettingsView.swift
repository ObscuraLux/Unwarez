import SwiftUI

struct SettingsView: View {
    @StateObject private var store = SettingsStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Settings")
                .font(.largeTitle.bold())

            Text("Both keys below are optional. Scans already work fully without them, using ReleaseSeal, CIRCL, the built-in threat-intel list, and ClamAV if installed. Adding a key turns on that one extra check.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 6) {
                Text("VirusTotal API key").font(.subheadline.bold())
                SecureField("Optional", text: $store.vtApiKey)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Link("Get a free key", destination: URL(string: "https://www.virustotal.com/gui/join-us")!)
                    .font(.caption)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("MalwareBazaar API key").font(.subheadline.bold())
                SecureField("Optional", text: $store.mbApiKey)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Link("Get a free key", destination: URL(string: "https://auth.abuse.ch/")!)
                    .font(.caption)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Alert email").font(.subheadline.bold())
                TextField("Optional", text: $store.alertEmail)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Text("Sent via Mail.app when a scan finds threats. Needs Mail configured with an account.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 10) {
                Button("Save") {
                    store.save()
                }
                .buttonStyle(.borderedProminent)

                if let message = store.saveMessage {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(message.contains("but:") ? Color.yellow : Color.secondary)
                }
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { store.load() }
    }
}
