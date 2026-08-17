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
                if store.vtKeychainAccessDenied {
                    keychainAccessDeniedWarning
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("MalwareBazaar API key").font(.subheadline.bold())
                SecureField("Optional", text: $store.mbApiKey)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                Link("Get a free key", destination: URL(string: "https://auth.abuse.ch/")!)
                    .font(.caption)
                if store.mbKeychainAccessDenied {
                    keychainAccessDeniedWarning
                }
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

    /// A previously-saved key exists in the Keychain but couldn't be read
    /// back - most likely this build's ad-hoc code signature no longer
    /// matches the one the item's access control was created under (ad-
    /// hoc signatures aren't stable across rebuilds the way a real
    /// Developer ID is), so macOS is refusing silent access. Re-entering
    /// and saving the key re-creates it under the current signature.
    private var keychainAccessDeniedWarning: some View {
        Label("Saved in Keychain, but this build can't read it back (likely a signature mismatch after a rebuild). Re-enter and save to fix.", systemImage: "exclamationmark.triangle.fill")
            .font(.caption)
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
    }
}
