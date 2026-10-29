import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @AppStorage("lockOnLeave") private var lockOnLeave = true
    @State private var settings: SettingsInfo?
    @State private var startedWith: SettingsInfo?
    @State private var error: String?
    @State private var erasing = false

    private static let sleepChoices: [UInt32?] = [nil, 5, 15, 30, 60]

    var body: some View {
        NavigationStack {
            Form {
                if let binding = Binding($settings) {
                    network(binding)
                    privacy(binding)
                }
                Section {
                    Toggle("Lock when I leave the app", isOn: $lockOnLeave)
                } header: {
                    Text("This phone")
                } footer: {
                    Text("Asks for your password again when you come back. Messages are stored only on this phone, encrypted with your password, and never backed up to iCloud.")
                }
                Section("Good to know") {
                    Text("There are no notifications: they would go through Apple. Open the app to get your messages; the network keeps them for about a day while you're away.")
                    Text("Only Apple's keyboard works in privmsg, and copied invite codes and messages stay on this phone for 3 minutes.")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
                Section {
                    Button("Erase my identity…", role: .destructive) { erasing = true }
                        .accessibilityIdentifier("erase")
                } footer: {
                    Text("Deletes every message, contact and key on this iPhone, for good. It can't be undone.")
                }
            }
            .sheet(isPresented: $erasing) { EraseView() }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear {
                settings = model.settings
                startedWith = startedWith ?? model.settings
            }
            .onChange(of: settings) { old, new in
                guard let new, old != nil, new != old else { return }
                Task {
                    do {
                        try await model.apply(new)
                        error = nil
                    } catch {
                        self.error = describe(error)
                        settings = model.settings
                    }
                }
            }
        }
    }

    private func network(_ settings: Binding<SettingsInfo>) -> some View {
        Section {
            Toggle("Hide my IP address with Tor", isOn: settings.tor)
            Picker("Data use", selection: settings.dataMode) {
                ForEach([DataModeChoice.saver, .balanced, .maximum], id: \.self) { mode in
                    Text("\(modeName(mode)) · about \(dataModeMbPerHour(mode: mode)) MB/hour").tag(mode)
                }
            }
        } header: {
            Text("Network")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("Tor keeps the mixnet from learning your IP address. Leave it on unless Tor is blocked where you are.")
                Text("Saver delivers in a few seconds and uses little data. Maximum sends constant cover traffic: the most protection, and a lot of data.")
                if let startedWith, startedWith.tor != settings.wrappedValue.tor
                    || startedWith.dataMode != settings.wrappedValue.dataMode
                {
                    Text("Close and reopen the app for this to take effect.").bold()
                }
            }
        }
    }

    private func privacy(_ settings: Binding<SettingsInfo>) -> some View {
        Section {
            Toggle("Decoy messages", isOn: settings.decoys)
            Picker("Rest when idle", selection: settings.autoSleepMinutes) {
                ForEach(Self.sleepChoices, id: \.self) { minutes in
                    Text(minutes.map { "after \($0) minutes" } ?? "never").tag(minutes)
                }
            }
        } header: {
            Text("Extra privacy")
        } footer: {
            Text("Decoys: each chat sends a message every 10 seconds or so, real or fake, so nobody can tell when you're actually talking. Your messages (and deletes and other changes) wait for the next one. Resting stops sending (not receiving) after a while without typing, to save data; decoys keep it awake.")
        }
    }

    private func modeName(_ mode: DataModeChoice) -> String {
        switch mode {
        case .saver: "Saver"
        case .balanced: "Balanced"
        case .maximum: "Maximum"
        }
    }
}
