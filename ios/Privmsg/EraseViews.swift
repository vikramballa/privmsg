import SwiftUI

/// Settings → Erase my identity: what goes and what can't be reached, then
/// the word ERASE, the password, and one last "are you sure".
struct EraseView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var word = ""
    @State private var passphrase = ""
    @State private var tellContacts = true
    @State private var confirming = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Every message, every contact, your keys and addresses on this iPhone — and the key in its Secure Enclave that could unlock any old copy of them. Nothing can bring them back, not even your password.")
                } header: {
                    Text("Erased for good")
                }
                Section {
                    Text("What your contacts have (unless you ask their apps to delete it below), screenshots, and any copy of this iPhone someone made before.")
                    Text("Deleting data can be against the law when it is evidence, for example during a search or under a court order.")
                } header: {
                    Text("Out of reach")
                }
                if !model.contacts.isEmpty {
                    Section {
                        Toggle("Ask my contacts' apps to delete our chats", isOn: $tellContacts)
                    } footer: {
                        Text("Their apps delete your messages and theirs, and forget you. They will see that you erased your identity. Without this, they keep their copies.")
                    }
                }
                Section {
                    TextField("Type ERASE", text: $word)
                        .accessibilityIdentifier("eraseWord")
                    SecureField("Your password", text: $passphrase)
                        .accessibilityIdentifier("erasePassword")
                } header: {
                    Text("To confirm")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
                Section {
                    Button(role: .destructive) {
                        confirming = true
                    } label: {
                        HStack {
                            Text("Erase everything")
                            if working { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(working || word != "ERASE" || passphrase.isEmpty)
                    .accessibilityIdentifier("eraseEverything")
                }
            }
            .navigationTitle("Erase my identity")
            .navigationBarTitleDisplayMode(.inline)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(working)
                }
            }
            .interactiveDismissDisabled(working)
            .alert("Erase everything now?", isPresented: $confirming) {
                Button("Erase", role: .destructive) { Task { await erase() } }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This can't be undone.")
            }
        }
    }

    private func erase() async {
        working = true
        defer { working = false }
        do {
            let tell = tellContacts && !model.contacts.isEmpty
            try await model.eraseIdentity(passphrase: passphrase, tellContacts: tell)
            passphrase = ""
        } catch {
            self.error = describe(error)
        }
    }
}

/// After an erase: nothing is left to show. Closing the app finishes it
/// (Tor, built into the app, only stops with it).
struct ErasedView: View {
    let note: String

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("Erased")
                .font(.title.bold())
            Text("Your identity is gone from this iPhone.")
            if !note.isEmpty {
                Text(note).foregroundStyle(.secondary)
            }
            Text("Close privmsg to finish. The next time it opens, it starts fresh.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button("Close privmsg") { exit(0) }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("closeAfterErase")
        }
        .multilineTextAlignment(.center)
        .padding(32)
    }
}
