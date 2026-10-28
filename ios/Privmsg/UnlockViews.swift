import SwiftUI

/// First start: choose the passphrase that locks the profile.
struct SetupView: View {
    @Environment(AppModel.self) private var model
    @State private var passphrase = ""
    @State private var again = ""
    @State private var working = false
    @State private var error: String?

    private var minimum: Int { Int(minPassphraseLength()) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("privmsg sends messages through Tor and the Nym mixnet, so nobody can see who you talk to. There is no account and no server: everything stays on this phone.")
                }
                Section {
                    SecureField("Password (at least \(minimum) characters)", text: $passphrase)
                    SecureField("Type it again", text: $again)
                } header: {
                    Text("Choose a password")
                } footer: {
                    Text("It locks your messages on this phone. It can't be recovered, so pick one you'll remember. Four random words, like \"maple cloud river tiger\", are strong and easy to remember.")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
                Section {
                    Button {
                        Task { await create() }
                    } label: {
                        HStack {
                            Text("Create my profile")
                            if working { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(working || passphrase.count < minimum || again.isEmpty)
                }
            }
            .navigationTitle("Welcome")
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
        }
    }

    private func create() async {
        guard passphrase == again else {
            error = "Those didn't match. Type them again."
            again = ""
            return
        }
        working = true
        defer { working = false }
        do {
            try await model.create(passphrase: passphrase)
        } catch {
            self.error = describe(error)
        }
    }
}

/// The profile exists: type the passphrase to open it.
struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @State private var passphrase = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        PassphrasePrompt(
            title: "privmsg",
            prompt: "Type your password to open your messages.",
            passphrase: $passphrase,
            working: working,
            error: error
        ) {
            working = true
            defer { working = false }
            do {
                try await model.unlock(passphrase: passphrase)
                passphrase = ""
            } catch {
                self.error = describe(error)
                passphrase = ""
            }
        }
    }
}

/// Back in the app after leaving it, with "lock when leaving" on. The
/// messenger kept running; this only covers the screen.
struct ScreenLockView: View {
    @Environment(AppModel.self) private var model
    @State private var passphrase = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        PassphrasePrompt(
            title: "Locked",
            prompt: "Type your password to continue.",
            passphrase: $passphrase,
            working: working,
            error: error
        ) {
            working = true
            defer { working = false }
            if await model.unlockScreen(passphrase: passphrase) {
                error = nil
            } else {
                error = "That's not the password."
            }
            passphrase = ""
        }
    }
}

private struct PassphrasePrompt: View {
    let title: String
    let prompt: String
    @Binding var passphrase: String
    let working: Bool
    let error: String?
    let submit: () async -> Void
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.fill")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(title).font(.largeTitle.bold())
            Text(prompt).foregroundStyle(.secondary)
            SecureField("Password", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit { Task { await submit() } }
                .disabled(working)
            if let error {
                Text(error).foregroundStyle(.red).multilineTextAlignment(.center)
            }
            Button {
                Task { await submit() }
            } label: {
                if working {
                    ProgressView()
                } else {
                    Text("Unlock").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(working || passphrase.isEmpty)
            Spacer()
            Spacer()
        }
        .padding(.horizontal, 32)
        .onAppear { focused = true }
    }
}
