import SwiftUI

/// One conversation.
struct ChatView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let name: String

    @State private var messages: [MessageInfo] = []
    @State private var draft = ""
    @State private var sending = false
    @State private var error: String?
    @State private var safetyNumber: String?
    @State private var confirmingRemove = false

    private var contact: ContactInfo? {
        model.contacts.first { $0.name == name }
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { scroller in
                ScrollView {
                    LazyVStack(spacing: 6) {
                        if let contact, contact.disappearAfter != nil {
                            Label("Messages disappear after \(contact.disappearLabel)", systemImage: "timer")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(.vertical, 8)
                        }
                        ForEach(Array(messages.enumerated()), id: \.offset) { index, message in
                            Bubble(message: message).id(index)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .defaultScrollAnchor(.bottom)
                .onChange(of: messages.count) { _, count in
                    withAnimation { scroller.scrollTo(count - 1, anchor: .bottom) }
                }
            }
            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
                    .padding(.top, 4)
            }
            if model.queued > 0 {
                Text("Waiting to leave with the next decoy…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.top, 4)
            }
            composer
        }
        .navigationTitle(contact?.displayName ?? name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .topBarTrailing) { menu } }
        .onAppear(perform: reload)
        .onChange(of: model.revision) { _, _ in reload() }
        .alert("Safety number", isPresented: .constant(safetyNumber != nil), presenting: safetyNumber) { _ in
            Button("OK") { safetyNumber = nil }
        } message: { number in
            Text("\(number)\n\nCompare it with \(contact?.displayName ?? name) in person or on a call (not in a chat app). If it matches, nobody intercepted your invite. If it doesn't, remove the contact and connect again with a new invite.")
        }
        .confirmationDialog(
            "Remove \(contact?.displayName ?? name)?",
            isPresented: $confirmingRemove,
            titleVisibility: .visible
        ) {
            Button("Remove and delete the chat", role: .destructive) {
                Task {
                    do {
                        try await model.remove(name)
                        dismiss()
                    } catch {
                        self.error = describe(error)
                    }
                }
            }
        } message: {
            Text("They are not told. To talk again, one of you sends a new invite.")
        }
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .accessibilityIdentifier("messageField")
                .lineLimit(1...6)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 18).fill(Color(.secondarySystemBackground)))
                // Keeps what you type out of the keyboard's learned words.
                .autocorrectionDisabled()
            Button {
                Task { await send() }
            } label: {
                Image(systemName: sending ? "ellipsis.circle.fill" : "arrow.up.circle.fill")
                    .font(.system(size: 32))
            }
            .disabled(sending || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityLabel("Send")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var menu: some View {
        Menu {
            Menu("Disappearing messages", systemImage: "timer") {
                ForEach(timerChoices(), id: \.label) { choice in
                    Button {
                        Task { await setTimer(choice.seconds) }
                    } label: {
                        if contact?.disappearAfter == choice.seconds {
                            Label(choice.label, systemImage: "checkmark")
                        } else {
                            Text(choice.label)
                        }
                    }
                }
            }
            Button("Safety number", systemImage: "checkmark.shield") {
                Task {
                    do {
                        safetyNumber = try await model.safetyNumber(with: name)
                    } catch {
                        self.error = describe(error)
                    }
                }
            }
            Button("Give them a new address", systemImage: "arrow.triangle.2.circlepath") {
                Task {
                    do {
                        try await model.rotate(name)
                        model.show("New address sent. The old one keeps working until they've switched.")
                    } catch {
                        self.error = describe(error)
                    }
                }
            }
            Button("Remove contact", systemImage: "trash", role: .destructive) {
                confirmingRemove = true
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
    }

    private func reload() {
        messages = model.messages(with: name)
        if (contact?.unread ?? 0) > 0 {
            model.markRead(name)
        }
    }

    private func send() async {
        let text = draft
        sending = true
        error = nil
        draft = ""
        defer { sending = false }
        do {
            try await model.send(text, to: name)
        } catch {
            draft = text
            self.error = "Not sent: \(describe(error))"
        }
    }

    private func setTimer(_ seconds: UInt64?) async {
        do {
            try await model.setTimer(seconds, for: name)
            error = nil
        } catch {
            self.error = describe(error)
        }
    }
}

private struct Bubble: View {
    let message: MessageInfo

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 48) }
            VStack(alignment: message.outgoing ? .trailing : .leading, spacing: 2) {
                Text(message.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .foregroundStyle(message.outgoing ? .white : .primary)
                    .background(
                        RoundedRectangle(cornerRadius: 18)
                            .fill(message.outgoing ? Color.blue : Color(.secondarySystemBackground))
                    )
                    .textSelection(.enabled)
                Text(shortTime(message.at))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
            }
            if !message.outgoing { Spacer(minLength: 48) }
        }
    }
}
