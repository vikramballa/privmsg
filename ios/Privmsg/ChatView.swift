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
    @State private var confirmingClear = false
    /// The message whose "Delete…" was picked, while asking how.
    @State private var deleting: MessageInfo?

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
                        if let contact, contact.clearedByThem {
                            Label("\(contact.displayName) cleared the chat", systemImage: "trash")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(.vertical, 8)
                        }
                        ForEach(messages, id: \.id) { message in
                            Bubble(message: message) { deleting = message }
                                .id(message.id)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .defaultScrollAnchor(.bottom)
                .onChange(of: messages.count) { old, new in
                    // Down to a new message, but not on a delete.
                    if new > old, let last = messages.last {
                        withAnimation { scroller.scrollTo(last.id, anchor: .bottom) }
                    }
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
        .confirmationDialog(
            "Delete this message?",
            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
            titleVisibility: .visible,
            presenting: deleting
        ) { message in
            Button("Delete for me", role: .destructive) {
                Task { await delete(message, everyone: false) }
            }
            if message.canDeleteForEveryone {
                Button("Delete for everyone", role: .destructive) {
                    Task { await delete(message, everyone: true) }
                }
            }
        } message: { message in
            if message.canDeleteForEveryone {
                Text("\u{201C}For everyone\u{201D} also deletes it from \(contact?.displayName ?? name)'s phone. If they already read it, that can't be undone.")
            }
        }
        .confirmationDialog(
            "Delete all messages with \(contact?.displayName ?? name)?",
            isPresented: $confirmingClear,
            titleVisibility: .visible
        ) {
            Button("Delete for me", role: .destructive) {
                Task { await clear(everyone: false) }
            }
            Button("Delete for everyone", role: .destructive) {
                Task { await clear(everyone: true) }
            }
        } message: {
            Text("\(contact?.displayName ?? name) stays in your chats. \u{201C}For everyone\u{201D} also empties their copy; they see that you cleared it.")
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
            Button("Delete chat", systemImage: "trash", role: .destructive) {
                confirmingClear = true
            }
            Button("Remove contact", systemImage: "person.crop.circle.badge.minus", role: .destructive) {
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

    private func delete(_ message: MessageInfo, everyone: Bool) async {
        do {
            try await model.deleteMessage(message.id, with: name, everyone: everyone)
            error = nil
        } catch {
            self.error = "Not deleted: \(describe(error))"
        }
    }

    private func clear(everyone: Bool) async {
        do {
            try await model.clearChat(with: name, everyone: everyone)
            error = nil
        } catch {
            self.error = "Not deleted: \(describe(error))"
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
    /// "Delete…" was picked from the long-press menu.
    let onDelete: () -> Void

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
                    .contextMenu {
                        Button("Copy", systemImage: "doc.on.doc") {
                            Clipboard.copyPrivately(message.text)
                        }
                        Button("Delete…", systemImage: "trash", role: .destructive, action: onDelete)
                    }
                Text(shortTime(message.at))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
            }
            if !message.outgoing { Spacer(minLength: 48) }
        }
    }
}
