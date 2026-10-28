import SwiftUI

/// Conversations, the connection status, and the ways to add someone.
struct ChatListView: View {
    @Environment(AppModel.self) private var model
    @State private var inviting = false
    @State private var adding = false
    @State private var showingSettings = false
    @State private var path: [String] = []

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    StatusRow(status: model.status)
                }
                if model.contacts.isEmpty && model.invites.isEmpty {
                    Section {
                        Text("No one here yet. Tap **+** to invite a friend, or to enter an invite code someone gave you.")
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    ForEach(model.contacts, id: \.name) { contact in
                        NavigationLink(value: contact.name) {
                            ContactRow(contact: contact)
                        }
                    }
                }
                if !model.invites.isEmpty {
                    Section("Waiting to join") {
                        ForEach(model.invites, id: \.self) { name in
                            Label(name, systemImage: "hourglass")
                                .foregroundStyle(.secondary)
                                .swipeActions {
                                    Button("Cancel", role: .destructive) {
                                        Task { try? await model.remove(name) }
                                    }
                                }
                        }
                    }
                }
            }
            .navigationTitle("Chats")
            .navigationDestination(for: String.self) { name in
                ChatView(name: name)
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Invite a friend", systemImage: "person.badge.plus") { inviting = true }
                        Button("I have an invite code", systemImage: "qrcode.viewfinder") { adding = true }
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add someone")
                }
            }
            .sheet(isPresented: $inviting) { InviteSheet() }
            .sheet(isPresented: $adding) {
                AddContactSheet { name in path = [name] }
            }
            .sheet(isPresented: $showingSettings) { SettingsView() }
        }
        .overlay(alignment: .top) { NoticeBanner() }
    }
}

struct ContactRow: View {
    let contact: ContactInfo

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(contact.displayName).font(.headline)
                if let text = contact.lastText {
                    Text((contact.lastOutgoing ? "You: " : "") + text)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                if let at = contact.lastAt {
                    Text(shortTime(at)).font(.caption).foregroundStyle(.secondary)
                }
                if contact.unread > 0 {
                    Text("\(contact.unread)")
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(.blue))
                }
            }
        }
    }
}

/// How privmsg is connected, in a sentence.
struct StatusRow: View {
    @Environment(AppModel.self) private var model
    let status: ConnectionStatus

    var body: some View {
        switch status {
        case let .startingTor(percent):
            VStack(alignment: .leading, spacing: 6) {
                Label("Starting Tor, so the network can't see your IP address… \(percent)%", systemImage: "network.badge.shield.half.filled")
                ProgressView(value: Double(percent), total: 100)
            }
        case .connecting:
            HStack {
                ProgressView()
                Text("Connecting securely through the mixnet…")
            }
        case .online:
            Label(model.settings?.tor == false ? "Connected (Tor is off)" : "Connected privately",
                  systemImage: "checkmark.shield.fill")
                .foregroundStyle(.green)
        case .resting:
            Label("Resting to save data. You still get messages.", systemImage: "moon.zzz")
                .foregroundStyle(.secondary)
        case let .offline(reason, retryInSecs):
            VStack(alignment: .leading, spacing: 6) {
                Label("Not connected", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text(reason).font(.footnote).foregroundStyle(.secondary)
                Button("Try again now (otherwise in \(retryInSecs) s)") { model.retry() }
                    .font(.footnote)
            }
        case .stopped:
            Label("Stopped. Close the app and open it again.", systemImage: "stop.circle")
                .foregroundStyle(.secondary)
        }
    }
}

/// The model's latest notice, briefly, at the top of the screen.
struct NoticeBanner: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let notice = model.notice {
            Text(notice)
                .font(.subheadline)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(.thinMaterial, in: Capsule())
                .padding(.top, 4)
                .transition(.move(edge: .top).combined(with: .opacity))
                .onTapGesture { model.notice = nil }
        }
    }
}

/// A time for a list: the time today, else the date.
func shortTime(_ unix: UInt64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(unix))
    if Calendar.current.isDateInToday(date) {
        return date.formatted(date: .omitted, time: .shortened)
    }
    return date.formatted(date: .numeric, time: .omitted)
}
