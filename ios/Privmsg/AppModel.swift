import Foundation
import Observation
import UIKit

/// The app's state, kept in step with the Rust messenger.
@Observable
@MainActor
final class AppModel {
    enum Phase {
        /// No profile yet: choose a passphrase.
        case setup
        /// A profile, still locked.
        case locked
        case ready
    }

    private(set) var phase: Phase
    private(set) var status: ConnectionStatus = .connecting
    private(set) var contacts: [ContactInfo] = []
    private(set) var invites: [String] = []
    private(set) var settings: SettingsInfo?
    private(set) var queued: UInt32 = 0
    /// Bumped whenever the messenger reports a change, so open chats reload.
    private(set) var revision = 0
    /// A short message for the user, shown for a few seconds.
    var notice: String?
    /// The app's own lock screen is up (after leaving the app, if that's on).
    var screenLocked = false

    private(set) var messenger: Messenger?
    private let profileDirectory = Storage.profileDirectory()
    private var backgroundSince: Date?
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var noticeTask: Task<Void, Never>?

    /// Ask for the passphrase again after leaving the app.
    var lockOnLeave: Bool {
        get { UserDefaults.standard.object(forKey: "lockOnLeave") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "lockOnLeave") }
    }

    init() {
        phase = profileExists(dir: profileDirectory.path) ? .locked : .setup
    }

    // MARK: Starting

    func create(passphrase: String) async throws {
        try await start { dir, listener in
            try Messenger.create(dir: dir, passphrase: passphrase, listener: listener)
        }
    }

    func unlock(passphrase: String) async throws {
        try await start { dir, listener in
            try Messenger.open(dir: dir, passphrase: passphrase, listener: listener)
        }
    }

    private func start(
        _ make: @escaping @Sendable (String, Listener) throws -> Messenger
    ) async throws {
        let dir = profileDirectory.path
        let listener = ListenerBridge(model: self)
        // The passphrase check is deliberately slow; keep it off the main thread.
        let messenger = try await Task.detached { try make(dir, listener) }.value
        self.messenger = messenger
        status = messenger.status()
        refresh()
        phase = .ready
    }

    // MARK: From the messenger

    fileprivate func statusChanged(_ status: ConnectionStatus) {
        self.status = status
    }

    fileprivate func refresh() {
        guard let messenger else { return }
        contacts = messenger.contacts()
        invites = messenger.invites()
        settings = messenger.settings()
        queued = messenger.queued()
        revision += 1
    }

    func show(_ text: String) {
        notice = text
        noticeTask?.cancel()
        noticeTask = Task {
            try? await Task.sleep(for: .seconds(5))
            if !Task.isCancelled { notice = nil }
        }
    }

    // MARK: Leaving and coming back

    func enteredBackground() {
        backgroundSince = Date()
        if phase == .ready && lockOnLeave {
            screenLocked = true
        }
        // A little time to hand off anything still being sent; then iOS
        // freezes the app and the connections drop.
        if messenger != nil && backgroundTask == .invalid {
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "send") { [weak self] in
                Task { @MainActor in self?.endBackgroundTask() }
            }
        }
    }

    func becameActive() {
        endBackgroundTask()
        if let since = backgroundSince {
            backgroundSince = nil
            messenger?.foreground(awaySecs: UInt64(max(0, Date().timeIntervalSince(since))))
        }
    }

    private func endBackgroundTask() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    func unlockScreen(passphrase: String) async -> Bool {
        guard let messenger else { return false }
        let ok = await messenger.checkPassphrase(passphrase: passphrase)
        if ok { screenLocked = false }
        return ok
    }

    // MARK: Doing

    func messages(with name: String) -> [MessageInfo] {
        messenger?.messages(name: name) ?? []
    }

    func markRead(_ name: String) {
        messenger?.markRead(name: name)
    }

    func send(_ text: String, to name: String) async throws {
        try await messenger?.send(name: name, text: text)
    }

    func createInvite(for name: String) async throws -> String {
        guard let messenger else { throw MobileError.Failed(message: "Not started yet.") }
        return try await messenger.createInvite(name: name)
    }

    func acceptInvite(code: String, name: String) async throws {
        try await messenger?.acceptInvite(code: code, name: name)
    }

    func setTimer(_ seconds: UInt64?, for name: String) async throws {
        try await messenger?.setTimer(name: name, after: seconds)
    }

    func safetyNumber(with name: String) async throws -> String {
        guard let messenger else { throw MobileError.Failed(message: "Not started yet.") }
        return try await messenger.safetyNumber(name: name)
    }

    func rotate(_ name: String) async throws {
        try await messenger?.rotate(name: name)
    }

    func remove(_ name: String) async throws {
        try await messenger?.remove(name: name)
    }

    func apply(_ settings: SettingsInfo) async throws {
        try await messenger?.setSettings(settings: settings)
    }

    func retry() {
        messenger?.retry()
    }
}

/// Receives the messenger's calls (on its threads) and hands them to the
/// model on the main thread.
private final class ListenerBridge: Listener, @unchecked Sendable {
    weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func status(status: ConnectionStatus) {
        Task { @MainActor [weak self] in self?.model?.statusChanged(status) }
    }

    func changed() {
        Task { @MainActor [weak self] in self?.model?.refresh() }
    }

    func notice(text: String) {
        Task { @MainActor [weak self] in self?.model?.show(text) }
    }
}
