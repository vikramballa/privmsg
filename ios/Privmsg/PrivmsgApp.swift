import SwiftUI
import UIKit

@main
struct PrivmsgApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                // Covers the screen whenever the app isn't in front, so the
                // app switcher's snapshot shows nothing.
                .overlay {
                    if scenePhase != .active {
                        PrivacyCover()
                    }
                }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: model.enteredBackground()
            case .active: model.becameActive()
            default: break
            }
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    /// Only Apple's own keyboard: a third-party one could send what is typed
    /// anywhere.
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication
            .ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        switch model.phase {
        case .setup: SetupView()
        case .locked: UnlockView()
        case .ready:
            if model.screenLocked {
                ScreenLockView()
            } else {
                ChatListView()
            }
        case .erased(let note): ErasedView(note: note)
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
        }
    }
}
