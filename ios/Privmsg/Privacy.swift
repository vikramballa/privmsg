import Foundation
import UIKit
import UniformTypeIdentifiers

/// Where the profile lives, and how it is kept off backups.
enum Storage {
    /// Application Support/privmsg: encrypted with the passphrase by privmsg,
    /// with iOS file protection on top, and never backed up to iCloud or a
    /// computer.
    static func profileDirectory() -> URL {
        let fm = FileManager.default
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var dir = base.appendingPathComponent("privmsg", isDirectory: true)
        // Files open while the phone locks stay usable (the mixnet keeps its
        // databases open); everything else is sealed until it is unlocked.
        let protection: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.completeUnlessOpen]
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: protection)
        try? fm.setAttributes(protection, ofItemAtPath: dir.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }
}

enum Clipboard {
    /// How long a copied invite code or message stays on the clipboard.
    static let lifetime: TimeInterval = 180

    /// Copy `text` for this phone only (not to other Apple devices through
    /// Universal Clipboard), and only for a few minutes.
    static func copyPrivately(_ text: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: text]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(lifetime)]
        )
    }
}

/// An error in words for the user.
func describe(_ error: Error) -> String {
    if case let MobileError.Failed(message) = error {
        return message
    }
    return error.localizedDescription
}
