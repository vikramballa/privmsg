import Foundation
import Security

/// Seals the profile's device key with a key that lives in this iPhone's
/// Secure Enclave and never leaves it. Erasing the identity deletes that
/// key, so the sealed device key — and with it every copy of the profile
/// ever written, wherever it lingers — can't be opened again, by anyone.
///
/// The simulator has no Secure Enclave; there the key is an ordinary
/// keychain key, which is enough to try the app.
final class SecureEnclaveVault: KeyVault, @unchecked Sendable {
    private static let tag = Data("privmsg.device-key-guard".utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    func seal(key: Data) throws -> Data {
        let guardKey = try existingKey() ?? makeKey()
        guard let publicKey = SecKeyCopyPublicKey(guardKey) else {
            throw MobileError.Failed(message: "The Secure Enclave key has no public half.")
        }
        var error: Unmanaged<CFError>?
        guard let sealed = SecKeyCreateEncryptedData(publicKey, Self.algorithm, key as CFData, &error)
        else { throw failure("seal the device key", error) }
        return sealed as Data
    }

    func unseal(sealed: Data) throws -> Data {
        guard let guardKey = try existingKey() else {
            throw MobileError.Failed(
                message: "This profile's key is gone from this iPhone (it was erased).")
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateDecryptedData(guardKey, Self.algorithm, sealed as CFData, &error)
        else { throw failure("open the device key", error) }
        return key as Data
    }

    func destroy() throws {
        let status = SecItemDelete(Self.query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw MobileError.Failed(message: "Could not delete the Secure Enclave key (\(status)).")
        }
    }

    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
        ]
    }

    private func existingKey() throws -> SecKey? {
        var query = Self.query
        query[kSecReturnRef as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw MobileError.Failed(message: "Could not read the Secure Enclave key (\(status)).")
        }
        return (item as! SecKey)
    }

    /// A P-256 key made inside the Secure Enclave, usable only while this
    /// iPhone is unlocked, never synced or backed up.
    private func makeKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        #if targetEnvironment(simulator)
            let flags: SecAccessControlCreateFlags = []
        #else
            let flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        #endif
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw failure("protect the Secure Enclave key", error) }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        #if !targetEnvironment(simulator)
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw failure("make the Secure Enclave key", error)
        }
        return key
    }

    private func failure(_ doing: String, _ error: Unmanaged<CFError>?) -> MobileError {
        let reason = error.map { $0.takeRetainedValue().localizedDescription } ?? "unknown error"
        return MobileError.Failed(message: "Could not \(doing): \(reason)")
    }
}
