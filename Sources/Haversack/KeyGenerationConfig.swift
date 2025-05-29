// SPDX-License-Identifier: MIT
// Copyright 2023, Jamf

import Foundation

/// Used with ``Haversack/Haversack`` to generate cryptographic keys.
///
/// Create a `KeyGenerationConfig` and then pass it to ``Haversack/Haversack/generateKey(fromConfig:itemSecurity:)-1r4ki``
/// or one of it's asynchronous variants.
public struct KeyGenerationConfig: Sendable {
    /// The keychain config query.
    ///
    /// Use the fluent methods such as ``labeled(_:)``,
    /// ``tagged(_:)``, and others in order to build up the key generation configuration.
    /// `nonisolated(unsafe)` because `SecurityFrameworkQuery` is not `Sendable`
    nonisolated(unsafe) public let query: SecurityFrameworkQuery

    /// Initializer for a key _not_ in the Secure Enclave.
    ///
    /// By default, only the private key will be stored in the keychain permanently.
    /// By default the key(s) will not be extractable.
    /// - Parameters:
    ///   - algorithm: The key algorithm that you want to use
    ///   - keySize: How large should the key be (in bits).
    public init(algorithm: KeyAlgorithm, keySize: Int) {
        self.query = Self.basicInfo(algorithm: algorithm, keySize: keySize)
    }

    /// Initializer for a key in the Secure Enclave.
    /// - Parameters:
    ///   - secureEnclaveRetrievableWhen: When is the key accessible.  Must be one of the `...ThisDeviceOnly` values.
    ///   - flags: Any _additional_ flags for the private key; Haversack will add `privateKeyUsage` automatically to this value.
    /// - Throws: A ``HaversackError`` if any problems occur initializing the query
    public init(secureEnclaveRetrievableWhen: RetrievabilityLevel, flags: SecAccessControlCreateFlags = []) throws {
        guard !secureEnclaveRetrievableWhen.synchronizable else {
            throw HaversackError.notPossible("Secure Enclave keys cannot be marked as synchronizable to iCloud Keychain and backups")
        }

        var configInfo = Self.basicInfo(algorithm: .ellipticCurvePrimeRandom, keySize: 256)

        var privateKeyInfo = configInfo[kSecPrivateKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        let retrievability = KeychainItemRetrievability.complex(secureEnclaveRetrievableWhen, flags.union(.privateKeyUsage))
        privateKeyInfo[retrievability.securityFrameworkKey] = try retrievability.securityFrameworkValue()
        configInfo[kSecPrivateKeyAttrs as String] = privateKeyInfo

        configInfo[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave

        self.query = configInfo
    }
    
    /// Shared query information for both SecureEnclave and non-SecureEnclave keys.
    private static func basicInfo(algorithm: KeyAlgorithm, keySize: Int) -> SecurityFrameworkQuery {
        var configInfo = SecurityFrameworkQuery()
        configInfo[kSecAttrKeyType as String] = algorithm.securityFrameworkKey
        configInfo[kSecAttrKeySizeInBits as String] = keySize

        let privateKeyInfo: SecurityFrameworkQuery = [kSecAttrIsPermanent as String: true]
        configInfo[kSecPrivateKeyAttrs as String] = privateKeyInfo

        let publicKeyInfo: SecurityFrameworkQuery = [kSecAttrIsPermanent as String: false]
        configInfo[kSecPublicKeyAttrs as String] = publicKeyInfo

        configInfo[kSecAttrIsExtractable as String] = false

        return configInfo
    }

    /// Helper initalizer for the fluent methods that return a new instance with a new query.
    private init(query: SecurityFrameworkQuery) {
        self.query = query
    }

    // MARK: - Top level info

    /// Add a label to the top level key description.
    ///
    /// This will be applied to both the public and private keys unless it is overridden by a call to ``publicKey(labeled:)``
    /// or ``privateKey(labeled:)``.
    /// - Parameter label: A human-readable label for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func labeled(_ label: String) -> Self {
        guard !label.isEmpty else {
            return self
        }

        var newQuery = self.query
        newQuery[kSecAttrLabel as String] = label
        return Self(query: newQuery)
    }

    /// Add a tag to the top level key description.
    ///
    /// This will be applied to both the public and private keys unless it is overridden by a call to ``publicKey(tagged:)``
    /// or ``privateKey(tagged:)``.  If the public key is also permanent having the same tag for both the public and private
    /// key makes it harder to search for the one that you want.
    /// - Parameter tag: An internal-only tag for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func tagged(_ tag: Data) -> Self {
        guard !tag.isEmpty else {
            return self
        }

        var newQuery = self.query
        newQuery[kSecAttrApplicationTag as String] = tag
        return Self(query: newQuery)
    }

    /// Allow the keys to be extracted from the keychain; default is `false`.
    ///
    /// Note: Calling this with `true` on a Secure Enclave key will throw a ``HaversackError/notPossible(_:)``
    /// error.
    /// - Parameter extractable: Whether or not the key should be extractable.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func extractionAllowed(_ extractable: Bool) throws -> Self {
        guard !extractable || query[kSecAttrTokenID as String] == nil else {
            throw HaversackError.notPossible("Secure Enclave keys cannot be marked as extractable")
        }

        var newQuery = self.query
        newQuery[kSecAttrIsExtractable as String] = extractable
        return Self(query: newQuery)
    }

    // MARK: - Private key info

    /// Set the way that the private key can be used by the Security framework.
    /// - Parameter usage: The usage options for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func privateKey(usage: KeyUsagePolicy) -> Self {
        var privateKeyInfo = query[kSecPrivateKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        usage.securityFrameworkKeyArray.forEach { (dictionaryKey) in
            privateKeyInfo[dictionaryKey as String] = true
        }
        KeyUsagePolicy.defaultPrivateKey.subtracting(usage).securityFrameworkKeyArray.forEach { (dictionaryKey) in
            privateKeyInfo[dictionaryKey as String] = false
        }
        var newQuery = self.query
        newQuery[kSecPrivateKeyAttrs as String] = privateKeyInfo
        return Self(query: newQuery)
    }

    /// Add a label to the private key description.
    ///
    /// This overrides (for the private key only) a label via ``labeled(_:)``.
    /// - Parameter label: A human-readable label for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func privateKey(labeled label: String) -> Self {
        guard !label.isEmpty else {
            return self
        }

        var newQuery = self.query
        var privateKeyInfo = newQuery[kSecPrivateKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        privateKeyInfo[kSecAttrLabel as String] = label
        newQuery[kSecPrivateKeyAttrs as String] = privateKeyInfo
        return Self(query: newQuery)

    }

    /// Add a tag to the private key description.
    ///
    /// This overrides (for the private key only) a tag set via ``tagged(_:)``.
    /// If the public key is also permanent having the same tag for both the public and private
    /// key makes it harder to search for the one that you want.
    /// - Parameter tag: An internal-only tag for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func privateKey(tagged tag: Data) -> Self {
        guard !tag.isEmpty else {
            return self
        }

        var newQuery = self.query
        var privateKeyInfo = newQuery[kSecPrivateKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        privateKeyInfo[kSecAttrApplicationTag as String] = tag
        newQuery[kSecPrivateKeyAttrs as String] = privateKeyInfo
        return Self(query: newQuery)
    }

    /// Whether the private key should be stored in the keychain; default is `true`.
    ///
    /// By default the private key _is_ stored in the keychain.  This should only be called in order
    /// to create an ephemeral key that only exists in RAM.  This will not work with Secure Enclave keys.
    /// - Parameter shouldBePermanent: Whether the private key should be permanent or not.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func privateKey(shouldBePermanent: Bool) throws -> Self {
        guard shouldBePermanent || query[kSecAttrTokenID as String] == nil else {
            throw HaversackError.notPossible("Secure Enclave keys must be permanent")
        }

        var privateKeyInfo = query[kSecPrivateKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        privateKeyInfo[kSecAttrIsPermanent as String] = shouldBePermanent

        var newQuery = self.query
        newQuery[kSecPrivateKeyAttrs as String] = privateKeyInfo
        return Self(query: newQuery)
    }

    // MARK: - Public key info

    /// Set the way that the public key can be used by the Security framework.
    /// - Parameter usage: The usage options for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func publicKey(usage: KeyUsagePolicy) -> Self {
        var publicKeyInfo = query[kSecPublicKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        usage.securityFrameworkKeyArray.forEach { (dictionaryKey) in
            publicKeyInfo[dictionaryKey as String] = true
        }
        KeyUsagePolicy.defaultPublicKey.subtracting(usage).securityFrameworkKeyArray.forEach { (dictionaryKey) in
            publicKeyInfo[dictionaryKey as String] = false
        }
        var newQuery = self.query
        newQuery[kSecPublicKeyAttrs as String] = publicKeyInfo
        return Self(query: newQuery)
    }

    /// Add a label to the public key description.
    ///
    /// This overrides (for the public key only) a label set via ``labeled(_:)``.
    /// - Parameter label: A human-readable label for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func publicKey(labeled label: String) -> Self {
        guard !label.isEmpty else {
            return self
        }

        var newQuery = self.query
        var publicKeyInfo = newQuery[kSecPublicKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        publicKeyInfo[kSecAttrLabel as String] = label
        newQuery[kSecPublicKeyAttrs as String] = publicKeyInfo
        return Self(query: newQuery)

    }

    /// Add a tag to the public key description.
    ///
    /// This overrides (for the public key only) a tag set via ``tagged(_:)``.
    /// If the public key is also permanent having the same tag for both the public and private
    /// key makes it harder to search for the one that you want.
    /// - Parameter tag: An internal-only tag for the key.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func publicKey(tagged tag: Data) -> Self {
        guard !tag.isEmpty else {
            return self
        }

        var newQuery = self.query
        var publicKeyInfo = newQuery[kSecPublicKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        publicKeyInfo[kSecAttrApplicationTag as String] = tag
        newQuery[kSecPublicKeyAttrs as String] = publicKeyInfo
        return Self(query: newQuery)
    }

    /// Whether the public key should be stored in the keychain; default is `false`.
    ///
    /// By default the public key is _NOT_ stored in the keychain, but can be retrieved by calling
    /// `SecKeyCopyPublicKey` with the private key.  That way you don’t need to keep track of another tag
    /// or clutter your keychain.
    /// - Parameter shouldBePermanent: Whether the public key should be permanent or not.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func publicKey(shouldBePermanent: Bool) -> Self {
        var publicKeyInfo = query[kSecPublicKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        publicKeyInfo[kSecAttrIsPermanent as String] = shouldBePermanent

        var newQuery = self.query
        newQuery[kSecPublicKeyAttrs as String] = publicKeyInfo
        return Self(query: newQuery)
    }

    /// Allow the public key to be extracted from the keychain; default is `false`.
    ///
    /// Note: Calling this with `true` on a Secure Enclave key will throw a ``HaversackError/notPossible(_:)``
    /// error.
    /// - Parameter extractable: Whether or not the public key should be extractable.
    /// - Returns: A ``KeyGenerationConfig`` structure.
    public func publicKey(extractionAllowed extractable: Bool) throws -> Self {
        guard !extractable || query[kSecAttrTokenID as String] == nil else {
            throw HaversackError.notPossible("Secure Enclave keys cannot be marked as extractable")
        }

        var publicKeyInfo = query[kSecPublicKeyAttrs as String] as? SecurityFrameworkQuery ?? SecurityFrameworkQuery()
        publicKeyInfo[kSecAttrIsExtractable as String] = extractable

        var newQuery = self.query
        newQuery[kSecPublicKeyAttrs as String] = publicKeyInfo
        return Self(query: newQuery)
    }
}
