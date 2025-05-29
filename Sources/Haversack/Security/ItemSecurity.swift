// SPDX-License-Identifier: MIT
// Copyright 2023, Jamf

import Foundation

/// Specify the security of the keychain item
public struct ItemSecurity: Sendable {

    /// The Haversack standard security for keychain items.
    ///
    /// The item is retrievable only when the device is unlocked and does NOT synchronize to other devices.
    /// The item is not part of any app group or keychain group.
    public static let standard = ItemSecurity().retrievableNoThrow(when: .simple(.unlockedThisDeviceOnly))

    /// The keychain query.
    ///
    /// Use the fluent methods such as ``containedIn(appGroup:)`` and ``retrievable(when:)``
    /// to build up the query.
    /// `nonisolated(unsafe)` because `SecurityFrameworkQuery` is not `Sendable`
    nonisolated(unsafe) public let query: SecurityFrameworkQuery

    /// Construct an empty ``ItemSecurity``
    ///
    /// Use one or more of the instance methods to populate this with the desired security settings for a keychain item.
    public init() {
        query = [:]
    }
    
    /// Helper initalizer for the fluent methods that return a new instance with a new query.
    private init(query: SecurityFrameworkQuery) {
        self.query = query
    }

    /// Specify an App Group that the item should be part of.  Uses `kSecAttrAccessGroup`.
    ///
    /// See [Apple: Sharing Keychain Items](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    /// for more information.
    ///
    /// If you do not call ``containedIn(appGroup:)`` or ``containedIn(teamID:keychainGroupName:)`` the
    /// default keychain group is used.  The Apple documentation describing ordering of all possible access groups is very helpful
    /// to understand the default group.
    /// - Important: This is mutually exclusive with ``containedIn(teamID:keychainGroupName:)``.
    /// A keychain item can only be part of a single group.
    /// - Parameter appGroup: The app group the item should be part of.
    /// - Returns: An ``ItemSecurity`` struct
    public func containedIn(appGroup: String) -> Self {
        guard !appGroup.isEmpty else {
            return self
        }

        var newQuery = self.query
        newQuery[kSecAttrAccessGroup as String] = appGroup
        return Self(query: newQuery)
    }

    /// Specify a Keychain Sharing group that the item should be part of.  Uses `kSecAttrAccessGroup`.
    ///
    /// See [Apple: Sharing Keychain Items](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps)
    /// for more information.
    ///
    /// If you do not call ``containedIn(appGroup:)`` or ``containedIn(teamID:keychainGroupName:)`` the
    /// default keychain group is used.  The Apple documentation describing ordering of all possible access groups is very helpful
    /// to understand the default group.
    /// - Important: This is mutually exclusive with ``containedIn(appGroup:)``.
    /// A keychain item can only be part of a single group.
    /// - Parameters:
    ///   - teamID: The developer team ID of the app.
    ///   - keychainGroupName: The keychain group name as seen in Xcode's Keychain Sharing entitlement.  Does not include the team ID prefix.
    /// - Returns: An ``ItemSecurity`` struct
    public func containedIn(teamID: String, keychainGroupName: String) -> Self {
        guard !teamID.isEmpty && !keychainGroupName.isEmpty else {
            return self
        }

        var newQuery = self.query
        newQuery[kSecAttrAccessGroup as String] = "\(teamID).\(keychainGroupName)"
        return Self(query: newQuery)
    }

    /// Specify when the item should be available.  Uses `kSecAttrAccessible` or `kSecAttrAccessControl`.
    /// - Parameter availability: A Haversack ``KeychainItemRetrievability`` enum value
    /// - Throws: A ``HaversackError`` or an `NSError` from the Security framework.
    /// - Returns: An ``ItemSecurity`` struct
    public func retrievable(when availability: KeychainItemRetrievability) throws -> Self {
        var newQuery = self.query
        newQuery[availability.securityFrameworkKey] = try availability.securityFrameworkValue()
        return Self(query: newQuery)
    }

#if os(macOS)
    /// Specify an access instance for the item.  Uses `kSecAttrAccess`
    /// - Important: Available on macOS only.
    /// - Parameter access: A `SecAccess` reference
    /// - Returns: An ``ItemSecurity`` struct
    public func macOnly(access: SecAccess) -> Self {
        var newQuery = self.query
        newQuery[kSecAttrAccess as String] = access
        return Self(query: newQuery)
    }

    /// Specify to use the data protection keychain available in macOS 10.15+
    /// - Parameter useDataProtection: Whether or not to use the data protection keychain
    /// - Returns: An ``ItemSecurity`` struct
    @available(macOS 10.15, *)
    public func macOnly(useDataProtection: Bool) -> Self {
        var newQuery = self.query
        newQuery[kSecUseDataProtectionKeychain as String] = useDataProtection
        return Self(query: newQuery)
    }
#endif
}

extension ItemSecurity {
    /// Internal version of the availability that does not report errors
    ///
    /// Useful when you know that you're only using `.simple` availability.
    /// - Parameter availability: A ``KeychainItemRetrievability`` enum value
    /// - Returns: An ``ItemSecurity`` struct
    func retrievableNoThrow(when availability: KeychainItemRetrievability) -> Self {
        do {
            let value = try availability.securityFrameworkValue()
            var newQuery = self.query
            newQuery[availability.securityFrameworkKey] = value
            return Self(query: newQuery)
        } catch {
        }

        return self
    }
}
