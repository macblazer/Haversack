// swift-tools-version:5.10
// SPDX-License-Identifier: MIT
// Copyright 2023, Jamf

import PackageDescription

let package = Package(
    name: "Haversack",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
		.visionOS(.v1),
        .watchOS(.v6)
    ],
    products: [
        .library(name: "Haversack", targets: ["Haversack"]),
        .library(name: "HaversackCryptoKit", targets: ["HaversackCryptoKit"]),
        .library(name: "HaversackMock", targets: ["HaversackMock"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.4.0")
    ],
    targets: [
        .target(name: "Haversack",
				dependencies: [
                    .product(name: "OrderedCollections", package: "swift-collections")
				],
				resources: [.process("Resources/")],
//                swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]
               ),
        .target(name: "HaversackCryptoKit", dependencies: ["Haversack"]),
        .target(name: "HaversackMock", dependencies: ["Haversack"]),
        .testTarget(name: "HaversackTests",
                    dependencies: ["HaversackMock"],
                    resources: [.copy("TestResources/")])
    ]
)
