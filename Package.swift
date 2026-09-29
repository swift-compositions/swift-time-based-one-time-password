// swift-tools-version: 6.4

import Foundation
import PackageDescription

let package = Package(
    name: "swift-time-based-one-time-password",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "TOTP", targets: ["TOTP"]),
        .library(name: "HOTP", targets: ["HOTP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "4.1.0"),
        .package(
            url: "https://github.com/swift-compositions/swift-dependencies.git",
            branch: "main"
        ),
        .package(url: "https://github.com/swift-ietf/swift-rfc-6238.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "OneTimePasswordShared",
            dependencies: [
                .product(name: "RFC 6238", package: "swift-rfc-6238"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "TOTP",
            dependencies: [
                .target(name: "OneTimePasswordShared"),
                .product(name: "Dependencies", package: "swift-dependencies"),
            ]
        ),
        .target(
            name: "HOTP",
            dependencies: [
                .target(name: "OneTimePasswordShared")
            ]
        ),
        .testTarget(
            name: "TOTP Tests",
            dependencies: [
                .target(name: "TOTP"),
                .target(name: "HOTP"),
                .product(name: "Dependencies Test Support", package: "swift-dependencies"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "HOTP Tests",
            dependencies: [
                .target(name: "HOTP"),
                .product(name: "Dependencies Test Support", package: "swift-dependencies"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

