// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "Swan",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "SwanCore", targets: ["SwanCore"]),
        .library(name: "SwanSpacesWire", targets: ["SwanSpacesWire"]),
        .library(name: "SwanPublicRepository", targets: ["SwanPublicRepository"]),
        .library(name: "SwanSpaces", targets: ["SwanSpaces"]),
        .library(name: "SwanStorage", targets: ["SwanStorage"]),
        .library(name: "SwanSQLite", targets: ["SwanSQLite"]),
        .library(name: "SwanAccounts", targets: ["SwanAccounts"]),
        .library(name: "SwanOAuth", targets: ["SwanOAuth"]),
        .library(name: "SwanHTTP", targets: ["SwanHTTP"]),
        .library(name: "SwanInterop", targets: ["SwanInterop"]),
        .executable(name: "swan", targets: ["swan"]),
    ],
    dependencies: [
        .package(path: "../Petrel"),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", exact: "2.25.1"),
        .package(url: "https://github.com/swift-server/async-http-client.git", exact: "1.36.0"),
        .package(url: "https://github.com/vapor/sqlite-nio.git", exact: "1.12.10"),
        .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", exact: "2.11.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CLibsodium",
            pkgConfig: "libsodium",
            providers: [
                .brew(["libsodium"]),
                .apt(["libsodium-dev"]),
            ]
        ),
        .target(
            name: "CBLAKE3",
            path: "Sources/CBLAKE3",
            publicHeadersPath: "include",
            cSettings: [
                .define("BLAKE3_NO_SSE2"),
                .define("BLAKE3_NO_SSE41"),
                .define("BLAKE3_NO_AVX2"),
                .define("BLAKE3_NO_AVX512"),
                // The upstream C headers autodetect NEON on AArch64. Keep the
                // first lab build portable by disabling that dispatch path as
                // well as the x86 SIMD paths above.
                .define("BLAKE3_USE_NEON", to: "0"),
            ]
        ),
        .target(
            name: "SwanCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .target(name: "SwanSpacesWire", dependencies: ["SwanCore", .product(name: "Petrel", package: "Petrel")]),
        .target(
            name: "SwanPublicRepository",
            dependencies: [
                "SwanCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanSpaces",
            dependencies: [
                "CBLAKE3", "SwanCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(name: "SwanStorage", dependencies: ["SwanCore", "SwanSpaces", .product(name: "Crypto", package: "swift-crypto")]),
        .target(
            name: "SwanSQLite",
            dependencies: [
                "SwanStorage", "SwanPublicRepository",
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwanAccounts",
            dependencies: [
                "CLibsodium", "SwanCore", "SwanPublicRepository", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwanOAuth",
            dependencies: [
                "SwanCore", "SwanSpaces", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
            ]
        ),
        .target(
            name: "SwanHTTP",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanSpaces", "SwanSpacesWire", "SwanStorage", "SwanOAuth",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
        .target(
            name: "SwanInterop",
            dependencies: [
                "SwanCore", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "swan",
            dependencies: [
                "SwanAccounts", "SwanHTTP", "SwanInterop", "SwanOAuth", "SwanSQLite",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
            ]
        ),
        .testTarget(name: "SwanCoreTests", dependencies: ["SwanCore", "SwanSpacesWire"]),
        .testTarget(
            name: "SwanSpacesTests",
            dependencies: [
                "SwanSpaces", "SwanStorage", "SwanSQLite",
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanSQLiteTests",
            dependencies: [
                "SwanCore", "SwanPublicRepository", "SwanSQLite", "SwanStorage",
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
            ]
        ),
        .testTarget(
            name: "SwanOAuthTests",
            dependencies: [
                "SwanOAuth", "SwanSQLite", "SwanStorage", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "SwanAccountsTests",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanPublicRepository", "SwanStorage", "SwanSQLite",
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
            ]
        ),
        .testTarget(
            name: "SwanCLITests",
            dependencies: [
                "SwanAccounts", "SwanSQLite", "SwanStorage",
            ]
        ),
        .testTarget(
            name: "SwanHTTPTests",
            dependencies: [
                "SwanAccounts", "SwanHTTP", "SwanOAuth", "SwanSQLite", "SwanSpacesWire",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
        .testTarget(
            name: "SwanInteropTests",
            dependencies: [
                "SwanInterop",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "SwanPublicRepositoryTests",
            dependencies: [
                "SwanPublicRepository",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
    ]
)
