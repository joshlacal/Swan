// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "Swan",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "SwanCore", targets: ["SwanCore"]),
        .library(name: "SwanSpacesWire", targets: ["SwanSpacesWire"]),
        .library(name: "SwanPublicWire", targets: ["SwanPublicWire"]),
        .library(name: "SwanPublicRepository", targets: ["SwanPublicRepository"]),
        .library(name: "SwanPublicFirehose", targets: ["SwanPublicFirehose"]),
        .library(name: "SwanPublicRelayVerifier", targets: ["SwanPublicRelayVerifier"]),
        .library(name: "SwanSpaces", targets: ["SwanSpaces"]),
        .library(name: "SwanStorage", targets: ["SwanStorage"]),
        .library(name: "SwanSQLite", targets: ["SwanSQLite"]),
        .library(name: "SwanAccounts", targets: ["SwanAccounts"]),
        .library(name: "SwanAccountExport", targets: ["SwanAccountExport"]),
        .library(name: "SwanOAuth", targets: ["SwanOAuth"]),
        .library(name: "SwanHTTP", targets: ["SwanHTTP"]),
        .library(name: "SwanInterop", targets: ["SwanInterop"]),
        .executable(name: "swan", targets: ["swan"]),
    ],
    dependencies: [
        .package(path: "../Petrel"),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", exact: "2.25.1"),
        .package(url: "https://github.com/hummingbird-project/hummingbird-websocket.git", exact: "2.7.0"),
        .package(url: "https://github.com/swift-server/async-http-client.git", exact: "1.36.0"),
        .package(url: "https://github.com/vapor/sqlite-nio.git", exact: "1.12.10"),
        .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", exact: "2.11.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
        // The notification connector owns the TCP/TLS connection so it can
        // pin and report the actual peer. Keep these direct pins aligned with
        // Hummingbird's resolved NIO line instead of relying on a transitive
        // import from the HTTP server.
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.101.3"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.2"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        // The pinned TypeScript PDS signs AT Protocol repository and space
        // JWTs with secp256k1 (`ES256K`). Keep verification in SwanOAuth
        // explicit rather than inheriting an unstable transitive product from
        // Petrel/JOSESwift.
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: "0.15.0"),
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
            name: "CATHandleDNS",
            path: "Sources/CATHandleDNS",
            publicHeadersPath: "include",
            linkerSettings: [.linkedLibrary("resolv")]
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
        .target(name: "SwanPublicWire", dependencies: ["SwanCore", .product(name: "Petrel", package: "Petrel")]),
        .target(
            name: "SwanPublicRepository",
            dependencies: [
                "SwanCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanPublicFirehose",
            dependencies: [
                "SwanPublicRepository",
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanPublicRelayVerifier",
            dependencies: [
                "SwanPublicFirehose", "SwanPublicRepository",
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
        .target(
            name: "SwanStorage",
            dependencies: [
                "SwanCore", "SwanPublicRepository", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwanSQLite",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanStorage", "SwanPublicRepository", "SwanPublicFirehose",
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwanAccounts",
            dependencies: [
                "CATHandleDNS", "CLibsodium", "SwanCore", "SwanPublicRepository", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanOAuth",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanSpaces", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]
        ),
        .target(
            name: "SwanAccountExport",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanPublicRepository",
                "SwanSQLite", "SwanSpaces", "SwanSpacesWire", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanHTTP",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanPublicFirehose", "SwanPublicRepository", "SwanPublicWire", "SwanSpaces", "SwanSpacesWire", "SwanStorage", "SwanOAuth", "SwanSQLite",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdWebSocket", package: "hummingbird-websocket"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
        .target(
            name: "SwanInterop",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanPublicRepository", "SwanSpaces", "SwanSpacesWire", "SwanSQLite", "SwanStorage", "SwanOAuth",
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .executableTarget(
            name: "swan",
            dependencies: [
                "SwanAccountExport", "SwanAccounts", "SwanHTTP", "SwanInterop", "SwanOAuth",
                "SwanPublicFirehose", "SwanPublicRelayVerifier", "SwanPublicRepository", "SwanSQLite",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Petrel", package: "Petrel"),
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
                "SwanAccounts", "SwanCore", "SwanHTTP", "SwanPublicFirehose", "SwanPublicRepository", "SwanSQLite", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
            ]
        ),
        .testTarget(
            name: "SwanOAuthTests",
            dependencies: [
                "SwanAccounts", "SwanOAuth", "SwanSQLite", "SwanStorage", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "SwanAccountsTests",
            dependencies: [
                "CATHandleDNS", "SwanAccounts", "SwanCore", "SwanPublicRepository", "SwanStorage",
                "SwanSQLite",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
            ]
        ),
        .testTarget(
            name: "SwanAccountExportTests",
            dependencies: [
                "SwanAccountExport", "SwanAccounts", "SwanPublicRepository",
                "SwanSQLite", "SwanSpaces", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanCLITests",
            dependencies: [
                "SwanAccountExport", "SwanAccounts", "SwanPublicRepository",
                "SwanSQLite", "SwanSpaces", "SwanStorage",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanHTTPTests",
            dependencies: [
                "swan", "SwanAccounts", "SwanHTTP", "SwanInterop", "SwanOAuth", "SwanPublicFirehose", "SwanPublicRepository", "SwanPublicWire", "SwanSQLite", "SwanSpacesWire", "SwanStorage",
                // `swan`'s startup refusals are ArgumentParser `ValidationError`s.
                // Asserting the concrete type is the difference between "it
                // threw" and "the operator gets a clean startup refusal".
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "HummingbirdWSTesting", package: "hummingbird-websocket"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
        .testTarget(
            name: "SwanInteropTests",
            dependencies: [
                "SwanAccounts", "SwanInterop", "SwanOAuth", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "SwanPublicFirehoseTests",
            dependencies: [
                "SwanPublicFirehose",
                "SwanPublicRelayVerifier",
                "SwanPublicRepository",
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanPublicWireTests",
            dependencies: [
                "SwanCore", "SwanPublicWire",
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanPublicRepositoryTests",
            dependencies: [
                "SwanPublicRepository",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]
        ),
    ]
)
