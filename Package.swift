// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "Swan",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "SwanCore", targets: ["SwanCore"]),
        .library(name: "SwanSpacesWire", targets: ["SwanSpacesWire"]),
        .library(name: "SwanPublicWire", targets: ["SwanPublicWire"]),
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
        // Petrel comes from its published repository, pinned to an exact
        // revision, not from a sibling checkout. A `path:` dependency compiles
        // against whatever line the neighbouring working copy happens to be
        // sitting on, which is invisible in this manifest and unreproducible
        // anywhere else: Swan silently built against three different Petrel
        // lines depending on who had checked out what. The pin below is the
        // commit that makes `CIDAsLink` public, which every record carrying a
        // blob or a StrongRef needs. Bump it deliberately, in a commit that
        // says why.
        .package(
            url: "https://github.com/joshlacal/Petrel.git",
            revision: "7575674e4b8d8fee9ef84ae265d3667081bf3a7c"
        ),
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
        // Direct dependency for the SwanCLITests composition tests (Task 1):
        // the credential-isolation assertions steer `atproto-proxy` headers,
        // which requires `HTTPField.Name` from HTTPTypes. Pinned to the
        // version Hummingbird already resolves.
        .package(url: "https://github.com/apple/swift-http-types.git", exact: "1.6.0"),
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
        .target(name: "SwanSpacesWire", dependencies: ["SwanCore"]),
        .target(name: "SwanPublicWire", dependencies: ["SwanCore", .product(name: "Petrel", package: "Petrel")]),
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
                "SwanCore", "SwanSpaces",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "PetrelRepo", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanSQLite",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanStorage",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "SwanAccounts",
            dependencies: [
                "CATHandleDNS", "CLibsodium", "SwanCore", "SwanStorage",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "NIOCore", package: "swift-nio"),
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
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanAccounts", "SwanCore",
                "SwanSQLite", "SwanSpaces", "SwanSpacesWire", "SwanStorage",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .target(
            name: "SwanHTTP",
            dependencies: [
                "SwanAccounts", "SwanCore", "SwanPublicWire", "SwanSpaces", "SwanSpacesWire", "SwanStorage", "SwanOAuth", "SwanSQLite",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanAccounts", "SwanCore", "SwanSpaces", "SwanSpacesWire", "SwanSQLite", "SwanStorage", "SwanOAuth",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanSQLite",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanAccounts", "SwanCore", "SwanHTTP", "SwanSQLite", "SwanStorage",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "Petrel", package: "Petrel"),
                .product(name: "SQLiteNIO", package: "sqlite-nio"),
            ]
        ),
        .testTarget(
            name: "SwanOAuthTests",
            dependencies: [
                "SwanAccounts", "SwanOAuth",
                "SwanSQLite", "SwanStorage", "SwanSpaces",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "CATHandleDNS", "SwanAccounts", "SwanCore", "SwanStorage",
                "SwanSQLite",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanAccountExport", "SwanAccounts",
                "SwanSQLite", "SwanSpaces", "SwanStorage",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanCLITests",
            dependencies: [
                "SwanAccountExport", "SwanAccounts",
                "SwanSQLite", "SwanSpaces", "SwanStorage",
                // Task 1 (runtime integration): the composition tests construct
                // the production `SwanHTTPServer` the way `swan serve` does, so
                // the test target needs the server type, the CLI module it
                // mirrors, and the direct module dependencies Swift requires
                // (no transitive imports).
                "swan", "SwanHTTP", "SwanCore", "SwanOAuth",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
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
                "swan", "SwanAccounts", "SwanHTTP", "SwanInterop", "SwanOAuth", "SwanPublicWire", "SwanSQLite", "SwanSpacesWire", "SwanStorage",
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
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
                "SwanAccounts", "SwanCore", "SwanInterop", "SwanOAuth",
                "SwanSpaces", "SwanSQLite",
                .product(name: "PetrelRepo", package: "Petrel"),
                .product(name: "PetrelFirehose", package: "Petrel"),
                .product(name: "PetrelPLC", package: "Petrel"),
                .product(name: "PetrelCrypto", package: "Petrel"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
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
    ]
)
