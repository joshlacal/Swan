import ArgumentParser
import Foundation
import Logging
import SwanHTTP
import SwanInterop
import SwanCore
import SwanOAuth
import SwanSQLite

@main
struct SwanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "swan",
        abstract: "Swift-native AT Protocol permissioned-data interoperability laboratory",
        subcommands: [Serve.self, Verify.self, Lab.self],
        defaultSubcommand: Verify.self
    )
}

extension SwanCommand {
    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run Swan's Hummingbird server")

        @Option(name: .long, help: "Pinned protocol profile JSON")
        var profile: String = "Profiles/permissioned-data-0016-2026-07-03.json"

        @Option(name: .long)
        var host: String = "127.0.0.1"

        @Option(name: .long)
        var port: Int = 3000

        @Option(name: .long, help: "Public issuer URL")
        var publicURL: String?

        @Option(name: .long, help: "Reserved root for control/account databases and blobs")
        var dataDirectory: String = ".swan-data"

        func run() async throws {
            let loadedProfile = try ProtocolProfile.load(from: URL(fileURLWithPath: profile))
            let baseURL = try publicURL.map { value in
                guard let url = URL(string: value) else { throw ValidationError("--public-url must be a URL") }
                return url
            } ?? URL(string: "http://\(host):\(port)")!
            let dataURL = URL(fileURLWithPath: dataDirectory)
            try FileManager.default.createDirectory(at: dataURL, withIntermediateDirectories: true)
            let serverKey = try loadOAuthServerKey()
            let controlDatabase = try await SQLiteControlDatabase(dataDirectory: dataURL)
            let oauthRuntime: SwanOAuthRuntime
            do {
                oauthRuntime = try SwanOAuthRuntime(
                    controlStore: controlDatabase,
                    serverKey: serverKey
                )
            } catch {
                try? await controlDatabase.close()
                throw error
            }
            var logger = Logger(label: "swan")
            logger.logLevel = .info
            let server = SwanHTTPServer(
                profile: loadedProfile,
                configuration: .init(host: host, port: port, publicURL: baseURL),
                oauthRuntime: oauthRuntime
            )
            logger.info("starting Swan", metadata: ["profile": .string(loadedProfile.id), "address": .string("\(host):\(port)")])
            do {
                try await server.buildApplication(logger: logger).runService()
                try await controlDatabase.close()
            } catch {
                try? await controlDatabase.close()
                throw error
            }
        }

        private func loadOAuthServerKey() throws -> Data {
            guard let encoded = ProcessInfo.processInfo.environment["SWAN_OAUTH_SERVER_KEY"],
                  let key = Data(base64URLEncoded: encoded),
                  key.count == 32 else {
                throw ValidationError(
                    "SWAN_OAUTH_SERVER_KEY must contain a URL-safe-base64 32-byte server key"
                )
            }
            return key
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify a pinned Swan artifact")

        @Option(name: .long, help: "Pinned protocol profile JSON")
        var profile: String = "Profiles/permissioned-data-0016-2026-07-03.json"

        @Option(name: .long, help: "Pinned reference checkout to checksum against")
        var referenceDirectory: String?

        func run() throws {
            let profileURL = URL(fileURLWithPath: profile)
            let loaded = try ProtocolProfile.load(from: profileURL)
            if let referenceDirectory {
                try ProtocolProfile.verifyPinnedLexicons(
                    profileURL: profileURL, referenceRoot: URL(fileURLWithPath: referenceDirectory)
                )
                print("PROFILE AND LEXICONS OK: \(loaded.id) reference=\(loaded.referenceImplementationCommit.prefix(12))")
            } else {
                print("PROFILE OK: \(loaded.id) reference=\(loaded.referenceImplementationCommit.prefix(12))")
            }
        }
    }

    struct Lab: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print pinned TypeScript interop source information")

        func run() throws {
            let pin = ReferenceSourcePin()
            print("REFERENCE: \(pin.repository.absoluteString)@\(pin.commit)")
            print("Use interop/fetch-reference.sh to populate the ignored .interop-cache directory.")
        }
    }
}
