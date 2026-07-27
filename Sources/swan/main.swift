import ArgumentParser
import Foundation
import Logging
import SwanAccounts
import SwanHTTP
import SwanInterop
import SwanCore
import SwanOAuth
import SwanSQLite
import ServiceLifecycle

@main
struct SwanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "swan",
        abstract: "Swift-native AT Protocol permissioned-data interoperability laboratory",
        subcommands: [Serve.self, Account.self, Verify.self, Lab.self],
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

        @Flag(name: .long, help: "Enable only the localhost-development-client OAuth PAR bridge; requires an HTTPS public issuer")
        var enableLocalhostPAR = false

        @Option(name: .long, help: "Reserved root for control/account databases and blobs")
        var dataDirectory: String = ".swan-data"

        @Option(name: .long, help: "Enable the separate loopback-only management listener on this port")
        var managementPort: Int?

        @Option(name: .long, help: "Literal loopback address for management: 127.0.0.1 or ::1")
        var managementAddress: String = "127.0.0.1"

        @Option(name: .long, help: "Mounted operator-secret file for the enabled management listener")
        var managementOperatorSecretFile: String?

        func run() async throws {
            let loadedProfile = try ProtocolProfile.load(from: URL(fileURLWithPath: profile))
            let baseURL = try publicURL.map { value in
                guard let url = URL(string: value) else { throw ValidationError("--public-url must be a URL") }
                return url
            } ?? URL(string: "http://\(host):\(port)")!
            let dataURL = URL(fileURLWithPath: dataDirectory)
            let serverKey = try loadOAuthServerKey()
            let controlDatabase = try await SQLiteControlDatabase(dataDirectory: dataURL)
            var preopenedAccountDirectory: SQLitePreMigratedAccountDirectory?
            do {
                // Permissioned lookup never creates or migrates an account
                // database during a request. Build the complete active set
                // before the public listener exists; failures keep the
                // endpoint unavailable rather than repairing state online.
                let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                    dataDirectory: dataURL,
                    controlStore: controlDatabase
                )
                preopenedAccountDirectory = directory
                let oauthRuntime = try SwanOAuthRuntime(
                    controlStore: controlDatabase,
                    serverKey: serverKey
                )
                // Make an unsafe public identity a startup error rather than
                // silently leaving the authenticated endpoint closed. The
                // server constructs its own instance from these same values
                // when it installs the route.
                _ = try SwanOAuthResourceAuthorizer(
                    publicURL: baseURL,
                    runtime: oauthRuntime,
                    accountControlStore: controlDatabase
                )
                var logger = Logger(label: "swan")
                logger.logLevel = .info
                let localhostPARConfiguration: SwanLocalhostPARConfiguration?
                if enableLocalhostPAR {
                    do {
                        localhostPARConfiguration = try SwanLocalhostPARConfiguration(issuer: baseURL)
                    } catch {
                        throw ValidationError("--enable-localhost-par requires an HTTPS public issuer URL")
                    }
                } else {
                    localhostPARConfiguration = nil
                }
                let server = SwanHTTPServer(
                    profile: loadedProfile,
                    configuration: .init(host: host, port: port, publicURL: baseURL),
                    oauthRuntime: oauthRuntime,
                    localhostPARConfiguration: localhostPARConfiguration,
                    authenticatedGetSpaceDirectory: directory,
                    accountControlStore: controlDatabase
                )
                guard server.authenticatedGetSpace != nil else {
                    throw ValidationError(
                        "permissioned resource endpoints require HTTPS, or an HTTP public URL and listener both bound to literal loopback on the same port"
                    )
                }
                // Both applications are built before a ServiceGroup starts
                // either one. A bad management bind/config/secret therefore
                // exits rather than silently serving a public-only process to
                // an operator who asked for control-plane access.
                let publicApplication = server.buildApplication(logger: logger)
                let managementApplication: (any Service)?
                if let managementPort {
                    guard managementPort != port else {
                        throw ValidationError("--management-port must differ from --port")
                    }
                    let managementConfiguration: SwanManagementHTTPConfiguration
                    do {
                        managementConfiguration = try .init(
                            bindAddressLiteral: managementAddress,
                            port: managementPort
                        )
                    } catch {
                        throw ValidationError("management listener must use literal 127.0.0.1 or ::1 and a valid port")
                    }
                    let verifier: OperatorSecretVerifier
                    do {
                        verifier = try OperatorSecretResolver.loadVerifier(
                            secretFile: managementOperatorSecretFile.map { URL(fileURLWithPath: $0) }
                        )
                    } catch {
                        throw ValidationError("management operator secret is unavailable")
                    }
                    let managementServer = SwanManagementHTTPServer(
                        configuration: managementConfiguration,
                        controlStore: controlDatabase,
                        operatorSecretVerifier: verifier
                    )
                    managementApplication = managementServer.buildApplication(
                        logger: Logger(label: "swan.management")
                    )
                } else {
                    guard managementOperatorSecretFile == nil else {
                        throw ValidationError("--management-operator-secret-file requires --management-port")
                    }
                    managementApplication = nil
                }
                logger.info("starting Swan", metadata: ["profile": .string(loadedProfile.id), "address": .string("\(host):\(port)")])
                var services: [any Service] = [publicApplication]
                if let managementApplication {
                    services.append(managementApplication)
                    logger.info("starting Swan management listener", metadata: [
                        "address": .string("\(managementAddress):\(managementPort!)"),
                    ])
                }
                let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
                    services: services,
                    logger: logger
                )
                try await serviceGroup.run()
                try await directory.close()
                try await controlDatabase.close()
            } catch {
                if let preopenedAccountDirectory {
                    try? await preopenedAccountDirectory.close()
                }
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

        @Option(name: .long, help: "Swan package root containing generated wire sources")
        var sourceRoot: String?

        @Option(name: .long, help: "Pinned reference checkout to checksum against")
        var referenceDirectory: String?

        func run() throws {
            let profileURL = URL(fileURLWithPath: profile)
            let report = OfflineProtocolProfileVerifier.verify(
                profileURL: profileURL,
                sourceRoot: sourceRoot.map { URL(fileURLWithPath: $0) }
            )
            guard report.isValid, let profileID = report.profileID else {
                for diagnostic in report.diagnostics {
                    FileHandle.standardError.write(Data((diagnostic.description + "\n").utf8))
                }
                throw ValidationError("offline protocol profile verification failed")
            }
            if let referenceDirectory {
                try ProtocolProfile.verifyPinnedLexicons(
                    profileURL: profileURL,
                    referenceRoot: URL(fileURLWithPath: referenceDirectory)
                )
            }
            let suffix = referenceDirectory == nil
                ? "offline artifacts verified"
                : "offline artifacts and pinned lexicons verified"
            print("PROFILE OK: \(profileID) (\(suffix))")
        }
    }

    struct Account: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Inspect or manage a provisioned Swan account",
            subcommands: [InstallLocal.self, Show.self, Deactivate.self, Reactivate.self, Delete.self]
        )

        /// Installs the local, durable half of a Swan account. It deliberately
        /// does not claim PLC registration or remote handle verification: the
        /// command is the offline/recoverable prerequisite for those future
        /// protocol operations, and creates the verified empty public repo.
        struct InstallLocal: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "install-local",
                abstract: "Install a local account, encrypted keys, and an empty public repository"
            )

            @Option(name: .long, help: "Swan data directory; control and per-account databases are created here")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to install")
            var did: String

            @Option(name: .long, help: "Canonical account handle")
            var handle: String

            @Option(name: .long, help: "Valid repository-v3 revision for the immutable empty public genesis")
            var revision: String

            @Option(name: .long, help: "Owner-only mounted file containing the account password; never accepted literally")
            var passwordFile: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64); SWAN_ACCOUNT_KEK is the alternative")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Account-KEK identifier written into encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                // Local installation is a management action even though it
                // has no HTTP listener. Resolve the process capability first
                // so an untrusted caller cannot cause key-store mutations.
                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let password = try AccountProvisioningSecrets.password(
                    secretFile: URL(fileURLWithPath: passwordFile)
                )
                let keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                    activeKeyID: accountKEKID,
                    secretFile: accountKEKFile.map { URL(fileURLWithPath: $0) }
                )
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }

                let dataURL = URL(fileURLWithPath: dataDirectory)
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? dataURL.appending(path: "keys")
                let control: SQLiteControlDatabase
                let accountDatabase: SQLiteAccountDatabase
                do {
                    control = try await SQLiteControlDatabase(dataDirectory: dataURL)
                    accountDatabase = try await SQLiteAccountDatabase(dataDirectory: dataURL, did: did)
                } catch {
                    throw ValidationError("unable to open Swan account storage")
                }
                do {
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
                    let passwordHasher = try LibsodiumArgon2idHasher()
                    let verificationExecutor = try Argon2idVerificationExecutor(hasher: passwordHasher)
                    let directory = DurableAccountDirectory(
                        store: control,
                        passwordHasher: passwordHasher,
                        verificationExecutor: verificationExecutor,
                        keyProvisioner: keyProvisioner
                    )
                    let installer = LocalAccountProvisioner(
                        directory: directory,
                        publicGenesisStore: accountDatabase,
                        keyProvisioner: keyProvisioner,
                        keyStore: keyStore
                    )
                    let installation = try await installer.install(
                        did: did,
                        handle: handle,
                        password: password,
                        revision: revision
                    )
                    try await accountDatabase.close()
                    try await control.close()
                    try AccountCommandSupport.write(
                        LocalAccountInstallationView(installation: installation)
                    )
                } catch {
                    try? await accountDatabase.close()
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        struct Show: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Show sanitized durable control metadata for one account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to look up")
            var did: String?

            @Option(name: .long, help: "Account handle to look up")
            var handle: String?

            func run() async throws {
                let lookup: AccountOperatorLookup
                switch (did, handle) {
                case let (.some(value), .none):
                    lookup = .did(value)
                case let (.none, .some(value)):
                    lookup = .handle(value)
                default:
                    throw ValidationError("supply exactly one of --did or --handle")
                }
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.show(lookup)
                }
                try AccountCommandSupport.write(view)
            }
        }

        struct Deactivate: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Deactivate a provisioned Swan account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to deactivate")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.deactivate(did: did, authorization: authorization)
                }
                try AccountCommandSupport.write(view)
            }
        }

        struct Reactivate: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Reactivate a provisioned Swan account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to reactivate")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.reactivate(did: did, authorization: authorization)
                }
                try AccountCommandSupport.write(view)
            }
        }

        struct Delete: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Permanently deactivate an account and retain its declared tombstone"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to delete")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Optional bounded tombstone reason")
            var tombstoneReason: String?

            @Option(name: .long, help: "Optional sha256:<64 lowercase hex> portable-export manifest reference")
            var exportReference: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.delete(
                        did: did,
                        tombstoneReason: tombstoneReason,
                        exportReference: exportReference,
                        authorization: authorization
                    )
                }
                try AccountCommandSupport.write(view)
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

private struct LocalAccountInstallationView: Encodable {
    let did: String
    let canonicalHandle: String
    let status: String
    let publicGenesisCommitCID: String
    let publicGenesisRevision: String
    let recovered: Bool

    init(installation: LocalAccountInstallation) {
        did = installation.account.did
        canonicalHandle = installation.account.canonicalHandle
        status = installation.account.status.rawValue
        publicGenesisCommitCID = installation.publicGenesis.genesis.commitCID.string
        publicGenesisRevision = installation.publicGenesis.genesis.revision
        recovered = installation.registrationWasRecovered
    }
}

private enum AccountCommandSupport {
    static func authorization(secretFilePath: String?) throws -> AccountOperatorAuthorization {
        do {
            return try OperatorSecretResolver.authorize(
                secretFile: secretFilePath.map { URL(fileURLWithPath: $0) }
            )
        } catch {
            throw validationError(for: error)
        }
    }

    static func withService(
        dataDirectory: String,
        operation: (AccountOperatorService) async throws -> AccountOperatorView
    ) async throws -> AccountOperatorView {
        guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ValidationError("--data-directory must not be empty")
        }
        let control: SQLiteControlDatabase
        do {
            control = try await SQLiteControlDatabase(
                dataDirectory: URL(fileURLWithPath: dataDirectory)
            )
        } catch {
            throw ValidationError("unable to open Swan control database")
        }
        do {
            let view = try await operation(AccountOperatorService(store: control))
            try await control.close()
            return view
        } catch {
            try? await control.close()
            throw validationError(for: error)
        }
    }

    static func write(_ view: some Encodable) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(view)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func write(_ view: AccountOperatorView) throws {
        let data = try AccountOperatorJSON.render(view)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func validationError(for error: any Error) -> ValidationError {
        if let error = error as? AccountOperatorError,
           let message = error.errorDescription {
            return ValidationError(message)
        }
        if let error = error as? SwanError {
            return ValidationError(error.description)
        }
        return ValidationError("account operation failed")
    }
}
