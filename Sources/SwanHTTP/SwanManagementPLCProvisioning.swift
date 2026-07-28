import Foundation
import SwanAccounts
import SwanSQLite

public struct SwanManagementPLCPrepareInput: Sendable {
    public let requestID: String
    public let handle: String
    public let pdsOrigin: URL
    public let repositoryRevision: String
    public let plcConfiguration: PLCClientConfiguration

    public init(
        requestID: String,
        handle: String,
        pdsOrigin: URL,
        repositoryRevision: String,
        plcConfiguration: PLCClientConfiguration
    ) {
        self.requestID = requestID
        self.handle = handle
        self.pdsOrigin = pdsOrigin
        self.repositoryRevision = repositoryRevision
        self.plcConfiguration = plcConfiguration
    }
}

public struct SwanManagementPLCActivateInput: Sendable {
    public let requestID: String
    public let password: String
    public let plcConfiguration: PLCClientConfiguration
    public let handlePolicy: ATHandleResolutionPolicy
    public let useStaticLaboratoryHandleVerifier: Bool

    public init(
        requestID: String,
        password: String,
        plcConfiguration: PLCClientConfiguration,
        handlePolicy: ATHandleResolutionPolicy,
        useStaticLaboratoryHandleVerifier: Bool = false
    ) {
        self.requestID = requestID
        self.password = password
        self.plcConfiguration = plcConfiguration
        self.handlePolicy = handlePolicy
        self.useStaticLaboratoryHandleVerifier = useStaticLaboratoryHandleVerifier
    }
}

public struct SwanManagementPLCPrepareResult: Codable, Sendable, Equatable {
    public let requestId: String
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String
    public let plcOperationCID: String
    public let publicGenesisCommitCID: String

    public init(identity: PreparedPLCAccountIdentity) {
        requestId = identity.requestID
        did = identity.did
        canonicalHandle = identity.canonicalHandle
        pdsOrigin = identity.pdsOrigin
        repositoryRevision = identity.repositoryRevision
        plcOperationCID = identity.plcOperationCID
        publicGenesisCommitCID = identity.publicGenesisCommitCID
    }

    public init(
        requestId: String,
        did: String,
        canonicalHandle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        plcOperationCID: String,
        publicGenesisCommitCID: String
    ) {
        self.requestId = requestId
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.repositoryRevision = repositoryRevision
        self.plcOperationCID = plcOperationCID
        self.publicGenesisCommitCID = publicGenesisCommitCID
    }
}

public struct SwanManagementPLCActivateResult: Codable, Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let status: String
    public let publicGenesisCommitCID: String
    public let publicGenesisRevision: String
    public let recovered: Bool

    public init(installation: LocalAccountInstallation) {
        did = installation.account.did
        canonicalHandle = installation.account.canonicalHandle
        status = installation.account.status.rawValue
        publicGenesisCommitCID = installation.publicGenesis.genesis.commitCID.string
        publicGenesisRevision = installation.publicGenesis.genesis.revision
        recovered = installation.registrationWasRecovered
    }

    public init(
        did: String,
        canonicalHandle: String,
        status: String,
        publicGenesisCommitCID: String,
        publicGenesisRevision: String,
        recovered: Bool
    ) {
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.status = status
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.publicGenesisRevision = publicGenesisRevision
        self.recovered = recovered
    }
}

/// Narrow seam used by the management router. Production construction uses
/// `SwanManagementPLCProvisioningRuntime`; the protocol keeps HTTP validation
/// and authorization independently testable without weakening either.
public protocol SwanManagementPLCProvisioning: Sendable {
    func prepare(
        _ input: SwanManagementPLCPrepareInput
    ) async throws -> SwanManagementPLCPrepareResult

    func activate(
        _ input: SwanManagementPLCActivateInput
    ) async throws -> SwanManagementPLCActivateResult
}

/// The single process-local composition root for both the CLI and management
/// PLC workflows. Domain services own the durable state machine. This runtime
/// only selects a validated remote policy and wires those services together.
public actor SwanManagementPLCProvisioningRuntime:
    SwanManagementPLCProvisioning
{
    private struct ActivationAttempt: Sendable, Equatable {
        let password: String
        let plcConfiguration: PLCClientConfiguration
        let handlePolicy: ATHandleResolutionPolicy
        let useStaticLaboratoryHandleVerifier: Bool

        init(_ input: SwanManagementPLCActivateInput) {
            password = input.password
            plcConfiguration = input.plcConfiguration
            handlePolicy = input.handlePolicy
            useStaticLaboratoryHandleVerifier = input.useStaticLaboratoryHandleVerifier
        }
    }

    private struct InFlightActivation: Sendable {
        let token: UUID
        let attempt: ActivationAttempt
        let task: Task<SwanManagementPLCActivateResult, any Error>
        var waiterCount: Int
    }

    private let controlDatabase: SQLiteControlDatabase
    private let opener: SQLitePLCAccountPreparationStoreOpener
    private let keyStore: FileAccountKeyStore
    private let directory: DurableAccountDirectory
    private let liveAccountDirectory: SQLitePreMigratedAccountDirectory?
    private var inFlightActivations: [String: InFlightActivation] = [:]

    public init(
        controlDatabase: SQLiteControlDatabase,
        dataDirectory: URL,
        keyStore: FileAccountKeyStore,
        liveAccountDirectory: SQLitePreMigratedAccountDirectory? = nil
    ) throws {
        let passwordHasher = try LibsodiumArgon2idHasher()
        self.controlDatabase = controlDatabase
        opener = SQLitePLCAccountPreparationStoreOpener(dataDirectory: dataDirectory)
        self.keyStore = keyStore
        self.liveAccountDirectory = liveAccountDirectory
        directory = DurableAccountDirectory(
            store: controlDatabase,
            passwordHasher: passwordHasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
            keyProvisioner: AccountKeyProvisioner(keyStore: keyStore)
        )
    }

    public func prepare(
        _ input: SwanManagementPLCPrepareInput
    ) async throws -> SwanManagementPLCPrepareResult {
        let service = PLCAccountPreparationService(
            intentStore: controlDatabase,
            accountStoreOpener: opener,
            keyStore: keyStore,
            plcClient: try PLCDirectoryClient(configuration: input.plcConfiguration)
        )
        let identity = try await service.prepare(
            requestID: input.requestID,
            handle: input.handle,
            pdsOrigin: input.pdsOrigin,
            repositoryRevision: input.repositoryRevision
        )
        return .init(identity: identity)
    }

    public func activate(
        _ input: SwanManagementPLCActivateInput
    ) async throws -> SwanManagementPLCActivateResult {
        let attempt = ActivationAttempt(input)
        if var inFlight = inFlightActivations[input.requestID] {
            guard inFlight.attempt == attempt else {
                throw PLCAccountActivationError.conflict
            }
            inFlight.waiterCount += 1
            inFlightActivations[input.requestID] = inFlight
            return try await inFlight.task.value
        }

        let token = UUID()
        let task = Task {
            try await self.performActivation(input)
        }
        inFlightActivations[input.requestID] = InFlightActivation(
            token: token,
            attempt: attempt,
            task: task,
            waiterCount: 1
        )
        do {
            let result = try await task.value
            clearInFlightActivation(requestID: input.requestID, token: token)
            return result
        } catch {
            clearInFlightActivation(requestID: input.requestID, token: token)
            throw error
        }
    }

    private func performActivation(
        _ input: SwanManagementPLCActivateInput
    ) async throws -> SwanManagementPLCActivateResult {
        let handleVerifier: any PLCHandleVerifying
        if input.useStaticLaboratoryHandleVerifier {
            handleVerifier = StaticLaboratoryHandleVerifier()
        } else {
            handleVerifier = ATProtocolHandleVerifier(
                policy: input.handlePolicy,
                http: try NIOPeerPinnedATHandleHTTPTransport()
            )
        }
        let service = PLCAccountActivationService(
            intentStore: controlDatabase,
            accountStoreOpener: opener,
            keyStore: keyStore,
            plcClient: try PLCDirectoryClient(configuration: input.plcConfiguration),
            handleVerifier: handleVerifier,
            directory: directory
        )
        let installation = try await service.activate(
            requestID: input.requestID,
            password: input.password
        )
        if let liveAccountDirectory {
            let admission: SQLiteActivatedAccountAdmission
            do {
                admission = try await opener.takeActivatedAccountAdmission(
                    did: installation.account.did
                )
            } catch {
                throw PLCAccountActivationError.unavailable
            }
            do {
                try await liveAccountDirectory.admitActivatedAccount(admission)
            } catch {
                throw PLCAccountActivationError.unavailable
            }
        }
        return .init(installation: installation)
    }

    private func clearInFlightActivation(requestID: String, token: UUID) {
        guard inFlightActivations[requestID]?.token == token else { return }
        inFlightActivations.removeValue(forKey: requestID)
    }

    func activationWaiterCountForTesting(requestID: String) -> Int {
        inFlightActivations[requestID]?.waiterCount ?? 0
    }

    public func close() async throws {
        try await opener.close()
    }
}
