import Crypto
import Foundation
import NIOCore
import SwanAccounts
import SwanCore
import SwanSQLite
import SwanStorage

/// Production `SwanCreateAccountAuthorizationPipeline` conformer: verifies
/// policy, email proof, invite/Turnstile and DID preparation through
/// `SignupService` before provisioning can run.
///
/// The request/authorization identifiers are derived deterministically from
/// the input so the pipeline and the provisioning conformer agree without
/// shared mutable state: the same handle/email/DID always yields the same
/// requestID, so a retry of the same createAccount input cannot mint a second
/// identity (spec §4.1).
public struct SwanCreateAccountAuthorizationPipelineProduction: SwanCreateAccountAuthorizationPipeline, Sendable {
    private let service: SignupService
    private let extractor: any SignupTrustedPeerIPExtractor
    private let proofService: SignupEmailProofService
    private let signupSecret: SignupSecret

    public init(
        service: SignupService,
        extractor: any SignupTrustedPeerIPExtractor,
        proofService: SignupEmailProofService,
        signupSecret: SignupSecret
    ) {
        self.service = service
        self.extractor = extractor
        self.proofService = proofService
        self.signupSecret = signupSecret
    }

    public func authorize(_ input: SwanCreateAccountXRPCInput, peerAddress: SocketAddress?, now: Date) async throws {
        guard input.verificationPhone == nil else {
            throw SwanError.invalidIdentifier("verificationPhone unsupported")
        }
        guard let email = input.email, let verificationCode = input.verificationCode else {
            throw SwanError.invalidIdentifier("verified email required")
        }
        let identityDID = try Self.identityDID(from: input)
        let requestID = Self.requestID(handle: input.handle, email: email, did: identityDID)
        let authorizationID = try SignupAuthorizationID(rawValue: requestID)
        let emailProofDigest = try proofService.digest(
            code: verificationCode,
            email: try AccountEmailAddress(email),
            handle: input.handle
        )
        let inviteDigest = try input.inviteCode.map {
            try SignupInviteService(secret: signupSecret).digest(code: $0)
        }
        let resolvedPeerAddress: SocketAddress
        if let peerAddress {
            resolvedPeerAddress = peerAddress
        } else {
            resolvedPeerAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 0)
        }
        _ = try await service.authorize(
            requestID: requestID,
            authorizationID: authorizationID,
            handle: input.handle,
            email: try AccountEmailAddress(email),
            identityDID: identityDID,
            emailProofDigest: emailProofDigest,
            inviteDigest: inviteDigest,
            verificationCode: verificationCode,
            turnstileToken: input.turnstileToken,
            peerAddress: resolvedPeerAddress,
            extractor: extractor,
            now: now
        )
    }

    /// The identity DID for signup. Task 3 accepts the caller-supplied
    /// PLC-prepared DID; did:web claim identity is a later task.
    public static func identityDID(from input: SwanCreateAccountXRPCInput) throws -> String {
        guard let did = input.did, AccountControlIdentifiers.isDID(did) else {
            throw SwanError.invalidIdentifier("signup DID required")
        }
        return did
    }

    /// Deterministic request identifier: SHA-256 over handle/email/DID.
    public static func requestID(handle: String, email: String, did: String) -> String {
        let material = "swan.signup.request.v1\0\(handle)\0\(email)\0\(did)"
        return Data(SHA256.hash(data: Data(material.utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Production `SwanCreateAccountProvisioning` conformer: hashes the password,
/// provisions the account key pair against the external key store, builds the
/// finalization request, and runs the atomic signup transaction through a
/// per-request coordinator whose connection-scoped writer persists the
/// account row, identity binding, and management session together with Task 4
/// proof/invite consumption and the idempotent result.
public struct SwanCreateAccountProvisioningProduction: SwanCreateAccountProvisioning, Sendable {
    private let passwordHasher: any PasswordHasher
    private let keyProvisioner: AccountKeyProvisioner
    private let sessionRuntime: SwanManagementSessionRuntime
    private let database: SQLiteControlDatabase
    private let signupSecret: SignupSecret

    public init(
        passwordHasher: any PasswordHasher,
        keyProvisioner: AccountKeyProvisioner,
        sessionRuntime: SwanManagementSessionRuntime,
        database: SQLiteControlDatabase,
        signupSecret: SignupSecret
    ) {
        self.passwordHasher = passwordHasher
        self.keyProvisioner = keyProvisioner
        self.sessionRuntime = sessionRuntime
        self.database = database
        self.signupSecret = signupSecret
    }

    public func createAccount(_ input: SwanCreateAccountXRPCInput, now: Date) async throws -> (account: AccountControlAccount, session: Data) {
        let identityDID = try SwanCreateAccountAuthorizationPipelineProduction.identityDID(from: input)
        let requestID = SwanCreateAccountAuthorizationPipelineProduction.requestID(
            handle: input.handle,
            email: input.email ?? "",
            did: identityDID
        )
        let authorizationID = try SignupAuthorizationID(rawValue: requestID)
        let verifier = try passwordHasher.hash(input.password)
        guard (try? passwordHasher.needsRehash(verifier)) == false else {
            throw SwanError.unavailable("password hasher did not produce its configured Argon2id policy")
        }
        let keys = try await keyProvisioner.provisionInitial(accountDID: identityDID)
        let signingReference = try AccountControlKeyReference(
            purpose: .signing,
            generation: keys.signingReference.generation
        ).reference
        let rotationReference = try AccountControlKeyReference(
            purpose: .rotation,
            generation: keys.rotationReference.generation
        ).reference
        let issued = try sessionRuntime.mint(accountDID: identityDID, strength: .password, now: now)
        let sessionDigest = SwanManagementSessionRuntime.digest(issued.sessionValue)
        let csrfDigest = SwanManagementSessionRuntime.digest(issued.csrfValue)
        let preAuthCSRFDigest = SwanManagementSessionRuntime.digest(issued.csrfValue)
        let emailProofDigest = try input.verificationCode.map {
            try SignupEmailProofService(secret: signupSecret).digest(
                code: $0,
                email: try AccountEmailAddress(input.email ?? ""),
                handle: input.handle
            )
        }
        let inviteDigest = try input.inviteCode.map {
            try SignupInviteService(secret: signupSecret).digest(code: $0)
        }
        let request = try SignupFinalizationRequest(
            authorizationID: authorizationID,
            accountDID: identityDID,
            handle: input.handle,
            identityDID: identityDID,
            reservedKeyID: signingReference,
            managementSession: issued.metadata,
            sessionDigest: sessionDigest,
            csrfDigest: csrfDigest,
            emailProofDigest: emailProofDigest,
            inviteDigest: inviteDigest,
            preAuthCSRFDigest: preAuthCSRFDigest,
            idempotencyKey: requestID
        )
        let writer = try SQLiteSignupFoundationWriter(
            passwordVerifier: verifier,
            signingReference: signingReference,
            rotationReference: rotationReference
        )
        let coordinator = AssembledSQLiteSignupCoordinator(database: database, writer: writer)
        let result = try await coordinator.finalizeSignup(request, now: now)
        guard let account = try await database.account(did: result.accountDID) else {
            throw AccountControlStoreError.notFound
        }
        return (account, sessionDigest)
    }
}

/// Durable `AccountLifecycleCapabilityVerifier`: validates the management
/// session through the durable session store, consumes the step-up receipt
/// through the durable receipt store, and mints a bounded capability. Nonce
/// replay is prevented by a bounded in-memory set; the durable receipt
/// consumption is the linearization point.
public struct SwanAccountLifecycleCapabilityVerifier: AccountLifecycleCapabilityVerifier, Sendable {
    private let sessionStore: any ManagementSessionStore
    private let stepUpStore: any SwanIdentityStepUpReceiptStore
    private let capabilityLifetime: TimeInterval
    private let nonceReplay: NonceReplaySet

    public init(
        sessionStore: any ManagementSessionStore,
        stepUpStore: any SwanIdentityStepUpReceiptStore,
        capabilityLifetime: TimeInterval = 300
    ) throws {
        guard capabilityLifetime.isFinite, (1 ... 900).contains(capabilityLifetime) else {
            throw SwanError.invalidIdentifier("lifecycle capability lifetime")
        }
        self.sessionStore = sessionStore
        self.stepUpStore = stepUpStore
        self.capabilityLifetime = capabilityLifetime
        nonceReplay = NonceReplaySet()
    }

    public func verify(
        role: AccountLifecycleAuthorizationRole,
        subjectDID: String?,
        sessionDigest: Data,
        stepUpReceipt: Data,
        now: Date
    ) async throws -> AccountLifecycleCapability {
        guard sessionDigest.count == 32, stepUpReceipt.count == 32 else {
            throw SwanError.invalidIdentifier("lifecycle capability material")
        }
        guard let session = try await sessionStore.managementSession(digest: sessionDigest, now: now),
              session.revokedAt == nil,
              session.idleExpiresAt >= now,
              session.absoluteExpiresAt >= now else {
            throw SwanError.unauthorized("management session is not valid")
        }
        if role == .managementSession {
            guard subjectDID == session.accountDID else {
                throw SwanError.unauthorized("management session subject mismatch")
            }
        }
        // Consume the step-up receipt durably. The receipt is the proof that
        // the session holder performed the required MFA step-up.
        try await stepUpStore.consumeIdentityStepUpReceipt(
            sessionID: session.sessionID.rawValue,
            accountDID: session.accountDID,
            operation: "lifecycle",
            mfaStrength: "stepUpPassword",
            verifiedAt: now,
            expiresAt: now.addingTimeInterval(capabilityLifetime),
            receiptDigest: stepUpReceipt,
            now: now
        )
        var generator = SystemRandomNumberGenerator()
        let nonce = Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        guard nonceReplay.insert(nonce, now: now) else {
            throw SwanError.unauthorized("lifecycle capability nonce replay")
        }
        return AccountLifecycleCapability(
            role: role,
            subjectDID: subjectDID,
            nonce: nonce,
            expiresAt: now.addingTimeInterval(capabilityLifetime),
            action: "lifecycle",
            stepUpDigest: stepUpReceipt
        )
    }

    public func consume(_ capability: AccountLifecycleCapability, action: String, now: Date) async throws {
        guard capability.permits(did: capability.subjectDID ?? "", action: action, now: now) else {
            throw SwanError.unauthorized("lifecycle capability is not valid for \(action)")
        }
        guard nonceReplay.consume(capability.nonce) else {
            throw SwanError.unauthorized("lifecycle capability already consumed")
        }
    }
}

/// Bounded in-memory nonce replay set. Capabilities are short-lived and
/// single-use; the durable receipt consumption is the real linearization
/// point, and this set only prevents same-process replay within the
/// capability lifetime. All state is guarded by `lock`.
private final class NonceReplaySet: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data: Date] = [:]
    private let maximum = 4096

    func insert(_ nonce: Data, now: Date) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        values = values.filter { $0.value > now }
        guard values[nonce] == nil, values.count < maximum else { return false }
        values[nonce] = now.addingTimeInterval(900)
        return true
    }

    func consume(_ nonce: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values.removeValue(forKey: nonce) != nil
    }
}
