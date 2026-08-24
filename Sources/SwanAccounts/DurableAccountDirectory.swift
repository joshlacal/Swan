import Foundation
import PetrelPLC
import SwanCore
import SwanStorage

/// The only successful result exposed by password authentication. Absence of
/// this value is intentionally indistinguishable across unknown accounts,
/// missing credentials, bad passwords, and every non-active lifecycle state.
public struct AccountAuthenticationSuccess: Sendable, Equatable {
    public let account: AccountControlAccount
    public let credentialWasRehashed: Bool
    /// Strength earned by the complete login transaction. Password-only
    /// callers retain the historical `.password` value; factor-token callers
    /// receive the durable factor service's authenticated strength.
    public let strength: AuthenticationStrength
    /// A one-time durable authorization grant created by the canonical login
    /// transaction when the caller supplied an issuance context. It is absent
    /// for source-compatible account-only callers and never contains a raw
    /// credential.
    public let authorizationGrantDigest: Data?
    /// Password verification has succeeded and an active second factor is
    /// required (for OAuth MFA phase admission or legacy session
    /// AuthFactorTokenRequired), but no protected session or token may be
    /// issued yet.
    public let requiresFactor: Bool

    public init(
        account: AccountControlAccount,
        credentialWasRehashed: Bool,
        strength: AuthenticationStrength = .password,
        authorizationGrantDigest: Data? = nil,
        requiresFactor: Bool = false
    ) {
        self.account = account
        self.credentialWasRehashed = credentialWasRehashed
        self.strength = strength
        self.authorizationGrantDigest = authorizationGrantDigest
        self.requiresFactor = requiresFactor
    }
}

public enum AccountLoginAuthenticationOutcome: Sendable, Equatable {
    case authenticated(AccountAuthenticationSuccess)
    case rejected
}

public enum AccountLoginAuthenticationError: Error, Sendable, Equatable {
    case unavailable
}

/// The exact account state one signing or key-resolution decision was
/// authorized against: the whole control row plus the key generation that row
/// names. It exists so a caller that suspends between the decision and the use
/// can name what it decided on, rather than re-deriving a subset by hand.
public struct AuthorizingAccountSnapshot: Sendable, Equatable {
    public let account: AccountControlAccount
    public let signing: AccountKeyReference
    public let rotation: AccountKeyReference

    public init(
        account: AccountControlAccount,
        signing: AccountKeyReference,
        rotation: AccountKeyReference
    ) {
        self.account = account
        self.signing = signing
        self.rotation = rotation
    }
}

/// Durable registry, lifecycle, and local-password service. It never stores a
/// raw password and never returns a verifier through directory lookup APIs.
/// DID lifecycle/PLC operations remain outside this local control-plane slice.
public actor DurableAccountDirectory {
    private let store: any AccountControlStore
    private let passwordHasher: any PasswordHasher
    private let verificationExecutor: Argon2idVerificationExecutor
    private let keyProvisioner: AccountKeyProvisioner?
    private let loginAdmissionService: AccountLoginAdmissionService?
    private let loginFactorTokenVerifier: (any AccountLoginFactorTokenVerifying)?
    private let authenticationFactors: (any AuthenticationFactorStore)?
    private let dummyPasswordVerifier: String?

    public init(
        store: any AccountControlStore,
        passwordHasher: any PasswordHasher,
        verificationExecutor: Argon2idVerificationExecutor,
        keyProvisioner: AccountKeyProvisioner? = nil,
        loginAdmissionService: AccountLoginAdmissionService? = nil,
        loginFactorTokenVerifier: (any AccountLoginFactorTokenVerifying)? = nil,
        authenticationFactors: (any AuthenticationFactorStore)? = nil
    ) {
        self.store = store
        self.passwordHasher = passwordHasher
        self.verificationExecutor = verificationExecutor
        self.keyProvisioner = keyProvisioner
        self.loginAdmissionService = loginAdmissionService
        self.loginFactorTokenVerifier = loginFactorTokenVerifier
        self.authenticationFactors = authenticationFactors
        var generator = SystemRandomNumberGenerator()
        let dummyPassword = Data(
            (0 ..< 32).map { _ in
                UInt8.random(in: 0 ... 255, using: &generator)
            }
        ).base64EncodedString()
        if let verifier = try? passwordHasher.hash(dummyPassword),
           (try? passwordHasher.needsRehash(verifier)) == false,
           verifier.hasPrefix("$argon2id$v=19$"),
           verifier.utf8.count <= 1_024,
           verifier.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) {
            dummyPasswordVerifier = verifier
        } else {
            // A deployment whose boot-time dummy hash cannot be generated may
            // still use non-login account APIs, but login fails unavailable.
            dummyPasswordVerifier = nil
        }
    }

    /// Creates key material in the configured external key store and records
    /// only its deterministic generation references in `control.sqlite`.
    public func provision(
        did: String,
        handle: String,
        password: String,
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        let did = try validateDID(did)
        let handle = try canonicalizeHandle(handle)
        guard let keyProvisioner else {
            throw SwanError.unavailable("account key provisioner is not configured")
        }
        let keys = try await keyProvisioner.provisionInitial(accountDID: did)
        return try await registerProvisionedAccount(
            did: did,
            canonicalHandle: handle,
            password: password,
            signingReference: keys.signingReference,
            rotationReference: keys.rotationReference,
            now: now
        )
    }

    /// Registers an account whose external key material was provisioned by an
    /// operator or a previous durable workflow. This accepts raw password only
    /// at registration time. A non-current restored verifier is not upgraded
    /// through login because doing so would expose its different work factor;
    /// password recovery or an operator migration must replace it.
    public func registerProvisionedAccount(
        did: String,
        canonicalHandle: String,
        password: String,
        signingReference: AccountKeyReference,
        rotationReference: AccountKeyReference,
        publicGenesisCommitCID: String? = nil,
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        let did = try validateDID(did)
        let handle = try canonicalizeHandle(canonicalHandle)
        guard signingReference.accountDID == did,
              rotationReference.accountDID == did,
              signingReference.purpose == .signing,
              rotationReference.purpose == .rotation,
              signingReference.generation == rotationReference.generation else {
            throw SwanError.malformed("account key references do not match the account generation")
        }
        let verifier = try passwordHasher.hash(password)
        guard (try? passwordHasher.needsRehash(verifier)) == false else {
            throw SwanError.unavailable(
                "password hasher did not produce its configured Argon2id policy"
            )
        }
        let registration = try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: verifier,
            signingKey: try controlReference(for: signingReference),
            rotationKey: try controlReference(for: rotationReference),
            publicGenesisCommitCID: publicGenesisCommitCID,
            createdAt: now
        )
        return try await store.createAccount(registration)
    }

    /// Normal account lookup returns control metadata only; a password
    /// verifier can never cross this API boundary.
    public func account(did: String) async throws -> AccountControlAccount? {
        try await store.account(did: validateDID(did))
    }

    /// Resolves a canonicalized handle without exposing credential material.
    public func resolve(handle: String) async throws -> AccountControlAccount? {
        try await store.account(canonicalHandle: canonicalizeHandle(handle))
    }

    /// Returns the external-key-store references reconstructed from durable
    /// generation metadata. This never reads or exports private key bytes.
    public func keyReferences(
        did: String
    ) async throws -> (signing: AccountKeyReference, rotation: AccountKeyReference)? {
        let did = try validateDID(did)
        guard let account = try await store.account(did: did) else {
            return nil
        }
        return try keyReferences(of: account)
    }

    /// The account together with the key generation it names, in **one**
    /// control-store read. `keyReferences(did:)` re-reads the same row, so a
    /// caller that needs both gets a cheaper and internally consistent answer
    /// here.
    ///
    /// `nil` means proven absence or a lifecycle state that does not authorize
    /// the account to act. Callers that must distinguish "not mine" from
    /// "changed underneath me" pair this with
    /// ``requireUnchangedAuthorizingAccount(did:expected:)``.
    public func authorizingAccount(
        did: String
    ) async throws -> AuthorizingAccountSnapshot? {
        let did = try validateDID(did)
        guard let account = try await store.account(did: did),
              account.status.authorizesAccount,
              let references = try keyReferences(of: account) else {
            return nil
        }
        return AuthorizingAccountSnapshot(
            account: account,
            signing: references.signing,
            rotation: references.rotation
        )
    }

    /// The fence every local signer applies after reading key material.
    ///
    /// Reading the signing scalar out of the key store is a suspension, and
    /// this directory exposes no atomic account/key projection, so a
    /// deactivation, a permanent-deletion revocation, or a key rotation can
    /// commit while it runs. The signer then emits a token or a signed commit
    /// under an authority that was revoked before the signature existed.
    ///
    /// Any intervening change is terminal, not a retryable miss: the artefact
    /// about to be produced outlives the revocation that should have prevented
    /// it. Callers surface this as an opaque availability failure — no call
    /// site widens its client-visible body with this message.
    ///
    /// This is one method rather than one copy per signer on purpose: four
    /// hand-copied bodies is what produced four identical omissions and two
    /// comments asserting an invariant the code did not hold.
    public func requireUnchangedAuthorizingAccount(
        did: String,
        expected: AuthorizingAccountSnapshot
    ) async throws {
        let current: AuthorizingAccountSnapshot?
        do {
            current = try await authorizingAccount(did: did)
        } catch {
            throw SwanError.unavailable("account authorization is unavailable")
        }
        guard let current, current == expected else {
            throw SwanError.unavailable("account authorization is unavailable")
        }
    }

    private func keyReferences(
        of account: AccountControlAccount
    ) throws -> (signing: AccountKeyReference, rotation: AccountKeyReference)? {
        guard let signing = account.signingKey,
              let rotation = account.rotationKey else {
            return nil
        }
        guard signing.purpose == .signing, rotation.purpose == .rotation,
              signing.generation == rotation.generation,
              signing.reference == "\(signing.purpose.rawValue):\(signing.generation)",
              rotation.reference == "\(rotation.purpose.rawValue):\(rotation.generation)" else {
            throw AccountControlStoreError.malformedRecord
        }
        return (
            try AccountKeyReference(
                accountDID: account.did,
                purpose: .signing,
                generation: signing.generation
            ),
            try AccountKeyReference(
                accountDID: account.did,
                purpose: .rotation,
                generation: rotation.generation
            )
        )
    }

    /// Compatibility wrapper for non-HTTP callers. OAuth login must use
    /// ``authenticateForLogin(handle:password:authFactorToken:now:)`` so capacity and storage
    /// unavailability cannot collapse into a bad-credentials response.
    public func authenticate(
        handle: String,
        password: String,
        now: Date = Date()
    ) async -> AccountAuthenticationSuccess? {
        guard let outcome = try? await authenticateForLogin(
            handle: handle,
            password: password,
            now: now
        ), case let .authenticated(success) = outcome, !success.requiresFactor else {
            return nil
        }
        return success
    }

    /// Enumeration-resistant password verification for browser login.
    ///
    /// Every bounded input performs exactly one Argon2id verification.
    /// Unknown, inactive, missing-credential, malformed-credential, and
    /// malformed-handle paths use a boot-generated dummy verifier. A real
    /// active credential uses its own verifier only when its PHC work factor
    /// exactly matches that dummy. Infrastructure or executor saturation is
    /// typed separately from the common rejected result.
    public func authenticateForLogin(
        handle: String,
        password: String,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome {
        try await authenticateForLoginInternal(
            handle: handle,
            password: password,
            authFactorToken: nil,
            authFactorSessionID: nil,
            authorizationContext: nil,
            now: now,
            enforceActiveFactors: true
        )
    }

    public func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String? = nil,
        now: Date = Date()
    ) async throws -> AccountLoginAuthenticationOutcome {
        try await authenticateForLoginInternal(
            handle: handle,
            password: password,
            authFactorToken: authFactorToken,
            authFactorSessionID: nil,
            authorizationContext: nil,
            now: now,
            enforceActiveFactors: true
        )
    }

    /// Portal management login supplies the pre-auth session that issued the
    /// factor receipt. The canonical account-only overload above remains for
    /// OAuth/legacy callers that do not have a management session cookie.
    public func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String?,
        authFactorSessionID: String?,
        now: Date = Date()
    ) async throws -> AccountLoginAuthenticationOutcome {
        try await authenticateForLoginInternal(
            handle: handle,
            password: password,
            authFactorToken: authFactorToken,
            authFactorSessionID: authFactorSessionID,
            authorizationContext: nil,
            now: now,
            enforceActiveFactors: true
        )
    }

    /// Channel-aware login used by the production portal, OAuth browser, and
    /// legacy issuance paths. The returned grant is created at the same
    /// durable linearization point as factor-token consumption (or the
    /// active-factor decision for password-only login).
    public func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String?,
        authorizationContext: AccountAuthorizationContext,
        now: Date = Date()
    ) async throws -> AccountLoginAuthenticationOutcome {
        try await authenticateForLoginInternal(
            handle: handle,
            password: password,
            authFactorToken: authFactorToken,
            authFactorSessionID: authorizationContext.sessionID,
            authorizationContext: authorizationContext,
            now: now,
            enforceActiveFactors: true
        )
    }

    /// Verifies only the password half of a two-step MFA login. It returns
    /// the same account metadata as normal login but never creates a session
    /// or issues a bearer token; the caller must immediately complete a
    /// factor ceremony and use the resulting management-login token.
    public func authenticatePasswordForMFAChallenge(
        handle: String,
        password: String,
        now: Date = Date()
    ) async throws -> AccountLoginAuthenticationOutcome {
        try await authenticateForLoginInternal(
            handle: handle,
            password: password,
            authFactorToken: nil,
            authFactorSessionID: nil,
            authorizationContext: nil,
            now: now,
            enforceActiveFactors: false
        )
    }

    /// Completes a previously admitted OAuth/portal factor ceremony without
    /// running password verification a second time. The durable factor store
    /// consumes the exact channel-bound receipt and creates the one-time grant
    /// in the same transaction.
    public func authenticateFactorForLogin(
        accountDID: String,
        authFactorToken: String,
        authorizationContext: AccountAuthorizationContext,
        now: Date = Date()
    ) async throws -> AccountLoginAuthenticationOutcome {
        guard !accountDID.isEmpty, !authFactorToken.isEmpty,
              let verifier = loginFactorTokenVerifier as? any AccountLoginAuthorizationGrantVerifying,
              let account = try await store.account(did: accountDID),
              account.status.authorizesAccount else {
            throw AccountLoginAuthenticationError.unavailable
        }
        do {
            let grant = try await verifier.authorizeLoginWithFactorToken(
                token: authFactorToken,
                accountDID: accountDID,
                context: authorizationContext,
                now: now
            )
            return .authenticated(AccountAuthenticationSuccess(
                account: account,
                credentialWasRehashed: false,
                strength: grant.strength,
                authorizationGrantDigest: grant.grantDigest
            ))
        } catch let error as AccountLoginAuthenticationError {
            throw error
        } catch {
            return .rejected
        }
    }

    private func authenticateForLoginInternal(
        handle: String,
        password: String,
        authFactorToken: String?,
        authFactorSessionID: String?,
        authorizationContext: AccountAuthorizationContext?,
        now: Date,
        enforceActiveFactors: Bool
    ) async throws -> AccountLoginAuthenticationOutcome {
        guard let dummyPasswordVerifier else {
            throw AccountLoginAuthenticationError.unavailable
        }

        var candidate:
            (account: AccountControlAccount, credential: AccountControlCredential)?
        var storageUnavailable = false
        if let canonicalHandle = try? canonicalizeHandle(handle) {
            do {
                if let account = try await store.account(
                    canonicalHandle: canonicalHandle
                ), account.status.authorizesAccount,
                   account.credentialState == .configured {
                    do {
                        if let credential = try await store.credential(
                            did: account.did
                        ) {
                            candidate = (account, credential)
                        }
                    } catch let error as AccountControlStoreError {
                        if error == .unavailable {
                            storageUnavailable = true
                        }
                        // Malformed/missing credential material deliberately
                        // falls through to the dummy verification path.
                    } catch {
                        storageUnavailable = true
                    }
                }
            } catch let error as AccountControlStoreError {
                if error == .unavailable {
                    storageUnavailable = true
                }
                // Identifier/account-record failures do not become an
                // existence oracle; they still consume the dummy verifier.
            } catch {
                storageUnavailable = true
            }
        }

        // A restored or legacy PHC string with a different work factor would
        // make known-account failures measurably faster or slower than the
        // unknown-account dummy path. Parse exactly one candidate (the dummy
        // when none exists) and admit a real verifier only when it matches the
        // configured hasher policy exactly. Non-current hashes
        // fail closed through the same boot-generated dummy verification and
        // require password recovery or an operator migration.
        let proposedVerifier = candidate?.credential.verifier
            ?? dummyPasswordVerifier
        let matchesConfiguredPolicy =
            (try? passwordHasher.needsRehash(proposedVerifier)) == false
        if !matchesConfiguredPolicy {
            candidate = nil
        }
        let selectedVerifier = candidate?.credential.verifier
            ?? dummyPasswordVerifier
        let verified: Bool
        do {
            verified = try await verificationExecutor.verify(
                password,
                encodedHash: selectedVerifier
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw AccountLoginAuthenticationError.unavailable
        }
        guard !storageUnavailable else {
            throw AccountLoginAuthenticationError.unavailable
        }
        guard verified, let candidate else {
            return .rejected
        }

        do {
            guard let finalized = try await store.finalizeAuthentication(
                did: candidate.account.did,
                expectedVerifier: candidate.credential.verifier,
                replacementVerifier: nil,
                now: now
            ) else {
                return .rejected
            }
            let strength: AuthenticationStrength
            let activeFactors: [AuthenticationFactorMetadata]
            do {
                activeFactors = try await authenticationFactors?.listFactors(
                    accountDID: finalized.account.did,
                    now: now
                ) ?? []
            } catch {
                throw AccountLoginAuthenticationError.unavailable
            }

            if let authorizationContext {
                guard let grantStore = store as? any AccountAuthorizationGrantStore else {
                    throw AccountLoginAuthenticationError.unavailable
                }
                if let authFactorToken {
                    guard let grantVerifier = loginFactorTokenVerifier as? any AccountLoginAuthorizationGrantVerifying else {
                        return .rejected
                    }
                    do {
                        let grant = try await grantVerifier.authorizeLoginWithFactorToken(
                            token: authFactorToken,
                            accountDID: finalized.account.did,
                            context: authorizationContext,
                            now: now
                        )
                        return .authenticated(AccountAuthenticationSuccess(
                            account: finalized.account,
                            credentialWasRehashed: finalized.credentialWasReplaced,
                            strength: grant.strength,
                            authorizationGrantDigest: grant.grantDigest
                        ))
                    } catch let error as AccountLoginAuthenticationError {
                        throw error
                    } catch {
                        return .rejected
                    }
                }
                do {
                    let grant = try await grantStore.createPasswordAuthorizationGrant(
                        grantDigest: Self.randomGrantDigest(),
                        accountDID: finalized.account.did,
                        context: authorizationContext,
                        now: now
                    )
                    return .authenticated(AccountAuthenticationSuccess(
                        account: finalized.account,
                        credentialWasRehashed: finalized.credentialWasReplaced,
                        strength: grant.strength,
                        authorizationGrantDigest: grant.grantDigest
                    ))
                } catch let error as AccountControlStoreError where error == .notFound {
                    guard !activeFactors.isEmpty else {
                        return .rejected
                    }
                    if authorizationContext.channel == .oauth {
                        guard let phaseStore = store as? any OAuthMFAAdmissionStore else {
                            return .rejected
                        }
                        do {
                            _ = try await phaseStore.beginOAuthMFAAdmission(
                                accountDID: finalized.account.did,
                                context: authorizationContext,
                                now: now
                            )
                        } catch {
                            throw AccountLoginAuthenticationError.unavailable
                        }
                        return .authenticated(AccountAuthenticationSuccess(
                            account: finalized.account,
                            credentialWasRehashed: finalized.credentialWasReplaced,
                            requiresFactor: true
                        ))
                    }
                    if authorizationContext.channel == .legacy {
                        // The account password verified successfully, but the account
                        // has active authentication factors and no factor token was
                        // presented. For the legacy XRPC channel (com.atproto.server.createSession),
                        // this outcome signals that the caller must present an
                        // authFactorToken to proceed. The legacy XRPC handler maps
                        // this to HTTP 401 AuthFactorTokenRequired.
                        return .authenticated(AccountAuthenticationSuccess(
                            account: finalized.account,
                            credentialWasRehashed: finalized.credentialWasReplaced,
                            requiresFactor: true
                        ))
                    }
                    return .rejected
                } catch {
                    throw AccountLoginAuthenticationError.unavailable
                }
            }
            if enforceActiveFactors && !activeFactors.isEmpty && authFactorToken == nil {
                // Once a factor is active, password verification alone is
                // never a management/OAuth/legacy login. The caller must
                // first complete a factor ceremony and present the opaque
                // management-login receipt on this same request.
                return .rejected
            }
            if let authFactorToken {
                guard let loginFactorTokenVerifier else {
                    // A presented factor token must never silently downgrade
                    // to password authority when the MFA capability is absent.
                    return .rejected
                }
                do {
                    if let authFactorSessionID {
                        guard let sessionVerifier = loginFactorTokenVerifier as? any AccountLoginFactorTokenSessionVerifying else {
                            return .rejected
                        }
                        if let atomicVerifier = loginFactorTokenVerifier as? any AccountLoginFactorTokenAtomicVerifying {
                            strength = try await atomicVerifier.verifyLoginFactorTokenAtomically(token: authFactorToken, accountDID: finalized.account.did, sessionID: authFactorSessionID, now: now)
                        } else {
                            strength = try await sessionVerifier.verifyLoginFactorToken(token: authFactorToken, accountDID: finalized.account.did, sessionID: authFactorSessionID, now: now)
                        }
                    } else {
                        if let atomicVerifier = loginFactorTokenVerifier as? any AccountLoginFactorTokenAtomicVerifying {
                            strength = try await atomicVerifier.verifyLoginFactorTokenAtomically(token: authFactorToken, accountDID: finalized.account.did, now: now)
                        } else {
                            strength = try await loginFactorTokenVerifier.verifyLoginFactorToken(token: authFactorToken, accountDID: finalized.account.did, now: now)
                        }
                    }
                } catch let error as AccountLoginAuthenticationError {
                    throw error
                } catch {
                    // Invalid, expired, replayed, or wrong-purpose tokens are
                    // indistinguishable from a rejected credential. Stores
                    // must fail closed; only explicit account infrastructure
                    // unavailability is surfaced as unavailable.
                    return .rejected
                }
                guard !enforceActiveFactors || (activeFactors.isEmpty || allowsLoginStrength(strength, activeFactors: activeFactors)) else {
                    // A recovery code is a login factor only when recovery is
                    // the account's sole active factor. It must never
                    // downgrade a mixed TOTP/passkey account to email-level
                    // authentication.
                    return .rejected
                }
            } else {
                strength = .password
            }
            if enforceActiveFactors {
                // Re-read immediately before returning the authenticated
                // result. Factor activation is durable and may race the
                // password hash; a password-only outcome must never be
                // issued from a stale pre-Argon2 factor snapshot.
                let finalActiveFactors: [AuthenticationFactorMetadata]
                do {
                    finalActiveFactors = try await authenticationFactors?.listFactors(
                        accountDID: finalized.account.did,
                        now: now
                    ) ?? []
                } catch {
                    throw AccountLoginAuthenticationError.unavailable
                }
                guard finalActiveFactors.isEmpty || allowsLoginStrength(strength, activeFactors: finalActiveFactors) else {
                    return .rejected
                }
            }
            return .authenticated(AccountAuthenticationSuccess(
                account: finalized.account,
                credentialWasRehashed: finalized.credentialWasReplaced,
                strength: strength
            ))
        } catch let error as AccountControlStoreError {
            if error == .unavailable {
                throw AccountLoginAuthenticationError.unavailable
            }
            return .rejected
        } catch {
            throw AccountLoginAuthenticationError.unavailable
        }
    }

    private func ifStepUpMFA(_ strength: AuthenticationStrength) -> Bool {
        if case .stepUpMFA = strength { return true }
        return false
    }

    private func allowsLoginStrength(
        _ strength: AuthenticationStrength,
        activeFactors: [AuthenticationFactorMetadata]
    ) -> Bool {
        if ifStepUpMFA(strength) { return true }
        guard strength == .emailRecovery, !activeFactors.isEmpty else { return false }
        return activeFactors.allSatisfy { $0.kind == .recoveryCode && $0.disabledAt == nil }
    }

    private static func randomGrantDigest() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    /// Applies the mandatory login abuse boundary using the actual accepted
    /// socket peer. A directory not composed with durable admission fails
    /// unavailable rather than silently enabling unthrottled OAuth login.
    public func admitLogin(
        handle: String,
        directPeer: String,
        now: Date = Date()
    ) async throws -> AccountLoginAdmissionDecision {
        guard let loginAdmissionService else {
            throw AccountLoginAdmissionError.unavailable
        }
        return try await loginAdmissionService.admit(
            handle: handle,
            directPeer: directPeer,
            now: now
        )
    }

    public func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration = .init(),
        emitting: AccountLifecycleEmission? = nil,
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        try await store.transitionStatus(
            did: validateDID(did),
            to: status,
            declaration: declaration,
            emitting: emitting,
            now: now
        )
    }

    private func controlReference(
        for reference: AccountKeyReference
    ) throws -> AccountControlKeyReference {
        let purpose: AccountControlKeyReference.Purpose = switch reference.purpose {
        case .signing: .signing
        case .rotation: .rotation
        }
        return try AccountControlKeyReference(
            purpose: purpose,
            generation: reference.generation
        )
    }
}

private func validateDID(_ did: String) throws -> String {
    do {
        return try AccountIdentifiers.validateDID(did)
    } catch let error as PetrelPLCError {
        throw translatePLCError(error)
    }
}

private func canonicalizeHandle(_ handle: String) throws -> String {
    do {
        return try AccountIdentifiers.canonicalHandle(handle)
    } catch let error as PetrelPLCError {
        throw translatePLCError(error)
    }
}

private func translatePLCError(_ error: PetrelPLCError) -> SwanError {
    switch error {
    case let .invalidIdentifier(message):
        return .invalidIdentifier(message)
    case let .invalidProfile(message):
        return .invalidProfile(message)
    case let .unauthorized(message):
        return .unauthorized(message)
    case let .conflict(expected, actual):
        return .conflict(expected: expected, actual: actual)
    case .expired:
        return .expired
    case let .malformed(message):
        return .malformed(message)
    case let .unavailable(message):
        return .unavailable(message)
    }
}
