import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanStorage

/// The production account portal's MFA composition. The runtime deliberately
/// depends on the additive factor services from SwanAccounts and the durable
/// storage contracts from SwanStorage; it does not create a second account or
/// password authority.
public struct SwanAccountPortalMFARuntime: SwanAccountPortalOAuthMFAService, Sendable {
    private let factors: any AuthenticationFactorStore
    private let totpSecrets: any TOTPSecretStore
    private let replayStore: any TOTPReplayStore
    private let recoveryStore: any RecoveryCodeStore
    private let webAuthnCredentials: any WebAuthnCredentialStore
    private let webAuthnChallenges: any WebAuthnChallengeLookupStore
    private let webAuthnEnrollmentStore: any WebAuthnEnrollmentStore
    private let totp: TOTPFactorService
    private let recovery: RecoveryCodeService
    private let factorTokens: FactorTokenService
    private let webAuthn: WebAuthnVerifier
    private let webAuthnEnrollment: WebAuthnEnrollmentService
    private let relyingPartyID: String
    private let origin: String
    private let totpKeyReference: String
    private let totpKey: Data

    /// `accountKEK` is retained from the descriptor-safe startup preflight.
    /// It is used only to seal/open TOTP envelopes; the control database sees
    /// the envelope and key reference, never this key or a plaintext seed.
    public init(
        factors: any AuthenticationFactorStore,
        totpSecrets: any TOTPSecretStore,
        replayStore: any TOTPReplayStore,
        recoveryStore: any RecoveryCodeStore,
        webAuthnCredentials: any WebAuthnCredentialStore,
        webAuthnChallenges: any WebAuthnChallengeLookupStore,
        webAuthnEnrollmentStore: any WebAuthnEnrollmentStore,
        factorTokens: FactorTokenService,
        accountKEK: Data,
        accountKEKID: String,
        relyingPartyID: String,
        origin: String
    ) throws {
        guard accountKEK.count == 32, !accountKEKID.isEmpty,
              !relyingPartyID.isEmpty, !origin.isEmpty else {
            throw SwanError.malformed("account MFA startup material")
        }
        let keyReference = "account-kek:\(accountKEKID)"
        let keyStore = MountedTOTPEnvelopeKeyStore(reference: keyReference, key: accountKEK)
        let webKeyStore = InlineWebAuthnPublicKeyStore()
        self.factors = factors
        self.totpSecrets = totpSecrets
        self.replayStore = replayStore
        self.recoveryStore = recoveryStore
        self.webAuthnCredentials = webAuthnCredentials
        self.webAuthnChallenges = webAuthnChallenges
        self.webAuthnEnrollmentStore = webAuthnEnrollmentStore
        self.totp = TOTPFactorService(
            keyStore: keyStore,
            replayGuard: TOTPReplayGuard(store: replayStore),
            factorStore: factors
        )
        self.recovery = RecoveryCodeService(store: recoveryStore, factorStore: factors)
        self.factorTokens = factorTokens
        self.webAuthn = WebAuthnVerifier(
            keyStore: webKeyStore,
            credentialStore: webAuthnCredentials,
            challengeStore: webAuthnChallenges,
            factorStore: factors,
            relyingPartyID: relyingPartyID,
            origin: origin
        )
        self.webAuthnEnrollment = WebAuthnEnrollmentService(
            store: webAuthnEnrollmentStore,
            factorStore: factors
        )
        self.relyingPartyID = relyingPartyID
        self.origin = origin
        self.totpKeyReference = keyReference
        self.totpKey = accountKEK
    }

    public func mutate(
        path: String,
        accountDID: String,
        sessionID: String,
        strength: AuthenticationStrength,
        expectedRevision: Int64?,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        // A factor-state mutation is committed under a revision compare-and-
        // swap: the portal service authorized against the revision it passes
        // here, and the store refuses to commit when a concurrent mutation
        // advanced the revision in between (Task 3 Finding 1 carry-forward).
        let revision = try authorizedRevision(expectedRevision)
        switch path {
        case "factors/totp":
            if payload == nil,
               let factor = try await factors.listFactors(accountDID: accountDID, now: now).first(where: { $0.kind == .totp && $0.disabledAt == nil }) {
                return try await disableFactor(id: factor.id, accountDID: accountDID, expected: .totp, expectedRevision: revision, now: now)
            }
            return try await enrollTOTP(accountDID: accountDID, payload: payload, expectedRevision: revision, now: now)
        case "factors/totp/verify":
            return try await verifyTOTPEnrollment(accountDID: accountDID, payload: payload, expectedRevision: revision, now: now)
        case "factors/passkeys/challenge", "factors/passkeys/options":
            return try await beginPasskeyEnrollment(accountDID: accountDID, sessionID: sessionID, payload: payload, now: now)
        case "factors/passkeys":
            if payload == nil,
               let factor = try await factors.listFactors(accountDID: accountDID, now: now).first(where: { $0.kind == .passkey && $0.disabledAt == nil }) {
                return try await disableFactor(id: factor.id, accountDID: accountDID, expected: .passkey, expectedRevision: revision, now: now)
            }
            return try await enrollPasskey(accountDID: accountDID, sessionID: sessionID, payload: payload, expectedRevision: revision, now: now)
        case "factors/passkeys/step-up-challenge", "factors/passkeys/assertion", "factors/step-up/passkey-challenge":
            return try await beginPasskeyAssertion(accountDID: accountDID, sessionID: sessionID, payload: payload, now: now)
        case "factors/recovery-codes/rotate":
            guard strength.isStepUp else { throw MFAError.stepUpRequired }
            return try await rotateRecoveryCodes(accountDID: accountDID, expectedRevision: revision, now: now)
        case "factors/step-up":
            return try await stepUp(accountDID: accountDID, sessionID: sessionID, payload: payload, purpose: .stepUp, now: now)
        case "factors/login":
            return try await stepUp(accountDID: accountDID, sessionID: sessionID, payload: payload, purpose: .managementLogin, now: now)
        case "factors":
            // The generic endpoint is retained for the portal's capability
            // discovery. It accepts an explicit `kind` and delegates to the
            // same typed enrollment implementations.
            let kind = try decodeKind(payload)
            switch kind {
            case .totp: return try await enrollTOTP(accountDID: accountDID, payload: payload, expectedRevision: revision, now: now)
            case .passkey: return try await enrollPasskey(accountDID: accountDID, sessionID: sessionID, payload: payload, expectedRevision: revision, now: now)
            case .recoveryCode:
                // Recovery activation is coupled to server-issued recovery
                // material/rotation; a generic caller-supplied kind must not
                // bootstrap a recovery factor by itself.
                throw MFAError.stepUpRequired
            }
        default:
            if path.hasPrefix("factors/totp/") {
                let factorID = String(path.dropFirst("factors/totp/".count))
                return try await disableFactor(id: factorID, accountDID: accountDID, expected: .totp, expectedRevision: revision, now: now)
            }
            if path.hasPrefix("factors/passkeys/") {
                let suffix = String(path.dropFirst("factors/passkeys/".count))
                if !suffix.isEmpty, payload != nil {
                    return try await enrollPasskey(accountDID: accountDID, sessionID: sessionID, payload: payload, factorIDOverride: suffix, expectedRevision: revision, now: now)
                }
                return try await disableFactor(id: suffix, accountDID: accountDID, expected: .passkey, expectedRevision: revision, now: now)
            }
            throw SwanAccountPortalServiceError.unsupported
        }
    }

    /// Resolves the portal-authorized revision predicate. A nil predicate
    /// (ceremony/login proofs) carries no CAS requirement; a non-nil predicate
    /// requires a durable store that can compare-and-swap, so a fixture
    /// without the capability fails closed instead of silently skipping the
    /// fence.
    private func authorizedRevision(_ expectedRevision: Int64?) throws -> Int64? {
        guard let expectedRevision else { return nil }
        guard factors is any FactorMutationAuthorizingStore else {
            throw MFAError.storageUnavailable
        }
        return expectedRevision
    }

    private func authorizedStore() throws -> any FactorMutationAuthorizingStore {
        guard let store = factors as? any FactorMutationAuthorizingStore else {
            throw MFAError.storageUnavailable
        }
        return store
    }

    /// OAuth factor proofs use the same verifier and durable factor-token
    /// store as the portal, but mint a receipt whose channel/purpose carries
    /// the signed OAuth browser binding. This is intentionally a separate
    /// entry point so a portal form can never select the OAuth channel.
    public func mutateOAuth(
        path: String,
        accountDID: String,
        sessionID: String,
        authorizationContext: AccountAuthorizationContext,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        guard authorizationContext.channel == .oauth,
              authorizationContext.sessionID == sessionID,
              authorizationContext.purpose == FactorTokenPurpose.oauthToken.rawValue else {
            throw MFAError.tokenInvalid
        }
        switch path {
        case "factors/passkeys/step-up-challenge", "factors/passkeys/assertion", "factors/step-up/passkey-challenge":
            return try await beginPasskeyAssertion(accountDID: accountDID, sessionID: sessionID, payload: payload, now: now)
        case "factors/login":
            return try await stepUp(accountDID: accountDID, sessionID: sessionID, payload: payload, purpose: .oauthToken, authorizationContext: authorizationContext, now: now)
        default:
            throw SwanAccountPortalServiceError.unsupported
        }
    }

    private func enrollTOTP(accountDID: String, payload: Data?, expectedRevision: Int64?, now: Date) async throws -> SwanAccountPortalMutation {
        guard let pendingStore = totpSecrets as? any TOTPEnrollmentStore else {
            throw MFAError.storageUnavailable
        }
        let request = try decodeTOTPRequest(payload)
        let factorID = request.factorID ?? UUID().uuidString.lowercased()
        let secret: Data
        do { secret = try TOTPAuthenticator.decodeBase32(request.secret) }
        catch { throw MFAError.invalidCode }
        guard !secret.isEmpty, secret.count <= 128 else { throw MFAError.invalidCode }
        let factor = try AuthenticationFactorMetadata(
            id: factorID,
            accountDID: accountDID,
            kind: .totp,
            label: request.label,
            lookupDigest: Data(SHA256.hash(data: Data(("swan-factor:" + factorID).utf8))),
            createdAt: now,
            disabledAt: now
        )
        if let expectedRevision {
            _ = try await authorizedStore().saveFactor(
                factor, expectedRevision: expectedRevision, now: now
            )
        } else {
            try await factors.saveFactor(factor, now: now)
        }
        do {
            let envelope = try TOTPEnvelopeCrypto.seal(
                secret: secret,
                factorID: factorID,
                keyReference: totpKeyReference,
                key: try await keyForTOTPEnvelope()
            )
            try await pendingStore.savePendingTOTPEnvelope(
                envelope,
                accountDID: accountDID,
                expiresAt: now.addingTimeInterval(10 * 60),
                now: now
            )
        } catch {
            // A partially enrolled factor cannot be used for authentication.
            // Disable it rather than leaving an active row without an
            // envelope; the durable delete/revoke path remains idempotent.
            try? await factors.disableFactor(id: factorID, accountDID: accountDID, now: now)
            throw MFAError.storageUnavailable
        }
        return .init(message: "TOTP enrollment pending verification", accountDID: accountDID, factorID: factorID)
    }

    private func verifyTOTPEnrollment(accountDID: String, payload: Data?, expectedRevision: Int64?, now: Date) async throws -> SwanAccountPortalMutation {
        guard let pendingStore = totpSecrets as? any TOTPEnrollmentStore else {
            throw MFAError.storageUnavailable
        }
        let request = try decodeTOTPVerificationRequest(payload)
        guard let pending = try await pendingStore.pendingTOTPEnvelope(
            factorID: request.factorID,
            accountDID: accountDID,
            now: now
        ) else { throw MFAError.invalidChallenge }
        guard let key = try await (MountedTOTPEnvelopeKeyStore(reference: totpKeyReference, key: totpKey).key(reference: pending.keyReference)) else {
            throw MFAError.invalidEnvelope
        }
        let secret = try TOTPEnvelopeCrypto.open(pending, key: key)
        guard let _ = try? TOTPAuthenticator.verify(code: request.code, secret: secret, at: now) else {
            throw MFAError.invalidCode
        }
        do {
            if let expectedRevision {
                _ = try await authorizedStore().activatePendingTOTPEnvelope(
                    factorID: request.factorID,
                    accountDID: accountDID,
                    expectedRevision: expectedRevision,
                    now: now
                )
            } else {
                _ = try await pendingStore.activatePendingTOTPEnvelope(
                    factorID: request.factorID,
                    accountDID: accountDID,
                    now: now
                )
            }
        } catch {
            throw MFAError.invalidChallenge
        }
        return .init(message: "TOTP factor enrolled", accountDID: accountDID, factorID: request.factorID)
    }

    private func beginPasskeyEnrollment(accountDID: String, sessionID: String, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation {
        _ = try decodePasskeyBeginRequest(payload)
        let factorID = UUID().uuidString.lowercased()
        let challenge = Self.serverChallengeBytes()
        let challengeRecord = try WebAuthnChallenge(
            challengeDigest: Data(SHA256.hash(data: challenge)),
            accountDID: accountDID,
            sessionID: sessionID,
            factorID: factorID,
            purpose: .enrollment,
            relyingPartyID: relyingPartyID,
            origin: origin,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        try await webAuthnChallenges.reserveWebAuthnChallenge(challengeRecord, now: now)
        return .init(
            message: "Passkey challenge issued",
            accountDID: accountDID,
            challenge: Self.base64URLEncoded(challenge),
            factorID: factorID
        )
    }

    private func beginPasskeyAssertion(accountDID: String, sessionID: String, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation {
        let request = try decodePasskeyBeginRequest(payload)
        let active = try await factors.listFactors(accountDID: accountDID, now: now)
        guard let factorID = request.factorID,
              active.contains(where: { $0.id == factorID && $0.kind == .passkey && $0.disabledAt == nil }) else {
            throw MFAError.credentialNotFound
        }
        let challenge = Self.serverChallengeBytes()
        let challengeRecord = try WebAuthnChallenge(
            challengeDigest: Data(SHA256.hash(data: challenge)),
            accountDID: accountDID,
            sessionID: sessionID,
            factorID: factorID,
            purpose: .stepUp,
            relyingPartyID: relyingPartyID,
            origin: origin,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        try await webAuthnChallenges.reserveWebAuthnChallenge(challengeRecord, now: now)
        return .init(
            message: "Passkey assertion challenge issued",
            accountDID: accountDID,
            challenge: Self.base64URLEncoded(challenge),
            factorID: factorID
        )
    }

    private func enrollPasskey(accountDID: String, sessionID: String, payload: Data?, factorIDOverride: String? = nil, expectedRevision: Int64? = nil, now: Date) async throws -> SwanAccountPortalMutation {
        let request = try decodePasskeyRequest(payload)
        let challenge = try request.challengeBytes()
        let clientData = try request.clientDataBytes()
        let authenticatorData = try request.authenticatorDataBytes()
        let credentialID = try request.credentialIDBytes()
        let requestedFactorID = factorIDOverride ?? request.factorID
        guard let requestedFactorID else { throw MFAError.invalidRequest }
        let digest = Data(SHA256.hash(data: challenge))
        guard let current = try await webAuthnChallenges.webAuthnChallenge(digest: digest, accountDID: accountDID, now: now),
              current.purpose == .enrollment,
              current.sessionID == sessionID,
              current.factorID == requestedFactorID,
              current.credentialIDDigest == nil else {
            throw MFAError.invalidChallenge
        }
        let factorID = requestedFactorID
        let registration: WebAuthnRegistrationResult
        do {
            registration = try WebAuthnRegistrationVerifier.verify(
                clientDataJSON: clientData,
                authenticatorData: authenticatorData,
                challenge: challenge,
                accountDID: accountDID,
                challengeRecord: current,
                expectedOrigin: origin,
                relyingPartyID: relyingPartyID,
                now: now
            )
        } catch let error as MFAError {
            throw error
        } catch {
            throw MFAError.invalidChallenge
        }
        guard registration.credentialIDDigest == Data(SHA256.hash(data: credentialID)) else {
            throw MFAError.invalidChallenge
        }
        let factor = try AuthenticationFactorMetadata(
            id: factorID,
            accountDID: accountDID,
            kind: .passkey,
            label: request.label,
            lookupDigest: Data(SHA256.hash(data: Data(("swan-factor:" + factorID).utf8))),
            createdAt: now
        )
        var created = false
        do {
            if let expectedRevision {
                let outcome = try await authorizedStore().saveFactorIfAbsent(
                    factor, expectedRevision: expectedRevision, now: now
                )
                created = outcome.inserted
            } else {
                created = try await factors.saveFactorIfAbsent(factor, now: now)
            }
            guard created else { throw MFAError.invalidChallenge }
            let publicKeyReference = "inline-p256:\(Self.base64URLEncoded(registration.publicKey.x963Representation))"
            _ = try await webAuthnEnrollment.enroll(
                clientDataJSON: clientData,
                authenticatorData: authenticatorData,
                challenge: challenge,
                accountDID: accountDID,
                factorID: factorID,
                publicKeyReference: publicKeyReference,
                transports: request.transports,
                challengeRecord: current,
                expectedOrigin: origin,
                relyingPartyID: relyingPartyID,
                now: now
            )
        } catch {
            // Only the caller that won the factor-ID insertion may compensate
            // its own row. A concurrent loser must never disable the winner.
            if created { try? await factors.disableFactor(id: factorID, accountDID: accountDID, now: now) }
            throw (error as? MFAError) ?? MFAError.storageUnavailable
        }
        _ = credentialID // The registration verifier binds the credential ID.
        return .init(message: "Passkey enrolled", accountDID: accountDID)
    }

    private func stepUp(accountDID: String, sessionID: String, payload: Data?, purpose: FactorTokenPurpose, authorizationContext: AccountAuthorizationContext? = nil, now: Date) async throws -> SwanAccountPortalMutation {
        let request = try decodeStepUpRequest(payload)
        switch request.kind {
        case .totp:
            guard let code = request.code, !code.isEmpty else { throw MFAError.invalidCode }
            guard let envelope = try await totpSecrets.totpEnvelope(factorID: request.factorID, accountDID: accountDID) else {
                throw MFAError.credentialNotFound
            }
            guard try await totp.verify(envelope: envelope, accountDID: accountDID, factorID: request.factorID, code: code, at: now) else {
                throw MFAError.invalidCode
            }
            let strength = try AuthenticationStrength.stepUp(base: .passwordPlusTOTP, factor: .totp, verifiedAt: now)
            let issued = try await factorTokens.issue(
                accountDID: accountDID,
                sessionID: sessionID,
                purpose: purpose,
                factor: .totp,
                factorID: request.factorID,
                strength: strength,
                now: now,
                channel: authorizationContext?.channel ?? .account,
                bindingDigest: authorizationContext?.csrfDigest,
                clientID: authorizationContext?.clientID,
                requestDigest: authorizationContext?.requestDigest
            )
            return .init(message: "MFA step-up accepted", accountDID: accountDID, factorToken: issued.token, factorID: request.factorID, factorKind: .totp)
        case .passkey:
            let assertion = try request.assertion()
            let challenge = try request.challengeBytes()
            let challengeDigest = Data(SHA256.hash(data: challenge))
            guard let credential = try await webAuthnCredentials.webAuthnCredential(
                credentialIDDigest: Data(SHA256.hash(data: assertion.credentialID)),
                accountDID: accountDID,
                now: now
            ) else { throw MFAError.credentialNotFound }
            guard let challengeRecord = try await webAuthnChallenges.webAuthnChallenge(digest: challengeDigest, accountDID: accountDID, now: now),
                  challengeRecord.purpose == .stepUp,
                  challengeRecord.sessionID == sessionID,
                  challengeRecord.factorID == credential.factorID else {
                throw MFAError.invalidChallenge
            }
            _ = try await webAuthn.verify(assertion: assertion, accountDID: accountDID, challenge: challenge, purpose: .stepUp, sessionID: sessionID, now: now)
            let strength = try AuthenticationStrength.stepUp(base: .passwordPlusPasskey, factor: .passkey, verifiedAt: now)
            let issued = try await factorTokens.issue(
                accountDID: accountDID,
                sessionID: sessionID,
                purpose: purpose,
                factor: .passkey,
                factorID: credential.factorID,
                strength: strength,
                now: now,
                channel: authorizationContext?.channel ?? .account,
                bindingDigest: authorizationContext?.csrfDigest,
                clientID: authorizationContext?.clientID,
                requestDigest: authorizationContext?.requestDigest
            )
            return .init(message: "MFA step-up accepted", accountDID: accountDID, factorToken: issued.token, factorID: credential.factorID, factorKind: .passkey)
        case .recoveryCode:
            let recoveryAccepted = try await recovery.consume(request.code ?? "", accountDID: accountDID, now: now)
            guard let code = request.code, recoveryAccepted else {
                throw MFAError.invalidCode
            }
            // OAuth recovery remains an OAuth-purpose receipt.  The
            // underlying strength is still `.emailRecovery`, but changing the
            // purpose to `loginRecovery` would make the strict OAuth grant
            // predicate reject it (or tempt a caller to widen that predicate).
            let tokenPurpose: FactorTokenPurpose = switch purpose {
            case .oauthToken: .oauthToken
            case .managementLogin: .managementLogin
            default: .loginRecovery
            }
            let issued = try await factorTokens.issue(
                accountDID: accountDID,
                sessionID: sessionID,
                purpose: tokenPurpose,
                factor: .recoveryCode,
                factorID: request.factorID,
                strength: .emailRecovery,
                now: now,
                channel: authorizationContext?.channel ?? .account,
                bindingDigest: authorizationContext?.csrfDigest,
                clientID: authorizationContext?.clientID,
                requestDigest: authorizationContext?.requestDigest
            )
            return .init(message: "Recovery factor accepted", accountDID: accountDID, factorToken: issued.token, factorID: request.factorID, factorKind: .recoveryCode)
        }
    }

    private func rotateRecoveryCodes(accountDID: String, expectedRevision: Int64?, now: Date) async throws -> SwanAccountPortalMutation {
        _ = try await ensureRecoveryFactor(accountDID: accountDID, expectedRevision: expectedRevision, now: now)
        let codes = try await recovery.replace(accountDID: accountDID, expectedRevision: expectedRevision, now: now)
        return .init(message: "Recovery codes rotated", accountDID: accountDID, recoveryCodes: codes)
    }

    private func ensureRecoveryFactor(accountDID: String, expectedRevision: Int64?, now: Date) async throws -> SwanAccountPortalMutation {
        let existing = try await factors.listFactors(accountDID: accountDID, now: now).contains {
            $0.kind == .recoveryCode && $0.disabledAt == nil
        }
        if !existing {
            let factorID = UUID().uuidString.lowercased()
            let factor = try AuthenticationFactorMetadata(
                id: factorID,
                accountDID: accountDID,
                kind: .recoveryCode,
                label: "Recovery codes",
                lookupDigest: Data(SHA256.hash(data: Data(("swan-factor:" + factorID).utf8))),
                createdAt: now
            )
            if let expectedRevision {
                _ = try await authorizedStore().saveFactor(
                    factor, expectedRevision: expectedRevision, now: now
                )
            } else {
                try await factors.saveFactor(factor, now: now)
            }
        }
        return .init(message: "Recovery factor ready", accountDID: accountDID)
    }

    private func disableFactor(id: String, accountDID: String, expected: AuthenticationFactorKind, expectedRevision: Int64?, now: Date) async throws -> SwanAccountPortalMutation {
        guard !id.isEmpty, let factor = try await factors.listFactors(accountDID: accountDID, now: now).first(where: { $0.id == id }) else {
            throw SwanAccountPortalServiceError.notFound
        }
        guard factor.kind == expected else { throw SwanAccountPortalServiceError.invalidRequest }
        if let expectedRevision {
            _ = try await authorizedStore().disableFactor(
                id: id, accountDID: accountDID, expectedRevision: expectedRevision, now: now
            )
        } else {
            try await factors.disableFactor(id: id, accountDID: accountDID, now: now)
        }
        if expected == .totp { try? await totpSecrets.deleteTOTPEnvelope(factorID: id, accountDID: accountDID, now: now) }
        return .init(message: "Authentication factor revoked", accountDID: accountDID)
    }

    private func keyForTOTPEnvelope() async throws -> Data {
        // This value was loaded once by the descriptor-safe account-program
        // preflight and retained by the runtime. It is never sourced from an
        // environment variable or re-opened path during enrollment.
        totpKey
    }

    private func decodeKind(_ payload: Data?) throws -> AuthenticationFactorKind {
        guard let payload, let value = try? JSONDecoder().decode(KindRequest.self, from: payload), let kind = value.kind else {
            throw SwanAccountPortalServiceError.invalidRequest
        }
        return kind
    }

    private func decodeTOTPRequest(_ payload: Data?) throws -> TOTPRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            let request = try JSONDecoder().decode(TOTPRequest.self, from: payload)
            guard request.label.utf8.count <= 128, !request.label.isEmpty, request.secret.utf8.count <= 512 else {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            return request
        } catch let error as SwanAccountPortalServiceError { throw error }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private func decodeTOTPVerificationRequest(_ payload: Data?) throws -> TOTPVerificationRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            let request = try JSONDecoder().decode(TOTPVerificationRequest.self, from: payload)
            guard !request.factorID.isEmpty, request.factorID.utf8.count <= 128,
                  request.code.utf8.count == 6,
                  request.code.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            return request
        } catch let error as SwanAccountPortalServiceError { throw error }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private func decodePasskeyRequest(_ payload: Data?) throws -> PasskeyRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do { return try JSONDecoder().decode(PasskeyRequest.self, from: payload) }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private func decodePasskeyBeginRequest(_ payload: Data?) throws -> PasskeyBeginRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            let request = try JSONDecoder().decode(PasskeyBeginRequest.self, from: payload)
            guard request.label.map({ !$0.isEmpty && $0.utf8.count <= 128 }) ?? true,
                  request.factorID.map({ !$0.isEmpty && $0.utf8.count <= 128 }) ?? true else {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            return request
        } catch let error as SwanAccountPortalServiceError { throw error }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private func decodeStepUpRequest(_ payload: Data?) throws -> StepUpRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do { return try JSONDecoder().decode(StepUpRequest.self, from: payload) }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private struct KindRequest: Decodable { let kind: AuthenticationFactorKind? }
    private struct TOTPRequest: Decodable {
        let kind: AuthenticationFactorKind?
        let factorID: String?
        let label: String
        let secret: String
    }
    private struct TOTPVerificationRequest: Decodable {
        let factorID: String
        let code: String
    }
    private struct PasskeyRequest: Decodable {
        let kind: AuthenticationFactorKind?
        let factorID: String?
        let label: String
        let challenge: String
        let clientDataJSON: String
        let authenticatorData: String
        let credentialID: String
        let transports: Set<String>
        func challengeBytes() throws -> Data { try SwanAccountPortalMFARuntime.decodeBase64URL(challenge) }
        func clientDataBytes() throws -> Data { try SwanAccountPortalMFARuntime.decodeBase64URL(clientDataJSON) }
        func authenticatorDataBytes() throws -> Data { try SwanAccountPortalMFARuntime.decodeBase64URL(authenticatorData) }
        func credentialIDBytes() throws -> Data { try SwanAccountPortalMFARuntime.decodeBase64URL(credentialID) }
    }
    private struct PasskeyBeginRequest: Decodable {
        let factorID: String?
        let label: String?
    }
    private struct StepUpRequest: Decodable {
        let kind: AuthenticationFactorKind
        let factorID: String
        let code: String?
        let challenge: String?
        let clientDataJSON: String?
        let authenticatorData: String?
        let credentialID: String?
        let signature: String?
        func challengeBytes() throws -> Data {
            guard let challenge else { throw MFAError.invalidChallenge }
            return try SwanAccountPortalMFARuntime.decodeBase64URL(challenge)
        }
        func assertion() throws -> WebAuthnAssertion {
            guard let clientDataJSON, let authenticatorData, let credentialID else { throw MFAError.invalidRequest }
            return WebAuthnAssertion(
                credentialID: try SwanAccountPortalMFARuntime.decodeBase64URL(credentialID),
                clientDataJSON: try SwanAccountPortalMFARuntime.decodeBase64URL(clientDataJSON),
                authenticatorData: try SwanAccountPortalMFARuntime.decodeBase64URL(authenticatorData),
                signature: try SwanAccountPortalMFARuntime.decodeBase64URL(signature ?? "")
            )
        }
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        guard value.utf8.count <= 16 * 1_024 else { throw MFAError.invalidRequest }
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), !data.isEmpty else { throw MFAError.invalidRequest }
        return data
    }

    private static func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func serverChallengeBytes() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

private struct MountedTOTPEnvelopeKeyStore: TOTPEnvelopeKeyStore, Sendable {
    let reference: String
    let key: Data
    func key(reference: String) async throws -> Data? { reference == self.reference ? key : nil }
}

private struct InlineWebAuthnPublicKeyStore: WebAuthnPublicKeyStore, Sendable {
    func publicKey(reference: String) async throws -> P256.Signing.PublicKey? {
        let prefix = "inline-p256:"
        guard reference.hasPrefix(prefix) else { return nil }
        var encoded = String(reference.dropFirst(prefix.count)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let data = Data(base64Encoded: encoded), data.count == 65 else { return nil }
        return try? P256.Signing.PublicKey(x963Representation: data)
    }
}
