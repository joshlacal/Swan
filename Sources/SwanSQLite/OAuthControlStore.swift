import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage

actor ControlSQLiteConnectionGate {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isHeld {
            isHeld = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

public enum SQLiteControlDatabaseOpenMode: Sendable, Equatable {
    case managed
    case existingPortableExportSource
    @_spi(PortableRestore) case descriptorBackedOperatorRestore(rootDescriptor: Int32)
    @_spi(PortableRestore) case descriptorBackedOperatorRestoreSource(rootDescriptor: Int32)
}

/// Durable OAuth control-plane state backed by `control.sqlite`. Repository
/// records deliberately never flow through this type. The actor serializes one
/// process while `BEGIN IMMEDIATE` makes consume/rotate/revoke semantics hold
/// across independently reopened Swan processes as well.
public actor SQLiteControlDatabase: OAuthControlStore, AccountControlStore,
    AccountControlKeyRotationStore,
    SpaceDelegationReplayStore, SpaceClientAttestationReplayStore
{
    private static let microsecondsPerSecond = 1_000_000.0
    /// Cold control connections can contend during WAL configuration or the
    /// idempotent migration transaction. SQLite can report that startup race
    /// as BUSY instead of waiting for `busy_timeout`, so retry the complete
    /// setup sequence with a bounded backoff.
    private static let migrationBusyRetryLimit = 12
    private static let migrationBusyInitialDelayNanoseconds: UInt64 = 5_000_000
    private static let migrationBusyMaximumDelayNanoseconds: UInt64 = 80_000_000

    let connection: SQLiteConnection
    let connectionGate = ControlSQLiteConnectionGate()
    private var dataDirectoryDescriptor: Int32
    private var databaseFileDescriptor: Int32
    private let descriptorBackedRestore: Bool
    private var activeWriteTransactions = 0

    public init(
        dataDirectory: URL,
        openMode: SQLiteControlDatabaseOpenMode = .managed
    ) async throws {
        let rootDescriptor = switch openMode {
        case .managed:
            try SQLiteProtectedPaths.openRoot(dataDirectory)
        case .existingPortableExportSource:
            try SQLiteProtectedPaths.openExistingRoot(dataDirectory)
        case let .descriptorBackedOperatorRestore(descriptor),
             let .descriptorBackedOperatorRestoreSource(descriptor):
            try SQLiteProtectedPaths.duplicateOwnerOnlyDirectory(descriptor)
        }
        let databasePath: String
        var heldDatabaseDescriptor: Int32 = -1
        do {
            let resolvedPath = SQLiteLayout.controlDatabase(in: dataDirectory)
                .standardizedFileURL.path
            switch openMode {
            case .managed:
                databasePath = try SQLiteProtectedPaths.openDatabaseFile(
                    parentDescriptor: rootDescriptor,
                    name: "control.sqlite",
                    resolvedPath: resolvedPath
                )
            case .existingPortableExportSource:
                databasePath = try SQLiteProtectedPaths.openExistingDatabaseFile(
                    parentDescriptor: rootDescriptor,
                    name: "control.sqlite",
                    resolvedPath: resolvedPath
                )
            case .descriptorBackedOperatorRestore:
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: rootDescriptor,
                    name: "control.sqlite",
                    create: true
                )
                databasePath = try SQLiteProtectedPaths.databasePath(
                    for: heldDatabaseDescriptor
                )
            case .descriptorBackedOperatorRestoreSource:
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: rootDescriptor,
                    name: "control.sqlite",
                    create: false
                )
                databasePath = try SQLiteProtectedPaths.databasePath(
                    for: heldDatabaseDescriptor
                )
            }
        } catch {
            SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        let readOnly: Bool
        let descriptorBacked: Bool
        switch openMode {
        case .managed:
            readOnly = false
            descriptorBacked = false
        case .existingPortableExportSource:
            readOnly = true
            descriptorBacked = false
        case .descriptorBackedOperatorRestore:
            readOnly = false
            descriptorBacked = true
        case .descriptorBackedOperatorRestoreSource:
            readOnly = true
            descriptorBacked = true
        }
        let openedConnection: SQLiteConnection
        do {
            let connectionPath = try readOnly
                ? SQLiteLayout.readOnlyURI(for: databasePath)
                : databasePath
            openedConnection = try await SQLiteConnection.open(
                storage: .file(path: connectionPath)
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        connection = openedConnection
        dataDirectoryDescriptor = rootDescriptor
        databaseFileDescriptor = heldDatabaseDescriptor
        descriptorBackedRestore = descriptorBacked
        switch openMode {
        case .managed, .descriptorBackedOperatorRestore:
            do {
                try await migrateWithBusyRetry()
                if !descriptorBacked {
                    try SQLiteProtectedPaths.hardenSQLiteFiles(
                        parentDescriptor: rootDescriptor,
                        databaseName: "control.sqlite"
                    )
                }
            } catch {
                try? await openedConnection.close()
                SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
                SQLiteProtectedPaths.closeDirectory(rootDescriptor)
                throw error
            }
        case .existingPortableExportSource, .descriptorBackedOperatorRestoreSource:
            do {
                _ = try await openedConnection.query("PRAGMA query_only=ON")
            } catch {
                try? await openedConnection.close()
                SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
                SQLiteProtectedPaths.closeDirectory(rootDescriptor)
                throw error
            }
        }
    }

    /// Callers own lifecycle explicitly; the connection is not closed from
    /// `deinit` because doing so would escape actor isolation.
    public func close() async throws {
        try await withConnectionGate {
            let descriptor = dataDirectoryDescriptor
            let databaseDescriptor = databaseFileDescriptor
            dataDirectoryDescriptor = -1
            databaseFileDescriptor = -1
            defer {
                SQLiteProtectedPaths.closeDirectory(databaseDescriptor)
                SQLiteProtectedPaths.closeDirectory(descriptor)
            }
            try await connection.close()
        }
    }

    public func migrate() async throws {
        try await withConnectionGate {
            try await migrateWithBusyRetry()
        }
    }

    // MARK: Client metadata

    public func cacheClientMetadata(
        _ metadata: OAuthCachedClientMetadata,
        now: Date = Date()
    ) async throws {
        try validate(metadata: metadata, now: now)
        let expiry = try timestamp(metadata.expiresAt)
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                _ = try await connection.query(
                    """
                    INSERT INTO oauth_control_client_metadata(client_id, document, expires_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        document = excluded.document,
                        expires_at = excluded.expires_at
                    """,
                    [.text(metadata.clientID), blob(metadata.document), .integer(expiry)]
                )
            }
        }
    }

    public func cachedClientMetadata(
        clientID: String,
        now: Date = Date()
    ) async throws -> OAuthCachedClientMetadata? {
        guard validText(clientID) else { throw OAuthControlStoreError.invalidInput }
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT document, expires_at
                    FROM oauth_control_client_metadata
                    WHERE client_id = ?
                    """,
                    [.text(clientID)]
                )
                guard let row = rows.first else { return nil }
                let expiresAt = try requiredDate(row, "expires_at")
                guard expiresAt > now else {
                    throw OAuthControlStoreError.malformedRecord
                }
                return OAuthCachedClientMetadata(
                    clientID: clientID,
                    document: try requiredBlob(row, "document"),
                    expiresAt: expiresAt
                )
            }
        }
    }

    // MARK: PAR and authorization code state

    public func storePushedAuthorizationRequest(
        _ request: OAuthPushedAuthorizationRequest,
        now: Date = Date()
    ) async throws {
        try validate(request: request, now: now)
        let scopes = try encodeScopes(request.binding.scopes)
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                _ = try await connection.query(
                    """
                    INSERT INTO oauth_control_par_requests(
                        request_digest, issuer, client_id, redirect_uri, scopes,
                        dpop_jkt, client_assertion_key_id, client_assertion_algorithm,
                        client_assertion_jkt, refresh_token_allowed, state, state_digest,
                        code_challenge_method, code_challenge_s256,
                        expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    [
                        blob(request.requestDigest), .text(request.binding.issuer),
                        .text(request.binding.clientID), .text(request.binding.redirectURI),
                        blob(scopes), optionalText(request.binding.dpopJKT),
                        optionalText(request.binding.confidentialClientKey?.keyID),
                        optionalText(request.binding.confidentialClientKey?.algorithm),
                        optionalText(request.binding.confidentialClientKey?.keyThumbprint),
                        .integer(request.binding.refreshTokenAllowed ? 1 : 0),
                        .text(request.state), blob(request.stateDigest),
                        .text(request.codeChallengeMethod.rawValue),
                        .text(request.codeChallengeS256),
                        .integer(try timestamp(request.expiresAt)),
                    ]
                )
                let stateRows = try await connection.query(
                    "SELECT state_digest FROM oauth_control_par_state_replays WHERE state_digest = ?",
                    [blob(request.stateDigest)]
                )
                guard stateRows.isEmpty else { throw OAuthControlStoreError.replayDetected }
                _ = try await connection.query(
                    """
                    INSERT INTO oauth_control_par_state_replays(state_digest, expires_at)
                    VALUES (?, ?)
                    """,
                    [blob(request.stateDigest), .integer(try timestamp(request.expiresAt))]
                )
            }
        }
    }

    public func consumePushedAuthorizationRequest(
        requestDigest: Data,
        binding: OAuthClientBinding,
        now: Date = Date()
    ) async throws -> OAuthPushedAuthorizationRequest {
        try validateDigest(requestDigest)
        try validate(binding: binding)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT issuer, client_id, redirect_uri, scopes, dpop_jkt,
                           client_assertion_key_id, client_assertion_algorithm,
                           client_assertion_jkt, refresh_token_allowed, state, state_digest,
                           code_challenge_method, code_challenge_s256,
                           expires_at, consumed_at
                    FROM oauth_control_par_requests
                    WHERE request_digest = ?
                    """,
                    [blob(requestDigest)]
                )
                guard let row = rows.first else { throw OAuthControlStoreError.notFound }
                let request = try decodePAR(row, digest: requestDigest)
                guard request.binding == binding else {
                    throw OAuthControlStoreError.bindingMismatch
                }
                guard request.expiresAt > now else { throw OAuthControlStoreError.expired }
                guard row.column("consumed_at")?.isNull != false else {
                    throw OAuthControlStoreError.alreadyConsumed
                }
                _ = try await connection.query(
                    """
                    UPDATE oauth_control_par_requests
                    SET consumed_at = ?
                    WHERE request_digest = ? AND consumed_at IS NULL
                    """,
                    [.integer(try timestamp(now)), blob(requestDigest)]
                )
                return request
            }
        }
    }

    public func activePushedAuthorizationRequest(
        requestDigest: Data,
        now: Date = Date()
    ) async throws -> OAuthPushedAuthorizationRequest? {
        try validateDigest(requestDigest)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT issuer, client_id, redirect_uri, scopes, dpop_jkt,
                           client_assertion_key_id, client_assertion_algorithm,
                           client_assertion_jkt, refresh_token_allowed, state, state_digest,
                           code_challenge_method, code_challenge_s256,
                           expires_at, consumed_at
                    FROM oauth_control_par_requests
                    WHERE request_digest = ?
                    """,
                    [blob(requestDigest)]
                )
                guard let row = rows.first else { return nil }
                let request = try decodePAR(row, digest: requestDigest)
                guard request.expiresAt > now,
                      row.column("consumed_at")?.isNull != false else {
                    return nil
                }
                return request
            }
        }
    }

    public func storeAuthorizationCode(
        _ code: OAuthAuthorizationCode,
        now: Date = Date()
    ) async throws {
        try validate(code: code, now: now)
        let family = OAuthTokenFamily(
            familyID: code.familyID,
            subject: code.subject,
            binding: code.binding,
            expiresAt: code.familyExpiresAt
        )
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                try await insertFamily(family)
                _ = try await connection.query(
                    """
                    INSERT INTO oauth_control_authorization_codes(
                        code_digest, family_id, code_challenge_method,
                        code_challenge_s256, expires_at,
                        reuse_expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    [
                        blob(code.codeDigest), .text(code.familyID.uuidString),
                        .text(code.codeChallengeMethod.rawValue),
                        .text(code.codeChallengeS256), .integer(try timestamp(code.expiresAt)),
                        .integer(try timestamp(code.familyExpiresAt)),
                    ]
                )
            }
        }
    }

    public func authorizationCode(
        codeDigest: Data,
        now: Date = Date()
    ) async throws -> OAuthAuthorizationCode? {
        try validateDigest(codeDigest)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    codeSelectSQL,
                    [blob(codeDigest)]
                )
                guard let row = rows.first else { return nil }
                let code = try decodeCode(row, digest: codeDigest)
                // A used code is intentionally retained through family expiry
                // so a later verified replay can revoke the issued family.
                if code.consumedAt == nil, code.expiresAt <= now {
                    _ = try await connection.query(
                        "DELETE FROM oauth_control_authorization_codes WHERE code_digest = ?",
                        [blob(codeDigest)]
                    )
                    return nil
                }
                return code
            }
        }
    }

    public func redeemAuthorizationCode(
        codeDigest: Data,
        binding: OAuthClientBinding,
        issuedTokens: OAuthIssuedTokenDigests,
        requireActiveSubject: Bool,
        now: Date = Date()
    ) async throws {
        try validateDigest(codeDigest)
        try validate(binding: binding)
        let replayDetected = try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(codeSelectSQL, [blob(codeDigest)])
                guard let row = rows.first else { throw OAuthControlStoreError.notFound }
                let code = try decodeCode(row, digest: codeDigest)
                guard code.binding == binding else {
                    throw OAuthControlStoreError.bindingMismatch
                }
                guard code.familyID == issuedTokens.familyID else {
                    throw OAuthControlStoreError.invalidInput
                }
                if code.consumedAt != nil {
                    try await revokeFamily(code.familyID, now: now)
                    return true
                }
                guard code.expiresAt > now else {
                    _ = try await connection.query(
                        "DELETE FROM oauth_control_authorization_codes WHERE code_digest = ?",
                        [blob(codeDigest)]
                    )
                    throw OAuthControlStoreError.expired
                }
                let family = try await loadFamily(code.familyID)
                guard family.subject == code.subject, family.binding == code.binding,
                      family.revokedAt == nil, family.expiresAt > now else {
                    throw OAuthControlStoreError.malformedRecord
                }
                if requireActiveSubject {
                    try await requireActiveAccount(family.subject)
                }
                try validate(tokens: issuedTokens, for: family, now: now)
                _ = try await connection.query(
                    """
                    UPDATE oauth_control_authorization_codes
                    SET consumed_at = ?
                    WHERE code_digest = ? AND consumed_at IS NULL
                    """,
                    [.integer(try timestamp(now)), blob(codeDigest)]
                )
                try await insertTokenPair(issuedTokens)
                return false
            }
        }
        if replayDetected { throw OAuthControlStoreError.replayDetected }
    }

    // MARK: Opaque access and refresh token state

    public func issueTokenPair(
        family: OAuthTokenFamily,
        tokens: OAuthIssuedTokenDigests,
        now: Date = Date()
    ) async throws {
        try validate(family: family, now: now)
        guard tokens.familyID == family.familyID, family.revokedAt == nil else {
            throw OAuthControlStoreError.invalidInput
        }
        try validate(tokens: tokens, for: family, now: now)
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                try await insertFamily(family)
                try await insertTokenPair(tokens)
            }
        }
    }

    public func validatedAccessToken(
        accessTokenDigest: Data,
        now: Date = Date()
    ) async throws -> OAuthTokenFamily {
        try validateDigest(accessTokenDigest)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT f.family_id, f.subject, f.issuer, f.client_id,
                           f.redirect_uri, f.scopes, f.dpop_jkt,
                           f.client_assertion_key_id, f.client_assertion_algorithm,
                           f.client_assertion_jkt, f.refresh_token_allowed, f.expires_at, f.revoked_at,
                           a.expires_at AS token_expires_at
                    FROM oauth_control_access_tokens a
                    JOIN oauth_control_token_families f ON f.family_id = a.family_id
                    WHERE a.token_digest = ?
                    """,
                    [blob(accessTokenDigest)]
                )
                guard let row = rows.first else { throw OAuthControlStoreError.notFound }
                let family = try decodeFamily(row)
                guard family.revokedAt == nil, family.expiresAt > now,
                      try requiredDate(row, "token_expires_at") > now else {
                    throw OAuthControlStoreError.expired
                }
                return family
            }
        }
    }

    public func refreshTokenFamily(
        refreshTokenDigest: Data,
        now: Date = Date()
    ) async throws -> OAuthTokenFamily {
        try validateDigest(refreshTokenDigest)
        let result = try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(refreshSelectSQL, [blob(refreshTokenDigest)])
                guard let row = rows.first else { throw OAuthControlStoreError.notFound }
                let family = try decodeFamily(row)
                guard family.revokedAt == nil, family.expiresAt > now,
                      try requiredDate(row, "token_expires_at") > now else {
                    throw OAuthControlStoreError.expired
                }
                if row.column("used_at")?.isNull == false {
                    // The preflight is also a replay boundary: a caller that
                    // races after a completed rotation must revoke the family
                    // rather than merely learn that the old token was used.
                    try await revokeFamily(family.familyID, now: now)
                    return (family, true)
                }
                return (family, false)
            }
        }
        if result.1 { throw OAuthControlStoreError.replayDetected }
        return result.0
    }

    public func tokenFamily(
        tokenDigest: Data,
        kind: OAuthOpaqueTokenKind,
        now: Date = Date()
    ) async throws -> OAuthTokenFamily? {
        try validateDigest(tokenDigest)
        let table: String
        switch kind {
        case .accessToken: table = "oauth_control_access_tokens"
        case .refreshToken: table = "oauth_control_refresh_tokens"
        }
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT f.family_id, f.subject, f.issuer, f.client_id,
                           f.redirect_uri, f.scopes, f.dpop_jkt,
                           f.client_assertion_key_id, f.client_assertion_algorithm,
                           f.client_assertion_jkt, f.refresh_token_allowed, f.expires_at, f.revoked_at,
                           t.expires_at AS token_expires_at
                    FROM \(table) t
                    JOIN oauth_control_token_families f ON f.family_id = t.family_id
                    WHERE t.token_digest = ?
                    """,
                    [blob(tokenDigest)]
                )
                guard let row = rows.first else { return nil }
                let family = try decodeFamily(row)
                guard family.revokedAt == nil, family.expiresAt > now,
                      try requiredDate(row, "token_expires_at") > now else {
                    return nil
                }
                return family
            }
        }
    }

    public func redeemRefreshToken(
        refreshTokenDigest: Data,
        replacement: OAuthIssuedTokenDigests,
        requireActiveSubject: Bool,
        now: Date = Date()
    ) async throws {
        try validateDigest(refreshTokenDigest)
        let replayDetected = try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(refreshSelectSQL, [blob(refreshTokenDigest)])
                guard let row = rows.first else { throw OAuthControlStoreError.notFound }
                let family = try decodeFamily(row)
                guard family.revokedAt == nil, family.expiresAt > now,
                      try requiredDate(row, "token_expires_at") > now else {
                    throw OAuthControlStoreError.expired
                }
                guard replacement.familyID == family.familyID else {
                    throw OAuthControlStoreError.invalidInput
                }
                if requireActiveSubject {
                    try await requireActiveAccount(family.subject)
                }
                if row.column("used_at")?.isNull == false {
                    try await revokeFamily(family.familyID, now: now)
                    return true
                }
                try validate(tokens: replacement, for: family, now: now)
                _ = try await connection.query(
                    """
                    UPDATE oauth_control_refresh_tokens
                    SET used_at = ?
                    WHERE token_digest = ? AND used_at IS NULL
                    """,
                    [.integer(try timestamp(now)), blob(refreshTokenDigest)]
                )
                try await insertTokenPair(replacement)
                return false
            }
        }
        if replayDetected { throw OAuthControlStoreError.replayDetected }
    }

    public func revokeTokenFamily(
        refreshTokenDigest: Data,
        now: Date = Date()
    ) async throws -> Bool {
        try validateDigest(refreshTokenDigest)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    "SELECT family_id FROM oauth_control_refresh_tokens WHERE token_digest = ?",
                    [blob(refreshTokenDigest)]
                )
                guard let rawID = try optionalRowText(rows.first, "family_id"),
                      let familyID = UUID(uuidString: rawID) else {
                    return false
                }
                try await revokeFamily(familyID, now: now)
                return true
            }
        }
    }

    public func revokeTokenFamily(
        familyID: UUID,
        now: Date = Date()
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                try await revokeFamily(familyID, now: now)
            }
        }
    }

    // MARK: Durable replay claims

    public func claimDPoPReplay(
        digest: Data,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        try await claimReplay(
            table: "oauth_control_dpop_replays",
            digest: digest,
            clientID: nil,
            expiresAt: expiresAt,
            now: now
        )
    }

    public func claimClientAssertion(
        digest: Data,
        clientID: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        guard validText(clientID) else { throw OAuthControlStoreError.invalidInput }
        return try await claimReplay(
            table: "oauth_control_client_assertion_replays",
            digest: digest,
            clientID: clientID,
            expiresAt: expiresAt,
            now: now
        )
    }

    /// Reserves a verified delegation in its own durable namespace. The
    /// digest is HMAC-protected by SwanOAuth before it reaches SQLite, and
    /// `claimReplay` performs the purge, uniqueness check, and insert inside
    /// one `BEGIN IMMEDIATE` transaction across reopened processes.
    public func claimSpaceDelegation(
        digest: Data,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        try validateDigest(digest)
        guard expiresAt > now else { throw OAuthControlStoreError.expired }
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    "SELECT expires_at FROM permissioned_space_delegation_replays WHERE jti_digest = ?",
                    [blob(digest)]
                )
                if let row = rows.first {
                    guard try requiredDate(row, "expires_at") > now else {
                        throw OAuthControlStoreError.malformedRecord
                    }
                    return false
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_delegation_replays(
                        jti_digest, expires_at
                    ) VALUES (?, ?)
                    """,
                    [blob(digest), .integer(try timestamp(expiresAt))]
                )
                return true
            }
        }
    }

    /// One attestation claim is one `BEGIN IMMEDIATE` transaction containing
    /// only bounded local SQLite work. Metadata/JWKS resolution and signature
    /// verification must already be complete before this method is invoked.
    public func claimSpaceClientAttestation(
        digest: Data,
        expiresAt: Date,
        now: Date = Date()
    ) async throws -> Bool {
        try validateDigest(digest)
        guard expiresAt > now else { throw OAuthControlStoreError.expired }
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    """
                    SELECT expires_at
                    FROM permissioned_space_client_attestation_replays
                    WHERE replay_digest = ?
                    """,
                    [blob(digest)]
                )
                if let row = rows.first {
                    guard try requiredDate(row, "expires_at") > now else {
                        throw OAuthControlStoreError.malformedRecord
                    }
                    return false
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_client_attestation_replays(
                        replay_digest, expires_at
                    ) VALUES (?, ?)
                    """,
                    [blob(digest), .integer(try timestamp(expiresAt))]
                )
                return true
            }
        }
    }

    public func purgeExpiredOAuthControlState(now: Date = Date()) async throws {
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
            }
        }
    }

    // MARK: Transactional helpers

    private func migrateWithBusyRetry() async throws {
        var delay = Self.migrationBusyInitialDelayNanoseconds
        for attempt in 0 ..< Self.migrationBusyRetryLimit {
            do {
                try await migrateWithoutGate()
                return
            } catch {
                guard isRetryableMigrationLock(error),
                      attempt + 1 < Self.migrationBusyRetryLimit else {
                    throw error
                }
                try await Task.sleep(nanoseconds: delay)
                delay = min(delay * 2, Self.migrationBusyMaximumDelayNanoseconds)
            }
        }
        preconditionFailure("migration retry loop must either return or throw")
    }

    private func migrateWithoutGate() async throws {
        // These PRAGMAs configure this connection and must remain outside the
        // DDL transaction. All schema inspection, CREATE, ALTER, trigger, and
        // index work below is one `BEGIN IMMEDIATE` transaction so two Swan
        // processes cold-starting an old control DB cannot race an additive
        // column migration.
        let pragmas = descriptorBackedRestore
            ? ["PRAGMA busy_timeout=5000", "PRAGMA journal_mode=MEMORY", "PRAGMA foreign_keys=ON"]
            : SQLiteLayout.controlConnectionPragmas
        for statement in pragmas {
            _ = try await connection.query(statement)
        }
        try await transaction {
            for statement in SQLiteLayout.controlMigrations.dropFirst(
                SQLiteLayout.controlConnectionPragmas.count
            ) {
                _ = try await connection.query(statement)
            }
            // `CREATE TABLE IF NOT EXISTS` preserves already-deployed control
            // databases, so evolving a durable binding needs explicit additive
            // columns. Existing identifier-only rows are rejected on decode
            // rather than downgraded to public clients.
            try await addColumnIfMissing(
                table: "oauth_control_token_families",
                column: "client_assertion_algorithm",
                definition: "TEXT"
            )
            try await addColumnIfMissing(
                table: "oauth_control_token_families",
                column: "client_assertion_jkt",
                definition: "TEXT"
            )
            try await addColumnIfMissing(
                table: "oauth_control_par_requests",
                column: "client_assertion_algorithm",
                definition: "TEXT"
            )
            try await addColumnIfMissing(
                table: "oauth_control_par_requests",
                column: "client_assertion_jkt",
                definition: "TEXT"
            )
            try await addColumnIfMissing(
                table: "oauth_control_token_families",
                column: "refresh_token_allowed",
                definition: "INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1))"
            )
            try await addColumnIfMissing(
                table: "oauth_control_par_requests",
                column: "refresh_token_allowed",
                definition: "INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1))"
            )
            try await migrateAccountControlSchema()
        }
    }

    func addColumnIfMissing(table: String, column: String, definition: String) async throws {
        let columns = try await connection.query("PRAGMA table_info(\(table))")
        guard !columns.contains(where: { $0.column("name")?.string == column }) else { return }
        _ = try await connection.query("ALTER TABLE \(table) ADD COLUMN \(column) \(definition)")
    }

    func withConnectionGate<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        await connectionGate.acquire()
        do {
            let result = try await body()
            await connectionGate.release()
            return result
        } catch {
            await connectionGate.release()
            throw error
        }
    }

    func transaction<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query("BEGIN IMMEDIATE")
        activeWriteTransactions += 1
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            activeWriteTransactions -= 1
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            activeWriteTransactions -= 1
            throw error
        }
    }

    func hasActiveWriteTransactionForTesting() -> Bool {
        activeWriteTransactions > 0
    }

    private func isRetryableMigrationLock(_ error: any Error) -> Bool {
        guard let sqliteError = error as? SQLiteError else { return false }
        switch sqliteError.reason {
        case .busy, .busyInRecovery, .busyInSnapshot, .busyTimeout,
             .locked, .lockedBySharedCache:
            return true
        default:
            return false
        }
    }

    private func purgeExpiredLocked(now: Date) async throws {
        let nowTimestamp = try timestamp(now)
        _ = try await connection.query(
            "DELETE FROM oauth_control_client_metadata WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_par_requests WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_par_state_replays WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        // Unredeemed codes have no sessions to protect. Redeemed codes remain
        // until family expiry so their replay sentinel survives code expiry.
        _ = try await connection.query(
            """
            DELETE FROM oauth_control_authorization_codes
            WHERE (consumed_at IS NULL AND expires_at <= ?)
               OR (consumed_at IS NOT NULL AND reuse_expires_at <= ?)
            """,
            [.integer(nowTimestamp), .integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_access_tokens WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_refresh_tokens WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_dpop_replays WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_client_assertion_replays WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            "DELETE FROM permissioned_space_delegation_replays WHERE expires_at <= ?",
            [.integer(nowTimestamp)]
        )
        // Bound cleanup work per claim/startup pass so an attacker cannot turn
        // expiry maintenance into an unbounded request-time transaction.
        _ = try await connection.query(
            """
            DELETE FROM permissioned_space_client_attestation_replays
            WHERE replay_digest IN (
                SELECT replay_digest
                FROM permissioned_space_client_attestation_replays
                WHERE expires_at <= ?
                ORDER BY expires_at, replay_digest
                LIMIT 512
            )
            """,
            [.integer(nowTimestamp)]
        )
        _ = try await connection.query(
            """
            DELETE FROM oauth_control_token_families
            WHERE expires_at <= ?
               OR (
                    NOT EXISTS (
                        SELECT 1 FROM oauth_control_authorization_codes c
                        WHERE c.family_id = oauth_control_token_families.family_id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM oauth_control_access_tokens a
                        WHERE a.family_id = oauth_control_token_families.family_id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM oauth_control_refresh_tokens r
                        WHERE r.family_id = oauth_control_token_families.family_id
                    )
               )
            """,
            [.integer(nowTimestamp)]
        )
    }

    private func claimReplay(
        table: String,
        digest: Data,
        clientID: String?,
        expiresAt: Date,
        now: Date
    ) async throws -> Bool {
        try validateDigest(digest)
        guard expiresAt > now else { throw OAuthControlStoreError.expired }
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredLocked(now: now)
                let rows = try await connection.query(
                    "SELECT expires_at FROM \(table) WHERE jti_digest = ?",
                    [blob(digest)]
                )
                if let row = rows.first {
                    guard try requiredDate(row, "expires_at") > now else {
                        throw OAuthControlStoreError.malformedRecord
                    }
                    return false
                }
                if let clientID {
                    _ = try await connection.query(
                        """
                        INSERT INTO oauth_control_client_assertion_replays(
                            jti_digest, client_id, expires_at
                        ) VALUES (?, ?, ?)
                        """,
                        [blob(digest), .text(clientID), .integer(try timestamp(expiresAt))]
                    )
                } else {
                    _ = try await connection.query(
                        """
                        INSERT INTO oauth_control_dpop_replays(jti_digest, expires_at)
                        VALUES (?, ?)
                        """,
                        [blob(digest), .integer(try timestamp(expiresAt))]
                    )
                }
                return true
            }
        }
    }

    private func insertFamily(_ family: OAuthTokenFamily) async throws {
        _ = try await connection.query(
            """
            INSERT INTO oauth_control_token_families(
                family_id, subject, issuer, client_id, redirect_uri, scopes,
                dpop_jkt, client_assertion_key_id, client_assertion_algorithm,
                client_assertion_jkt, refresh_token_allowed, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                .text(family.familyID.uuidString), .text(family.subject),
                .text(family.binding.issuer), .text(family.binding.clientID),
                .text(family.binding.redirectURI), blob(try encodeScopes(family.binding.scopes)),
                optionalText(family.binding.dpopJKT),
                optionalText(family.binding.confidentialClientKey?.keyID),
                optionalText(family.binding.confidentialClientKey?.algorithm),
                optionalText(family.binding.confidentialClientKey?.keyThumbprint),
                .integer(family.binding.refreshTokenAllowed ? 1 : 0),
                .integer(try timestamp(family.expiresAt)),
                family.revokedAt.map { try? timestamp($0) }.flatMap { $0 }.map(SQLiteData.integer) ?? .null,
            ]
        )
    }

    private func insertTokenPair(_ tokens: OAuthIssuedTokenDigests) async throws {
        _ = try await connection.query(
            """
            INSERT INTO oauth_control_access_tokens(token_digest, family_id, expires_at)
            VALUES (?, ?, ?)
            """,
            [
                blob(tokens.accessTokenDigest), .text(tokens.familyID.uuidString),
                .integer(try timestamp(tokens.accessExpiresAt)),
            ]
        )
        if let refreshTokenDigest = tokens.refreshTokenDigest,
           let refreshExpiresAt = tokens.refreshExpiresAt {
            _ = try await connection.query(
                """
                INSERT INTO oauth_control_refresh_tokens(token_digest, family_id, expires_at, used_at)
                VALUES (?, ?, ?, NULL)
                """,
                [
                    blob(refreshTokenDigest), .text(tokens.familyID.uuidString),
                    .integer(try timestamp(refreshExpiresAt)),
                ]
            )
        }
    }

    private func revokeFamily(_ familyID: UUID, now: Date) async throws {
        _ = try await connection.query(
            """
            UPDATE oauth_control_token_families
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE family_id = ?
            """,
            [.integer(try timestamp(now)), .text(familyID.uuidString)]
        )
    }

    /// Account lifecycle is authority state, not a cache hint.  This helper
    /// is invoked inside the same `BEGIN IMMEDIATE` transaction that consumes
    /// a code or rotates a refresh token, closing the consent-to-token race.
    private func requireActiveAccount(_ did: String) async throws {
        let rows = try await connection.query(
            "SELECT 1 FROM accounts WHERE did = ? AND status = 'active'",
            [.text(did)]
        )
        guard !rows.isEmpty else { throw OAuthControlStoreError.bindingMismatch }
    }

    private func loadFamily(_ familyID: UUID) async throws -> OAuthTokenFamily {
        let rows = try await connection.query(
            """
            SELECT family_id, subject, issuer, client_id, redirect_uri, scopes,
                   dpop_jkt, client_assertion_key_id, client_assertion_algorithm,
                   client_assertion_jkt, refresh_token_allowed, expires_at, revoked_at
            FROM oauth_control_token_families
            WHERE family_id = ?
            """,
            [.text(familyID.uuidString)]
        )
        guard let row = rows.first else { throw OAuthControlStoreError.notFound }
        return try decodeFamily(row)
    }

    private var codeSelectSQL: String {
        """
        SELECT c.family_id, c.code_challenge_method, c.code_challenge_s256, c.expires_at,
               c.reuse_expires_at, c.consumed_at,
               f.subject, f.issuer, f.client_id, f.redirect_uri, f.scopes,
               f.dpop_jkt, f.client_assertion_key_id, f.client_assertion_algorithm,
               f.client_assertion_jkt, f.refresh_token_allowed, f.expires_at AS family_expires_at,
               f.revoked_at
        FROM oauth_control_authorization_codes c
        JOIN oauth_control_token_families f ON f.family_id = c.family_id
        WHERE c.code_digest = ?
        """
    }

    private var refreshSelectSQL: String {
        """
        SELECT f.family_id, f.subject, f.issuer, f.client_id, f.redirect_uri,
               f.scopes, f.dpop_jkt, f.client_assertion_key_id,
               f.client_assertion_algorithm, f.client_assertion_jkt, f.refresh_token_allowed, f.expires_at,
               f.revoked_at, r.expires_at AS token_expires_at, r.used_at
        FROM oauth_control_refresh_tokens r
        JOIN oauth_control_token_families f ON f.family_id = r.family_id
        WHERE r.token_digest = ?
        """
    }

    // MARK: Strict decoding and validation

    private func decodePAR(
        _ row: SQLiteRow,
        digest: Data
    ) throws -> OAuthPushedAuthorizationRequest {
        OAuthPushedAuthorizationRequest(
            requestDigest: digest,
            binding: try decodeBinding(row),
            state: try requiredText(row, "state"),
            stateDigest: try requiredBlob(row, "state_digest"),
            codeChallengeMethod: try decodeChallengeMethod(row),
            codeChallengeS256: try requiredText(row, "code_challenge_s256"),
            expiresAt: try requiredDate(row, "expires_at")
        )
    }

    private func decodeCode(_ row: SQLiteRow, digest: Data) throws -> OAuthAuthorizationCode {
        guard let familyID = UUID(uuidString: try requiredText(row, "family_id")) else {
            throw OAuthControlStoreError.malformedRecord
        }
        let code = OAuthAuthorizationCode(
            codeDigest: digest,
            familyID: familyID,
            subject: try requiredText(row, "subject"),
            binding: try decodeBinding(row),
            codeChallengeMethod: try decodeChallengeMethod(row),
            codeChallengeS256: try requiredText(row, "code_challenge_s256"),
            expiresAt: try requiredDate(row, "expires_at"),
            familyExpiresAt: try requiredDate(row, "family_expires_at"),
            consumedAt: try optionalDate(row, "consumed_at")
        )
        do {
            try validate(code: code, now: Date.distantPast, permitExpired: true)
        } catch {
            // Rows crossed a durable trust boundary. Never reinterpret a
            // malformed binding as an ordinary request-validation failure.
            throw OAuthControlStoreError.malformedRecord
        }
        return code
    }

    private func decodeChallengeMethod(_ row: SQLiteRow) throws -> OAuthCodeChallengeMethod {
        guard let method = OAuthCodeChallengeMethod(
            rawValue: try requiredText(row, "code_challenge_method")
        ) else {
            throw OAuthControlStoreError.malformedRecord
        }
        return method
    }

    private func decodeFamily(_ row: SQLiteRow) throws -> OAuthTokenFamily {
        guard let familyID = UUID(uuidString: try requiredText(row, "family_id")) else {
            throw OAuthControlStoreError.malformedRecord
        }
        let family = OAuthTokenFamily(
            familyID: familyID,
            subject: try requiredText(row, "subject"),
            binding: try decodeBinding(row),
            expiresAt: try requiredDate(row, "expires_at"),
            revokedAt: try optionalDate(row, "revoked_at")
        )
        do {
            try validate(family: family, now: Date.distantPast, permitExpired: true)
        } catch {
            throw OAuthControlStoreError.malformedRecord
        }
        return family
    }

    private func decodeBinding(_ row: SQLiteRow) throws -> OAuthClientBinding {
        let keyID = try optionalText(row, "client_assertion_key_id")
        let algorithm = try optionalText(row, "client_assertion_algorithm")
        let keyThumbprint = try optionalText(row, "client_assertion_jkt")
        let confidentialClientKey: OAuthConfidentialClientKeyBinding?
        switch (keyID, algorithm, keyThumbprint) {
        case (nil, nil, nil):
            confidentialClientKey = nil
        case let (.some(keyID), .some(algorithm), .some(keyThumbprint)):
            confidentialClientKey = OAuthConfidentialClientKeyBinding(
                keyID: keyID,
                algorithm: algorithm,
                keyThumbprint: keyThumbprint
            )
        default:
            throw OAuthControlStoreError.malformedRecord
        }
        let binding = OAuthClientBinding(
            issuer: try requiredText(row, "issuer"),
            clientID: try requiredText(row, "client_id"),
            redirectURI: try requiredText(row, "redirect_uri"),
            scopes: try decodeScopes(try requiredBlob(row, "scopes")),
            dpopJKT: try optionalText(row, "dpop_jkt"),
            confidentialClientKey: confidentialClientKey,
            refreshTokenAllowed: try requiredBoolean(row, "refresh_token_allowed")
        )
        do {
            try validate(binding: binding)
        } catch {
            throw OAuthControlStoreError.malformedRecord
        }
        return binding
    }

    private func validate(metadata: OAuthCachedClientMetadata, now: Date) throws {
        guard validText(metadata.clientID), !metadata.document.isEmpty,
              metadata.document.count <= 1_048_576 else {
            throw OAuthControlStoreError.invalidInput
        }
        guard metadata.expiresAt > now else { throw OAuthControlStoreError.expired }
    }

    private func validate(request: OAuthPushedAuthorizationRequest, now: Date) throws {
        try validateDigest(request.requestDigest)
        try validateDigest(request.stateDigest)
        try validate(binding: request.binding)
        guard validState(request.state), request.codeChallengeMethod == .s256,
              validS256Challenge(request.codeChallengeS256) else {
            throw OAuthControlStoreError.invalidInput
        }
        guard request.expiresAt > now else { throw OAuthControlStoreError.expired }
    }

    private func validate(
        code: OAuthAuthorizationCode,
        now: Date,
        permitExpired: Bool = false
    ) throws {
        try validateDigest(code.codeDigest)
        try validate(binding: code.binding)
        guard validText(code.subject), code.codeChallengeMethod == .s256,
              validS256Challenge(code.codeChallengeS256),
              code.familyExpiresAt >= code.expiresAt else {
            throw OAuthControlStoreError.invalidInput
        }
        guard permitExpired || (code.expiresAt > now && code.familyExpiresAt > now) else {
            throw OAuthControlStoreError.expired
        }
    }

    private func validate(
        family: OAuthTokenFamily,
        now: Date,
        permitExpired: Bool = false
    ) throws {
        try validate(binding: family.binding)
        guard validText(family.subject) else { throw OAuthControlStoreError.invalidInput }
        guard permitExpired || family.expiresAt > now else {
            throw OAuthControlStoreError.expired
        }
        if let revokedAt = family.revokedAt, revokedAt > family.expiresAt {
            throw OAuthControlStoreError.invalidInput
        }
    }

    private func validate(
        tokens: OAuthIssuedTokenDigests,
        for family: OAuthTokenFamily,
        now: Date
    ) throws {
        try validateDigest(tokens.accessTokenDigest)
        guard tokens.accessExpiresAt > now,
              tokens.accessExpiresAt <= family.expiresAt else {
            throw OAuthControlStoreError.invalidInput
        }
        switch (tokens.refreshTokenDigest, tokens.refreshExpiresAt) {
        case (nil, nil):
            return
        case let (.some(refreshTokenDigest), .some(refreshExpiresAt)):
            try validateDigest(refreshTokenDigest)
            guard tokens.accessTokenDigest != refreshTokenDigest,
                  refreshExpiresAt > now,
                  refreshExpiresAt <= family.expiresAt else {
                throw OAuthControlStoreError.invalidInput
            }
        case (.some, nil), (nil, .some):
            throw OAuthControlStoreError.invalidInput
        }
    }

    private func validate(binding: OAuthClientBinding) throws {
        guard validText(binding.issuer), validText(binding.clientID),
              validText(binding.redirectURI),
              binding.scopes.allSatisfy(validScope),
              hasATProtocolResourceScope(binding.scopes),
              binding.dpopJKT.map(validDPoPJKT) ?? false,
              binding.confidentialClientKey.map(validConfidentialClientKey) ?? true else {
            throw OAuthControlStoreError.invalidInput
        }
    }

    private func validateDigest(_ digest: Data) throws {
        guard digest.count == 32 else { throw OAuthControlStoreError.invalidInput }
    }

    private func encodeScopes(_ scopes: Set<String>) throws -> Data {
        guard scopes.allSatisfy(validScope) else { throw OAuthControlStoreError.invalidInput }
        do {
            return try JSONEncoder().encode(scopes.sorted())
        } catch {
            throw OAuthControlStoreError.invalidInput
        }
    }

    private func decodeScopes(_ data: Data) throws -> Set<String> {
        do {
            let values = try JSONDecoder().decode([String].self, from: data)
            let scopes = Set(values)
            guard scopes.count == values.count, scopes.allSatisfy(validScope) else {
                throw OAuthControlStoreError.malformedRecord
            }
            return scopes
        } catch let error as OAuthControlStoreError {
            throw error
        } catch {
            throw OAuthControlStoreError.malformedRecord
        }
    }

    private func timestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw OAuthControlStoreError.invalidInput
        }
        let value = seconds * Self.microsecondsPerSecond
        guard value.isFinite, value <= Double(Int.max) else {
            throw OAuthControlStoreError.invalidInput
        }
        return Int(value.rounded(.down))
    }

    private func requiredDate(_ row: SQLiteRow?, _ column: String) throws -> Date {
        guard let row else { throw OAuthControlStoreError.malformedRecord }
        return try requiredDate(row, column)
    }

    private func requiredDate(_ row: SQLiteRow, _ column: String) throws -> Date {
        guard case let .integer(value) = row.column(column), value >= 0 else {
            throw OAuthControlStoreError.malformedRecord
        }
        let seconds = Double(value) / Self.microsecondsPerSecond
        guard seconds.isFinite else { throw OAuthControlStoreError.malformedRecord }
        return Date(timeIntervalSince1970: seconds)
    }

    private func requiredBoolean(_ row: SQLiteRow, _ column: String) throws -> Bool {
        guard case let .integer(value) = row.column(column), value == 0 || value == 1 else {
            throw OAuthControlStoreError.malformedRecord
        }
        return value == 1
    }

    private func optionalDate(_ row: SQLiteRow, _ column: String) throws -> Date? {
        guard let value = row.column(column) else {
            throw OAuthControlStoreError.malformedRecord
        }
        if value.isNull { return nil }
        guard case let .integer(raw) = value, raw >= 0 else {
            throw OAuthControlStoreError.malformedRecord
        }
        let seconds = Double(raw) / Self.microsecondsPerSecond
        guard seconds.isFinite else { throw OAuthControlStoreError.malformedRecord }
        return Date(timeIntervalSince1970: seconds)
    }

    private func requiredBlob(_ row: SQLiteRow, _ column: String) throws -> Data {
        guard let value = row.column(column), let data = Data(sqliteData: value) else {
            throw OAuthControlStoreError.malformedRecord
        }
        return data
    }

    private func optionalRowText(_ row: SQLiteRow?, _ column: String) throws -> String? {
        guard let row else { return nil }
        return try requiredText(row, column)
    }

    private func requiredText(_ row: SQLiteRow, _ column: String) throws -> String {
        guard case let .text(value) = row.column(column), validText(value) else {
            throw OAuthControlStoreError.malformedRecord
        }
        return value
    }

    private func optionalText(_ row: SQLiteRow, _ column: String) throws -> String? {
        guard let value = row.column(column) else {
            throw OAuthControlStoreError.malformedRecord
        }
        if value.isNull { return nil }
        guard case let .text(text) = value, validText(text) else {
            throw OAuthControlStoreError.malformedRecord
        }
        return text
    }

    private func optionalText(_ value: String?) -> SQLiteData {
        value.map(SQLiteData.text) ?? .null
    }

    private func blob(_ data: Data) -> SQLiteData {
        data.sqliteData!
    }

    private func validText(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && !value.utf8.contains(0)
    }

    private func validScope(_ value: String) -> Bool {
        validText(value) && value.utf8.count <= 256 &&
            value.unicodeScalars.allSatisfy {
                !$0.properties.isWhitespace && !CharacterSet.controlCharacters.contains($0)
            }
    }

    private func hasATProtocolResourceScope(_ scopes: Set<String>) -> Bool {
        scopes.contains("atproto") || scopes.contains { scope in
            PermissionedSpaceScopeSyntax.isQualified(scope)
        }
    }

    private func validState(_ value: String) -> Bool {
        validText(value) && value.utf8.count <= 4_096
    }

    private func validS256Challenge(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

    /// A DPoP JKT is the base64url SHA-256 thumbprint defined by RFC 7638.
    /// OAuth families are sender constrained, so NULL, empty, or malformed
    /// values are always a corrupt/invalid control-plane state.
    private func validDPoPJKT(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

    private func validConfidentialClientKey(_ key: OAuthConfidentialClientKeyBinding) -> Bool {
        validText(key.keyID) && key.algorithm == "ES256" && validDPoPJKT(key.keyThumbprint)
    }
}
