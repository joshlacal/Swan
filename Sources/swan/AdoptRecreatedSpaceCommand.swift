import ArgumentParser
import Crypto
import Foundation
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite

/// SWAN-SYNC-1: the production caller of
/// ``SQLiteAccountDatabase/adoptRecreatedRemoteSpace(_:expectedDeletionEventID:authorization:credentialIssuedAt:credentialDigest:now:)``.
///
/// A recipient deletion tombstone closes this account's replicated copy of a
/// remote space. October 22 section 6 lets the authority recreate the space
/// under the same URI; syncers then treat it as a new space: obtain a
/// credential, register, and resync from scratch. Adoption is an explicit
/// operator step, never a side effect of a read or retry: the operator
/// presents an authority-issued credential for the recreated space, Swan
/// verifies it with the same trust material `serve` uses, and the database
/// accepts it only when it was issued after the retained deletion. The old
/// projection is purged, never revived.
enum RecreatedSpaceAdoption {
    struct Outcome: Encodable, Equatable {
        let space: String
        let deletionEventID: String
        let credentialIssuedAt: Int64
        let adopted: Bool
    }

    /// Verifies `token` as a space credential for exactly `space`, then
    /// adopts the recreated lifecycle. When `deletionEventID` is `nil` the
    /// retained tombstone's event is used; the database still compares it
    /// inside the adoption transaction.
    static func adopt(
        credential token: String,
        space: SpaceURI,
        deletionEventID: String?,
        database: SQLiteAccountDatabase,
        publicKeys: any SpaceCredentialPublicKeyResolver,
        now: Date = Date()
    ) async throws -> Outcome {
        guard let tombstone = try await database.recipientSpaceDeletionTombstone(space) else {
            throw SwanError.unauthorized("no recipient deletion is retained for this space")
        }
        let expectedEvent = deletionEventID ?? tombstone.deletionEventID
        let authorization = try await DurableSpaceCredentialVerifier(publicKeys: publicKeys)
            .authorization(for: token, expectedSpace: space, now: now)
        // The signature, issuer, subject and lifetime were verified above;
        // inspection only reads the issue time of that same token.
        let issuedAt = try PermissionedDataJWT.inspectSpaceCredential(token).claims.iat
        try await database.adoptRecreatedRemoteSpace(
            space,
            expectedDeletionEventID: expectedEvent,
            authorization: authorization,
            credentialIssuedAt: Date(timeIntervalSince1970: TimeInterval(issuedAt)),
            credentialDigest: Data(SHA256.hash(data: Data(token.utf8))),
            now: now
        )
        return Outcome(
            space: space.rawValue,
            deletionEventID: expectedEvent,
            credentialIssuedAt: issuedAt,
            adopted: true
        )
    }
}

extension SwanCommand.Account {
    struct AdoptRecreatedSpace: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "adopt-recreated-space",
            abstract: "Adopt a remote space that its authority recreated after a recipient deletion"
        )

        @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
        var dataDirectory: String

        @Option(name: .long, help: "Managed receiver account DID holding the deletion tombstone")
        var did: String

        @Option(name: .long, help: "Recreated space URI")
        var space: String

        @Option(name: .customLong("deletion-event-id"), help: "Retained deletion event to supersede; defaults to the retained tombstone's event")
        var deletionEventID: String?

        @Option(name: .customLong("credential-file"), help: "Owner-only file holding an authority-issued space credential for the recreated space")
        var credentialFile: String

        @Option(name: .customLong("notification-config"), help: "The serve --notification-config file whose credential key pins or PLC resolver verify the credential")
        var notificationConfig: String

        @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
        var operatorSecretFile: String?

        func run() async throws {
            _ = try AccountCommandSupport.authorization(secretFilePath: operatorSecretFile)
            let parsedSpace: SpaceURI
            do { parsedSpace = try SpaceURI(space) }
            catch { throw ValidationError("--space is not a valid space URI") }
            let tokenData = try readBoundedRegularFileNoFollow(
                URL(fileURLWithPath: credentialFile),
                maximumBytes: 16 * 1_024,
                requireOwnerOnly: true,
                validationMessage: "--credential-file is unavailable"
            )
            guard let token = String(data: tokenData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty else {
                throw ValidationError("--credential-file is unavailable")
            }
            let root = URL(fileURLWithPath: dataDirectory)
            let control: SQLiteControlDatabase
            do { control = try await SQLiteControlDatabase(dataDirectory: root) }
            catch { throw ValidationError("unable to open Swan control database") }
            let publicKeys: any SpaceCredentialPublicKeyResolver
            do {
                guard let account = try await control.account(did: did),
                      account.status.authorizesAccount else {
                    throw ValidationError("active hosted account required")
                }
                let runtime = try ServeNotificationRuntime.load(
                    from: URL(fileURLWithPath: notificationConfig),
                    continuityStore: control
                )
                publicKeys = try await CompositeSpaceCredentialPublicKeyResolver(
                    local: UnavailableSpaceCredentialPublicKeyResolver(),
                    remote: runtime.remoteCredentialPublicKeys,
                    pinned: runtime.credentialPins
                )
            } catch {
                try? await control.close()
                throw error as? ValidationError ?? AccountCommandSupport.validationError(for: error)
            }
            let database: SQLiteAccountDatabase
            do {
                database = try await SQLiteAccountDatabase(
                    dataDirectory: root,
                    did: did,
                    openMode: .existingManaged
                )
            } catch {
                try? await control.close()
                throw ValidationError("receiver account database is unavailable")
            }
            do {
                let outcome = try await RecreatedSpaceAdoption.adopt(
                    credential: token,
                    space: parsedSpace,
                    deletionEventID: deletionEventID,
                    database: database,
                    publicKeys: publicKeys
                )
                try await database.close()
                try await control.close()
                try AccountCommandSupport.write(outcome)
            } catch {
                try? await database.close()
                try? await control.close()
                throw AccountCommandSupport.validationError(for: error)
            }
        }
    }
}
