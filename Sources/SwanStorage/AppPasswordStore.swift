import Foundation

public protocol AppPasswordStore: Sendable {
    func createAppPassword(_ metadata: AppPasswordMetadata, now: Date) async throws
    func appPassword(accountDID: String, canonicalName: String, now: Date) async throws -> AppPasswordMetadata?
    func appPassword(id: String, now: Date) async throws -> AppPasswordMetadata?
    func listAppPasswords(accountDID: String, now: Date) async throws -> [AppPasswordMetadata]
    func updateAppPasswordScopes(accountDID: String, canonicalName: String, scopes: Set<String>, now: Date) async throws
    func revokeAppPassword(accountDID: String, canonicalName: String, now: Date) async throws
    func markAppPasswordUsed(id: String, now: Date) async throws
    func createLegacySessionFromAppPassword(_ metadata: AppPasswordMetadata, family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws
}
