import Foundation
import SwanCore

public extension AuthorizationContext {
    /// Builds an `.accountOAuth` context from raw scope strings, for TESTS AND
    /// LABORATORY HARNESSES ONLY.
    ///
    /// Production has exactly one construction point for this context —
    /// `SwanOAuthResourceAuthorizer.authorize` (`SwanOAuthResourceAuthorization.swift`,
    /// §6.5.2) — which builds the permissions value from durable token state
    /// *including* the durable provenance record. Nothing else in `Sources/`
    /// may construct an `.accountOAuth`, and the deliberately awkward name here
    /// is what keeps that greppable: a production call site spelling
    /// `ForTesting` is a review failure, not a style preference.
    ///
    /// **`statedKeys` defaults to empty, which is FAIL CLOSED** (§9-D23). A
    /// context built without it satisfies ordinary matching but fails both
    /// provenance fences, so a test that means to exercise
    /// `getDelegationToken` or `listSpaces` must pass the stated keys
    /// explicitly. That is the correct default: the alternative — inferring
    /// provenance from the scope strings — is precisely the defect the durable
    /// record exists to prevent, and a helper that inferred it would make every
    /// test pass while production failed.
    ///
    /// `subject` is bound into the permissions value as well as the context, so
    /// a `space:` grant naming `authority=self` resolves against the same DID
    /// the context names (§6.1).
    static func accountOAuthForTesting(
        subject: String,
        scopes: Set<String>,
        statedKeys: [String: Set<String>] = [:]
    ) -> AuthorizationContext {
        .accountOAuth(
            subject: subject,
            permissions: SwanScopePermissions(
                rawScopes: scopes,
                subject: subject,
                statedKeys: statedKeys
            )
        )
    }

    /// The legacy (app-password) equivalent, for TESTS AND LABORATORY HARNESSES
    /// ONLY, under the same rule as above.
    ///
    /// It exists mainly so a test can prove a surface REFUSES this context.
    /// Every predicate written as `case let .accountOAuth(...)` already fails
    /// closed against it by construction; the value of pinning that in a test is
    /// that the refusal survives someone later "simplifying" the two cases
    /// together.
    static func accountLegacySessionForTesting(
        subject: String,
        scopes: Set<String>,
        statedKeys: [String: Set<String>] = [:]
    ) -> AuthorizationContext {
        .accountLegacySession(
            subject: subject,
            permissions: SwanScopePermissions(
                rawScopes: scopes,
                subject: subject,
                statedKeys: statedKeys
            )
        )
    }
}
