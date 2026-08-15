import Foundation
import Logging
import SwanCore
import SwanSpaces

/// The authenticated principal behind one scope-enforced request.
///
/// Carries the parsed permissions beside the subject because the two are
/// produced by the same single `authorize` call and must not be re-derived.
/// `OAuthDPoPProofValidator` durably claims the proof's `jti`
/// (`SwanOAuth/OAuthProofValidation.swift:117-119`), so authorizing a second
/// time to recover the permissions would be indistinguishable from a replay and
/// would deny every legitimate command.
struct AuthorizedPrincipal: Sendable {
    let subject: String
    let permissions: SwanScopePermissions
}

/// Runs one scope predicate and converts its `ScopeDenied` into the route's own
/// opaque failure.
///
/// §9-D6: the needed scope is for the SERVER LOG ONLY. Upstream's
/// `ScopeMissingError` is `expose = true` and echoes `needed` to the caller;
/// Swan deliberately does not, because this boundary already collapses every
/// invalid, expired, replayed, token-binding and account-lifecycle predicate
/// into one denial and must not become an oracle for any of them. `needed` is
/// logged at `.info` with the route path (§6.5.8) so an operator can explain a
/// 403 that the client cannot.
///
/// The `denial` is passed by the caller rather than chosen here so each route
/// keeps its own existing error body. Nothing on this path may widen a
/// client-visible error.
func enforcingScope(
    route: String,
    logger: Logger,
    denial: @autoclosure () -> any Error,
    _ check: () throws -> Void
) throws {
    do {
        try check()
    } catch let denied as ScopeDenied {
        logger.info(
            "scope denied",
            metadata: [
                "route": .string(route),
                "needed": .string(denied.needed),
            ]
        )
        throw denial()
    }
}
