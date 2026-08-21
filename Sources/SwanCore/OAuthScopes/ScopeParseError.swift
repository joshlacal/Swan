/// Upstream has **no error type**: every failure is `return null` (`parser.ts`'s
/// own `@NOTE` at `:98-100` says a `ValidationResult<T>` "could easily" be added
/// and never was), and the provider then either silently drops the token
/// (`request-manager.ts:177-185`) or raises `invalid_scope` for a different
/// reason entirely. This typed enum is the missing half.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.8.
/// `description` renders each case WITHOUT echoing a full attacker-chosen string
/// into a log line; the associated value fields are for structured logging only.
public enum ScopeParseError: Error, Sendable, Hashable, CustomStringConvertible {
    case notAScopeToken(String)
    case malformedPercentEncoding(String)
    case unknownPrefix(String)
    case prefixMismatch(expected: String, actual: String)
    case unknownParameter(prefix: String, key: String)
    case repeatedSingleValuedParameter(prefix: String, key: String)
    case positionalAndNamedConflict(prefix: String, key: String)
    case emptyMultiValuedParameter(prefix: String, key: String)
    case invalidParameterValue(prefix: String, key: String, value: String)
    case invalidPositionalValue(prefix: String, key: String, value: String)
    case missingRequiredParameter(prefix: String, key: String)
    case forbiddenParameterCombination(prefix: String, detail: String)
    case scopeTooLong(bytes: Int, limit: Int)

    public var description: String {
        switch self {
        case .notAScopeToken: "not a valid RFC 6749 scope-token"
        case .malformedPercentEncoding: "malformed percent-encoding in scope"
        case .unknownPrefix: "unknown scope prefix"
        case let .prefixMismatch(expected, actual: _): "scope does not name prefix \"\(expected)\""
        case let .unknownParameter(prefix, key): "unknown parameter \"\(key)\" for \"\(prefix)\""
        case let .repeatedSingleValuedParameter(prefix, key):
            "parameter \"\(key)\" for \"\(prefix)\" repeated, but is single-valued"
        case let .positionalAndNamedConflict(prefix, key):
            "parameter \"\(key)\" for \"\(prefix)\" given both positionally and by name"
        case let .emptyMultiValuedParameter(prefix, key):
            "parameter \"\(key)\" for \"\(prefix)\" is empty"
        case let .invalidParameterValue(prefix, key, value: _):
            "invalid value for parameter \"\(key)\" of \"\(prefix)\""
        case let .invalidPositionalValue(prefix, key, value: _):
            "invalid positional value for parameter \"\(key)\" of \"\(prefix)\""
        case let .missingRequiredParameter(prefix, key):
            "missing required parameter \"\(key)\" for \"\(prefix)\""
        case let .forbiddenParameterCombination(prefix, detail):
            "forbidden parameter combination for \"\(prefix)\": \(detail)"
        case let .scopeTooLong(bytes, limit):
            "scope is \(bytes) bytes, over the \(limit)-byte limit"
        }
    }
}
