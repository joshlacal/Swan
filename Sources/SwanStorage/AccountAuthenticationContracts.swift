import SwanCore

// Re-export the dependency-neutral values from the storage contract module so
// storage adapters do not need to know which lower-level target owns them.
public typealias AuthenticationFactorKind = SwanCore.AuthenticationFactorKind
public typealias AuthenticationStrength = SwanCore.AuthenticationStrength
public typealias ManagementSessionID = SwanCore.ManagementSessionID
public typealias LegacySessionID = SwanCore.LegacySessionID
