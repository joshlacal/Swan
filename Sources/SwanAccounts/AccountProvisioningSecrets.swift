import Foundation
import SwanCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Loads the two secret inputs needed by the local account-installation
/// workflow without accepting either one as a command-line value. Account
/// KEKs stay deployment configuration; account passwords are deliberately
/// read only from an owner-protected mounted file.
public enum AccountProvisioningSecrets {
    public static let kekEnvironmentName = "SWAN_ACCOUNT_KEK"
    private static let maximumPasswordBytes = 4 * 1_024
    private static let maximumEncodedKEKBytes = 128

    /// Builds the development file-key-store configuration from an injected
    /// environment value and/or a selected mounted secret file. When both
    /// sources are present they must carry the exact same 32-byte decoded
    /// key; no source silently overrides another.
    public static func accountKeyConfiguration(
        activeKeyID: String = "primary",
        secretFile: URL? = nil
    ) throws -> AccountKeyEncryptionConfiguration {
        try accountKeyConfiguration(
            environment: ProcessInfo.processInfo.environment,
            activeKeyID: activeKeyID,
            secretFile: secretFile
        )
    }

    /// Loads the account KEK for an offline operator backup from exactly one
    /// selected mounted file. Unlike the general provisioning entry point,
    /// this never consults process environment and requires canonical,
    /// unpadded base64url for one 32-byte key.
    public static func requiredMountedAccountKeyConfiguration(
        activeKeyID: String = "primary",
        secretFile: URL
    ) throws -> AccountKeyEncryptionConfiguration {
        let key = try requiredMounted32ByteSecret(secretFile: secretFile)
        return try AccountKeyEncryptionConfiguration(activeKeyID: activeKeyID, activeKey: key)
    }

    /// Reads a canonical, unpadded base64url-encoded 32-byte secret from an
    /// owner-only mounted file.  This is shared by other process secrets that
    /// use the same deployment-safe file format (for example the account
    /// recovery proof key) without exposing the descriptor-reading primitive.
    public static func requiredMounted32ByteSecret(secretFile: URL) throws -> Data {
        let encoded = try readOwnerOnlyRegularFile(
            secretFile,
            maximumPayloadBytes: maximumEncodedKEKBytes
        )
        let normalized = try normalize(encoded, maximumBytes: maximumEncodedKEKBytes)
        guard normalized.count == 43,
              let text = String(data: normalized, encoding: .utf8),
              text.utf8.allSatisfy({
                  ($0 >= 0x41 && $0 <= 0x5a)
                      || ($0 >= 0x61 && $0 <= 0x7a)
                      || ($0 >= 0x30 && $0 <= 0x39)
                      || $0 == 0x2d || $0 == 0x5f
              }),
              let key = decodeBase64URL(text),
              key.count == 32,
              encodeBase64URL(key) == text else {
            throw SwanError.malformed("mounted 32-byte secret is invalid")
        }
        return key
    }

    /// Reads one account password. A terminal LF or CRLF is accepted for
    /// mounted-secret compatibility; all other bytes are preserved exactly.
    public static func password(secretFile: URL) throws -> String {
        let data = try readOwnerOnlyRegularFile(
            secretFile,
            maximumPayloadBytes: maximumPasswordBytes
        )
        let normalized = try normalize(data, maximumBytes: maximumPasswordBytes)
        guard !normalized.contains(0),
              let password = String(data: normalized, encoding: .utf8) else {
            throw SwanError.malformed("account password secret is invalid")
        }
        return password
    }

    /// Module-visible so the account suite can validate source conflicts and
    /// descriptor-safe file behavior without mutating process environment.
    static func accountKeyConfiguration(
        environment: [String: String],
        activeKeyID: String,
        secretFile: URL?
    ) throws -> AccountKeyEncryptionConfiguration {
        let environmentKey = try environment[kekEnvironmentName].map(decodeKEKString)
        let fileKey = try secretFile.map { url in
            try decodeKEKData(
                try readOwnerOnlyRegularFile(url, maximumPayloadBytes: maximumEncodedKEKBytes)
            )
        }
        guard let key = environmentKey ?? fileKey else {
            throw SwanError.unavailable("account KEK is unavailable")
        }
        if let environmentKey, let fileKey,
           !constantTimeEqual(environmentKey, fileKey) {
            throw SwanError.malformed("account KEK sources do not match")
        }
        return try AccountKeyEncryptionConfiguration(activeKeyID: activeKeyID, activeKey: key)
    }

    private static func decodeKEKString(_ value: String) throws -> Data {
        try decodeKEKData(Data(value.utf8))
    }

    private static func decodeKEKData(_ encoded: Data) throws -> Data {
        let normalized = try normalize(encoded, maximumBytes: maximumEncodedKEKBytes)
        guard let text = String(data: normalized, encoding: .utf8),
              let key = decodeBase64URL(text), key.count == 32 else {
            throw SwanError.malformed("account KEK is invalid")
        }
        return key
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        return Data(base64Encoded: base64)
    }

    private static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func normalize(_ data: Data, maximumBytes: Int) throws -> Data {
        var normalized = data
        if normalized.last == 0x0A {
            normalized.removeLast()
            if normalized.last == 0x0D {
                normalized.removeLast()
            }
        }
        guard !normalized.isEmpty, normalized.count <= maximumBytes else {
            throw SwanError.malformed("account provisioning secret is invalid")
        }
        return normalized
    }

    /// Opens exactly one filesystem object without following a link, then
    /// validates and reads that same descriptor. Path metadata plus a later
    /// path read would permit a rename/link swap between the checks.
    private static func readOwnerOnlyRegularFile(
        _ url: URL,
        maximumPayloadBytes: Int
    ) throws -> Data {
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("account provisioning secret is unavailable")
        }
        defer { _ = close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0,
              metadata.st_size > 0,
              metadata.st_size <= off_t(maximumPayloadBytes + 2) else {
            throw SwanError.unavailable("account provisioning secret is unavailable")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            let data = try handle.read(upToCount: maximumPayloadBytes + 3) ?? Data()
            guard data.count <= maximumPayloadBytes + 2 else {
                throw SwanError.malformed("account provisioning secret is invalid")
            }
            return data
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("account provisioning secret is unavailable")
        }
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        let count = max(lhs.count, rhs.count)
        var difference = UInt64(lhs.count) ^ UInt64(rhs.count)
        for index in 0 ..< count {
            let left = index < lhs.count ? lhs[lhs.startIndex + index] : 0
            let right = index < rhs.count ? rhs[rhs.startIndex + index] : 0
            difference |= UInt64(left ^ right)
        }
        return difference == 0
    }
}
