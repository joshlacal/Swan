import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import PetrelCrypto
import SwanCore

/// A fail-closed view of an existing account key store for logical export.
///
/// Unlike ``FileAccountKeyStore``, this reader never creates, repairs, migrates,
/// chmods, fsyncs, or replaces key-store state. Its shared lock pins a coherent
/// read window while the export is assembled.
public final class ExistingFileAccountKeyReader: AccountKeyMaterialReader, @unchecked Sendable {
    private static let lockFilename = ".swan-key-store.lock"
    private static let maximumEnvelopeBytes = 16 * 1_024

    private struct Envelope: Codable {
        let format: String
        let kid: String
        let purpose: AccountKeyPurpose
        let accountDID: String
        let generation: UInt64
        let sealedKey: Data
        let publicKey: Data?
        let publicKeyAuthentication: Data?
    }

    private let directoryDescriptor: Int32
    private let lockDescriptor: Int32
    private let configuration: AccountKeyEncryptionConfiguration

    public init(root: URL, configuration: AccountKeyEncryptionConfiguration) throws {
        let directory = open(
            root.standardizedFileURL.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directory >= 0 else {
            throw SwanError.unavailable("existing account key-store root is unavailable")
        }
        var directoryStatus = stat()
        guard fstat(directory, &directoryStatus) == 0,
              (directoryStatus.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              directoryStatus.st_uid == geteuid(),
              Int(directoryStatus.st_mode & mode_t(0o777)) == 0o700 else {
            _ = close(directory)
            throw SwanError.unavailable(
                "existing account key-store root failed ownership or permission validation"
            )
        }

        let lock = openat(
            directory,
            Self.lockFilename,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard lock >= 0 else {
            _ = close(directory)
            throw SwanError.unavailable("existing account key-store lock is unavailable")
        }
        var lockStatus = stat()
        guard fstat(lock, &lockStatus) == 0,
              (lockStatus.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              lockStatus.st_uid == geteuid(),
              lockStatus.st_nlink == 1,
              Int(lockStatus.st_mode & mode_t(0o777)) == 0o600 else {
            _ = close(lock)
            _ = close(directory)
            throw SwanError.unavailable("existing account key-store lock failed validation")
        }
        while flock(lock, LOCK_SH) != 0 {
            guard errno == EINTR else {
                _ = close(lock)
                _ = close(directory)
                throw SwanError.unavailable("could not acquire account key-store reader lock")
            }
        }
        directoryDescriptor = directory
        lockDescriptor = lock
        self.configuration = configuration
    }

    @_spi(OperatorRestore)
    public init(
        operatorRestoreDirectoryDescriptor descriptor: Int32,
        configuration: AccountKeyEncryptionConfiguration
    ) throws {
        let directory = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else {
            throw SwanError.unavailable("existing account key-store root is unavailable")
        }
        var directoryStatus = stat()
        guard fstat(directory, &directoryStatus) == 0,
              (directoryStatus.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              directoryStatus.st_uid == geteuid(),
              Int(directoryStatus.st_mode & mode_t(0o777)) == 0o700 else {
            _ = close(directory)
            throw SwanError.unavailable(
                "existing account key-store root failed ownership or permission validation"
            )
        }
        let lock = openat(
            directory,
            Self.lockFilename,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard lock >= 0 else {
            _ = close(directory)
            throw SwanError.unavailable("existing account key-store lock is unavailable")
        }
        var lockStatus = stat()
        guard fstat(lock, &lockStatus) == 0,
              (lockStatus.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              lockStatus.st_uid == geteuid(),
              lockStatus.st_nlink == 1,
              Int(lockStatus.st_mode & mode_t(0o777)) == 0o600 else {
            _ = close(lock)
            _ = close(directory)
            throw SwanError.unavailable("existing account key-store lock failed validation")
        }
        while flock(lock, LOCK_SH) != 0 {
            guard errno == EINTR else {
                _ = close(lock)
                _ = close(directory)
                throw SwanError.unavailable("could not acquire account key-store reader lock")
            }
        }
        directoryDescriptor = directory
        lockDescriptor = lock
        self.configuration = configuration
    }

    deinit {
        while flock(lockDescriptor, LOCK_UN) != 0, errno == EINTR {}
        _ = close(lockDescriptor)
        _ = close(directoryDescriptor)
    }

    public func keyIfPresent(for reference: AccountKeyReference) async throws -> Data? {
        var status = stat()
        if fstatat(directoryDescriptor, Self.filename(for: reference), &status, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw SwanError.unavailable("account key-store entry is unavailable") }
            return nil
        }
        return try await key(for: reference)
    }

    public func key(for reference: AccountKeyReference) async throws -> Data {
        let encoded = try readProtected(named: Self.filename(for: reference))
        let envelope: Envelope
        do {
            envelope = try JSONDecoder().decode(Envelope.self, from: encoded)
        } catch {
            throw SwanError.malformed("invalid account key envelope")
        }
        guard envelope.format == FileAccountKeyStore.envelopeFormat,
              envelope.accountDID == reference.accountDID,
              envelope.purpose == reference.purpose,
              envelope.generation == reference.generation else {
            throw SwanError.malformed("account key envelope binding mismatch")
        }
        guard let keyData = configuration.key(for: envelope.kid) else {
            throw SwanError.unavailable("account key envelope references an unavailable KEK")
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: envelope.sealedKey),
                using: SymmetricKey(data: keyData),
                authenticating: Self.additionalAuthenticatedData(
                    keyID: envelope.kid,
                    reference: reference
                )
            )
        } catch {
            throw SwanError.unauthorized("account key envelope authentication failed")
        }
        guard plaintext.count == 32 else {
            throw SwanError.malformed("account key envelope contains an invalid private key size")
        }
        return plaintext
    }

    private func readProtected(named filename: String) throws -> Data {
        let descriptor = openat(
            directoryDescriptor,
            filename,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw SwanError.malformed("account key-store entry is unavailable")
        }
        defer { _ = close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_uid == geteuid(),
              status.st_nlink == 1,
              Int(status.st_mode & mode_t(0o777)) == 0o600,
              status.st_size > 0,
              status.st_size <= off_t(Self.maximumEnvelopeBytes) else {
            throw SwanError.malformed("account key-store entry failed validation")
        }
        let expectedSize = Int(status.st_size)
        var data = Data(count: expectedSize)
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < expectedSize {
                let count = read(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    expectedSize - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw SwanError.malformed("account key-store entry changed during read")
                }
                offset += count
            }
        }
        var extra: UInt8 = 0
        let extraCount = withUnsafeMutablePointer(to: &extra) { read(descriptor, $0, 1) }
        guard extraCount == 0 else {
            throw SwanError.malformed("account key-store entry changed during read")
        }
        return data
    }

    private static func filename(for reference: AccountKeyReference) -> String {
        let identity = [
            FileAccountKeyStore.envelopeFormat,
            reference.accountDID,
            reference.purpose.rawValue,
            String(reference.generation),
        ].joined(separator: "\u{0}")
        return "\(Hex.encode(SHA256.hash(data: Data(identity.utf8)))).key"
    }

    private static func additionalAuthenticatedData(
        keyID: String,
        reference: AccountKeyReference
    ) -> Data {
        var data = Data()
        for field in [
            FileAccountKeyStore.envelopeFormat,
            keyID,
            reference.purpose.rawValue,
            reference.accountDID,
            String(reference.generation),
        ] {
            var length = UInt64(field.utf8.count).bigEndian
            withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
            data.append(contentsOf: field.utf8)
        }
        return data
    }
}
