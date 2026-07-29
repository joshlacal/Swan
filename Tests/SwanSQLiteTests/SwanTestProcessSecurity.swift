import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum SwanTestChildProcessSecurity {
    private static let inheritedToolchainKeys = [
        "DEVELOPER_DIR",
        "SDKROOT",
        "TOOLCHAINS",
        "SWIFT_EXEC",
        "SWIFT_DRIVER_SWIFT_FRONTEND_EXEC",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "TMPDIR",
    ]

    static func environment(
        parent: [String: String] = ProcessInfo.processInfo.environment,
        testVariables: [String: String]
    ) -> [String: String] {
        precondition(
            testVariables.keys.allSatisfy { $0.hasPrefix("SWAN_") },
            "child test variables must use the SWAN_ namespace"
        )
        var environment = [
            "PATH": parent["PATH"] ?? "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        ]
        for key in inheritedToolchainKeys {
            if let value = parent[key], !value.isEmpty {
                environment[key] = value
            }
        }
        for (key, value) in testVariables {
            environment[key] = value
        }
        return environment
    }
}

final class SwanTestBoundedProcessOutput: @unchecked Sendable {
    private let maximumDiagnosticBytes: Int
    private let maximumCaptureBytes: Int
    private let sensitiveValues: [String]
    private let pipe = Pipe()
    private let group = DispatchGroup()
    private let lock = NSLock()
    private var captured = Data()
    private var droppedByteCount = 0
    private var readerStarted = false

    init(
        maximumDiagnosticBytes: Int = 32 * 1_024,
        sensitiveValues: [String]
    ) {
        precondition(maximumDiagnosticBytes >= 128)
        self.maximumDiagnosticBytes = maximumDiagnosticBytes
        self.sensitiveValues = sensitiveValues
            .filter { !$0.isEmpty }
            .sorted { $0.utf8.count > $1.utf8.count }
        let overlap = min(
            4 * 1_024,
            self.sensitiveValues.map { $0.utf8.count }.max() ?? 0
        )
        maximumCaptureBytes = maximumDiagnosticBytes + overlap
    }

    func attach(to process: Process) {
        let shouldStart = lock.withLock {
            guard !readerStarted else { return false }
            readerStarted = true
            return true
        }
        precondition(shouldStart, "process output capture is single-use")
        process.standardOutput = pipe
        process.standardError = pipe
        group.enter()
        DispatchQueue.global(qos: .utility).async { [self] in
            defer { group.leave() }
            while true {
                do {
                    guard let bytes = try pipe.fileHandleForReading.read(
                        upToCount: 8 * 1_024
                    ), !bytes.isEmpty else {
                        return
                    }
                    record(bytes)
                } catch {
                    return
                }
            }
        }
    }

    func childDidLaunch() {
        try? pipe.fileHandleForWriting.close()
    }

    func cancel() {
        try? pipe.fileHandleForWriting.close()
        try? pipe.fileHandleForReading.close()
    }

    func finish() -> String {
        group.wait()
        return diagnosticForTesting()
    }

    func recordForTesting(_ bytes: Data) {
        record(bytes)
    }

    func diagnosticForTesting() -> String {
        let snapshot = lock.withLock {
            (captured, droppedByteCount > 0)
        }
        return Self.redactedDiagnostic(
            snapshot.0,
            sensitiveValues: sensitiveValues,
            maximumBytes: maximumDiagnosticBytes,
            wasTruncated: snapshot.1
        )
    }

    private func record(_ bytes: Data) {
        lock.withLock {
            let remaining = max(0, maximumCaptureBytes - captured.count)
            if remaining > 0 {
                captured.append(contentsOf: bytes.prefix(remaining))
            }
            droppedByteCount += max(0, bytes.count - remaining)
        }
    }

    private static func redactedDiagnostic(
        _ bytes: Data,
        sensitiveValues: [String],
        maximumBytes: Int,
        wasTruncated: Bool
    ) -> String {
        var text = String(decoding: bytes, as: UTF8.self)
        for value in sensitiveValues {
            text = text.replacingOccurrences(
                of: value,
                with: "<redacted>"
            )
        }
        text = replacingMatches(
            in: text,
            pattern:
                #"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]+"#,
            with: "Bearer <redacted>"
        )
        text = replacingMatches(
            in: text,
            pattern:
                #"(?im)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSCODE|PRIVATE_KEY|AUTHORIZATION|COOKIE|IKM)[A-Z0-9_]*)[ \t]*[:=][ \t]*[^\r\n]*"#,
            with: "$1=<redacted>"
        )

        let truncationSuffix = "\n[output truncated]"
        var includeSuffix = wasTruncated
        var textBytes = Data(text.utf8)
        if textBytes.count > maximumBytes {
            includeSuffix = true
        }
        let suffixBytes = includeSuffix ? Data(truncationSuffix.utf8) : Data()
        let textBudget = max(0, maximumBytes - suffixBytes.count)
        if textBytes.count > textBudget {
            textBytes = Data(textBytes.prefix(textBudget))
            while !textBytes.isEmpty,
                  String(data: textBytes, encoding: .utf8) == nil
            {
                textBytes.removeLast()
            }
        }
        let boundedText = String(data: textBytes, encoding: .utf8) ?? ""
        return boundedText + (includeSuffix ? truncationSuffix : "")
    }

    private static func replacingMatches(
        in text: String,
        pattern: String,
        with template: String
    ) -> String {
        guard let expression = try? NSRegularExpression(
            pattern: pattern
        ) else {
            return text
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return expression.stringByReplacingMatches(
            in: text,
            range: range,
            withTemplate: template
        )
    }
}

enum SwanTestPrivateFilesystem {
    static func createOwnerOnlyDirectory(at url: URL) throws {
        let path = url.standardizedFileURL.path
        #if canImport(Darwin)
        let creationResult = Darwin.mkdir(path, mode_t(0o700))
        #elseif canImport(Glibc)
        let creationResult = Glibc.mkdir(path, mode_t(0o700))
        #else
        let creationResult = -1
        #endif
        guard creationResult == 0 || errno == EEXIST else {
            throw posixError()
        }

        #if canImport(Darwin)
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        #elseif canImport(Glibc)
        let descriptor = Glibc.open(
            path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        #else
        let descriptor: Int32 = -1
        #endif
        guard descriptor >= 0 else {
            throw posixError()
        }
        defer {
            #if canImport(Darwin)
            _ = Darwin.close(descriptor)
            #elseif canImport(Glibc)
            _ = Glibc.close(descriptor)
            #endif
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              metadata.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o700)) == 0
        else {
            throw posixError()
        }
    }

    static func writeOwnerOnlyNewFile(_ data: Data, to url: URL) throws {
        let path = url.standardizedFileURL.path
        #if canImport(Darwin)
        let descriptor = Darwin.open(
            path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        #elseif canImport(Glibc)
        let descriptor = Glibc.open(
            path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        #else
        let descriptor: Int32 = -1
        #endif
        guard descriptor >= 0 else {
            throw posixError()
        }
        var succeeded = false
        defer {
            #if canImport(Darwin)
            _ = Darwin.close(descriptor)
            #elseif canImport(Glibc)
            _ = Glibc.close(descriptor)
            #endif
            if !succeeded {
                try? FileManager.default.removeItem(at: url)
            }
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o600)) == 0
        else {
            throw posixError()
        }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                guard let baseAddress = buffer.baseAddress else { break }
                #if canImport(Darwin)
                let result = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
                #elseif canImport(Glibc)
                let result = Glibc.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
                #else
                let result = -1
                #endif
                if result < 0, errno == EINTR {
                    continue
                }
                guard result > 0 else {
                    throw posixError()
                }
                offset += result
            }
        }
        succeeded = true
    }

    static func permissions(at url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(
            atPath: url.path
        )
        guard let permissions = attributes[.posixPermissions] as? NSNumber
        else {
            throw CocoaError(.fileReadUnknown)
        }
        return permissions.intValue & 0o777
    }

    private static func posixError() -> Error {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
}
