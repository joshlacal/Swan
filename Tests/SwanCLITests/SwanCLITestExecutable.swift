import Foundation
import XCTest

/// The `swan` binary the CLI tests drive, resolved one way for the whole
/// target.
///
/// Seven copies of this used to be written inline, and three of them ignored
/// `SWAN_TEST_EXECUTABLE` — which is the entire pre-existing 15-test failure
/// set on Linux, where the binary is not where the macOS layout puts it.
///
/// The policy here is the strictest of the six the copies implemented, for the
/// reason `LabCLITests` argued and the others did not: a package-root
/// `.build/debug/swan` may belong to a different scratch build or a different
/// source revision, so exercising it produces *evidence about the wrong
/// binary*. A skip is a better answer than a stale pass. The per-lane
/// `.build-task19/20/21` candidates the copies accumulated are dropped for the
/// same reason.
enum SwanCLITestExecutable {
    /// `nil` when no eligible binary exists, for call sites that treat an
    /// absent CLI as "nothing to exercise here".
    static func resolved() -> URL? {
        if let override = ProcessInfo.processInfo.environment["SWAN_TEST_EXECUTABLE"],
           !override.isEmpty {
            let executable = URL(filePath: override)
            return FileManager.default.isExecutableFile(atPath: executable.path)
                ? executable
                : nil
        }
        return coBuiltExecutable()
    }

    /// Throws `XCTSkip` rather than returning `nil`, and distinguishes "the
    /// override was set but is not runnable" — an operator error worth saying
    /// out loud — from "nothing was built beside these tests".
    static func require() throws -> URL {
        if let override = ProcessInfo.processInfo.environment["SWAN_TEST_EXECUTABLE"],
           !override.isEmpty {
            let executable = URL(filePath: override)
            guard FileManager.default.isExecutableFile(atPath: executable.path) else {
                throw XCTSkip("SWAN_TEST_EXECUTABLE is not executable")
            }
            return executable
        }
        guard let coBuilt = coBuiltExecutable() else {
            throw XCTSkip(
                "co-built swan executable is unavailable; set SWAN_TEST_EXECUTABLE explicitly"
            )
        }
        return coBuilt
    }

    /// Only the product built beside this exact test bundle is eligible.
    ///
    /// Both layouts are tried because the bundle URL does not mean the same
    /// thing on both platforms: on Darwin it is `…/debug/SwanPackageTests
    /// .xctest`, so the product is one level up, while on Linux the tests link
    /// into one executable and the bundle URL is already the directory holding
    /// `swan`. Checking only the Darwin shape is why the override had to exist
    /// on Linux in the first place.
    private static func coBuiltExecutable() -> URL? {
        let bundleURL = Bundle(for: SwanCLITestExecutableAnchor.self).bundleURL
        for candidate in [
            bundleURL.deletingLastPathComponent().appending(path: "swan"),
            bundleURL.appending(path: "swan"),
        ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        return nil
    }
}

/// `Bundle(for:)` needs a class in this target; it is not otherwise used.
private final class SwanCLITestExecutableAnchor {}
