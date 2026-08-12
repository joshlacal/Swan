### Task 2: Re-admit a stale generation instead of failing

The core fix. Confirmed correct empirically: the live outage cleared with no restart when a record was created and its post-commit refresh re-admitted the generation.

**Files:**
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1387-1409`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`

**Interfaces:**
- Consumes: Task 1's `.generationPinStale`.

- [ ] **Step 1: Write the failing test**

This is the regression test for the 2026-08-12 outage. It must reproduce the trigger exactly: a commit from a **second connection** to the account database that leaves repository state untouched.

```swift
func testForeignConnectionCommitDoesNotBreakPublicReads() async throws {
    let directory = try await makeDirectory(seeded: .twoPostAccount)
    let before = try await directory.publicRepositoryStatus(did: did)
    XCTAssertEqual(before?.revision, "…")

    // A second connection commits something irrelevant — a scratch table.
    // This is what PRAGMA data_version observes, and it never returns.
    try await commitFromSecondConnection(touchingRepositoryState: false)

    let after = try await directory.publicRepositoryStatus(did: did)
    XCTAssertEqual(after?.revision, before?.revision,
        "A foreign commit that touches no repository state must not " +
        "make the account permanently unreadable.")
}

func testGenuinelyUnadmittableAccountStill503sAndLogsWhy() async throws {
    // Re-admission must not become a way to serve a broken account.
}

func testReAdmissionHappensOnceNotInALoop() async throws {
    // A permanently-failing re-admit must not retry per read forever.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadStaleGenerationTests`
Expected: FAIL — the first test throws `.unavailable`.

- [ ] **Step 3: Implement**

In `activePublicReadContext`, treat `.generationPinStale` from a generation-validated read as a signal to re-admit **once** and retry, returning 503 only if the re-admission itself fails. Re-admission must be bounded — one attempt per request, not a retry loop.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: re-admit a stale public-read generation instead of failing"
jj new
```

---

