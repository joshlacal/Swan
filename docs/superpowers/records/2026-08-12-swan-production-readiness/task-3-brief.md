### Task 3: Evict rather than fail when a post-mutation refresh errors

**Files:**
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1936-1941`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
func testFailedPostMutationRefreshDoesNotFailTheMutation() async throws {
    // The commit is durable before the refresh runs. A refresh error must
    // not fail a request whose write already succeeded.
}

func testFailedPostMutationRefreshEvictsRatherThanCachingStale() async throws {
    // With Task 2 in place, the next read re-admits.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadStaleGenerationTests`
Expected: FAIL on the two new cases.

- [ ] **Step 3: Implement** — evict `publicReadGenerations[did]` and swallow the refresh error, logging at `warning`.

- [ ] **Step 4: Run the full suite** — `xcrun --toolchain XcodeDefault swift test`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: evict rather than fail when a post-mutation refresh errors"
jj new
```

---

