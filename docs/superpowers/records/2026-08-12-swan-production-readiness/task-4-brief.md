### Task 4: Demote `data_version` to change detection

**Files:**
- Modify: `Sources/SwanSQLite/PublicRepositoryReadStore.swift:796-797`
- Test: existing stale-generation tests

- [ ] **Step 1: Write the failing test**

```swift
func testDataVersionDriftAloneTriggersReAdmissionNotRejection() async throws {
    // With Tasks 2-3 in place this is belt and braces, but it pins the
    // intent: data_version is a hint that something changed, not proof
    // that the generation is invalid.
}
```

- [ ] **Step 2: Run to verify it fails.** Run: `xcrun --toolchain XcodeDefault swift test --filter StaleGeneration`. Confirm the filter matched.

- [ ] **Step 3: Implement** — `data_version` movement maps to `.generationPinStale` (re-admit) rather than a hard failure. `fileIdentity` and `state` keep their meaning.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: treat data_version movement as change detection"
jj new
```

---

