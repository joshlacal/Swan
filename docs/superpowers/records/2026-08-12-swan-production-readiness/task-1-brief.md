### Task 1: Name the failing guard in logs

Do this **first**. Every later task in W1 is easier to verify when a failure says which guard fired, and this is the only thing that will diagnose a recurrence. Three hours of live 503s produced zero journal lines.

**Files:**
- Modify: `Sources/SwanSQLite/PublicRepositoryReadStore.swift`
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1456-1460`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift` (six catch sites: `:298-300, 360-362, 424-426, 450-452, 476-478, 511-513`)
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift`

**Interfaces:**
- Produces: `PublicRepositoryReadError.unavailable(reason: PublicReadUnavailableReason)` — an enum naming which guard failed. Tasks 2-4 pattern-match on it.

- [ ] **Step 1: Write the failing test**

```swift
func testAdmissionFailureNamesTheGuardThatFired() async throws {
    // An account whose journal stage is not .submitted must fail with a
    // reason identifying THAT guard, not a bare .unavailable.
    let outcome = await captureAdmissionFailure(stage: .submissionPending)
    XCTAssertEqual(outcome, .identityStageNotSubmitted)
}

func testDataVersionDriftIsDistinguishableFromIdentityFailure() async throws {
    // The two must not collapse to the same reason — telling them apart
    // is the entire point of this task.
    let drift = await captureAdmissionFailure(afterForeignCommit: true)
    XCTAssertEqual(drift, .generationPinStale)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadDiagnosticsTests`
Expected: FAIL — the reason type does not exist. Confirm the filter matched tests.

- [ ] **Step 3: Add the reason enum and thread it through**

Give `PublicRepositoryReadError.unavailable` an associated `PublicReadUnavailableReason` with one case per guard: `identityRowCount`, `identityStageNotSubmitted`, `genesisCIDMismatch`, `missingKeyMaterial`, `keyReferenceMismatch`, `historyVerifierUnavailable`, `terminalIdentityMismatch`, `commitAuthenticationFailed`, `projectionMismatch`, `generationPinStale`, `intentVerificationFailed`.

Replace each bare `throw PublicRepositoryReadError.unavailable` with the specific case. Do **not** change what the client sees.

- [ ] **Step 4: Log at the boundary**

At `SQLitePreMigratedAccountDirectory.swift:1456-1460` and each of the six handler catch sites, log one structured `warning` naming the DID and the reason. Client body unchanged.

- [ ] **Step 5: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
jj describe -m "SwanSQLite: name the guard that fails public-read admission"
jj new
```

---

