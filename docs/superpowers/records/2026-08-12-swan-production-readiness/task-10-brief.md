### Task 10: Make `--profile` control the public route surface

**Files:**
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:966`
- Test: `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift` or a sibling

- [ ] **Step 1: Write the failing test**

```swift
func testRouteSurfaceFollowsTheLoadedProfile() async throws {
    // Registration currently iterates a hardcoded PublicDataTesting20260727
    // while the process loads --profile. The control is not the control.
}

func testStartupFailsLoudlyForAProfileWithNoRegistry() async throws {
    // Profiles/ ships public-data-testing-2026-08-06 with no Swift registry.
    // Silently registering the wrong surface is worse than refusing to boot.
}
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** — select the descriptor list from the loaded profile; throw a `ValidationError` at startup when a profile id has no matching registry.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: drive public route registration from the loaded profile"
jj new
```

---

## W3 — Relay activation

