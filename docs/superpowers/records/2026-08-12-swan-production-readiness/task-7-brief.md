### Task 7: Implement `com.atproto.identity.resolveHandle`

**Files:**
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:11-18, 247, 516-534`
- Modify: `Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift:38-41`
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testResolveHandleAnswersUnauthenticated() async throws {
    let response = try await client.get(
        "/xrpc/com.atproto.identity.resolveHandle?handle=swan.place")
    XCTAssertEqual(response.status, .ok)
    XCTAssertEqual(try response.decode(ResolveHandleOutput.self).did,
                   "did:plc:6u6rzv6fk3ga37kgs3tybgdk")
}

func testResolveHandleRejectsUnknownHandleWithInvalidRequest() async throws { }
func testResolveHandleDoesNotRequireGenerationAdmission() async throws {
    // Must work even when public-read admission would fail — this is why
    // it ships independently of W1.
}
func testOtherIdentityMethodsReturn404NotUnauthorized() async throws { }
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404 after Task 6.

- [ ] **Step 3: Implement** — a `router.get` handler registered from `registerPublicRepositoryReadEndpoints`, using `controlStore.account(canonicalHandle:)`. Add the NSID to `publicReadNSIDs` and its wrong-method guards. Add `/xrpc/com.atproto.identity.*` to `registerUnknownPublicEndpointGuards`.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: implement unauthenticated resolveHandle"
jj new
```

---

