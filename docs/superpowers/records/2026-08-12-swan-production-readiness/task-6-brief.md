### Task 6: Route before authenticating

**Files:**
- Modify: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:302, 317-349`
- Test: `Tests/SwanHTTPTests/` (existing pipethrough test file)

- [ ] **Step 1: Write the failing test**

```swift
func testUnknownNSIDReturns404NotUnauthorized() async throws {
    // No Authorization header.
    let response = try await client.get("/xrpc/com.atproto.identity.resolveHandle")
    XCTAssertEqual(response.status, .notFound)
}

func testDeniedNamespaceReturns404WithoutTouchingCredentials() async throws {
    // blue.catbird.* is explicitly denied by the router.
}

func testAnonymousCallerStillCannotCauseAnOutboundConnection() async throws {
    // The invariant this reordering must preserve.
}
```

- [ ] **Step 2: Run to verify they fail.** Expected: 401 rather than 404.

- [ ] **Step 3: Implement** — move the `SwanXRPCProxyRouter(...).route(...)` block from `:336-349` to immediately after the NSID parse at `:317-320`, keeping `authorizedPipethroughSubject` at `:322-329` **after** it. `.denied`/`.unrouted` now 404 without touching credentials. Routing opens no sockets; the resolver at `:386` does, and it stays after auth.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: route before authenticating so missing routes 404"
jj new
```

---

