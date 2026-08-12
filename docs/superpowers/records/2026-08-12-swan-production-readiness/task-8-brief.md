### Task 8: Move public blob reads off the write flag

**Files:**
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:536-611` (remove)
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:247` (add)
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:979-982` (delete the special case)
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testGetBlobIsServedWhenPublicMutationsAreDisabled() async throws {
    // Today disabling public writes silently disables avatar and image
    // serving for the entire network.
    let http = try makeRouter(publicRepositoryMutations: nil)
    let response = try await http.get("/xrpc/com.atproto.sync.getBlob?did=…&cid=…")
    XCTAssertNotEqual(response.status, .notFound)
}
```

- [ ] **Step 2: Run to verify it fails.** Expected: 404.

- [ ] **Step 3: Implement** — move the `blobPath` block into `registerPublicRepositoryReadEndpoints`, backed by the read directory so it registers whenever `publicRepositoryReadDirectory != nil`. Delete the `SwanHTTP.swift:979-982` special case.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: serve public blob reads from the read path"
jj new
```

---

