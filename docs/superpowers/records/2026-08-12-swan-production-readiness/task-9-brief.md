### Task 9: Serve `did.json` and stop advertising invite codes

**Files:**
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:733-756, 807-814`
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testWellKnownDidJSONResolvesTheServiceDID() async throws {
    let response = try await client.get("/.well-known/did.json")
    XCTAssertEqual(response.status, .ok)
    let doc = try response.decode(DIDDocument.self)
    XCTAssertEqual(doc.id, "did:web:swan.place")
    XCTAssertTrue(doc.service.contains { $0.type == "AtprotoPersonalDataServer" })
}

func testDescribeServerDoesNotClaimInviteCodesAreRequired() async throws {
    XCTAssertFalse(try describeServer().inviteCodeRequired)
}
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404, and `inviteCodeRequired: true`.

- [ ] **Step 3: Implement** — register `/.well-known/did.json` beside the OAuth well-knowns, with an `AtprotoPersonalDataServer` service entry for the public URL. Derive `inviteCodeRequired` from configuration rather than the hardcoded literal, defaulting to `false`.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: serve did.json and stop advertising unsupported invites"
jj new
```

---

