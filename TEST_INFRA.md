# E2E Test Infra: Swan Account Management Portal

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Tests are designed directly from user requirements (`ORIGINAL_REQUEST.md`) and project architecture specifications (`PROJECT.md`), exercising the web portal through public HTTP REST APIs, DOM elements, and standard WebAuthn/browser interfaces without reliance on internal component states.
- **Methodology**: 4-Tier verification incorporating Category-Partition, Boundary Value Analysis (BVA), Pairwise Combinatorial Testing, and Real-World Application Workloads.
- **Hermetic Execution**: High-fidelity in-memory mock backend harness supporting both Vitest runner (fast integration/unit execution) and Playwright browser execution over local HTTPS with strict CSP compliance.

## Feature Inventory & Tier Allocation
| # | Feature | Source (Requirement) | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (Workloads) |
|---|---------|----------------------|:-----------------:|:-----------------:|:-----------------:|:------------------:|
| F1 | Typed Models & API Client | R3, PROJECT §Feature 1 | 5 tests | 5 tests | ✓ | ✓ |
| F2 | Base64URL & WebAuthn Helpers | R2, PROJECT §Feature 2 | 5 tests | 5 tests | ✓ | ✓ |
| F3 | Inline SVG QR Generator | R2, PROJECT §Feature 3 | 5 tests | 5 tests | ✓ | ✓ |
| F4 | Reactive Stores & UI Kit | R2, R3, PROJECT §Feature 4 | 5 tests | 5 tests | ✓ | ✓ |
| F5 | Step-Up Coordinator & Interceptor | R1, PROJECT §Feature 5 | 5 tests | 5 tests | ✓ | ✓ |
| F6 | Interactive Step-Up Dialog | R1, PROJECT §Feature 6 | 5 tests | 5 tests | ✓ | ✓ |
| F7 | Accessible Modal Dialog Base | R2, PROJECT §Feature 7 | 5 tests | 5 tests | ✓ | ✓ |
| F8 | App Password Workflow Modal | R2, PROJECT §Feature 8 | 5 tests | 5 tests | ✓ | ✓ |
| F9 | Passkey WebAuthn Enrollment Modal | R2, PROJECT §Feature 9 | 5 tests | 5 tests | ✓ | ✓ |
| F10 | TOTP Enrollment Modal | R2, PROJECT §Feature 10 | 5 tests | 5 tests | ✓ | ✓ |
| F11 | Recovery Code Rotation Modal | R2, PROJECT §Feature 11 | 5 tests | 5 tests | ✓ | ✓ |
| F12 | did:web Domain Wizard Modal | R2, PROJECT §Feature 12 | 5 tests | 5 tests | ✓ | ✓ |
| F13 | Export & Lifecycle Modals | R2, PROJECT §Feature 13 | 5 tests | 5 tests | ✓ | ✓ |
| F14 | Modular Views Refactoring | R2, PROJECT §Feature 14 | 5 tests | 5 tests | ✓ | ✓ |
| F15 | Correct HTTP Verb Routing | R3, PROJECT §Feature 15 | 5 tests | 5 tests | ✓ | ✓ |
| F16 | Root SPA Shell & Navigation | R2, R3, PROJECT §Feature 16 | 5 tests | 5 tests | ✓ | ✓ |
| F17 | Test Infrastructure & Scripts | R4, PROJECT §Feature 17 | 5 tests | 5 tests | ✓ | ✓ |
| F18 | Opaque-Box E2E Test Suite | R4, PROJECT §Feature 18 | 5 tests | 5 tests | ✓ | ✓ |
| F19 | Production Build & Rollout | R4, PROJECT §Feature 19 | 5 tests | 5 tests | ✓ | ✓ |
| **Total** | **19 Features** | | **95 Tests** | **95 Tests** | **19 Tests** | **10 Scenarios** |

**Grand Total Test Target**: 219 tests.

---

## Test Architecture

### Test Runner & Invocation
- **Test Command**: `npm test` (or `npm run test:unit`) in `Swan-account-integration/web/`
- **Browser E2E Command**: `npm run test:browser` (Playwright against local HTTPS fixture)
- **All-In-One Verification**: `npm run check && npm test && npm run build`
- **Pass/Fail Semantics**: All test suites must execute with 0 failures, 0 uncaught errors, and exit code 0.

### Directory Layout
```
Swan-account-integration/web/
├── src/
│   └── lib/
│       ├── api.test.ts                     # API client unit tests
│       ├── webauthn.test.ts                # WebAuthn helper unit tests
│       └── qrcode.test.ts                  # QR code generator unit tests
├── tests/
│   ├── https-fixture.mjs                   # Local HTTPS mock server fixture for Playwright
│   ├── portal.spec.ts                      # Browser shell & security tests
│   └── e2e/
│       ├── harness/
│       │   ├── mock-backend.ts             # Stateful in-memory mock backend server
│       │   └── test-env.ts                 # Test fixture setup & teardown helpers
│       ├── tier1-features/
│       │   ├── f01-api-client.test.ts      # F1: Typed Models & API Client (5 tests)
│       │   ├── f02-webauthn.test.ts        # F2: WebAuthn & Base64URL Helpers (5 tests)
│       │   ├── f03-qrcode.test.ts          # F3: Inline SVG QR Generator (5 tests)
│       │   ├── f04-stores-uikit.test.ts    # F4: Reactive Stores & UI Kit (5 tests)
│       │   ├── f05-stepup-interceptor.test.ts # F5: Step-Up Coordinator (5 tests)
│       │   ├── f06-stepup-dialog.test.ts   # F6: Step-Up Dialog (5 tests)
│       │   ├── f07-modal-base.test.ts      # F7: Modal Base & Accessibility (5 tests)
│       │   ├── f08-app-passwords.test.ts   # F8: App Passwords Modal (5 tests)
│       │   ├── f09-passkeys.test.ts        # F9: Passkey Registration (5 tests)
│       │   ├── f10-totp.test.ts            # F10: TOTP Enrollment (5 tests)
│       │   ├── f11-recovery.test.ts        # F11: Recovery Code Rotation (5 tests)
│       │   ├── f12-did-web.test.ts         # F12: did:web Domain Wizard (5 tests)
│       │   ├── f13-lifecycle.test.ts       # F13: Export & Lifecycle Modals (5 tests)
│       │   ├── f14-modular-views.test.ts   # F14: Modular Views (5 tests)
│       │   ├── f15-http-verbs.test.ts      # F15: HTTP Verb Routing (5 tests)
│       │   ├── f16-spa-navigation.test.ts  # F16: Root SPA Shell & Nav (5 tests)
│       │   ├── f17-test-infra.test.ts      # F17: Test Infrastructure (5 tests)
│       │   ├── f18-opaque-e2e.test.ts      # F18: Opaque-Box E2E Verifications (5 tests)
│       │   └── f19-build-deploy.test.ts    # F19: Static Build & Deployment (5 tests)
│       ├── tier2-boundary/
│       │   ├── boundary-api-csrf.test.ts   # Edge cases: CSRF mismatches, Origin, malformed JSON
│       │   ├── boundary-webauthn-qr.test.ts # Edge cases: base64 padding, long TOTP labels, overflow
│       │   ├── boundary-stepup.test.ts     # Edge cases: expired step-up token, replay, receipts
│       │   ├── boundary-modals.test.ts     # Edge cases: long strings, rapid clicks, network drop
│       │   └── boundary-lifecycle.test.ts  # Edge cases: missing scopes, deleted user recovery
│       ├── tier3-combinations/
│       │   └── pairwise-interactions.test.ts # 19 Pairwise cross-feature combinatorial tests
│       └── tier4-scenarios/
│           └── real-world-journeys.test.ts   # 10 Real-world application user journeys
```

---

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| S1 | New User Security Hardening Journey | F1, F4, F6, F9, F10, F11, F14, F16 | High |
| S2 | Compromised Device Emergency Response | F1, F5, F6, F11, F14, F15 | High |
| S3 | BYO did:web Domain Identity Migration | F1, F5, F6, F12, F14 | High |
| S4 | Developer OAuth & App Passwords Lifecycle | F1, F5, F6, F8, F14, F15 | High |
| S5 | Full Data Portability & GDPR Export | F1, F5, F6, F13, F14 | Medium |
| S6 | Multi-Factor Step-Up Cascade Under High Security | F1, F5, F6, F9, F10, F15 | High |
| S7 | Session Expiry & Seamless Re-Authentication | F1, F4, F5, F6, F16 | Medium |
| S8 | Lost Factor Emergency Recovery with Backup Codes | F1, F6, F10, F11, F14 | High |
| S9 | CSRF and CSP Cross-Site Attack Defense | F1, F3, F7, F15, F16 | High |
| S10 | Account Lifecycle Termination & Deletion Confirmation | F1, F5, F6, F7, F13, F14, F15 | High |

---

## Coverage Thresholds
- **Tier 1**: ≥5 per feature (95 tests across 19 features)
- **Tier 2**: ≥5 per feature area (95 tests covering boundaries, limits, CSRF, security violations)
- **Tier 3**: ≥19 pairwise interaction tests (covering all major feature intersections)
- **Tier 4**: ≥10 realistic application user journeys
- **Total Minimum Target**: ≥219 test cases, 100% pass rate.
