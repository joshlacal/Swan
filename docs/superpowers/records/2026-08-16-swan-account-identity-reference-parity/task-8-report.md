# Task 8 — remaining reference breadth and operations

Foundation: `884b92fd`.

This lane adds storage-neutral, bounded seams for PLC identity updates,
repository import and sync enumeration, operator lifecycle audit, moderation
delivery, identifier-free metrics/readiness, and disposable backup/restore/key
rotation contracts. These seams are not router registration and do not claim
production availability. The capability matrix is the adjacent generated
`task-8-reference-parity-manifest.json`; entries retain `registered: false`
until the integration owner supplies route assembly.

Local evidence:

```
Scripts/test-task8-disposable-drills.sh  # deferred (integration seam unavailable)
```

Focused Swift tests cover bounded cursor pages, createdAt-key+DID keyset
ordering, account-bound missing-blob store enumeration, import digest/signature
preflight before commit, and the explicit full-CAR/MST verifier seam. Import remains
`assembled: false` until a durable full verifier is injected; the in-memory
CAS committer is only a conformance model. PLC step-up, operator authorization
verification, audit-on-success, moderation typed repoRef/strongRef subject and
details delivery over a trusted pinned transport with explicit `$type` subject
unions and typed output validation (`id`, `reasonType`, `subject`,
`reportedBy`, `createdAt`), plus versioned keyed HMAC log correlations. HMAC is
not claimed to redact public values. Runtime health/metrics and route
registration remain deferred.

The focused Swift suite was not rerun in this correction: the shared disk was
under the serialized onboarding rebuild budget. Changed sources and focused
test files were syntax-parsed successfully; consolidated integration
verification remains deferred.

Backup/restore and key-rotation drills are also explicitly deferred because
this lane does not own the storage-integrated encryption and key-store seams;
the disposable scripts perform no fake cryptographic success claim.

Unexecuted gates: official client flows, reference-network interop,
browser/Playwright, Linux x86_64 pinned-toolchain, deployment/startup, and any
production or relay operation. No secrets, network activation, push, or
deployment was performed.
