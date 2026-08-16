# Task 8 — remaining reference breadth and operations

Foundation: `884b92fd`.

This lane adds storage-neutral, bounded seams for PLC identity updates,
repository import and sync enumeration, operator lifecycle audit, moderation
delivery, identifier-free metrics/readiness, and disposable backup/restore/key
rotation drills. These seams are not router registration and do not claim
production availability. The capability matrix is the adjacent generated
`task-8-reference-parity-manifest.json`; entries retain `registered: false`
until the integration owner supplies route assembly.

Local evidence:

```
Scripts/test-task8-disposable-drills.sh  # pass
```

Focused Swift tests cover bounded cursor pages, missing-blob deduplication,
import preflight before commit, step-up-gated PLC delegation, operator audit
redaction, moderation peer/path pinning and redaction, and identifier-free
metrics/readiness. Exact Swift results are recorded only after a fresh run.

Unexecuted gates: official client flows, reference-network interop,
browser/Playwright, Linux x86_64 pinned-toolchain, deployment/startup, and any
production or relay operation. No secrets, network activation, push, or
deployment was performed.
