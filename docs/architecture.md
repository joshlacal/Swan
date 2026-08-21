# Swan Modular Architecture & Component Overview

Swan is a Swift-native AT Protocol Personal Data Server (PDS) and permissioned-data interoperability engine built for extreme protocol fidelity, cryptographic correctness, strict data isolation, and crash resilience. It is developed on Swift 6 with Swift Concurrency and runs on the Hummingbird 2 server framework.

```mermaid
flowchart TB
    subgraph Ingress ["Public Ingress & Reverse Proxy"]
        Client["Client / AppView / Relay / Browser"]
        Proxy["Reverse Proxy (Caddy / Nginx)"]
        Client -->|TLS 1.3 / HTTPS / WSS| Proxy
    end

    subgraph SwanHTTPRuntime ["Swan Hummingbird 2 Runtime (Port 3000)"]
        Router["Hummingbird 2 Router\n(Strict Phase Registration)"]
        CORS["SwanCORSMiddleware\n(Origin, Headers, Methods)"]
        Admission["Body Admission & Limiter\n(16KB JSON / 2MB Blob Stream)"]
        
        Proxy -->|HTTP/1.1 / WS| Router
        Router --> CORS
        CORS --> Admission
        
        subgraph Subsystems ["Core Service Subsystems"]
            OAuthSubsys["OAuth 2.1 & DPoP Engine\n(RFC 9449, RFC 9126 PAR, JAR)"]
            RepoSubsys["Public Repository Engine\n(MST, Signed Commits, CAR v1)"]
            FirehoseSubsys["Public Firehose Sequencer\n(subscribeRepos, Diff CARs)"]
            SpaceSubsys["Permissioned Spaces Engine\n(LtHash, Delegations, Outbox)"]
            PortalSubsys["Account Portal & MFA Engine\n(WebAuthn, TOTP, SvelteKit SPA)"]
            LegacySubsys["Legacy Auth & App Passwords\n(createSession, AppView Proxy)"]
        end
        
        Admission --> Subsystems
    end

    subgraph StorageLayer ["Durable SQLite Dual-Plane Storage"]
        ControlDB[("control.sqlite (WAL)\nControl Plane: Accounts, Identity,\nSessions, OAuth, MFA, Outbox")]
        AccountDB[("<did>.sqlite (WAL)\nPer-Account Data Plane: Public Records,\nMST Blocks, Private Space Records")]
        FirehoseDB[("firehose.sqlite (WAL)\nFirehose Sequence, Frames, Diff CARs")]
        Blobs[("Blobs Directory\nContent-Addressed Public & Private Blobs")]
        KeysDir[("Keys Directory (0700)\nEncrypted Key Envelopes (AES-GCM / KEK)")]
    end

    Subsystems --> StorageLayer

    subgraph ManagementPlane ["Isolated Management Runtime (Loopback Port 3001)"]
        MgmtRouter["Management HTTP Router\n(Bearer Operator-Secret)"]
        MgmtOps["PLC Account Lifecycle\nPermanent Deletion & Tombstoning\nFirehose Sync Ingestion"]
        MgmtRouter --> MgmtOps
        MgmtOps --> StorageLayer
    end
```

---

## 1. Hummingbird 2 Server Runtime

Swan uses **Hummingbird 2** on top of **SwiftNIO** to achieve asynchronous, non-blocking HTTP and WebSocket processing with deterministic memory management and Swift 6 structured concurrency.

### Key Architectural Invariants
1. **Immutable Route Assembly:** Hummingbird 2 bakes middleware stacks and route handlers into the routing tree during startup. All routes must be registered before the `Application` instance is created (`SwanHTTP.buildRouter()`). Route additions after initialization are strictly forbidden and rejected.
2. **CORS Middleware Precedence:** `SwanCORSMiddleware` is attached as the very first middleware on the router. This guarantees that `OPTIONS` preflight requests for any registered path or 404 fallback receive proper CORS headers without falling into unhandled route exceptions.
3. **Bounded Request Body Admission:** All HTTP JSON write bodies are gated by `SwanRequestBodyAdmissionConfiguration` with strict size ceilings (16 KiB default for JSON payloads, 2 MiB for public blobs) to eliminate Denial of Service (DoS) attack vectors via unconstrained allocations.
4. **Graceful Service Lifecycle:** Background tasks (such as firehose sequencers, retention reapers, did:web revalidation workers, and SMTP outbox dispatchers) conform to `Service` or `CustomStringConvertible` lifecycle actors. When `SIGTERM` or `SIGINT` is received, the server stops accepting new connections, allows in-flight SQLite transactions to drain, and gracefully closes network listeners.

---

## 2. SQLite Dual-Plane Storage Architecture

Swan enforces a strict separation between the **control plane** and the **data plane** to isolate account metadata from repository data.

```mermaid
graph LR
    subgraph ControlPlane ["Control Plane (Shared)"]
        CDB[("control.sqlite\n- accounts\n- identity_bindings\n- mfa_factors\n- portal_sessions\n- oauth_tokens\n- outbox_deliveries")]
    end
    
    subgraph DataPlane ["Data Plane (Isolated Per-Account)"]
        ADB1[("did:plc:account1.sqlite\n- public_records\n- repo_mst_blocks\n- repo_commits\n- space_records\n- space_oplog")]
        ADB2[("did:plc:account2.sqlite\n- public_records\n- repo_mst_blocks\n- repo_commits\n- space_records\n- space_oplog")]
    end
    
    subgraph FirehosePlane ["Firehose Plane"]
        FDB[("firehose.sqlite\n- public_firehose_events\n- public_firehose_frames\n- public_firehose_diff_cars")]
    end
```

### Storage Principles
- **`control.sqlite`:** Owns global state including account identities (DIDs, handles), password hashes (Argon2id/bcrypt), MFA credentials, active OAuth client registrations, browser sessions, and cross-account delivery outboxes.
- **`<did>.sqlite`:** Every account has its own SQLite database file named after its canonical DID (e.g. `did:plc:12345678.sqlite`). It contains the user's public repository records, Merkle Search Tree (MST) nodes, signed commits, and private space operations.
- **`firehose.sqlite`:** Dedicated sequencer database storing the continuous monotonic event stream, event frames, and diff CARs.
- **Write-Ahead Logging (WAL):** All SQLite databases operate strictly in `WAL` mode with `PRAGMA synchronous = NORMAL` and `PRAGMA foreign_keys = ON`.
- **No Network I/O Inside Transactions:** Database transactions are kept microsecond-short. Network requests (PLC resolution, SMTP sends, OAuth JWKS fetches) are **never** executed while a SQLite transaction lock is held.
- **Compare-And-Swap (CAS) Correctness:** Mutations to repositories and sequences require explicit revision/CID compare-and-swap checks, preventing lost updates under concurrency.

---

## 3. OAuth 2.1 & DPoP Sender-Constrained Subsystem

Swan implements an OAuth 2.1 authorization server with mandatory sender-constraining via **DPoP (Demonstrating Proof-of-Possession at the Application Layer, RFC 9449)**.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant Client as AT Protocol Client / App
    participant AS as Swan OAuth AS (/oauth/*)
    participant RS as Swan Resource Server (/xrpc/*)

    Client->>AS: 1. POST /oauth/par (Signed Request, DPoP Proof)
    AS-->>Client: 2. 201 Created (request_uri, expires_in)
    
    Client->>User: 3. Redirect to /oauth/authorize?client_id=...&request_uri=...
    User->>AS: 4. GET /oauth/authorize (Interactive Login & Consent)
    AS-->>User: 5. Redirect to client redirect_uri with ?code=...
    
    Client->>AS: 6. POST /oauth/token (grant_type=authorization_code, code, code_verifier, DPoP Proof)
    AS-->>Client: 7. 200 OK (access_token, refresh_token, token_type=DPoP, sub=DID)
    
    Client->>RS: 8. POST /xrpc/com.atproto.repo.putRecord (Authorization: DPoP <token>, DPoP: <proof>)
    RS-->>Client: 9. 200 OK (Verified & Executed)
```

### Security & Protocol Features
- **Mandatory PAR (RFC 9126):** Clients must push authorization parameters to `/oauth/par` before directing the user agent to `/oauth/authorize`. Authorization parameters in query strings are rejected.
- **Sender-Constrained Tokens (RFC 9449):** Access and refresh tokens are bound to the client's ephemeral public key via DPoP proofs (using ES256). Intercepted bearer tokens cannot be replayed from other endpoints.
- **Server Nonce Enforcement:** Swan issues and rotates high-entropy server nonces to protect against proof replay.
- **Private Key JWT Client Authentication (RFC 7523):** Confidential clients authenticate using client assertions signed with their registered keys.
- **Dynamic Client Metadata Discovery:** Client configurations are fetched securely over HTTPS from `client_id` URLs with strict loopback/private IP blocking to prevent Server-Side Request Forgery (SSRF).
- **Fine-Grained Scope Resolution:** Supports `atproto`, `include:<nsid>`, `space:<type>`, and collection-scoped permissions with cryptographic lexicon validation.
### OAuth Browser Pages & Inlined Style Security
Swan's interactive OAuth browser surfaces—the sign-in page, client authorization consent, and second-factor MFA ceremony—are rendered by a unified HTML implementation in `Sources/SwanHTTP/SwanBrowserPages.swift` shared across both the production authorization server and localhost development endpoints.
- **Inlined daisyUI Stylesheet:** The markup is styled with daisyUI 5 (built on Tailwind CSS v4). The compiled CSS is embedded directly into `Sources/SwanHTTP/SwanBrowserStyleSheet.swift` and inlined into `<style>` tags on served pages, eliminating static asset routes and remote stylesheet requests during authentication.
- **Dynamic CSP Hash Derivation:** To enforce `default-src 'none'` without resorting to `'unsafe-inline'` or external style origins, `SwanBrowserPages.browserStyleCSPSource` derives a SHA-256 base64 digest of the exact inlined stylesheet string at runtime. Hummingbird injects this hash as `style-src 'sha256-…'` in the response `Content-Security-Policy` header. Per-response nonces (`script-src 'nonce-…'`) protect inline WebAuthn ceremony scripts.
- **Stylesheet Build Process:** The stylesheet is tree-shaken against class names in `Sources/SwanHTTP/SwanBrowserPages.swift` and `Sources/SwanHTTP/ScopeDescription.swift`. Whenever class names in either file are modified, `Scripts/build-browser-css.sh` must be executed to regenerate `SwanBrowserStyleSheet.swift`.
- **System Theme Adaptation:** Pages declare `<meta name="color-scheme" content="light dark">` and utilize semantic daisyUI theme variables (`bg-base-200`, `text-base-content`, `card bg-base-100`), automatically adapting to the user's `prefers-color-scheme` setting.

---

## 4. Public Firehose & Repository Engine

The public repository engine is a complete, native AT Protocol repository implementation featuring Merkle Search Trees (MST) and real-time streaming.

```mermaid
graph TD
    Commit["Repository Commit\n(Signed via K-256 / secp256k1)"]
    MST["Merkle Search Tree (MST)\nDeterministic Binary Key-Path Trie"]
    Records["Record Blocks (CBOR / CIDv1)"]
    Outbox["Outbox Staging Table\n(Atomic with Commit)"]
    Sequencer["Public Firehose Sequencer\n(Assigns Monotonic Sequence)"]
    Streamer["WebSocket Streamer\n(/xrpc/com.atproto.sync.subscribeRepos)"]
    Reaper["Firehose Retention Reaper\n(72h / 1M rows / 1GB cap)"]

    Commit --> MST
    MST --> Records
    Commit -.->|Atomic Commit| Outbox
    Outbox --> Sequencer
    Sequencer --> FirehoseDB[("firehose.sqlite")]
    FirehoseDB --> Streamer
    FirehoseDB --> Reaper
```

### Engine Components
- **Deterministic MST:** Records are organized in deterministic CBOR-encoded Merkle Search Trees, enabling cryptographic proof of inclusion/exclusion and compact CAR generation.
- **Secp256k1 Commit Signing:** Every commit is cryptographically signed by the account's repository signing key, verifiable against the account's DID document or PLC directory history.
- **Monotonic Sequencer:** Events (`#commit`, `#sync`, `#identity`, `#account`, `#info`) receive contiguous, gap-free 64-bit integer sequence IDs stored in `firehose.sqlite`.
- **Diff CAR Packaging:** Firehose commit events carry minimal diff CAR slices containing only newly created/modified blocks, minimizing network overhead.
- **Subscriber Connection Budgeting:** Connection quotas reserve 75% of available capacity for standard API calls and assign a dedicated 25% quota for firehose WebSocket consumers (`PublicFirehoseSubscriberAdmission`).
- **Configurable Retention Reaper:** Automatically reaps expired firehose entries based on age (default: 72h), row count (default: 1,000,000), or byte limits (default: 1 GiB).

### Public Identity & Foreign Handle Resolution
The AT Protocol endpoint `com.atproto.identity.resolveHandle` resolves user handles to canonical DIDs. By default, Swan answers exclusively for accounts locally provisioned in `control.sqlite`. Queries for third-party handles return an immediate `InvalidRequest` error without contacting the network.

Passing `--enable-foreign-handle-resolution` (default off) enables Swan to resolve external handles across the network:
- **Pinned Verification Engine:** External handles are resolved using the same verified DNS TXT record (`_atproto.<handle>`) and HTTPS `/.well-known/atproto-did` mechanisms that validate `did:web` identity documents.
- **Network Boundary & SSRF Defense:** This flag is the sole mechanism that allows the anonymous `resolveHandle` endpoint to initiate outbound network traffic. Before any DNS query or HTTP connection is initiated, the resolver verifies the target domain against strict SSRF rules, immediately rejecting reserved TLDs and non-public IP address ranges.
- **Deduplicated In-Memory Caching:** Resolved DIDs are cached in memory for 5 minutes (300 seconds), while failed resolutions are cached for 30 seconds to mitigate denial-of-service amplification. Concurrent requests for the same handle share a single in-flight resolution task.
- **Reference PDS Divergence:** Reference PDS implementations (such as `bsky.social`) answer foreign handle queries with HTTP 200 and the resolved DID by default. Swan defaults to rejecting unhosted handles with `InvalidRequest` unless foreign handle resolution is explicitly enabled by the operator.

---

## 5. MFA & WebAuthn / Passkey Subsystem

Swan provides enterprise-grade multi-factor authentication built directly into the account portal and OAuth authorization workflows.

```mermaid
flowchart TD
    LoginReq["User Enters Handle & Password"]
    VerifyPassword{"Password Valid?"}
    CheckMFA{"MFA Enrolled?"}
    IssueSession["Issue Authenticated Session Cookie"]
    PromptMFA["Issue Pre-Auth Challenge\nReturn Required Factor Kinds"]
    
    LoginReq --> VerifyPassword
    VerifyPassword -- No --> Reject["401 Unauthorized"]
    VerifyPassword -- Yes --> CheckMFA
    CheckMFA -- No --> IssueSession
    CheckMFA -- Yes --> PromptMFA
    
    PromptMFA --> SelectFactor{"Select MFA Factor"}
    SelectFactor -->|FIDO2 Passkey| WebAuthn["WebAuthn Assertion\n(ES256/RS256 Challenge Verification)"]
    SelectFactor -->|TOTP Code| TOTP["TOTP (RFC 6238)\n30s Time Window Verification"]
    SelectFactor -->|Recovery Code| RecCode["Recovery Code\n(Argon2id Salted Hash Check)"]
    
    WebAuthn --> VerifyFactor{"Factor Valid?"}
    TOTP --> VerifyFactor
    RecCode --> VerifyFactor
    
    VerifyFactor -- Yes --> IssueSession
    VerifyFactor -- No --> RejectMFA["403 Forbidden"]
```

### Supported Factor Kinds
1. **WebAuthn / FIDO2 Passkeys:** Hardware security keys (YubiKey, Apple Touch ID/Face ID, Windows Hello) using standard W3C WebAuthn Level 3 assertions.
2. **TOTP (RFC 6238):** Standard time-based one-time passwords with SHA-1 HMAC and 30-second windows.
3. **Backup Recovery Codes:** Salted and cryptographically hashed one-time recovery codes for account salvage.
4. **Step-Up Authentication:** High-risk actions (modifying credentials, generating app passwords, account deletion) require interactive re-authentication or biometric step-up challenges resulting in single-use `stepUpReceipt` tokens.

---

## 6. SvelteKit Static Portal & Management Service

Swan includes an integrated account management interface built with SvelteKit.

- **Static Pre-Rendering & Build:** The account portal is implemented as a SvelteKit single-page application under `web/`. It is compiled in container environments by the Dockerfile's `account-web-build` stage (`FROM node:22-bookworm-slim ... AS account-web-build`) and copied to `/usr/local/share/swan/account` in the runtime image (configurable via `--account-portal-directory`).
- **Hummingbird Asset Handler:** Hummingbird serves `/account/**` SPA routes with secure headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`).
- **daisyUI Component Styling:** The portal interface is built using daisyUI components, sharing visual tokens with the server-rendered OAuth browser pages. Standalone static CSS files such as `web/static/auth-tokens.css` and the `/account/auth-tokens.css` route have been removed in favor of the unified build.
- **Session Security:**
  - `__Host-swan-session`: `HTTPOnly`, `Secure`, `SameSite=Lax` cookie storing cryptographically signed session identifiers.
  - `__Host-swan-csrf`: Anti-CSRF token validated via double-submit header checks (`X-Swan-CSRF`).
  - Strict pre-auth isolation prevents unauthenticated users from accessing any account data before factor verification.
---

## 7. Permissioned Data / Spaces Subsystem

Swan's permissioned-data plane provides structured collaboration spaces with cryptographic auditability without placing sensitive data into the public AT Protocol firehose.

- **LtHash Cryptographic Accumulator:** Uses additively homomorphic hashing (LtHash16) to maintain an incremental commitment over repository state.
- **Reader-Bound Commits:** Commit signatures bind the space author, space identifier, revision, and reader context.
- **Delegation & Space Credentials:** Space authorities issue short-lived, single-use delegation tokens that are exchanged for read-only space credentials.
- **Durable Outbox Delivery:** Peer-pinned notification workers ensure at-least-once notification delivery to remote space members and authorities across network interruptions and daemon restarts.

---

## 8. AppView Proxying & Scoped App Passwords

- **Legacy App Passwords:** Enables third-party AT Protocol clients that do not yet support OAuth 2.1 to authenticate via `com.atproto.server.createSession` using scoped, revocable app passwords.
- **Transparent AppView Proxying:** Unmatched `app.bsky.*` read queries are proxied upstream to the official Bluesky AppView (`https://api.bsky.app`) with minted service-auth JWTs, providing complete feed and social graph access out of the box.

### XRPC Proxy Routing & Namespace Admission
The XRPC proxy router (`SwanXRPCProxyRouter`) transparently routes unsupported XRPC endpoints to upstream AT Protocol services while safeguarding local state.

- **Namespace-Based Admission:** Method admission is decided strictly by namespace prefix (`app.bsky.`, `chat.bsky.`, `tools.ozone.`) and exact moderation methods (`com.atproto.moderation.createReport`, `com.atproto.label.queryLabels`), rather than membership in the generated method registry. Because the generated method registry reflects a static lexicon pin that lags behind upstream releases, gating on registry membership previously caused published upstream methods (such as `chat.bsky.convo.getUnreadCounts` and `app.bsky.video.*`) to return unexpected 404 errors.
- **Protected Local State:** Swan-owned namespaces (`com.atproto.space.`, `blue.catbird.`) and local state methods within proxyable namespaces (`app.bsky.actor.getPreferences`, `app.bsky.actor.putPreferences`) are denied and never forwarded upstream.
- **Destination Routing via `atproto-proxy`:**
  - When the client includes an `atproto-proxy` header (`did:web:...#service_id`), the proxy resolves the target service endpoint and admits any method within the allowable namespaces. Methods in `chat.bsky.*` and `tools.ozone.*` require this header.
  - When no `atproto-proxy` header is present, the proxy admits only the configured AppView's own namespace (`app.bsky.*`) and forwards requests directly to the configured upstream AppView (`--appview-url` / `--appview-did`). Requests for other namespaces without an explicit destination header fail closed with HTTP 404 (unrouted).

### Operator Diagnostics & Failure Observability
To ensure diagnostic traceability for authentication and proxy failures without leaking credentials or violating timing invariants, Swan emits structured log events:
- **`legacy createSession rejected`:** Emitted when legacy authentication on `com.atproto.server.createSession` fails. To prevent account enumeration, client responses remain constant-time opaque errors. The log entry includes a fixed-vocabulary `stage` parameter (`identifier_unresolved`, `no_credential_matched`, `auth_factor_token_required`, `rate_limited`, `malformed_request`, `token_rejected`, `unavailable`) and a `factorToken` descriptor (`absent`, `empty`, or `present`). No identifiers, passwords, or token strings are recorded. This allows operators to distinguish wrong-password attempts from clients sending empty or misconfigured second-factor tokens.
- **`xrpc pipethrough upstream failed`:** Emitted when an outbound HTTP request to an upstream service (such as the AppView or an `atproto-proxy` target) fails. While clients receive a generic HTTP 502 Bad Gateway response, the log records `nsid` (the requested XRPC method), `host` (the target upstream host), and `reason` (the underlying transport failure, such as DNS lookup errors, connection timeouts, or TLS handshakes). Minted service authentication JWTs are never logged.
