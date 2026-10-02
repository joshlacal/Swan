# Swan API and protocol reference

Swan exposes four distinct HTTP surfaces across two network listeners:

1. **Public XRPC Surface**: Mounted under `/xrpc/` on the public listener (default port `3000`). Serves standard AT Protocol XRPC methods, local permissioned space extensions, and transparent AppView proxying.
2. **OAuth 2.1 Authorization Server**: Mounted under `/.well-known/` and `/oauth/` on the public listener (default port `3000`). Implements RFC 8414 discovery, RFC 9126 Pushed Authorization Requests (PAR), interactive authorization, DPoP-constrained token exchange, and RFC 7009 token revocation.
3. **Account Portal REST API**: Mounted under `/account/api/` on the public listener (default port `3000`). Drives the self-service web portal for credential management, multi-factor authentication (MFA/WebAuthn), scoped app passwords, `did:web` bindings, and data export.
4. **Loopback Management REST API**: Mounted under `/v1/` on a dedicated loopback-only listener (default `127.0.0.1:3001`). Provides administrative controls for account lifecycle state, PLC genesis provisioning, and manual firehose synchronisation.

---

## Public XRPC surface

All XRPC endpoints are mounted under `/xrpc/`. Responses use JSON encoding with `Cache-Control: no-store` unless explicitly noted as binary CAR or blob streams.

### Server discovery and metadata

#### `com.atproto.server.describeServer`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: None
- **Returns**: JSON object containing `did` (service DID, e.g. `did:web:example.com`), `availableUserDomains` (array of supported domain suffixes), `inviteCodeRequired` (boolean, always `false` in standard Swan builds), and `swanProfile` (active permissioned profile ID, e.g. `permissioned-data-0016-2026-10-01`).

#### `community.lexicon.service.describe`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: None
- **Returns**: JSON object containing `roles: ["pds"]` and `methods: [ { "$type": "community.lexicon.service.describe#nsid", "value": "<nsid>" } ]`. Enumerates all XRPC method NSIDs served locally by the active configuration.

#### `com.atproto.identity.resolveHandle`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameter `handle` (string, required).
- **Returns**: JSON object `{ "did": "did:..." }`. Resolves local account handles against `control.sqlite`.

---

### Public repository reads

Public read endpoints enforce bounded concurrency and memory admission via `SwanRequestBodyAdmissionConfiguration`.

#### `com.atproto.repo.describeRepo`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameter `repo` (DID or handle, required).
- **Returns**: JSON object containing `handle`, `did`, `didDoc`, `collections` (array of NSIDs present in repository), and `handleIsCorrect` (boolean).

#### `com.atproto.repo.getRecord`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameters `repo` (DID or handle, required), `collection` (NSID, required), `rkey` (record key string, required), `cid` (CID string, optional).
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "value": { ... } }`.

#### `com.atproto.repo.listRecords`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameters `repo` (DID or handle, required), `collection` (NSID, required), `limit` (integer 1–100, default 50), `cursor` (string, optional), `reverse` (boolean, default `false`).
- **Returns**: JSON object `{ "records": [ { "uri": "...", "cid": "...", "value": { ... } } ], "cursor": "..." }`.

---

### Public repository mutations

All mutation endpoints require authentication and enforce granular scope authorization matching AT Protocol repository action semantics.

#### `com.atproto.repo.createRecord`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT (requires scope for `create` action on target collection).
- **Request Body**: JSON object `{ "repo": "did:...", "collection": "nsid", "record": { ... }, "rkey": "...", "validate": true, "swapCommit": "cid" }`.
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "commit": { "cid": "...", "rev": "..." }, "validationStatus": "valid" }`.

#### `com.atproto.repo.putRecord`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT (requires scope for both `create` and `update` actions on target collection).
- **Request Body**: JSON object `{ "repo": "did:...", "collection": "nsid", "rkey": "...", "record": { ... }, "validate": true, "swapRecord": "cid", "swapCommit": "cid" }`.
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "commit": { "cid": "...", "rev": "..." }, "validationStatus": "valid" }`.

#### `com.atproto.repo.deleteRecord`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT (requires scope for `delete` action on target collection).
- **Request Body**: JSON object `{ "repo": "did:...", "collection": "nsid", "rkey": "...", "swapRecord": "cid", "swapCommit": "cid" }`.
- **Returns**: JSON object `{ "commit": { "cid": "...", "rev": "..." } }`.

#### `com.atproto.repo.applyWrites`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT (requires matching scopes for each create, update, or delete operation in the batch).
- **Request Body**: JSON object `{ "repo": "did:...", "writes": [ ... ], "validate": true, "swapCommit": "cid" }`.
- **Returns**: JSON object `{ "commit": { "cid": "...", "rev": "..." }, "results": [ ... ] }`.

#### `com.atproto.repo.uploadBlob`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT (requires blob upload permission).
- **Request Body**: Raw binary octets (`*/*`) with `Content-Type` header (max default size 2 MiB, admitted through streaming spool).
- **Returns**: JSON object `{ "blob": { "$type": "blob", "ref": { "$link": "<cid>" }, "mimeType": "...", "size": 12345 } }`.

---

### Synchronization and firehose

#### `com.atproto.sync.subscribeRepos`
- **Method**: `GET` (HTTP/1.1 WebSocket Upgrade)
- **Authentication**: None
- **Parameters**: Query parameter `cursor` (integer sequence number, optional).
- **Returns**: WebSocket binary stream of CBOR-encoded frame objects (`#commit`, `#identity`, `#account`, `#sync`, `#tombstone`). Uses auto-ping liveness with a 4 KiB inbound frame limit.

#### `com.atproto.sync.getLatestCommit`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameter `did` (DID string, required).
- **Returns**: JSON object `{ "cid": "...", "rev": "..." }`.

#### `com.atproto.sync.getRepoStatus`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameter `did` (DID string, required).
- **Returns**: JSON object `{ "did": "did:...", "active": true, "status": "active", "rev": "..." }`.

#### `com.atproto.sync.getRepo`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameter `did` (DID string, required). Parameter `since` is not supported and is rejected with `400 InvalidRequest`.
- **Returns**: Complete repository export as a verified CAR v1 binary stream (`application/vnd.ipld.car`).

#### `com.atproto.sync.getBlob`
- **Method**: `GET`
- **Authentication**: None
- **Parameters**: Query parameters `did` (DID string, required), `cid` (CID string, required).
- **Returns**: Raw content-addressed binary bytes with original MIME `Content-Type`.

---

### Legacy session and app password management

Legacy session management implements password and app password authentication for clients that do not support OAuth 2.1.
The read-only `getSession` and `getServiceAuth` routes also accept OAuth DPoP access tokens. These requests require a matching DPoP proof; a nonce challenge returns `401 use_dpop_nonce` with a `DPoP-Nonce` header.
Missing, invalid, or expired resource nonces receive a fresh challenge. Clients retry with the returned nonce and a newly signed DPoP proof; successful token exchange or re-login does not renew a cached resource nonce.

#### `com.atproto.server.createSession`
- **Method**: `POST`
- **Authentication**: Password or App Password in request body.
- **Request Body**: JSON object `{ "identifier": "<handle-or-email>", "password": "<password>", "authFactorToken": "<totp-code-optional>" }`.
- **Returns**: JSON object containing `did`, `handle`, `email`, `emailConfirmed`, `accessJwt`, `refreshJwt`, `active`, and `status`.

#### `com.atproto.server.refreshSession`
- **Method**: `POST`
- **Authentication**: `Authorization: Bearer <refreshJwt>`.
- **Request Body**: Empty.
- **Returns**: JSON object with rotated `accessJwt` and `refreshJwt`.

#### `com.atproto.server.getSession`
- **Method**: `GET`
- **Authentication**: OAuth DPoP access token and proof, or `Authorization: Bearer <accessJwt>`.
- **Parameters**: None.
- **Returns**: JSON object containing account status and metadata (`did`, `handle`, `email`, `emailConfirmed`, `active`).

#### `com.atproto.server.getServiceAuth`
- **Method**: `GET`
- **Authentication**: OAuth DPoP access token and proof, or `Authorization: Bearer <accessJwt>`. The grant must permit the exact downstream `aud` and `lxm`.
- **Parameters**: Query parameters `aud` (service DID or DID service reference, required), `exp` (bounded integer expiry timestamp, optional), `lxm` (lexicon method NSID, required).
- **Returns**: JSON object `{ "token": "<signed-inter-service-jwt>" }`.

#### `com.atproto.server.deleteSession`
- **Method**: `POST`
- **Authentication**: `Authorization: Bearer <refreshJwt>`.
- **Request Body**: Empty.
- **Returns**: 200 OK empty response. Revokes the session.

App password management is deliberately **not** available over XRPC. All three
methods below are registered so that they fail closed with a stable
`403 request_not_allowed` for both `GET` and `POST`, rather than falling
through to a bare bearer check or to the upstream proxy.

Each method requires an authenticated management session cookie plus a fresh
step-up receipt. XRPC never carries management cookies, so no XRPC request can
satisfy that requirement. Manage app passwords through the account portal
instead; see the account portal REST API section.

#### `com.atproto.server.createAppPassword`
- **Method**: `POST`, `GET`
- **Authentication**: Not satisfiable over XRPC.
- **Returns**: `403` with body `{ "error": "request_not_allowed" }`.

#### `com.atproto.server.listAppPasswords`
- **Method**: `POST`, `GET`
- **Authentication**: Not satisfiable over XRPC.
- **Returns**: `403` with body `{ "error": "request_not_allowed" }`.

#### `com.atproto.server.revokeAppPassword`
- **Method**: `POST`, `GET`
- **Authentication**: Not satisfiable over XRPC.
- **Returns**: `403` with body `{ "error": "request_not_allowed" }`.

---

### Account email and password management

#### `com.atproto.server.createAccount`
- **Method**: `POST`
- **Authentication**: None (governed by signup policy: open, invite, or closed; admits optional Turnstile token, invite code, or email proof).
- **Request Body**: JSON object `{ "handle": "...", "password": "...", "email": "...", "inviteCode": "...", "turnstileToken": "..." }`.
- **Returns**: JSON object `{ "did": "did:...", "handle": "...", "accessJwt": "", "refreshJwt": "" }`.

#### `com.atproto.server.requestPasswordReset`
- **Method**: `POST`
- **Authentication**: None
- **Request Body**: JSON object `{ "email": "user@example.com" }`.
- **Returns**: 200 OK empty response (timing-equalized to prevent email enumeration). Emits recovery email token to transactional outbox.

#### `com.atproto.server.resetPassword`
- **Method**: `POST`
- **Authentication**: Reset token from email.
- **Request Body**: JSON object `{ "token": "<recovery-token>", "password": "<new-password>" }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.server.requestEmailConfirmation`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT.
- **Request Body**: Empty.
- **Returns**: 200 OK empty response. Dispatches confirmation email token.

#### `com.atproto.server.confirmEmail`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT.
- **Request Body**: JSON object `{ "email": "user@example.com", "token": "<confirmation-token>" }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.server.requestEmailUpdate` and `com.atproto.server.updateEmail`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT.
- **Returns**: `403 Forbidden` (`accountEmailError(.forbidden)`).
- **Operational Note**: Swan intentionally refuses email mutation over public XRPC. All email modifications must be performed via the authenticated Account Portal with step-up verification.

---

### Actor preferences

Actor preferences are managed as local PDS state and are explicitly denied from AppView proxy forwarding.

#### `app.bsky.actor.getPreferences`
- **Method**: `GET`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT.
- **Parameters**: None.
- **Returns**: JSON object `{ "preferences": [ { "$type": "...", ... } ] }`.

#### `app.bsky.actor.putPreferences`
- **Method**: `POST`
- **Authentication**: OAuth 2.1 DPoP token or Legacy Bearer JWT.
- **Request Body**: JSON object `{ "preferences": [ ... ] }`.
- **Returns**: 200 OK empty response.

---

### Deliberately unserved or divergent XRPC endpoints

Swan intentionally closes or does not implement several reference PDS XRPC endpoints. Requests to these endpoints return structured `404 Not Found` (`public_endpoint_unavailable`) or `400 Bad Request`:

| NSID | Expected method | Public status | Canonical alternative in Swan |
|---|---|---|---|
| `com.atproto.server.deleteAccount` | `POST` | `404 Not Found` | Loopback management API (`POST /v1/accounts/delete`) or Account Portal (`POST /account/api/lifecycle/delete`). |
| `com.atproto.server.createInviteCode` | `POST` | `404 Not Found` | Not implemented. Swan does not issue runtime invite codes. |
| `com.atproto.server.getAccountInviteCodes` | `GET` | `404 Not Found` | Not implemented. |
| `com.atproto.server.reserveSigningKey` | `POST` | `404 Not Found` | Loopback management API (`POST /v1/accounts/plc/prepare`) or Account Portal. |
| `com.atproto.identity.updateHandle` | `POST` | `404 Not Found` | Account Portal (`POST /account/api/identity/*`) or Loopback management API. |
| `com.atproto.repo.listMissingBlobs` | `GET` | `404 Not Found` | Not implemented. |
| `com.atproto.sync.getRecord` | `GET` | `404 Not Found` | Use `com.atproto.repo.getRecord`. |
| `com.atproto.sync.getBlocks` | `GET` | `404 Not Found` | Use `com.atproto.sync.getRepo` for complete CAR exports. |
| `com.atproto.sync.listBlobs` | `GET` | `404 Not Found` | Public sync listBlobs is not served; permissioned space sync provides `com.atproto.space.listBlobs`. |
| `com.atproto.sync.listRepoOps` | `GET` | `404 Not Found` | Public sync listRepoOps is not served; permissioned space sync provides `com.atproto.space.listRepoOps`. |
| `com.atproto.sync.getHostStatus` | `GET` | `404 Not Found` | Use `/health` or `describeServer`. |
| `com.atproto.sync.getBlobLimit` | `GET` | `404 Not Found` | Not implemented. |
| `com.atproto.space.getSpace` | `GET` | `404 Not Found` | Use `com.atproto.simplespace.getSpace`. |

---

## XRPC proxy routing and admission rules

When an inbound request under `/xrpc/**` matches no exact local route, Swan evaluates it through `SwanXRPCProxyRouter` (`Sources/SwanHTTP/SwanXRPCProxyRouting.swift`).

### Routing admission logic

1. **Deny-list check**: Prefixes `com.atproto.space.` and `blue.catbird.` and exact NSIDs `app.bsky.actor.getPreferences` and `app.bsky.actor.putPreferences` are always denied with `403/404` and never leave the host.
2. **Proxy header presence (`atproto-proxy`)**:
   - If an `atproto-proxy: <did>#<service-id>` header is present, the NSID must match the proxyable namespace allow-list:
     - Namespaces: `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*`
     - Exact NSIDs: `com.atproto.moderation.createReport`, `com.atproto.label.queryLabels`
   - If the header targets the configured AppView DID and fragment, the request is forwarded directly to the configured endpoint. Otherwise, the destination DID document is resolved via HTTPS.
3. **No proxy header (default route)**:
   - Only requests with the `app.bsky.*` prefix are forwarded to the configured AppView (`appViewDID`). All other namespaces return `404 Not Found`.

---

## Permissioned spaces plane

Swan implements the `permissioned-data-0016-2026-10-01` profile for access-controlled collaborative data spaces. All endpoints are mounted under `/xrpc/`. Space references are `at://` URIs, not bare DIDs. Policy and app-access values are tagged union objects with a lexicon `$type`, not strings.

### Space lifecycle and membership (`com.atproto.simplespace.*`)

#### `com.atproto.simplespace.createSpace`
- **Method**: `POST`
- **Authentication**: Account OAuth DPoP.
- **Request Body**: JSON object with required `type` (space-type NSID), `readPolicy`, `writePolicy`, and `appAccess`; optional `skey` (record key). The authenticated account is the authority; do not send a `did` field.
- **Returns**: JSON object `{ "uri": "<space-ref>" }`.

#### `com.atproto.simplespace.getSpace`
- **Method**: `GET`
- **Authentication**: OAuth or a space credential; the caller must be authorized for the space.
- **Parameters**: Query parameter `space` (space reference, required).
- **Returns**: JSON object with `uri`, `readPolicy`, `writePolicy`, and `appAccess`. Use `listMembers` for the member roster.

#### `com.atproto.simplespace.updateSpace`
- **Method**: `POST`
- **Authentication**: Space Owner.
- **Request Body**: JSON object `{ "space": "<space URI>", "readPolicy": <policy (optional)>, "writePolicy": <policy (optional)>, "appAccess": <access (optional)> }` — each policy updates independently; omitted policies are preserved.
- **Returns**: 200 OK empty response.

#### `com.atproto.simplespace.deleteSpace`
- **Method**: `POST`
- **Authentication**: Space Owner.
- **Request Body**: JSON object `{ "space": "<space-ref>" }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.simplespace.putMember`
- **Method**: `POST`
- **Authentication**: Space Owner.
- **Request Body**: JSON object `{ "space": "<space-ref>", "did": "<member DID>", "read": true|false, "write": true|false }` (all fields required; both flags replaced atomically).
- **Returns**: 200 OK empty response.

#### `com.atproto.simplespace.removeMember`
- **Method**: `POST`
- **Authentication**: Space Owner.
- **Request Body**: JSON object `{ "space": "<space-ref>", "did": "<member DID>" }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.simplespace.listMembers`
- **Method**: `GET`
- **Authentication**: Owner OAuth on the authority's PDS, with a covering read grant. A space credential is not sufficient.
- **Parameters**: Query parameters `space` (space reference, required), `cursor` (optional), `limit` (integer, 1–1000; default 100).
- **Returns**: JSON object `{ "members": [ { "did": "...", "read": true, "write": false } ], "cursor": "..." }`.

#### `com.atproto.simplespace.checkUserAccess`
- **Method**: `GET`
- **Authentication**: Service JWT.
- **Parameters**: Query parameters `space` (space reference, required), `user` (user DID, required), `access` (`read` or `write`, required), `clientId` (optional; must be omitted for `access=write`).
- **Returns**: JSON object `{ "authorized": true|false }`.

---

### Space delegation and credentials (`com.atproto.space.*`)

#### `com.atproto.space.listSpaces`
- **Method**: `GET`
- **Authentication**: Account Auth.
- **Parameters**: None.
- **Returns**: JSON object `{ "spaces": [ { "space": "did:...", "name": "...", "role": "..." } ] }`.

#### `com.atproto.space.getDelegationToken`
- **Method**: `GET`
- **Authentication**: Account Auth.
- **Parameters**: Query parameter `space` (space reference, required). A covering account OAuth `read` grant is required; `read_self` does not permit delegation.
- **Returns**: JSON object `{ "token": "<delegation-token-jwt>" }`.

#### `com.atproto.space.getSpaceCredential`
- **Method**: `POST`
- **Authentication**: `Authorization: Bearer <delegation-token>` plus a `DPoP` proof signed by the key to bind to the resulting credential. This initial proof omits `ath`; space credential proofs do not use server nonces.
- **Request Body**: JSON object `{ "space": "<space-ref>", "clientAttestation": "<optional-attestation-jwt>" }`. An attestation is required when the space gates access on client identity.
- **Returns**: JSON object `{ "credential": "<space-read-credential>" }`; the JWT carries the signing key thumbprint in `cnf.jkt`. Deleted spaces return `SpaceDeleted`.

Use the credential with `Authorization: DPoP <credential>` and a fresh `DPoP` proof on every space request. The proof binds the credential through `ath`, the HTTP method through `htm`, and the origin and path (without query or fragment) through `htu`. Bearer space credentials are rejected. Credentials remain read-only at repository hosts; writes use the account's OAuth grant.

---

### Space records and repository operations (`com.atproto.space.*`)

#### `com.atproto.space.getRecord`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `repo` (required), `collection` (required), `rkey` (required), `cid` (optional).
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "value": { ... } }`.

#### `com.atproto.space.listRecords`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `repo` (required), `collection` (required), `limit` (optional), `cursor` (optional), `reverse` (optional).
- **Returns**: JSON object `{ "records": [ ... ], "cursor": "..." }`.

#### `com.atproto.space.createRecord`
- **Method**: `POST`
- **Authentication**: Space OAuth or Writer Credential.
- **Request Body**: JSON object `{ "space": "did:...", "repo": "did:...", "collection": "nsid", "record": { ... } }`.
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "commit": { ... } }`.

#### `com.atproto.space.putRecord`
- **Method**: `POST`
- **Authentication**: Space OAuth or Writer Credential.
- **Request Body**: JSON object `{ "space": "did:...", "repo": "did:...", "collection": "nsid", "rkey": "...", "record": { ... } }`.
- **Returns**: JSON object `{ "uri": "at://...", "cid": "...", "commit": { ... } }`.

#### `com.atproto.space.deleteRecord`
- **Method**: `POST`
- **Authentication**: Space OAuth or Writer Credential.
- **Request Body**: JSON object `{ "space": "did:...", "repo": "did:...", "collection": "nsid", "rkey": "..." }`.
- **Returns**: JSON object `{ "commit": { ... } }`.

#### `com.atproto.space.applyWrites`
- **Method**: `POST`
- **Authentication**: Space OAuth or Writer Credential.
- **Request Body**: JSON object `{ "space": "did:...", "repo": "did:...", "writes": [ ... ] }`.
- **Returns**: JSON object `{ "commit": { ... }, "results": [ ... ] }`.

---

### Space blobs, sync, and notifications (`com.atproto.space.*`)

#### `com.atproto.space.getBlob`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `did` (required), `cid` (required).
- **Returns**: Private blob binary bytes.

#### `com.atproto.space.listBlobs`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `did` (required), `cursor` (optional), `limit` (optional).
- **Returns**: JSON object `{ "blobs": [ "<cid>" ], "cursor": "..." }`.

#### `com.atproto.space.getLatestCommit`
- **Method**: `GET` (also served under alias `com.atproto.space.getRepoState`)
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `did` (required).
- **Returns**: JSON object `{ "cid": "...", "rev": "...", "lthash": "..." }`.

#### `com.atproto.space.listRepoOps`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `did` (required), `since` (optional rev string).
- **Returns**: JSON object `{ "ops": [ ... ] }`.

#### `com.atproto.space.getRepo`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameters `space` (required), `did` (required), `since` (optional).
- **Returns**: CAR v1 binary stream of private space repository.

#### `com.atproto.space.listRepos`
- **Method**: `GET`
- **Authentication**: Space Credential.
- **Parameters**: Query parameter `space` (required).
- **Returns**: JSON object `{ "repos": [ "did:..." ] }`.

#### `com.atproto.space.registerNotify`
- **Method**: `POST`
- **Authentication**: Space Credential.
- **Request Body**: JSON object `{ "space": "did:...", "endpoint": "https://..." }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.space.unregisterNotify`
- **Method**: `POST`
- **Authentication**: Space Credential.
- **Request Body**: JSON object `{ "space": "did:...", "endpoint": "https://..." }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.space.notifyWrite`
- **Method**: `POST`
- **Authentication**: Outbox authorization / writer proof.
- **Request Body**: JSON object `{ "space": "did:...", "repo": "did:...", "commit": "..." }`.
- **Returns**: 200 OK empty response.

#### `com.atproto.space.notifySpaceDeleted`
- **Method**: `POST`
- **Authentication**: Outbox authorization / space owner proof.
- **Request Body**: JSON object `{ "space": "did:..." }`.
- **Returns**: 200 OK empty response.

---

## OAuth 2.1 and authorization server endpoints

Swan acts as an OAuth 2.1 Authorization Server and Protected Resource Server.

| Path | Method | Standard | Description |
|---|---|---|---|
| `/.well-known/did.json` | `GET` | W3C DID Core | Publishes service DID document (`did:web:<host>`, service entry `#atproto_pds`). |
| `/.well-known/oauth-protected-resource` | `GET` | RFC 8414 | Resource server metadata declaring issuer, resource URI, and supported scopes. |
| `/.well-known/oauth-authorization-server` | `GET` | RFC 8414 | Authorization server metadata (endpoints, response types, DPoP signing algorithms). |
| `/oauth/par` | `POST` | RFC 9126 (PAR) | Pushed Authorization Request endpoint. Requires `DPoP` header. Returns `{"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 300}`. |
| `/oauth/authorize` | `GET` | OAuth 2.1 | Renders the browser authentication and authorization challenge UI. |
| `/oauth/authorize` | `POST` | OAuth 2.1 | Consumes primary account credentials submitted via browser. |
| `/oauth/authorize/mfa` | `POST` | FIDO2 / TOTP | Consumes MFA response (TOTP or WebAuthn assertion) during OAuth flow. |
| `/oauth/authorize/consent` | `POST` | OAuth 2.1 | Submits user consent decision (`approve` or `deny`) for requested scopes. |
| `/oauth/token` | `POST` | OAuth 2.1 / DPoP | Exchanges authorization code or refresh token for sender-constrained DPoP access tokens. |
| `/oauth/revoke` | `POST` | RFC 7009 | Revokes an access token or refresh token. |
| `/health` | `GET` | Health Check | Returns plain text `OK` when the HTTP listener is operational. |

---

## Account portal REST API

The account portal backend is mounted under `/account/api/`. Browser clients must maintain an authenticated cookie (`__Host-swan-session` or pre-auth session) and transmit the corresponding anti-CSRF token in the `X-Swan-CSRF` header on all mutating requests (`POST`, `DELETE`).

### Bootstrap and authentication

- `GET /account/api/signup/policy`: Returns current registration mode (`{"policy": "closed" | "inviteRequired" | "openProtected"}`).
- `GET /account/api/bootstrap`: Issues a pre-auth session cookie and CSRF token for unauthenticated portal pages.
- `POST /account/api/login`: Submits `handle` and `password`. Returns authenticated session or factor challenge.
- `POST /account/api/login/factor-challenge`: Requests WebAuthn or TOTP challenge options.
- `POST /account/api/login/factor`: Completes login using WebAuthn assertion or TOTP code.
- `POST /account/api/signup/email/request`: Requests email confirmation code during portal registration.
- `POST /account/api/signup/authorize`: Validates registration tokens and challenge solutions.
- `POST /account/api/signup`: Creates account, provisions repository, and issues session cookie.
- `POST /account/api/logout`: Revokes active browser session and clears session cookies.

### Account snapshots and projections

- `GET /account/api/portal`: Returns full sanitized account snapshot (DID, handle, email, sessions, MFA factors, app passwords, connected apps).
- `GET /account/api/session`, `/sessions`, `/profile`, `/identity`, `/app-passwords`, `/scope-presets`, `/factors`, `/connected-apps`, `/export`, `/migration`: Section-specific projections of account state.

### Multi-factor authentication and security factors

- `POST /account/api/factors/totp`: Generates TOTP secret key and QR code URI for enrollment.
- `POST /account/api/factors/totp/verify`: Submits TOTP code to confirm enrollment.
- `DELETE /account/api/factors/totp`: Removes enrolled TOTP factor.
- `POST /account/api/factors/passkeys/options`: Generates WebAuthn registration options.
- `POST /account/api/factors/passkeys`: Completes WebAuthn passkey enrollment with signed attestation.
- `DELETE /account/api/factors/passkeys` and `DELETE /account/api/factors/passkeys/*`: Deletes an enrolled passkey.
- `POST /account/api/factors/recovery-codes/rotate`: Rotates emergency backup recovery codes (requires step-up receipt).
- `POST /account/api/step-up` and `POST /account/api/step-up/password`: Initiates re-authentication step-up for high-risk actions.

### App passwords and connected apps

- `POST /account/api/app-passwords`: Creates a scoped app password (returns plaintext once).
- `DELETE /account/api/app-passwords` and `DELETE /account/api/app-passwords/*`: Revokes app passwords.
- `DELETE /account/api/connected-apps`: Revokes authorized third-party OAuth client grants.
- `DELETE /account/api/sessions` and `DELETE /account/api/sessions/*`: Revokes specific browser sessions.
- `POST /account/api/sessions/revoke-others`: Revokes all sessions except the caller's current session.

### `did:web` identity binding endpoints

- `GET /.well-known/swan/did-web-claim/*`: Public endpoint serving the unauthenticated cryptographic claim nonce for external domain verification.
- `POST /account/api/identity/reserve`: Reserves a `did:web` signing key and claim nonce.
- `POST /account/api/identity/claim`: Validates claim nonce on external domain and binds `did:web`.
- `POST /account/api/identity/rotate`: Rotates `did:web` signing key.
- `POST /account/api/identity/remove`: Removes `did:web` binding.
- `POST /account/api/identity/reverify`: Re-validates DID document against the external host.
- `POST /account/api/identity/admission`: Configures write and token admission policy for the identity.

### Data export and erasure

- `POST /account/api/export/request`: Requests generation of a portable CAR and blob archive.
- `POST /account/api/migration/request`: Initiates account migration export package.
- `POST /account/api/lifecycle/delete`: Submits permanent account deletion and erasure request.

---

## Loopback management REST API

The management server runs on a dedicated HTTP listener bound strictly to `127.0.0.1` (default port `3001`). All requests require the `Authorization: Bearer <operator-secret>` header.

### `GET /v1/accounts`
- **Method**: `GET`
- **Authentication**: Operator secret bearer token.
- **Parameters**: Query parameter `did` (DID string) or `handle` (handle string).
- **Returns**: JSON object containing account record metadata: `did`, `handle`, `email`, `lifecycleStatus` (`active`, `deactivated`, `tombstoned`), `factorsCount`, `activeSessionsCount`, `keyIDs`, and creation timestamp.

### `POST /v1/accounts/deactivate`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "did": "did:..." }`.
- **Returns**: JSON object with updated account view showing `lifecycleStatus: "deactivated"`. Suspends login, firehose emission, and write mutations.

### `POST /v1/accounts/reactivate`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "did": "did:..." }`.
- **Returns**: JSON object with updated account view showing `lifecycleStatus: "active"`. Restores full account operations.

### `POST /v1/accounts/delete`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "did": "did:...", "tombstoneReason": "<reason>", "exportReference": "<ref-optional>" }`.
- **Returns**: JSON object with tombstone confirmation. Executes irreversible erasure of account database `<did>.sqlite`, purges control records, and emits PLC tombstone operation.

### `POST /v1/accounts/plc/prepare`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "handle": "user.example.com", "signingKey": "did:key:..." }`.
- **Returns**: JSON object containing unsigned PLC genesis operation and generated rotation credentials.

### `POST /v1/accounts/plc/activate`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "did": "did:plc:...", "handleProof": "<proof>" }`.
- **Returns**: JSON object confirming PLC activation and directory publication.

### `POST /v1/firehose/sync`
- **Method**: `POST`
- **Authentication**: Operator secret bearer token.
- **Request Body**: JSON object `{ "did": "did:..." }`.
- **Returns**: JSON object confirming immediate firehose sequencer synchronization for the account.
