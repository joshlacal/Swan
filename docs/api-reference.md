# Swan API & Protocol Reference

This document provides an exhaustive reference of all XRPC endpoints, OAuth 2.1 authorization server endpoints, account portal REST APIs, and loopback management interfaces implemented by Swan.

---

## 1. AT Protocol XRPC Surface

All XRPC endpoints are mounted under the `/xrpc/` path prefix.

### Server & Account Discovery
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.server.describeServer` | `GET` | None | Returns server DID, available domain suffixes, invite code requirements, and active protocol profile ID. |
| `community.lexicon.service.describe` | `GET` | None | Lists all supported XRPC method NSIDs served by this instance. |
| `com.atproto.server.createAccount` | `POST` | Optional Invite / Proof | Provisions a new AT Protocol account, registers DID with PLC, and initializes an empty repository. |
| `com.atproto.server.deleteAccount` | `POST` | Bearer Token / Password | Deletes an account and associated repository data. |
| `com.atproto.server.requestPasswordReset` | `POST` | None | Generates an email password-reset token via the transactional email outbox. |
| `com.atproto.server.resetPassword` | `POST` | Reset Token | Consumes reset token to establish a new account password. |
| `com.atproto.server.createInviteCode` | `POST` | Admin / Authorized | Generates single-use or multi-use registration invite codes. |
| `com.atproto.server.getAccountInviteCodes` | `GET` | Account Auth | Retrieves invite codes created by or allocated to the caller. |
| `com.atproto.server.reserveSigningKey` | `POST` | Pre-auth | Reserves a public key for PLC identity preparation. |

### Legacy Session Management (App Passwords)
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.server.createSession` | `POST` | Password / App Password | Authenticates an account and mints legacy access and refresh JWTs. |
| `com.atproto.server.getSession` | `GET` | Bearer Access JWT | Returns metadata for the currently active legacy session. |
| `com.atproto.server.refreshSession` | `POST` | Bearer Refresh JWT | Rotates legacy access JWT and refresh JWT. |
| `com.atproto.server.deleteSession` | `POST` | Bearer Refresh JWT | Revokes the active legacy session. |

### Public Repository Reads & Mutations
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.repo.describeRepo` | `GET` | None | Returns repo DID, handle, signing DID key, and collection list. |
| `com.atproto.repo.getRecord` | `GET` | None | Fetches a single CBOR record by `repo`, `collection`, and `rkey`. |
| `com.atproto.repo.listRecords` | `GET` | None | Lists records within a collection with pagination (`cursor`, `limit`). |
| `com.atproto.repo.createRecord` | `POST` | OAuth / DPoP | Creates a new record in a collection with an auto-generated or specified TID. |
| `com.atproto.repo.putRecord` | `POST` | OAuth / DPoP | Writes or replaces a record with CAS validation (`swapCommit`, `swapRecord`). |
| `com.atproto.repo.deleteRecord` | `POST` | OAuth / DPoP | Deletes a record with CAS validation. |
| `com.atproto.repo.applyWrites` | `POST` | OAuth / DPoP | Atomic batch of create, update, and delete operations. |
| `com.atproto.repo.uploadBlob` | `POST` | OAuth / DPoP | Streams and stores a content-addressed binary blob (up to 2 MiB default). |
| `com.atproto.repo.listMissingBlobs` | `GET` | OAuth / DPoP | Lists blob references present in records that have not been uploaded. |

### Synchronization & Public Firehose
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.sync.subscribeRepos` | `GET (WebSocket)` | None | Real-time firehose stream of sequential commits, syncs, identity updates, and tombstones. |
| `com.atproto.sync.getRepo` | `GET` | None | Exports a repository's full state as a verified CAR v1 stream. |
| `com.atproto.sync.getRepoStatus` | `GET` | None | Returns repo status, active state, and latest commit CID. |
| `com.atproto.sync.getLatestCommit` | `GET` | None | Returns the latest signed commit CID and revision. |
| `com.atproto.sync.getRecord` | `GET` | None | Returns record data and Merkle Search Tree proof. |
| `com.atproto.sync.getBlocks` | `GET` | None | Fetches raw CAR blocks for specified CIDs. |
| `com.atproto.sync.getBlob` | `GET` | None | Downloads public content-addressed blob bytes by `did` and `cid`. |
| `com.atproto.sync.listBlobs` | `GET` | None | Lists public blob CIDs associated with an account repository. |
| `com.atproto.sync.listRepoOps` | `GET` | None | Returns an incremental log of repository operations since a given revision. |
| `com.atproto.sync.getHostStatus` | `GET` | None | Returns PDS host operational status. |
| `com.atproto.sync.getBlobLimit` | `GET` | None | Returns upload and storage size limits for blobs. |

### Identity & Preferences
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.identity.resolveHandle` | `GET` | None | Resolves a handle to its corresponding DID. |
| `com.atproto.identity.updateHandle` | `POST` | OAuth / DPoP | Updates the canonical handle associated with an account. |
| `com.atproto.actor.getPreferences` | `GET` | OAuth / DPoP | Returns user-defined client preferences. |
| `com.atproto.actor.putPreferences` | `POST` | OAuth / DPoP | Updates user-defined client preferences. |

### Permissioned Spaces Plane
| NSID | Method | Auth | Description |
|---|---|---|---|
| `com.atproto.space.getSpace` | `GET` | Space Credential | Retrieves metadata and member lists for a permissioned space. |
| `com.atproto.space.listSpaces` | `GET` | Account Auth | Lists all permissioned spaces an account participates in. |
| `com.atproto.space.listRepos` | `GET` | Space Credential | Lists writer repository DIDs participating in a space. |
| `com.atproto.space.getDelegationToken` | `GET` | Account Auth | Mints a short-lived delegation token for authority exchange. |
| `com.atproto.space.getSpaceCredential` | `POST` | Delegation Token | Exchanges delegation token at space authority for a read-only space credential. |
| `com.atproto.space.getRecord` | `GET` | Space Credential | Reads a permissioned record within a space. |
| `com.atproto.space.listRecords` | `GET` | Space Credential | Lists permissioned records within a space collection. |
| `com.atproto.space.createRecord` | `POST` | Space OAuth | Writes a permissioned record into the caller's space repo. |
| `com.atproto.space.putRecord` | `POST` | Space OAuth | Updates a permissioned record within a space. |
| `com.atproto.space.deleteRecord` | `POST` | Space OAuth | Removes a permissioned record from a space. |
| `com.atproto.space.applyWrites` | `POST` | Space OAuth | Executes batch mutations within a permissioned space. |
| `com.atproto.space.getLatestCommit` | `GET` | Space Credential | Returns latest reader-bound signed commit CID and LtHash accumulator. |
| `com.atproto.space.listRepoOps` | `GET` | Space Credential | Incremental sync log for space repository operations. |
| `com.atproto.space.getRepo` | `GET` | Space Credential | Exports space repository CAR with dual-root recovery commitments. |
| `com.atproto.space.getBlob` | `GET` | Space Credential | Downloads private blob bytes attached to a space record. |
| `com.atproto.space.listBlobs` | `GET` | Space Credential | Lists private blob CIDs within a space. |
| `com.atproto.space.registerNotify` | `POST` | Space Credential | Subscribes an endpoint to space write notifications. |
| `com.atproto.space.unregisterNotify` | `POST` | Space Credential | Unsubscribes an endpoint from space write notifications. |
| `com.atproto.space.notifyWrite` | `POST` | Outbox Auth | Ingests peer-pinned write notification from space writer. |
| `com.atproto.space.notifySpaceDeleted`| `POST` | Outbox Auth | Ingests space deletion notification. |
| `com.atproto.simplespace.checkUserAccess`| `GET` | Service JWT | Verifies user membership and permissions in a space. |

---

## 2. OAuth 2.1 & DPoP Endpoints

| Endpoint | Method | RFC / Standard | Description |
|---|---|---|---|
| `/.well-known/oauth-protected-resource` | `GET` | RFC 8414 / ATProto | Resource server metadata declaring issuer and supported scopes. |
| `/.well-known/oauth-authorization-server` | `GET` | RFC 8414 / OAuth 2.1 | Authorization server metadata (endpoints, grant types, DPoP algs). |
| `/.well-known/did.json` | `GET` | W3C DID Core | Service DID document containing verification keys and service endpoints. |
| `/oauth/par` | `POST` | RFC 9126 (PAR) | Pushed Authorization Request endpoint. Returns `request_uri`. Requires DPoP proof. |
| `/oauth/authorize` | `GET` | OAuth 2.1 | Interactive browser endpoint for authentication, MFA verification, and consent. |
| `/oauth/authorize` | `POST` | OAuth 2.1 | Handles user credential submission and begins session. |
| `/oauth/authorize/mfa` | `POST` | FIDO2 / TOTP | Consumes MFA challenge/response during OAuth flow. |
| `/oauth/authorize/consent` | `POST` | OAuth 2.1 | Records user authorization decision (`approve` or `deny`). |
| `/oauth/token` | `POST` | OAuth 2.1 / DPoP | Exchanges authorization code or refresh token for sender-constrained access tokens. |
| `/oauth/revoke` | `POST` | RFC 7009 | Revokes an access token or refresh token. |

---

## 3. Account Portal REST APIs

All portal endpoints are mounted under `/account/api/` and require valid session cookies (`__Host-swan-session`) and anti-CSRF headers (`X-Swan-CSRF`).

### Authentication & Bootstrap
| Path | Method | Description |
|---|---|---|
| `/account/api/signup/policy` | `GET` | Returns current registration policy (`closed`, `inviteRequired`, `openProtected`). |
| `/account/api/bootstrap` | `GET` | Issues a pre-auth session and anti-CSRF token for unauthenticated pages. |
| `/account/api/login` | `POST` | Submits handle and password; issues session or returns required MFA challenge. |
| `/account/api/login/factor-challenge` | `POST` | Generates WebAuthn or TOTP challenge during login. |
| `/account/api/login/factor` | `POST` | Submits WebAuthn assertion or TOTP code to complete login. |
| `/account/api/logout` | `POST` | Revokes current browser session and clears session cookies. |

### Account Snapshot & Sessions
| Path | Method | Description |
|---|---|---|
| `/account/api/portal` | `GET` | Returns full account snapshot (DID, handle, email, active sessions, MFA factors, app passwords). |
| `/account/api/sessions` | `GET` | Lists all active web and OAuth browser sessions. |
| `/account/api/sessions/:id` | `DELETE` | Revokes a specific session. |
| `/account/api/sessions/revoke-others` | `POST` | Revokes all sessions except the caller's current session. |

### Credentials & Security Factors
| Path | Method | Description |
|---|---|---|
| `/account/api/factors/totp` | `POST` | Initializes TOTP enrollment; returns secret key and QR code URI. |
| `/account/api/factors/totp/verify` | `POST` | Confirms TOTP code and activates factor on account. |
| `/account/api/factors/passkeys/options` | `POST` | Generates WebAuthn registration options (relying party ID, user entity, challenge). |
| `/account/api/factors/passkeys` | `POST` | Completes WebAuthn passkey enrollment with signed attestation. |
| `/account/api/factors/passkeys/:id` | `DELETE` | Removes an enrolled passkey. |
| `/account/api/factors/recovery-codes/rotate` | `POST` | Rotates backup recovery codes (requires step-up receipt). |
| `/account/api/step-up` | `POST` | Initiates biometric or password re-authentication for high-risk operations. |

### App Passwords & Third-Party Apps
| Path | Method | Description |
|---|---|---|
| `/account/api/app-passwords` | `GET` | Lists all active scoped app passwords. |
| `/account/api/app-passwords` | `POST` | Generates a new scoped app password. Plaintext returned **only once**. |
| `/account/api/app-passwords/:name` | `DELETE` | Revokes an app password. |
| `/account/api/connected-apps` | `GET` | Lists authorized OAuth client applications and granted scopes. |
| `/account/api/connected-apps/:client_id` | `DELETE` | Revokes authorization for a third-party OAuth app. |

### Export & Deletion
| Path | Method | Description |
|---|---|---|
| `/account/api/export/request` | `POST` | Requests a downloadable portable archive of user records and blobs. |
| `/account/api/lifecycle/delete` | `POST` | Submits GDPR account erasure request with permanent PLC tombstoning. |

---

## 4. Loopback Management REST APIs

The loopback management listener (default port 3001) is strictly bound to `127.0.0.1` and requires an `Authorization: Bearer <operator-secret>` header.

| Path | Method | Request Body | Description |
|---|---|---|---|
| `/v1/accounts` | `GET` | `?did=<did>` or `?handle=<handle>` | Returns comprehensive account metadata, lifecycle status, and key IDs. |
| `/v1/accounts/deactivate` | `POST` | `{"did": "..."}` | Suspends account login, firehose output, and mutations. |
| `/v1/accounts/reactivate` | `POST` | `{"did": "..."}` | Restores a deactivated account to active status. |
| `/v1/accounts/delete` | `POST` | `{"did": "...", "tombstoneReason": "..."}` | Executes permanent account deletion and publishes PLC tombstone. |
| `/v1/accounts/plc/prepare` | `POST` | `{"handle": "...", "signingKey": "..."}` | Prepares a new PLC genesis operation. |
| `/v1/accounts/plc/activate` | `POST` | `{"did": "...", "handleProof": "..."}` | Completes PLC activation and publishes identity. |
| `/v1/firehose/sync` | `POST` | `{"did": "..."}` | Manually triggers in-process firehose emission for an account. |
