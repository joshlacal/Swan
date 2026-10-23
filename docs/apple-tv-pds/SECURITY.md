# Security

Swan's existing invariants (`Swan/AGENTS.md` §Security invariants) stay in
force; SwanTV adds a second trust boundary (Apple TV ↔ vault) and a weaker
host (purgeable local storage, a consumer device in a living room).

## Threat model

| Adversary / event | What they get | Mitigation | Residual |
|---|---|---|---|
| Compromised LAN device | can reach `:8080` (Swan public surface) and `:7180` (vault) | Swan's surface is designed to be public; vault requires a 48+ byte bearer PSK, constant-time compared (`subtle::ct_eq`); after M2, vault binds only to the WireGuard interface so LAN peers cannot reach it at all | until M2, PSK is sent in clear on the LAN → D-004: vault traffic is LAN-only and the PSK is rotated when M2 lands |
| Compromised OpenWrt router | full read/write of vault data | repository/blocks/records are public data by protocol design; blobs are public or, for permissioned spaces, already encrypted/authorized at Swan's layer; key envelopes are ciphertext under the account KEK, which never reaches the router; TOTP envelopes are ciphertext; OAuth token digests, not tokens, are stored | attacker can *delete* or *roll back* data → detectable: the Apple TV tracks the vault's `next_seq`/generation and refuses to run against a manifest that is behind its own local state; off-router backups (STORAGE_MODEL §4) |
| Stolen Apple TV | app container: cached SQLite copies + bootstrap secret | Data Protection class for the bootstrap secret (keychain `WhenUnlockedThisDeviceOnly` equivalent on tvOS: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); tvOS has no user passcode, so assume the cache is readable → cached DB must not contain plaintext secrets it does not already contain on a normal Swan host (true today: passwords are Argon2id, tokens are digests, keys are envelopes) | the account KEK on the device decrypts key envelopes → revoke by rotating keys via PLC/did:web from another machine using the operator's off-device copy of identity material |
| Stolen USB disk | same as compromised router, offline | same | recommend LUKS/fscrypt on the USB volume (OpenWrt supports `cryptsetup`) — operational, not in code |
| Malicious remote XRPC client | Swan's normal threat | unchanged Swan defenses; request-size admission (`PublicRepositoryJSONWriteAdmission`, blob spool admission) | memory ceiling makes DoS-by-concurrency more effective on tvOS → `maximumConnections` tuned down (RESOURCE_PROFILE) |
| Vault unavailable | writes stall | barrier timeout → 503, write fence; reads continue from cache | availability only |
| Vault returns stale/corrupt data | wrong restore | segments are SHA-256'd in the manifest and re-verified on compaction/restore; snapshot SHA-256 recorded; WAL checksum chain validated on ingest; manifest `next_seq` compared to the Apple TV's last acknowledged seq (persisted locally and in the app group) → stale → refuse to serve writes | a router that rewrites *both* manifest and segments consistently can present an older but internally consistent history; detection requires the off-device seq watermark (store the last acked `(db, seq, sha)` in the Apple TV keychain and in the operator's monitoring) |
| Extension killed mid-transaction | local SQLite handles it (WAL atomicity); vault never got a partial segment | nothing to do; on restart the shipper resumes from the manifest's `next_frame` | none |
| Second Apple TV pointed at the same vault | split brain | lease generation fencing (PROVEN in selftest) | operator must re-lease deliberately |

## Secrets placement

| Secret | Location | Backup |
|---|---|---|
| Vault PSK | Apple TV keychain (device-only class); router `/etc/swan-vault/token` 0600 | operator password manager |
| Account KEK (`--*-account-kek-file`) | Apple TV keychain; loaded into a 0600 file in the extension's container at start (Swan requires a file) | operator password manager; **required for disaster recovery** |
| OAuth server key, email proof key, operator secret | same pattern | same |
| Per-account signing/rotation keys | vault objects (envelopes, ciphertext) + local cache | vault backups |
| PLC rotation key material | as Swan today (envelopes) | operator must also hold an out-of-band PLC rotation key so a lost Apple TV + lost KEK does not lose the DID |

## Rules carried into implementation

* No secret ever passes through environment variables (Swan invariant 4);
  SwanTV writes keychain-held secrets to owner-only files inside the extension
  container before constructing Swan.
* Vault requests never log the bearer; Swan's fixed-vocabulary error policy
  applies to barrier failures (client sees `503 upstream storage unavailable`).
* Request bodies: vault caps segments at 64 MiB and objects at 256 MiB and
  rejects declared-length mismatches; Swan-side admission caps remain.
* Blob upload path must stream to the vault (chunked PUT) before M8; the
  current buffered PUT is acceptable only for the sub-1 MB blobs used in early
  gates.
