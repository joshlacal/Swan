# Spaces open interop and the 2026-10-01 alignment changes

Swan is hardened beyond the reference atproto-spaces implementation (bluesky-social/atproto PR #5187) in ways that stop upstream peers from talking to it. On 2026-10-01 Josh approved closing those gaps behind one opt-in flag, `swan serve --enable-spaces-open-interop`, and approved a set of always-on fixes (credential `kid`, credential lifetimes, managing-app rejection, two wire gaps). This note lists exactly what each change does, so an operator can decide where to turn the flag on. Decisions: `Catbird+Petrel/docs/DECISIONS.md`, entries dated 2026-10-01. Background: `Catbird+Petrel/docs/research/2026-09-30-atproto-spaces/swan.md` (items SWAN-01, -04, -05, -07, -08, -09, -13, -24).

The pinned profile `Profiles/permissioned-data-0016-2026-09-19.json` is hash-pinned and immutable, so it was not edited. Its `intentionalDivergences` must be updated when the next profile is cut; the list below is the input for that.

## Always on (no flag)

| Item | Change | Wire effect |
|---|---|---|
| SWAN-01 | Credentials are minted with header `kid: #atproto` for Swan-hosted did:plc and did:web authorities (the only method they publish). Verification still accepts `#atproto_space` (dedicated method first, `#atproto` only when it is absent; a present-but-malformed method is fail-closed). Operator credential pins now default to `#atproto`. | Minted bytes change. Reference repo hosts stop answering 401 BadJwtIss. |
| #5567 | Credential `exp - iat` is capped at 3600 s at mint and at verify (was 7200 s); the generic mint default is 600 s; `iat` may lead the verifier by at most 5 s; `exp` must be after `iat`; `jti` is required. Swan's own authority still issues 300 s credentials. | Credentials longer than one hour, including old two-hour ones, are rejected. |
| SWAN-24 (option B) | `createSpace` / `updateSpace` with a `#managingAppPolicy` read or write policy return 400 `UnsupportedPolicy`. Swan has no outbound `checkUserAccess` client, so such a space would deny every non-owner. Stored spaces are untouched. | New 400 for a previously accepted body. |
| SWAN-08 | `getRepo?excludeValues=true` returns a CAR with only the `[commit, index]` blocks. `listRepoOps` accepts `cursor` (`<rev>/<idx>`, preferred over `since`; malformed → 400 `MalformedCursor`) and returns one on every page without a commit. | Two previously rejected parameters now work. |

## `--enable-spaces-open-interop` (default off)

Without the flag every route behaves exactly as before.

### (a) Unbound notify service auth (SWAN-04)

`notifyWrite` and `notifySpaceDeleted` accept an upstream service JWT that has no `req` (body-digest) claim when all of these hold:

- `iss` is the writer repo (`notifyWrite`) or the space authority (`notifySpaceDeleted`);
- `aud` is the bare authority DID or `<authority>#atproto_space_host` (`notifyWrite`);
- `lxm` is the route;
- the token has `iat` and `exp - iat <= 60` s;
- its `jti` has not been used (a durable single-use reservation; upstream keeps none).

A token that does carry `req` must still match the body, and Swan still sends `req` on everything it signs.

### (b) Optional `Atproto-Service-Auth` (SWAN-05)

`registerNotify` / `unregisterNotify` accept the space credential alone for `service` registrations, as upstream does; the registration is owned by the named service's DID. When the header is present it must still prove ownership of `service`. Legacy endpoint-only registrations still require the header. Header-less registrations are capped at 32 per space per hour and 8 per (space, credential subject) per hour, on top of the durable 1024-per-space ceiling and the 24 h TTL.

### (c) Open federation (SWAN-07)

This overrides the `AGENTS.md` rule that unknown issuers never trigger network lookups, for these lookups only:

- Delegation, space-credential and service-JWT keys for any `did:plc` / `did:web` issuer are read from its DID document after local, PLC-config and pinned sources have no answer. Fetches use the existing peer-pinned, redirect-free, SSRF-policied DID-document fetcher; documents are cached at most 60 s, failures 30 s, and new-issuer lookups are capped at 120 per minute.
- As a writer, Swan routes `notifyWrite` to an operator-configured destination if one exists, else the authority's `#atproto_space_host` entry (must be typed `AtprotoSpaceHost`; `aud = <did>#atproto_space_host`), else `#atproto_pds` (`aud` = bare DID). A malformed space-host entry is an error, not a fallback. Delivery still needs `--enable-notification-delivery` and `--notification-config`.

### (d) Upstream scope and legacy-session semantics (SWAN-09)

- OAuth: an omitted `action` (defaulting to read/create/update/delete) satisfies `getDelegationToken` and `listSpaces`, and a wildcard space type may exchange. Type/authority/skey matching is unchanged; an unfiltered listing still needs a wildcard grant.
- Legacy sessions (needs `--enable-legacy-sessions`): account-password sessions may call `getDelegationToken`; app-password sessions get 401 there. Both kinds may read and write their own space repository and call `listSpaces`. They never get `manage` operations or another account's repository.

## Operator flags

Add to `swan serve`:

```
--enable-spaces-open-interop
```

It acts on whatever is already composed: (a)/(b) need the notification routes (`--notification-config` with service keys, or `--enable-local-space-interop`); (c) widens resolvers that already exist and, for outbound routing, needs `--enable-notification-delivery`; (d)'s legacy half needs `--enable-legacy-sessions`.

Client attestation for `getSpaceCredential` is enabled by `--enable-local-space-interop` alone. That flag builds the OAuth client-metadata loader (the same hardened fetcher as `--enable-oauth-authorization-server`) and a durable attestation replay store keyed by `--oauth-server-key-file`. It also requires an owner-only `--space-account-kek-file` (plus `--space-account-kek-id` / `--space-account-key-directory` when not defaults) and an HTTPS `--public-url`. `--oauth-allow-metadata-ip` is only for lab metadata hosts on literal IPs; production client metadata is fetched over public DNS under the SSRF policy.

## Decisions made while implementing (Yellow, overridable before merge)

- Swan's authority keeps issuing 300 s credentials instead of upstream's 600 s default: it is a ratified hardening (F03) and already within the new rules.
- Unbound-token `jti` reservations reuse the delegation replay table with a domain-separated HMAC instead of a new migration.
- Header-less registration caps are an in-memory hourly rate (32/space, 8/subject), not a new stored count.
- Legacy sessions reach spaces by being mapped, at the space-route authorization boundary only, to an account grant for `space:*?authority=*&collection=*` with default actions, instead of opening `.accountLegacySession` in every domain switch.
- The profile JSON is not edited (hash-pinned); this note records the divergences until the next profile.

## Not done

- Swan's own recovery verifier (Swan as a consumer) does not yet accept an index-only CAR.
- An outbox row for an authority that cannot be routed still retries without an attempt cap.
- `com.atproto.simplespace.checkUserAccess` is still served as a generic denial; managing-app option A (outbound `checkUserAccess`) is not implemented.
