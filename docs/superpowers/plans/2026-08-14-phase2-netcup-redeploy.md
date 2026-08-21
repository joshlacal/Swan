# Phase 2 → netcup redeploy readiness

**Status: DEPLOYED 2026-08-14 ~21:52 UTC, on Josh's go.**
**Hotfix 2026-08-14 ~22:33 UTC:** immediately post-deploy, bulleted.app
sign-in failed against swan.place — Bulleted's client library (the
`atproto-oauth` Rust crate, `resources.rs`,
`ScopesSupportedMustIncludeTransitionGeneric`) refuses any authorization
server whose `scopes_supported` omits `transition:generic`; Catbird's nest
client requests transition scopes at login too. Swan already parsed and
admitted all three transition scopes at PAR — only the advertisement was
missing. Fix `e9f0a3cb` advertises
`["atproto","transition:chat.bsky","transition:email","transition:generic"]`
at the composition root (metadata type default and §6.6 fixtures
untouched). Image `234a41d2` promoted to `swan:local`; prior Phase-2 image
`6851d778` kept as `swan:rollback-20260815`. All four endpoints 200; public
doc verified serving the four scopes through Cloudflare.
**Hotfix 2, ~22:55 UTC:** Bulleted then failed at PAR itself
(`stage=form_parse reason=malformed`) — the same crate appends the typed
handle as `login_hint` to every PAR, and both of Swan's PAR parsers
rejected any field outside their exact allowlists, so the form died before
the DPoP nonce challenge and the client surfaced it as a DPoP error. Fix
`e6e4aa96`: both parsers admit optional `login_hint` (bounded, ignored)
and `prompt` limited to `login`/`consent`/`select_account`
(`prompt=none` stays refused — this server can never answer silently),
mirroring the reference PDS. Redeployed; prior image kept as
`swan:rollback-20260815-b`; live probe of a hinted PAR returns
`use_dpop_nonce` as expected. All three gates
closed the same day. `swan:next` (image `6851d778`, built from the merged tree
at `b4e7118d`) promoted to `swan:local`; previous image preserved as
`swan:rollback-20260814` (`0e77c5ad`). Service restarted, started clean
("Server started and listening"), and **all four verification endpoints
returned 200 post-deploy** (health, describeServer, oauth-authorization-server,
public `swan.place`). `--enable-lexicon-resolution` remains **off** — enabling
it is a deliberate separate follow-up (see "Open decision" below).

## Live state — verified today, not remembered

Checked read-only over `ssh netcup` on 2026-08-14. **Two of these contradict
what memory said**, which is why they were checked:

| fact | value |
|---|---|
| host arch | `x86_64` (image builds natively — no aarch64 cross-compile problem) |
| `swan.service` | **active** |
| public URL | **`https://swan.place`** — the domain migration has landed; memory still said `swan.catbird.blue` |
| health | `/health` 200, `describeServer` 200, `/.well-known/oauth-authorization-server` 200, public `swan.place/xrpc/…describeServer` 200 |
| image | `swan:local`, 4.96 GB, built **13 h ago** |
| disk | 346 G free of 503 G (29 % used) — ample for a rebuild |
| source | `~/dev/swan-src/{Swan,Petrel}` — **not a git checkout**; an rsync'd tree carrying `.build-*` dirs and `artifacts/` |

**Live flags (`systemctl cat swan.service`) — memory recorded three of these as
disabled; they are ON:**

```
--enable-oauth-authorization-server
--enable-local-space-interop
--enable-public-repository-mutations
--enable-public-firehose
--login-trusted-proxy-peer 172.17.0.1
--profile .../permissioned-data-0016-2026-07-30.json
```

Container shape: `--user 994:984 --workdir /data --read-only`, tmpfs `/tmp`,
`--memory=2g --pids-limit=512`, `-p 127.0.0.1:3020:3000`, data at
`/srv/swan/data:/data`, secrets at `/srv/swan/secrets:/run/secrets/swan-runtime:ro`.

## What Phase 2 ships, and why this deploy is low-risk

**Phase 2 is inert unless explicitly enabled.**

- New flag `--enable-lexicon-resolution`, **default `false`**
  (`SwanCommand.swift:1907`), and it *requires* `--enable-oauth-authorization-server`
  (`:2639-2642`), which prod already has. So the precondition is satisfied but
  the flag is not passed — the resolver does not run.
- With the flag off, both Phase-2 transformations are documented pass-throughs
  (P2-F's F3). Behaviour is unchanged from today's build.
- **No new outbound I/O unless the flag is on.** When on, the resolver performs
  DNS TXT + DID document + `sync.getRecord` per authority, all through the
  existing `OAuthRemoteFetchPolicy` (public-address-only peer check, redirect
  policy, admission control, 256 KiB cap, 5 s timeout, 10 s group deadline).

**The schema change is automatic and idempotent.** `oauth_lexicon_documents` is
a `CREATE TABLE IF NOT EXISTS` appended to `SQLiteLayout.controlMigrations`
(`SwanSQLite.swift:147`), applied at startup inside a transaction
(`OAuthControlStore.swift:1470-1474`). The pragma-skip is **computed**
(`dropFirst(SQLiteLayout.controlConnectionPragmas.count)`), not a hardcoded
index, so appending to the list is safe. **No manual migration step, and no
rollback migration needed** — an older binary simply ignores the extra table.

## Blocking

1. ~~**P2-H is not landed.**~~ **CLOSED 2026-08-14.** P2-H sealed at
   `5458a6a3`, integrated at `b2809f3d`. Refresh now re-derives the token scope
   (7 new tests green, negative control measured: 4/7 fail with the fix
   reverted). One expected behaviour post-deploy: **families minted before this
   binary have no requested-side provenance and stay frozen at their mint-time
   grant for the rest of their ≤14-day life** — a frozen legacy family during
   that window is not the F2 defect recurring. New additive column
   `scope_provenance_requested`; same automatic-migration story as below.
2. ~~**Full macOS suite not yet confirmed on the merged tree.**~~ **CLOSED
   2026-08-14**, measured on the merge (`b2809f3d`), both frameworks counted:
   **XCTest 1853 passed / 11 skipped / 0 failed (1864 executed); Swift Testing
   163 / 0** (zero `✘` in the transcript), exit 0. The known
   `NIOPeerPinnedOAuthPostTransportTests` load flake did not fire.
3. ~~**Linux build not yet run for Phase-2 code.**~~ **CLOSED 2026-08-14.**
   `sudo docker build -t swan:next` completed on netcup with exit 0 from the
   merged tree — the image build *is* the Linux gate (release build of the
   `swan` product inside the Dockerfile). Build log: `/tmp/swan-next-build.log`
   on netcup.

## Procedure

```bash
# 1. sync source (rsync target, NOT a git checkout — exclude build dirs)
rsync -az --delete \
  --exclude '.build*' --exclude '.jj' --exclude '.git' --exclude 'artifacts' \
  ~/Developer/Catbird+Petrel/Swan-merge3/  netcup:~/dev/swan-src/Swan/
rsync -az --delete --exclude '.build*' --exclude '.jj' --exclude '.git' \
  ~/Developer/Catbird+Petrel/Petrel/       netcup:~/dev/swan-src/Petrel/

# 2. build on netcup (x86_64 native). `josh` is NOT in the docker group.
ssh netcup 'cd ~/dev/swan-src && sudo docker build -t swan:next -f Swan/Dockerfile .'

# 3. keep the current image as a rollback point BEFORE retagging
ssh netcup 'sudo docker tag swan:local swan:rollback-$(date +%Y%m%d) && sudo docker tag swan:next swan:local'

# 4. restart and verify
ssh netcup 'sudo systemctl restart swan.service && sleep 5 && \
  curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:3020/health'
```

**Verify after restart** — all four were 200 before the deploy, so any non-200
is a regression:
`/health`, `/xrpc/com.atproto.server.describeServer`,
`/.well-known/oauth-authorization-server`, and public
`https://swan.place/xrpc/com.atproto.server.describeServer`.

**Rollback:** `sudo docker tag swan:rollback-<date> swan:local && sudo systemctl restart swan.service`.
The new table is additive, so the old binary runs against the migrated DB
unchanged.

## Gotchas that have bitten this deployment before

Carried from `project_swan_netcup_deployment`; **the flag list in that memory is
now stale** (see above), so treat its other claims as needing the same check.

- `josh` is deliberately **not** in the docker group → always `sudo docker`.
- **`systemctl reload caddy` is a NO-OP** on this host (unit stuck "reloading"
  since Apr 2026 while serving fine). Use
  `sudo caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile`.
- Running `caddy validate/reload` as **root** creates per-site logs owned
  `root:root 0600` which the `caddy` user then cannot open → chown back to
  `caddy:caddy`.
- **`DOCKER-USER` needs the conntrack RETURN rule FIRST**, then the DROP. A bare
  `-i eth0 -j DROP` kills all container egress by dropping return packets —
  which would break the lexicon resolver's outbound fetches specifically, if the
  flag is ever enabled.
- **`journalctl` on netcup uses LOCAL time (UTC+2).** `--since "<UTC wall time>"`
  silently reads a window 2 h off. Use `--since @<epoch> --until @<epoch>`.
- Image user is uid 999; the service runs `--user 994:984` and therefore cannot
  traverse the image's `/var/lib/swan` — hence `--workdir /data`.

## Resolved — resolver ENABLED 2026-08-14 ~23:10 UTC

The sequencing below was honored: the build shipped dark, P2-H landed, two
client-interop hotfixes (transition-scopes advertisement, PAR
`login_hint`/`prompt`) and a refresh-grant fix (`redirect_uri` accepted and
ignored, `0e18b2cd`) deployed and verified — and then
`--enable-lexicon-resolution` was added to the unit as its own restart
(backup at `/etc/systemd/system/swan.service.bak-20260815`). Trigger:
Bulleted's spaces flow requests `include:app.bulleted.authFull`, which
renders as "Swan does not currently grant capabilities derived from this
set" while the resolver is off. The set's chain was verified resolvable
first: `_lexicon.bulleted.app` TXT → `did:plc:geqwme5xqva5iasvlrwi4izj` →
vesuvius.pyroclastic.cloud → `com.atproto.lexicon.schema/app.bulleted.authFull`.
Flag confirmed in the running container; all four endpoints 200.

## Open decision — enabling the resolver (RESOLVED above; kept for context)

Deploying the build and *enabling* `--enable-lexicon-resolution` are separate
choices, and they should be separate deploys. Recommended order:

1. Ship the build with the flag **off**. Behaviour is unchanged; this only
   proves Phase 2 compiles, migrates and runs in production.
2. Land P2-H.
3. Enable the flag as its own change, so any resolver-related symptom has an
   unambiguous cause.

Enabling it turns on outbound DNS and HTTPS from the container to arbitrary
lexicon authorities. The transport hardening is already in place, but the
`DOCKER-USER` conntrack rule above is what makes container egress work at all.
