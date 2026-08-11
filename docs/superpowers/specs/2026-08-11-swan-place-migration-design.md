# Swan `swan.place` Migration Design

Date: 2026-08-11
Status: approved design, not yet planned or implemented

## Goal

Move Swan's public PDS endpoint from `https://swan.catbird.blue` to
`https://swan.place`, and establish `*.swan.place` as the handle namespace, so
that later work — the SvelteKit web shell, OAuth signup, and account
management — is built against the domain we intend to keep.

This spec covers the domain move only. It deliberately does **not** cover
dynamic wildcard handle resolution, identity update, the web shell, or signup.

## Why a new domain

Handles must be resolvable hostnames. Under `catbird.blue` a handle would be
`alice.swan.catbird.blue` — a second-level wildcard, which no free certificate
covers: Cloudflare Universal SSL and ordinary wildcard certificates cover
exactly one subdomain level, so `*.catbird.blue` never covers
`alice.swan.catbird.blue`. Closing that gap would need Advanced Certificate
Manager (a paid add-on on every plan, including Free) or a custom uploaded
certificate (Business plan and above).

The alternatives were worse. Delegating `swan.catbird.blue` as its own
Cloudflare zone requires an **Enterprise** plan (Free/Pro/Business are all
"No"), and `swan.catbird.blue` already has a proxied A record, so it cannot be
NS-delegated without breaking the PDS hostname itself. Resolving handles by DNS
TXT would work but requires Swan to hold a Cloudflare API token, and tokens
scope **per zone, not per subtree** — a token able to write handle records
under `catbird.blue` could equally rewrite that zone's iCloud `MX` records or
the `_atproto.catbird.blue` TXT record that is the operator's own personal
atproto identity. Attaching that blast radius to a public signup endpoint is
not acceptable.

On `swan.place`, handles are **first-level** (`alice.swan.place`), so Universal
SSL covers them at no cost, no token is required, nothing is unproxied, and the
zone is naturally isolated from `catbird.blue`.

## Decisions

**Fresh account, not identity migration.** Swan cannot currently change a DID's
handle or service endpoint: `rotate-plc` rotates keys only, reusing
`journal.pdsOrigin` and passing `handle: nil`. The underlying
`PLCATProfile.regularOperation` does accept both, but no command exposes it.
Rather than couple this migration to a new PLC write path, we provision a fresh
account on `swan.place`. The existing account
`did:plc:7wr3tbi7gg5nyuocq64qietz` is hours old and holds no records; it exists
only to prove the provisioning pipeline. An `update-identity` command belongs
in the account-management spec, where user-driven handle changes live — handle
changes are table stakes for a PDS, but they are not this spec's job.

**First handle is `josh.swan.place`, not the apex.** It leaves `swan.place` as
purely the PDS, it matches the shape of every future user handle, and it
exercises the `*.swan.place` wildcard for TLS and handle resolution now, so
signup is not the first thing to discover a problem there.

**`swan.catbird.blue` keeps serving.** Both vhosts point at the same Swan
instance. No redirect: redirecting an OAuth issuer origin causes more problems
than it solves. The old DID is abandoned in place rather than tombstoned,
because tombstoning is itself a permanent public write and doing nothing is the
lower-risk default. `account delete` remains available if an explicit tombstone
is later preferred.

## Infrastructure

DNS on `swan.place` (zone `efeb61a1fea3abb83eb0e083533a82ba`, currently empty),
both proxied so the netcup origin stays hidden:

| Record | Value | Proxied |
|---|---|---|
| `A swan.place` | `152.53.37.120` | yes |
| `A *.swan.place` | `152.53.37.120` | yes |

The zone's SSL/TLS mode must be **Full (strict)**, verified rather than
assumed: a new zone can default to Flexible, which silently makes the
edge-to-origin connection plaintext.

Origin TLS is a Cloudflare Origin CA certificate with SANs `swan.place` and
`*.swan.place`, installed on netcup alongside the existing certificate. Both
names are first-level, so one ordinary certificate suffices.

Caddy gains one vhost covering `swan.place` and `*.swan.place`, reverse-proxying
to `127.0.0.1:3020` — the same Swan instance, not a second one. Two operational
facts about this host are requirements, not discoveries:

- Pre-create `/var/log/caddy/swan.place.log` owned by `caddy:caddy`. A
  root-owned log file causes the config load to fail with `permission denied`.
- Reload with `caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile`.
  `systemctl reload caddy` is a silent no-op on this box, whose unit has been
  stuck in systemd state `reloading` since April while serving correctly.

Swan itself changes one flag: `--public-url https://swan.place`. Same
container, same port, same data directory.

## Cutover sequence

Ordering principle: **nothing that mints a permanent public record happens
until the domain is proven to work.** The orphaned DID created on 2026-08-11
came from performing an irreversible action before the path was verified.

1. Create both DNS records, set Full (strict), install the origin certificate,
   add the Caddy vhost, reload via the admin API. Verify
   `https://swan.place/health` returns 200 while Swan still advertises
   `swan.catbird.blue` — proving DNS, edge TLS, origin TLS and proxying before
   any identity exists.
2. Verify an arbitrary wildcard host (`josh.swan.place`) also terminates TLS
   and reaches Swan.
3. Flip `--public-url` to `https://swan.place` and restart. Verify
   `describeServer` and that the OAuth metadata `issuer` is now
   `https://swan.place` — that value matters because client assertions bind
   their `aud` to it.
4. Run `account prepare-plc` with `--handle josh.swan.place --pds-origin
   https://swan.place` and a fresh `--request-id`; read the staged DID from its
   output; add the static Caddy handle-proof handler returning that DID.
5. Run `account activate-plc` with the same `--request-id`.
6. Re-enable `--enable-local-space-interop` and
   `--enable-public-repository-mutations`, which require an active account, and
   confirm Swan starts with the space notification routes enabled.

**If step 4 or 5 fails, retry with the same `--request-id`.** Preparation
persists its journal at `.submissionPending` before submitting and resumes via
`fetchAuditIfPresent`, so the same request-id re-derives the same keys, genesis
and DID and adopts the existing registration. A *new* request-id mints a second
permanent DID.

## Verification

- `https://swan.place/health` → 200
- `https://josh.swan.place/.well-known/atproto-did` → the new DID
- `/.well-known/oauth-authorization-server` and
  `/.well-known/oauth-protected-resource` → 200, `issuer` = `https://swan.place`
- `com.atproto.server.describeServer` → 200
- `account show` → `status: active`, handle `josh.swan.place`
- `plc.directory` DID document → `alsoKnownAs: at://josh.swan.place`,
  `serviceEndpoint: https://swan.place`
- An actual OAuth sign-in, because that is the outcome that matters
- All five prod services on netcup still active, and `catbird.blue` vhosts
  unaffected

## Rollback

Rollback is cheap through step 3 and asymmetric after step 5. Steps 1–3 revert
by flipping `--public-url` back and restarting; the DNS records and certificate
can remain, harmless. After step 5 the new DID exists permanently: rollback
means reverting `--public-url` and not using the new identity. No PLC operation
is ever undone, only abandoned. That asymmetry is the reason the irreversible
step is last.

A failed Caddy config load is self-limiting — Caddy rejects bad configuration
atomically, so the running config, and therefore the `catbird.blue` vhosts,
survive a mistake.

## Out of scope

Dynamic `*.swan.place` handle resolution (Swan answering
`/.well-known/atproto-did` per `Host`), `account update-identity`, the
SvelteKit web shell, OAuth signup screens, and account management. Those are
the next three specs, in that order.
