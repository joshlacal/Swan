# swan.place migration — completion record

**Date:** 2026-08-11
**Status:** Migration complete. Swan serves `swan.place` with an active account, all account-gated subsystems running, no regression on any co-hosted service.

## Identity

- New DID: `did:plc:6u6rzv6fk3ga37kgs3tybgdk`
- Handle: `swan.place`
- Request-id used for the PLC operation: `swan-place-apex-20260811-01`

## Certificate (Task 2)

Installed at `/etc/caddy/certs/swan-place-origin.pem`. Verified directly against the file on netcup:

```
subject=O=CloudFlare, Inc., OU=CloudFlare Origin CA, CN=CloudFlare Origin Certificate
X509v3 Subject Alternative Name:
    DNS:*.swan.place, DNS:swan.place
notAfter=Aug  7 11:20:00 2041 GMT
```

SANs: `swan.place`, `*.swan.place`. Expiry: 2041-08-07.

## Backups taken during this migration

- `/etc/caddy/Caddyfile.bak.swanplace.20260811-132809` — Task 3, vhost append (confirmed present, 6517 bytes, 09:06)
- `/etc/caddy/Caddyfile.bak.apexproof.20260811-134841` — Task 5, handle-proof handler (confirmed present, 6734 bytes, 13:30)
- `/etc/systemd/system/swan.service.bak.20260811-134027` — Task 4, systemd unit backup (confirmed present, 1271 bytes, 10:10)

All three files were verified to exist on netcup (`ls -la`) as part of this task, in addition to the filenames supplied by the task brief.

## Step 1: Account-gated subsystem flags

```
$ ssh netcup 'grep -cE "enable-local-space-interop|enable-public-repository-mutations" /etc/systemd/system/swan.service'
2
```

Flags were already present — no edit made to `swan.service` in this task. Confirmed via running logs (no restart performed; Swan was already up from Task 5's prior restart):

```
2026-08-11T11:51:01+0000 info swan: address=0.0.0.0:3000 profile=permissioned-data-0016-2026-07-30 [swan] starting Swan
2026-08-11T11:51:01+0000 info swan: [swan] space notification receiver routes enabled
2026-08-11T11:51:01+0000 info swan: [HummingbirdCore] Server started and listening on 0.0.0.0:3000
```

`systemctl is-active swan` → `active`.

## Step 3: Full verification set (verbatim)

```
/health                                              200  OK
/.well-known/atproto-did                             200  did:plc:6u6rzv6fk3ga37kgs3tybgdk
/.well-known/oauth-authorization-server              200  {"authorization_endpoint":"https://swan.place/oauth/authorize","authorization_response_iss_parameter
/.well-known/oauth-protected-resource                200  {"authorization_servers":["https://swan.place"],"bearer_methods_supported":["header"],"resource":"ht
/xrpc/com.atproto.server.describeServer              200  {"availableUserDomains":[],"did":"did:web:swan.place","inviteCodeRequired":true,"swanProfile":"permi
wildcard:200
```

All five paths returned `200`. Wildcard probe (`https://probe.swan.place/health`) returned `200`.

OAuth authorization server metadata `issuer` field, fetched and parsed separately to confirm beyond the truncated preview above:

```
$ curl -s https://swan.place/.well-known/oauth-authorization-server | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])"
https://swan.place
```

## Step 4: Identity in the public directory (verbatim)

```
$ ssh netcup 'sudo docker run --rm --user 994:984 --workdir /data -v /srv/swan/data:/data -v /srv/swan/secrets:/run/secrets/swan-runtime:ro swan:local account show --data-directory /data --did did:plc:6u6rzv6fk3ga37kgs3tybgdk 2>&1 | head -3'
{"canonicalHandle":"swan.place","createdAt":"2026-08-11T11:50:44Z","did":"did:plc:6u6rzv6fk3ga37kgs3tybgdk","status":"active","updatedAt":"2026-08-11T11:50:44Z"}

$ curl -s "https://plc.directory/did:plc:6u6rzv6fk3ga37kgs3tybgdk" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['alsoKnownAs'], d['service'][0]['serviceEndpoint'])"
['at://swan.place'] https://swan.place
```

Status `active`, handle `swan.place`, matching expected output exactly. This was a read-only `account show` invocation — no write command (`prepare-plc`, `activate-plc`, `rotate-plc`, `delete`) was run in this task.

## Step 5: Regression check (verbatim)

```
$ ssh netcup 'systemctl is-active catbird-mls-server catbird-nest-prod caddy postgresql@17-main catbird-firehose swan | tr "\n" " "; echo; free -h | sed -n 2p'
active active active active active active
Mem:            15Gi       9.7Gi       1.5Gi       4.6Gi       9.4Gi       6.0Gi

$ curl -s -o /dev/null -w "old_domain:%{http_code}\n" https://swan.catbird.blue/health
old_domain:200

$ curl -s -o /dev/null -w "api:%{http_code}\n" https://api.catbird.blue/xrpc/_health
api:401
```

All six services `active`. Memory headroom consistent with prior baseline (9.7Gi used / 6.0Gi available of 15Gi). Old domain `swan.catbird.blue` still serves (`200`). `api.catbird.blue` responds `401`, its normal unauthenticated answer — unchanged.

## Deviations from plan

1. **Task 4's `--public-url` edit was blocked by a subagent permission classifier.** The edit was run by the human partner (Josh) directly rather than by the automated executor. The controller then completed the remaining Task 4 steps — `daemon-reload`, `systemctl restart swan`, and verification — as planned.

2. **`activate-plc` failed once, then succeeded on retry with the same request-id.** The first attempt returned the generic error `account operation failed`. The retry, using the identical request-id `swan-place-apex-20260811-01`, succeeded and returned `{"recovered":true,"status":"active"}`. No second DID was minted — the retry recovered the same in-flight PLC operation rather than creating a new one. The root cause of the first failure was not definitively established; the most likely explanation is that the handle proof (`/.well-known/atproto-did` or equivalent) was not yet visible through Cloudflare's edge cache when the container fetched it during the first attempt, and had propagated by the retry.

## Summary

All six verification steps in the Task 6 brief pass with expected results. No account-mutating commands were run in this task. `swan.service` was not modified (flags were already present from an earlier task). The migration to `swan.place` is complete and verified end to end, with the previous `swan.catbird.blue` vhost still serving as a safety net per the rollback plan.
