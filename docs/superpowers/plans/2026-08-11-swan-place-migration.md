# swan.place Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve Swan's PDS at `https://swan.place` with `*.swan.place` reserved as the handle namespace, and provision one active account whose handle is the apex `swan.place`.

**Architecture:** No Swan source changes. This is DNS, TLS, one Caddy vhost, one systemd flag, and one account provisioning run against live `plc.directory`. The same Swan container serves both `swan.catbird.blue` and `swan.place`; the old vhost keeps working.

**Tech Stack:** Cloudflare DNS + Universal SSL + Origin CA, Caddy 2, systemd, Docker, the `swan` CLI.

**Spec:** `docs/superpowers/specs/2026-08-11-swan-place-migration-design.md`

## Global Constraints

- Host is `ssh netcup` (Debian 13, x86_64, IP `152.53.37.120`). Production services `catbird-mls-server`, `catbird-nest-prod`, `caddy`, `postgresql@17-main`, `catbird-firehose` must remain `active` throughout.
- `josh` is deliberately NOT in the `docker` group. Every docker command uses `sudo docker`.
- Cloudflare zone `swan.place` = `efeb61a1fea3abb83eb0e083533a82ba`; account = `e98ce550d90d37d4834b7f9b76d8cb14`.
- Reload Caddy with `sudo caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile`. **`systemctl reload caddy` is a silent no-op on this host** — its unit has been stuck in systemd state `reloading` since April while serving correctly.
- Any per-site Caddy log file must exist and be owned `caddy:caddy` **before** the reload. A root-owned log file makes the config load fail with `permission denied`.
- Caddy validates and swaps config atomically; a rejected config leaves the running `catbird.blue` vhosts untouched.
- Swan runs as container `swan` (systemd unit `swan`), user `994:984`, data `/srv/swan/data`, secrets `/srv/swan/secrets`, published on `127.0.0.1:3020`.
- **Nothing that writes to `plc.directory` happens before Task 5.** A PLC write is permanent and public.
- **If a `prepare-plc` or `activate-plc` step fails, retry with the SAME `--request-id`.** A new request-id mints a second permanent DID. The request-id for this migration is exactly `swan-place-apex-20260811-01`.

---

### Task 1: DNS records and SSL mode on swan.place

**Files:**
- No repository files. Cloudflare zone state only.

**Interfaces:**
- Produces: `swan.place` and `*.swan.place` resolving through Cloudflare to `152.53.37.120`, zone SSL mode `strict`.

- [ ] **Step 1: Verify the zone is empty and record the starting SSL mode**

Using the Cloudflare API MCP tool (`mcp__plugin_cloudflare_cloudflare-api__execute`):

```javascript
async () => {
  const zoneId = "efeb61a1fea3abb83eb0e083533a82ba";
  const recs = await cloudflare.request({ method: "GET", path: `/zones/${zoneId}/dns_records`, query: { per_page: 100 } });
  const ssl = await cloudflare.request({ method: "GET", path: `/zones/${zoneId}/settings/ssl` });
  return { records: (recs.result || []).map(r => `${r.type} ${r.name}`), ssl: ssl.result };
}
```

Expected: `records: []` and an `ssl.value` that is very likely `flexible` or `full` — record whichever it is.

- [ ] **Step 2: Confirm the hostnames do not resolve yet**

Run: `dig +short swan.place A; dig +short probe.swan.place A`
Expected: both empty. This is the "test fails first" state.

- [ ] **Step 3: Create both A records, proxied**

```javascript
async () => {
  const zoneId = "efeb61a1fea3abb83eb0e083533a82ba";
  const out = [];
  for (const name of ["swan.place", "*.swan.place"]) {
    const r = await cloudflare.request({
      method: "POST", path: `/zones/${zoneId}/dns_records`,
      body: { type: "A", name, content: "152.53.37.120", proxied: true, ttl: 1,
              comment: "Swan PDS + handle namespace" },
    });
    out.push({ name, success: r.success, errors: r.errors });
  }
  return out;
}
```

Expected: both `success: true`.

- [ ] **Step 4: Set SSL mode to Full (strict)**

```javascript
async () => {
  const zoneId = "efeb61a1fea3abb83eb0e083533a82ba";
  const r = await cloudflare.request({ method: "PATCH", path: `/zones/${zoneId}/settings/ssl`, body: { value: "strict" } });
  return { success: r.success, value: r.result && r.result.value, errors: r.errors };
}
```

Expected: `success: true`, `value: "strict"`. A new zone defaulting to `flexible` would silently make the edge-to-origin hop plaintext, which is why this is explicit.

- [ ] **Step 5: Verify resolution**

Run: `dig +short swan.place A; dig +short probe.swan.place A`
Expected: both return Cloudflare edge addresses (NOT `152.53.37.120` — proxied records resolve to Cloudflare). Both must return the same pair.

---

### Task 2: Origin certificate for swan.place

**Files:**
- Create on netcup: `/etc/caddy/certs/swan-place-origin.pem`, `/etc/caddy/certs/swan-place-origin-key.pem`

**Interfaces:**
- Consumes: Task 1's zone state.
- Produces: an origin certificate valid for `swan.place` and `*.swan.place`, readable by Caddy.

- [ ] **Step 1: Confirm the existing certificate does not cover the new domain**

Run: `ssh netcup 'sudo openssl x509 -in /etc/caddy/certs/cloudflare-origin.pem -noout -text | grep -A2 "Subject Alternative Name"'`
Expected: `DNS:*.catbird.blue, DNS:catbird.blue` — no `swan.place`. This is why a second certificate is needed.

- [ ] **Step 2: Generate a private key and CSR on the host**

```bash
ssh netcup 'sudo mkdir -p /etc/caddy/certs && cd /tmp && umask 077 && \
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout /tmp/swan-place-origin-key.pem \
    -out /tmp/swan-place.csr \
    -subj "/CN=swan.place" \
    -addext "subjectAltName=DNS:swan.place,DNS:*.swan.place" && \
  echo CSR_OK && cat /tmp/swan-place.csr'
```

Expected: `CSR_OK` followed by a PEM CSR block. Copy the CSR text for the next step.

- [ ] **Step 3: Request the Origin CA certificate**

Attempt via API first:

```javascript
async () => {
  const csr = `-----BEGIN CERTIFICATE REQUEST-----
...paste the CSR from Step 2 verbatim, preserving newlines...
-----END CERTIFICATE REQUEST-----`;
  const r = await cloudflare.request({
    method: "POST", path: "/certificates",
    body: { hostnames: ["swan.place", "*.swan.place"], requested_validity: 5475,
            request_type: "origin-rsa", csr },
  });
  return { success: r.success, errors: r.errors, certificate: r.result && r.result.certificate };
}
```

Expected: `success: true` and a PEM certificate.

**If this returns an authentication error**, the Origin CA API requires an Origin CA Key rather than the OAuth token. In that case create the certificate in the dashboard instead: **SSL/TLS → Origin Server → Create Certificate**, paste the CSR from Step 2, list hostnames `swan.place` and `*.swan.place`, and copy the resulting PEM. Do not generate the key in the browser — we already have one on the host, and it must not leave it.

- [ ] **Step 4: Install the certificate and fix ownership**

```bash
ssh netcup 'sudo tee /etc/caddy/certs/swan-place-origin.pem > /dev/null <<"EOF"
...paste the certificate PEM...
EOF
sudo mv /tmp/swan-place-origin-key.pem /etc/caddy/certs/swan-place-origin-key.pem
sudo chown caddy:caddy /etc/caddy/certs/swan-place-origin.pem /etc/caddy/certs/swan-place-origin-key.pem
sudo chmod 0640 /etc/caddy/certs/swan-place-origin.pem /etc/caddy/certs/swan-place-origin-key.pem
rm -f /tmp/swan-place.csr'
```

- [ ] **Step 5: Verify the installed certificate covers both names**

Run: `ssh netcup 'sudo openssl x509 -in /etc/caddy/certs/swan-place-origin.pem -noout -text | grep -A2 "Subject Alternative Name"; sudo openssl x509 -in /etc/caddy/certs/swan-place-origin.pem -noout -enddate'`
Expected: SANs include both `DNS:swan.place` and `DNS:*.swan.place`, with an expiry far in the future.

---

### Task 3: Caddy vhost for swan.place

**Files:**
- Modify on netcup: `/etc/caddy/Caddyfile` (append one site block)
- Create on netcup: `/var/log/caddy/swan.place.log`

**Interfaces:**
- Consumes: Task 2's certificate.
- Produces: `https://swan.place/health` and `https://<anything>.swan.place/health` reaching Swan on `127.0.0.1:3020`.

- [ ] **Step 1: Verify the new hostname does not yet reach Swan**

Run: `curl -s -o /dev/null -w "%{http_code}\n" --max-time 12 https://swan.place/health`
Expected: a Cloudflare error (`521`/`522`) or similar — NOT 200. This is the failing state.

- [ ] **Step 2: Back up the Caddyfile and pre-create the log file**

```bash
ssh netcup 'sudo cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak.swanplace.$(date +%Y%m%d-%H%M%S)
sudo touch /var/log/caddy/swan.place.log
sudo chown caddy:caddy /var/log/caddy/swan.place.log
sudo chmod 0644 /var/log/caddy/swan.place.log
sudo ls -l /var/log/caddy/swan.place.log'
```

Expected: the file exists owned `caddy caddy`. Skipping this is what previously made a reload fail.

- [ ] **Step 3: Append the vhost**

Append exactly this block to `/etc/caddy/Caddyfile` (use `sudo tee -a`; note the leading blank line):

```
swan.place, *.swan.place {
	tls /etc/caddy/certs/swan-place-origin.pem /etc/caddy/certs/swan-place-origin-key.pem

	handle {
		reverse_proxy localhost:3020
	}

	log {
		output file /var/log/caddy/swan.place.log
	}
}
```

- [ ] **Step 4: Validate, then reload via the admin API**

```bash
ssh netcup 'sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -2
sudo caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | grep -iE "^Error|error:" | head -3
echo RELOAD_DONE'
```

Expected: `Valid configuration`, no error lines, `RELOAD_DONE`. If the reload reports `permission denied` on the log file, redo Step 2 — a root-owned log file is the usual cause.

- [ ] **Step 5: Verify both the apex and the wildcard reach Swan, and prod is untouched**

```bash
curl -s -o /dev/null -w "apex:%{http_code}\n" --max-time 12 https://swan.place/health
curl -s -o /dev/null -w "wildcard:%{http_code}\n" --max-time 12 https://probe.swan.place/health
curl -s -o /dev/null -w "old:%{http_code}\n" --max-time 12 https://swan.catbird.blue/health
ssh netcup 'systemctl is-active catbird-mls-server catbird-nest-prod caddy postgresql@17-main catbird-firehose | tr "\n" " "'
```

Expected: `apex:200`, `wildcard:200`, `old:200`, and five `active`. The wildcard 200 is the load-bearing check — it proves edge TLS, origin TLS, and routing for `*.swan.place` **before** any account depends on it.

---

### Task 4: Point Swan's public URL at swan.place

**Files:**
- Modify on netcup: `/etc/systemd/system/swan.service` (one flag)

**Interfaces:**
- Consumes: Task 3's working vhost.
- Produces: OAuth metadata whose `issuer` is `https://swan.place`.

- [ ] **Step 1: Record the current issuer**

Run: `curl -s --max-time 12 https://swan.place/.well-known/oauth-authorization-server | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])"`
Expected: `https://swan.catbird.blue` — served over the new domain but still advertising the old issuer. That mismatch is what this task fixes.

- [ ] **Step 2: Change the flag**

```bash
ssh netcup 'sudo cp -a /etc/systemd/system/swan.service /etc/systemd/system/swan.service.bak.$(date +%Y%m%d-%H%M%S)
sudo sed -i "s|--public-url https://swan.catbird.blue|--public-url https://swan.place|" /etc/systemd/system/swan.service
sudo grep -n "public-url" /etc/systemd/system/swan.service'
```

Expected: exactly one line showing `--public-url https://swan.place`.

- [ ] **Step 3: Restart and verify the service is healthy**

```bash
ssh netcup 'sudo systemctl daemon-reload && sudo systemctl restart swan && sleep 12
systemctl is-active swan
sudo docker logs swan 2>&1 | tail -4'
```

Expected: `active`, and startup lines ending with `Server started and listening on 0.0.0.0:3000`.

- [ ] **Step 4: Verify the issuer changed**

```bash
curl -s --max-time 12 https://swan.place/.well-known/oauth-authorization-server | python3 -c "import json,sys; d=json.load(sys.stdin); print('issuer:', d['issuer']); print('par:', d['pushed_authorization_request_endpoint'])"
curl -s --max-time 12 https://swan.place/xrpc/com.atproto.server.describeServer
```

Expected: `issuer: https://swan.place`, the PAR endpoint on `swan.place`, and `describeServer` returning JSON. The issuer matters beyond cosmetics: confidential clients bind their assertion `aud` to it.

---

### Task 5: Provision the apex account

**Files:**
- Modify on netcup: `/etc/caddy/Caddyfile` (handle-proof handler inside the `swan.place` block)

**Interfaces:**
- Consumes: Task 4's issuer.
- Produces: an active account with handle `swan.place`, and a DID whose `serviceEndpoint` is `https://swan.place`.

**This is the first irreversible task.** Everything before it can be undone by reverting a flag; a PLC write cannot.

- [ ] **Step 1: Confirm no account exists for this handle yet**

```bash
ssh netcup 'sudo docker run --rm --user 994:984 --workdir /data \
  -v /srv/swan/data:/data -v /srv/swan/secrets:/run/secrets/swan-runtime:ro \
  swan:local account show --data-directory /data --did did:plc:7wr3tbi7gg5nyuocq64qietz 2>&1 | head -3'
```

Expected: the existing `swan.catbird.blue` account, `status: active`. It stays untouched; this records the starting state.

- [ ] **Step 2: Stop Swan to avoid SQLite contention with the CLI**

```bash
ssh netcup 'sudo systemctl stop swan && systemctl is-active swan || true'
```

Expected: `inactive`. The CLI writes the same control database the server holds open.

- [ ] **Step 3: Prepare the PLC identity — this writes to the public directory**

```bash
ssh netcup 'sudo docker run --rm --user 994:984 --workdir /data \
  -v /srv/swan/data:/data -v /srv/swan/secrets:/run/secrets/swan-runtime:ro \
  swan:local account prepare-plc \
    --data-directory /data \
    --handle swan.place \
    --request-id swan-place-apex-20260811-01 \
    --pds-origin https://swan.place \
    --repository-revision 3jzfcijpj2z2a \
    --operator-secret-file /run/secrets/swan-runtime/operator-secret \
    --account-kek-file /run/secrets/swan-runtime/account-kek 2>&1 | head -5'
```

Expected: one JSON line containing `"did": "did:plc:..."`, `"canonicalHandle": "swan.place"`. **Record that DID; Step 4 needs it.**

If this fails, re-run this exact command unchanged — the same `--request-id` re-derives the same keys and DID and adopts any registration that already succeeded. Do not change the request-id.

- [ ] **Step 4: Serve the handle proof for the apex**

Insert this into the `swan.place, *.swan.place` block in `/etc/caddy/Caddyfile`, immediately before the existing `handle {` line, substituting the DID from Step 3:

```
	@atprotoDid path /.well-known/atproto-did
	handle @atprotoDid {
		header Content-Type text/plain
		respond "did:plc:REPLACE_WITH_DID_FROM_STEP_3" 200
	}
```

Then validate and reload:

```bash
ssh netcup 'sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
sudo caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | grep -iE "^Error" | head -3; echo RELOADED'
curl -s --max-time 12 https://swan.place/.well-known/atproto-did; echo
```

Expected: `Valid configuration`, no errors, and the DID returned as plain text. `activate-plc` fetches this URL to prove handle control, so it must be live first.

- [ ] **Step 5: Activate**

```bash
ssh netcup 'sudo docker run --rm --user 994:984 --workdir /data \
  -v /srv/swan/data:/data -v /srv/swan/secrets:/run/secrets/swan-runtime:ro \
  swan:local account activate-plc \
    --data-directory /data \
    --request-id swan-place-apex-20260811-01 \
    --password-file /run/secrets/swan-runtime/account-password \
    --operator-secret-file /run/secrets/swan-runtime/operator-secret \
    --account-kek-file /run/secrets/swan-runtime/account-kek 2>&1 | head -5'
```

Expected: JSON with `"status": "active"` and the handle `swan.place`.

- [ ] **Step 6: Restart Swan and confirm the account**

```bash
ssh netcup 'sudo systemctl start swan && sleep 12 && systemctl is-active swan'
```

Expected: `active`.

---

### Task 6: Re-enable account-gated subsystems and verify end to end

**Files:**
- Modify on netcup: `/etc/systemd/system/swan.service` (subsystem flags, if they were removed)

**Interfaces:**
- Consumes: Task 5's active account.
- Produces: the migration's completion evidence.

- [ ] **Step 1: Confirm the subsystem flags are present**

```bash
ssh netcup 'grep -cE "enable-local-space-interop|enable-public-repository-mutations" /etc/systemd/system/swan.service'
```

Expected: `2`. These require at least one active account, which now exists on the new domain.

If the count is `0`, append exactly these six continuation lines to the `ExecStart` command in `/etc/systemd/system/swan.service`, before the closing line, keeping the trailing backslashes consistent with the surrounding lines:

```
  --enable-local-space-interop \
  --space-account-kek-file /run/secrets/swan-runtime/account-kek \
  --space-account-kek-id primary \
  --enable-public-repository-mutations \
  --public-account-kek-file /run/secrets/swan-runtime/account-kek \
  --public-account-kek-id primary
```

- [ ] **Step 2: Restart and confirm the space routes come up**

```bash
ssh netcup 'sudo systemctl restart swan && sleep 14 && systemctl is-active swan && sudo docker logs swan 2>&1 | tail -4'
```

Expected: `active`, and a log line reading `space notification receiver routes enabled`. That line is the proof the account-gated runtime started rather than falling back.

- [ ] **Step 3: Run the full verification set**

```bash
for p in "/health" "/.well-known/atproto-did" "/.well-known/oauth-authorization-server" "/.well-known/oauth-protected-resource" "/xrpc/com.atproto.server.describeServer"; do
  printf "%-52s " "$p"; curl -s -o /tmp/v.txt -w "%{http_code}" --max-time 12 "https://swan.place$p"; echo -n "  "; head -c 100 /tmp/v.txt; echo
done
curl -s -o /dev/null -w "wildcard:%{http_code}\n" --max-time 12 https://probe.swan.place/health
```

Expected: all `200`; the OAuth metadata shows `issuer` `https://swan.place`.

- [ ] **Step 4: Verify the identity in the public directory**

```bash
ssh netcup 'sudo docker run --rm --user 994:984 --workdir /data -v /srv/swan/data:/data -v /srv/swan/secrets:/run/secrets/swan-runtime:ro swan:local account show --data-directory /data --did <DID_FROM_TASK_5> 2>&1 | head -3'
curl -s --max-time 15 "https://plc.directory/<DID_FROM_TASK_5>" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['alsoKnownAs'], d['service'][0]['serviceEndpoint'])"
```

Expected: `status: active` with handle `swan.place`, and `['at://swan.place'] https://swan.place`.

- [ ] **Step 5: Confirm nothing else regressed**

```bash
ssh netcup 'systemctl is-active catbird-mls-server catbird-nest-prod caddy postgresql@17-main catbird-firehose swan | tr "\n" " "; echo; free -h | sed -n 2p'
curl -s -o /dev/null -w "old_domain:%{http_code}\n" --max-time 12 https://swan.catbird.blue/health
curl -s -o /dev/null -w "api:%{http_code}\n" --max-time 12 https://api.catbird.blue/xrpc/_health
```

Expected: six `active`, memory headroom unchanged, `old_domain:200` (the previous vhost still serves), and `api` responding as before (401 is its normal unauthenticated answer).

- [ ] **Step 6: Write the completion record and commit**

Create `docs/superpowers/plans/2026-08-11-swan-place-migration-completion-record.md` capturing: the new DID, the exact request-id used, the certificate SANs and expiry, the Caddyfile backup filenames, every verification result from Steps 3–5 verbatim, and anything that deviated from this plan. Then:

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Swan
jj commit docs/superpowers/plans/2026-08-11-swan-place-migration-completion-record.md -m "docs: record swan.place migration completion"
```

---

## Rollback

Through Task 4 inclusive: restore the backed-up `swan.service`, `daemon-reload`, restart, and Swan advertises `swan.catbird.blue` again. The DNS records, certificate, and Caddy vhost are harmless if left in place, and the old vhost never stopped serving.

After Task 5: the new DID exists permanently and cannot be withdrawn. Rollback means reverting `--public-url` and not using the new identity — no PLC operation is undone, only abandoned. This asymmetry is why the PLC write is the last irreversible step and why Tasks 1–4 prove the domain first.

A rejected Caddy config is self-limiting: Caddy swaps atomically, so a mistake leaves the running `catbird.blue` vhosts serving.

## Out of scope

Dynamic `*.swan.place` handle resolution (Swan answering `/.well-known/atproto-did` per `Host`), `account update-identity`, the SvelteKit web shell, OAuth signup screens, and account management. Those are the next three specs.
