# Forum test vehicle

The `swan lab forum` command is a minimal command-line test vehicle for testing permissioned-data social workflows across distributed hosts. It exercises a space authority, multiple per-user permissioned repositories on mixed host implementations, and a consumer syncer that merges records from multiple writers into a single conversation thread.

The test vehicle uses existing lexicon patterns without custom schemas:
- Space type: `blue.catbird.lab.forum`
- Record collections: `blue.catbird.lab.post` and `blue.catbird.lab.reply`
- The permissioned space layer treats all record contents as opaque values.

## Subcommands

### Provision a space

The `provision` subcommand creates a forum space on an authority host and registers a member account:

```sh
export SWAN_LAB_AUTHORITY_HANDLE=admin.swan.test
export SWAN_LAB_AUTHORITY_PASSWORD=operator-password

swift run swan lab forum provision \
  --authority-url https://swan.test \
  --space at://did:plc:authority123/space/blue.catbird.lab.forum/lab-1 \
  --member-did did:plc:member456
```

### Post a record

The `post` subcommand writes a record into the caller's own permissioned repository at their home PDS. The operation uses OAuth with the space-write scope (`com.atproto.space.write`). The read-only space credential issued by an authority cannot be used as a write capability.

```sh
export SWAN_LAB_PRODUCER_HANDLE=alice.pds.test
export SWAN_LAB_PRODUCER_PASSWORD=member-password

swift run swan lab forum post \
  --producer-url https://pds.test \
  --space at://did:plc:authority123/space/blue.catbird.lab.forum/lab-1 \
  --text "hello forum" \
  --reply-to at://did:plc:authority123/space/blue.catbird.lab.forum/lab-1/did:plc:member456/blue.catbird.lab.post/2222222222222
```

Options and defaults:
- `--collection`: Defaults to `blue.catbird.lab.post`.
- `--rkey`: Defaults to a freshly minted sortable TID.
- `--reply-to`: References the parent post URI. Replies are stored using the `{root, parent}` schema convention matching `app.bsky.feed.post`.
- `--reply-root`: Defaults to the value of `--reply-to` when omitted.
- `--repo`: Target repository DID. When using OAuth authentication, this defaults to the authenticated subject DID.

### Sync and render a thread

The `thread` subcommand acts as a consumer client (such as Carol reading the forum):

1. Mints a single-use delegation token at the consumer's home PDS.
2. Exchanges the delegation token at the space authority for a single space read credential.
3. Discovers the authorized writer set by querying `com.atproto.space.listRepos` on the authority.
4. For each writer repository, fetches, cryptographically verifies (checking signed commits and LtHash commitments), and durably applies incremental operations from the writer's host using the space credential. If incremental history is unavailable, it falls back to full-CAR repository recovery.
5. Merges records from all writers into a single conversation thread, renders the thread to standard output, and writes a sanitized verification artifact.

```sh
export SWAN_LAB_CONSUMER_HANDLE=carol.pds.test
export SWAN_LAB_CONSUMER_PASSWORD=consumer-password
export SWAN_LAB_PERMISSIONED_COMMIT_KEY=... # base64url secp256k1 writer public key

swift run swan lab forum thread \
  --consumer-url https://pds.test \
  --authority-url https://swan.test \
  --space at://did:plc:authority123/space/blue.catbird.lab.forum/lab-1 \
  --receiver-did did:plc:consumer789 \
  --data-directory .swan-data \
  --output /tmp/forum-thread.json
```

#### Writer host and key resolution

- **Writer host discovery:** The syncer resolves each writer host from the writer DID's `#atproto_pds` service endpoint in PLC, or from explicit `--writer-host <did>=<url>` command-line overrides.
- **Commit signature verification:** Set `SWAN_LAB_PERMISSIONED_COMMIT_KEY` to supply a global public key for verifying writer repository commits. When writers use distinct keys, append the writer's public key to the host override as `--writer-host <did>=<url>:<did:key:z...>` to override the global verification key for that specific writer.
- **Output artifact:** The `--output` file is written with `0600` permissions. It contains counts, DIDs, record CIDs, and post text. Credentials, tokens, and private keys are never written to the output file.

## Thread merge semantics

Thread reconstruction is implemented by `ForumThreadMerger` using deterministic ordering rules:

- **Root posts:** A record whose `reply.root` field is missing or references its own URI is treated as a top-level root post.
- **Child replies:** A record with a valid `reply.parent` field attaches directly under the identified parent post.
- **Orphaned replies:** If a reply's parent record is absent from the synced repository data, the reply is placed into a separate `unlinked` section.
- **Sorting order:** Root posts and sibling replies are sorted primarily by record timestamp (`createdAt`, falling back to the TID timestamp extracted from the record key), secondarily by repository revision, and finally by record URI.
- **Multi-writer convergence:** Records authored by different writer DIDs merge into the same unified thread tree.
