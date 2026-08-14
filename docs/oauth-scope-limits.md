# OAuth scope limits and divergences

Swan's OAuth authorization server applies bounds and one admission rule that
upstream `@atproto` does not. Both are deliberate, and both are published here
rather than advertised through a nonstandard authorization-server metadata field,
because a nonstandard key is a worse interop outcome than a documented limit.

Upstream imposes no scope length limit at all: `OAuthClientMetadata.scope` is
validated by `oauthScopeSchema`
(`packages/oauth/oauth-types/src/oauth-scope.ts:17-19`), which is
`OAUTH_SCOPE_REGEXP` (`:5-6`) and nothing else — a charset and separator grammar
with no quantifier bound and no dictionary of permission families. A conformant
client can therefore construct a legal scope that Swan refuses. These are the
exact points at which that happens.

## Two budgets

They measure different strings, are enforced in different places, and blame
different parties. The numbers currently coincide; the budgets do not.

| budget | measures | enforced at | reported as |
|---|---|---|---|
| **raw input** | exactly the bytes the client sent in `scope`, before any Swan transformation | the wire, at PAR and at the localhost bridge | `invalid_request` — the client sent too much |
| **expanded grant** | what Swan holds *after its own* rewrites: `authority=self` resolved to the subject DID today, plus permission-set expansion when that ships | token mint, and persistence | a server-side failure — Swan's expansion grew a legal request past the limit |

| bound | value |
|---|---|
| bytes per scope | 1024 |
| scopes per request | 64 |
| bytes per whole `scope` parameter | 8192 |

A short request can exceed the expanded-grant budget without ever approaching
the raw-input one. That is why the two are named separately: the failure belongs
to Swan, not to the client, and it must not be reported as though the client had
sent something oversized.

## Divergences from upstream

**Swan rejects an unparseable requested scope; upstream silently drops it.**
Upstream's provider filters unrecognised scopes out of the request
(`request-manager.ts:177-185`) and relies on a re-consent path to recover once
support lands. Swan has no such path, and a silent drop interacts badly with the
registration subset check: a client asking for `atproto` plus one malformed
`space:` grant would receive an `atproto`-only token and then an opaque 401 at
the resource plane, with nothing in the OAuth response pointing at the cause. A
requested scope that does not parse is `invalid_scope` at PAR.

A scope Swan has already *issued* behaves the opposite way, and deliberately: a
stored scope a future binary cannot parse grants nothing, and never fails a
request open or crashes it.

**Swan's base-scope floor is looser than upstream's.** Upstream requires the
literal `atproto` scope unconditionally (`request-manager.ts:241-243`). Swan
accepts `atproto` **or** any `space:` grant, so a request carrying only `space:…`
is admitted where a reference authorization server rejects it. Tightening this
would break every existing space-only session.

**A stated write action must name a collection.** A `space:` grant that
explicitly names `create`, `update` or `delete` and no `collection` is rejected
at PAR as `invalid_scope`, because such a grant is a latent whole-repository
capability. Upstream expresses the same intent as a default rather than a gate —
`collection` defaults to the empty list, meaning "no write targets, not all
collections" (`space-permission.ts:193-198`) — and so mints a grant that
authorizes no writes instead of refusing the request. A grant that does not state
`action` at all is unaffected: its defaulted action set beside the default empty
collection authorizes no writes, exactly as upstream intends.

**`openid` is refused.** The literal token is rejected at the tokenizer and
reported as `invalid_scope`, matching upstream (`request-manager.ts:243-248`).

## What registration does not do

Client metadata `scope` is validated lexically and against the raw-input budget,
and nothing else. **Registration grants nothing.** A client may safely declare a
scope name Swan does not implement, or one that does not exist yet; it is refused
later, at PAR, if it is actually requested. This matches upstream exactly, which
never asks at registration whether a token names a known permission family.
