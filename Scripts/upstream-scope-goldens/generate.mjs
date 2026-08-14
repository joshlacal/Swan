// Emits golden vectors by running upstream's own @atproto/oauth-scopes, unbuilt,
// at the commit Swan targets. The point is that no vector in the corpus is
// hand-transcribed: every expected value below is whatever the normative
// TypeScript actually returns.
//
//   node --experimental-transform-types --import ./ts-hook-register.mjs generate.mjs
//
import {
  ScopePermissions,
  ScopesSet,
  normalizeAtprotoOauthScope,
  normalizeAtprotoOauthScopeValue,
  isAtprotoOauthScope,
  isAtprotoDidRefAbsolute,
} from '@atproto/oauth-scopes'

const REFERENCE_COMMIT = 'bddc99fb24c34b4078b9bf65837283f37b49ab66'

// --- 1. Per-value parse + canonical form ------------------------------------

const SCOPE_VALUES = [
  // bulleted.app, verbatim from https://bulleted.app/oauth-client-metadata.json
  'atproto',
  'include:app.bulleted.authFull',
  'blob:image/*',
  'include:app.bulleted.spaceAccess',
  'space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self',

  // space: defaults and shapes
  'space:com.example.group',
  'space:com.example.group?authority=self',
  'space:com.example.group?authority=did:plc:z72i7hdynmk6r22z27h6tvur',
  'space:com.example.group?skey=*',
  'space:com.example.group?skey=default',
  'space:com.example.group?action=read',
  'space:com.example.group?action=read&action=create',
  'space:com.example.group?manage=create',
  'space:com.example.group?collection=app.bsky.feed.post',
  'space:com.example.group?authority=did:plc:z72i7hdynmk6r22z27h6tvur&skey=default&action=read',
  // parameter order and duplication
  'space:com.example.group?skey=default&authority=did:plc:z72i7hdynmk6r22z27h6tvur',
  'space:com.example.group?action=create&action=read',

  // repo / rpc / blob / account / identity
  'repo:app.bsky.feed.post',
  'repo:*',
  'repo:app.bsky.feed.post?action=create',
  'repo:app.bsky.feed.post?action=create&action=delete',
  'rpc:app.bsky.feed.getFeed?aud=did:web:example.com#bsky_fg',
  'rpc:*?aud=*',
  'rpc:app.bsky.feed.getFeed?aud=did:plc:z72i7hdynmk6r22z27h6tvur%23bsky_fg',
  'rpc:app.bsky.feed.getFeed?aud=*',
  'blob:*/*',
  'blob:image/png',
  'blob:image/svg+xml',
  'blob:image/*',
  'account:email',
  'account:email?action=manage',
  'account:*',
  'identity:handle',
  'identity:*',
  'include:com.example.permissionSet',

  // encoder edge cases — the ~ asymmetry and friends
  'space:com.example.group?skey=a~b',
  'space:com.example.group?skey=a%7Eb',
  'space:com.example.group?skey=a+b',
  'space:com.example.group?skey=a%20b',
  'space:com.example.group?skey=a,b',
  'space:com.example.group?skey=a:b',
  'space:com.example.group?skey=a/b',
  'space:com.example.group?skey=a@b',
  'space:com.example.group?skey=a%25b',

  // malformed / rejected
  '',
  'space:',
  'space:short',
  'space:com.example.group?unknown=1',
  'notafamily:whatever',
  'repo:',
  'blob:image',
  'rpc:app.bsky.feed.getFeed',
]

const values = SCOPE_VALUES.map((input) => {
  let canonical = null
  let threw = null
  try {
    canonical = normalizeAtprotoOauthScopeValue(input) ?? null
  } catch (err) {
    threw = String(err && err.message ? err.message : err)
  }
  return {
    input,
    isAtprotoOauthScope: isAtprotoOauthScope(input),
    canonical,
    threw,
    roundTripStable: canonical === null ? null : normalizeAtprotoOauthScopeValue(canonical) === canonical,
  }
})

// --- 2. Whole scope-string normalisation ------------------------------------

const SCOPE_STRINGS = [
  'atproto',
  'atproto include:app.bulleted.authFull blob:image/* include:app.bulleted.spaceAccess space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self',
  'repo:app.bsky.feed.post atproto',
  'atproto atproto',
  'atproto notafamily:whatever',
  'atproto space:com.example.group?skey=default&authority=did:plc:z72i7hdynmk6r22z27h6tvur',
]

const strings = SCOPE_STRINGS.map((input) => ({
  input,
  normalized: normalizeAtprotoOauthScope(input),
}))

// --- 3. Match outcomes ------------------------------------------------------

const GRANTS = {
  bulleted:
    'atproto include:app.bulleted.authFull blob:image/* include:app.bulleted.spaceAccess space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self',
  bareSpace: 'atproto space:com.example.group',
  spaceReadOnly: 'atproto space:com.example.group?authority=did:plc:z72i7hdynmk6r22z27h6tvur&skey=default&action=read',
  repoNarrow: 'atproto repo:app.bsky.feed.post?action=create',
  repoWide: 'atproto repo:*',
  blobImages: 'atproto blob:image/*',
  identityHandle: 'atproto identity:handle',
  atprotoOnly: 'atproto',
}

const REPO_CHECKS = [
  { action: 'create', collection: 'app.bsky.feed.post' },
  { action: 'delete', collection: 'app.bsky.feed.post' },
  { action: 'create', collection: 'app.bsky.graph.follow' },
]
const BLOB_CHECKS = [{ mime: 'image/png' }, { mime: 'image/svg+xml' }, { mime: 'video/mp4' }]
const RPC_CHECKS = [
  { aud: 'did:web:example.com#bsky_fg', lxm: 'app.bsky.feed.getFeed' },
  { aud: 'did:web:other.example#bsky_fg', lxm: 'app.bsky.feed.getFeed' },
]
const IDENTITY_CHECKS = [{ attr: 'handle' }, { attr: '*' }]
const ACCOUNT_CHECKS = [
  { attr: 'email', action: 'read' },
  { attr: 'email', action: 'manage' },
]
const SPACE_CHECKS = [
  { type: 'com.example.group', authority: 'did:plc:z72i7hdynmk6r22z27h6tvur', skey: 'default', action: 'read' },
  { type: 'com.example.group', authority: 'did:plc:z72i7hdynmk6r22z27h6tvur', skey: 'default', action: 'delete' },
  { type: 'com.example.group', authority: 'did:plc:other', skey: 'default', action: 'read' },
  { type: 'app.bulleted.space', authority: 'did:plc:z72i7hdynmk6r22z27h6tvur', skey: 'x', action: 'read_self' },
]

function outcomesFor(scopeString) {
  const p = new ScopePermissions(new ScopesSet(scopeString))
  const call = (fn, arg) => {
    try {
      return { arg, allowed: fn.call(p, arg) }
    } catch (err) {
      return { arg, allowed: null, threw: String(err && err.message ? err.message : err) }
    }
  }
  return {
    repo: REPO_CHECKS.map((a) => call(p.allowsRepo, a)),
    blob: BLOB_CHECKS.map((a) => call(p.allowsBlob, a)),
    rpc: RPC_CHECKS.map((a) => call(p.allowsRpc, a)),
    identity: IDENTITY_CHECKS.map((a) => call(p.allowsIdentity, a)),
    account: ACCOUNT_CHECKS.map((a) => call(p.allowsAccount, a)),
    space: SPACE_CHECKS.map((a) => call(p.allowsSpace, a)),
  }
}

const matches = Object.fromEntries(
  Object.entries(GRANTS).map(([name, scope]) => [name, { scope, outcomes: outcomesFor(scope) }]),
)

// --- 4. did-ref vectors (Q1) -------------------------------------------------

const DID_REFS = [
  'did:plc:z72i7hdynmk6r22z27h6tvur#service_id',
  'did:plc:asdf123#service_id',
  'did:web:example.com#bsky_fg',
  'did:web:example.com:path#bsky_fg',
  'did:example:456#service_id',
  'did:plc:z72i7hdynmk6r22z27h6tvur',
  'did:plc:z72i7hdynmk6r22z27h6tvur#',
  'did:plc:z72i7hdynmk6r22z27h6tvur#a#b',
  'did:plc:z72i7hdynmk6r22z27h6tvur#has/slash',
  'did:plc:z72i7hdynmk6r22z27h6tvur#has?question',
  'did:plc:z72i7hdynmk6r22z27h6tvur#has%20escape',
  'did:plc:z72i7hdynmk6r22z27h6tvur#has space',
  'not-a-did#frag',
]

const didRefs = DID_REFS.map((input) => ({
  input,
  isAtprotoDidRefAbsolute: isAtprotoDidRefAbsolute(input),
}))

// --- 5. Encoder asymmetry (Q3) ----------------------------------------------

const ENCODER_INPUTS = ['a~b', 'a+b', 'a b', 'a,b', 'a:b', 'a/b', 'a@b', 'a%b', 'a&b', 'a=b', 'é']

const encoders = ENCODER_INPUTS.map((raw) => ({
  raw,
  encodeURIComponent: encodeURIComponent(raw),
  urlSearchParams: new URLSearchParams([['x', raw]]).toString().slice(2),
}))

process.stdout.write(
  JSON.stringify(
    {
      $comment:
        'Generated by running @atproto/oauth-scopes unbuilt at the pinned commit. Do not hand-edit: regenerate.',
      referenceCommit: REFERENCE_COMMIT,
      source: 'packages/oauth/oauth-scopes (run unbuilt via node --experimental-transform-types)',
      nodeVersion: process.version,
      values,
      strings,
      matches,
      didRefs,
      encoders,
    },
    null,
    2,
  ) + '\n',
)
