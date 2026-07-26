# Swan threat boundaries

Permissioned data provides access control, not end-to-end confidentiality. A
repo or space host can read data it serves. Swan’s alpha therefore focuses on
preventing accidental public exposure and unauthorized cross-space access.

- `AuthorizationContext` is explicit: public, account OAuth, self-only read,
  space credential, and service contexts are distinct. No repository API takes
  an authenticated boolean.
- A space credential is read-only at the repo host. Writes require a scope
  covering the authenticated account’s own `(space, repo)`.
- The content-binding MAC is a deniable integrity check, never an author
  signature. `verifyContextSignature` and `verifyContentBinding` remain
  separate APIs.
- Account keys are encrypted in owner-only files with a process/mounted-secret
  master key. The master key, tokens, passwords, DPoP private keys, and IKM
  cannot be fixture or logging values.
- Remote OAuth metadata/JWKS retrieval must be HTTPS and reject unsafe
  destinations and redirects except explicit loopback laboratory settings.
- Operator management is a separate loopback listener protected by an operator
  secret; it is not a browser administration surface.

The current in-process HMAC credential authority exists only to exercise local
policy semantics. It is not a replacement for signed JWT delegation tokens or
space credentials on the wire.
