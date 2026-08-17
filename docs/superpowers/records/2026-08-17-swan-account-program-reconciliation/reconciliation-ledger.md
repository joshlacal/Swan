# Reconciliation ledger: Swan account-program Task 1

Workspace: /Users/joshlacalamito/Developer/Catbird+Petrel/Swan-account-integration

This is a read-only topology ledger. No production source was resolved or
edited by Task 1. The immutable initial merge intentionally remains conflicted
at five textual paths.

## Frozen revisions, ancestry, and source trees

| Role | Full commit | Change ID | Parents | Root tree / state |
|---|---|---|---|---|
| nearest common ancestor | d58a7583ddb4d5793061d7865a6f4daf922ba4b8 | ouystzzupzpzsvzrlynpwxuzyvsotkrr | a78c539fe00cc7388ba0492640ee7df3a482c422 | 9ad9c871bde78aaa1b258041cf5446ae4674fd1c; resolved |
| current-main parent | d0e8e114c0deb4a6c38758466063f1ca1ac8224c | rnyupkpsmvvxuxkxplopzspstpsotwqk | 27ae0e4ac88ba9d8d16c49c473f81a59ed169c92 | 81f722fc0cbe359ed31a5e1e468278eed326ce86; resolved |
| account-program parent | 30b751b6a083babdcd6d73c3a385e7251aa63b3d | vtqukyumrrklovsnrvvltsvxlnvouszk | 9d44bf290e1a65631347e38a888dac9f5aabf408 | 17e02e47bf8fcd5365da66091530b1234db4cee7; resolved |
| excluded empty child | 0c04c519b046b209eda8f9dee9fd1884ac657fa3 | upvxvprrpslkloswvtxtumqrwslvwzwm | 30b751b6a083babdcd6d73c3a385e7251aa63b3d | 17e02e47bf8fcd5365da66091530b1234db4cee7; empty and tree-identical to account parent |
| immutable initial integration working copy (authoritative Task 1 topology) | 0d2dbc498daf32c897011d2631e1f9f91b036c75 | mwkpwxmmqyxpzrxvxumuxztvyxnvyvrp | d0e8e114c0deb4a6c38758466063f1ca1ac8224c, 30b751b6a083babdcd6d73c3a385e7251aa63b3d | conflicted root sides 8d9fc72a60419a2b5e39ac15635e8e6a235d7543, 721aeca54b4e68e957c70bfda42483f2f53faff1, 05ef6728f450f5e37d8a86f882a23a94cf7b3669; empty |
| later documentation successor (not frozen) | 3a7c2d9d9e2a48340999d927f693bd71476bbe2a | mwkpwxmmqyxpzrxvxumuxztvyxnvyvrp | d0e8e114c0deb4a6c38758466063f1ca1ac8224c, 30b751b6a083babdcd6d73c3a385e7251aa63b3d | same topology; packaged four-path documentation/metadata delta only |

The workspace-add operation was 9ac9a6fbb307 and used only revisions
d0e8e114c0de and 30b751b6a083. The nearest common-ancestor heads query,
heads(ancestors(d0e8e114c0de) & ancestors(30b751b6a083)), returns only
d58a7583ddb4d5793061d7865a6f4daf922ba4b8. The excluded child is a
single-parent descendant of the account tip, is empty, and has the same root
tree as that tip.

The topology operation's clean working-copy check was run at
9ac9a6fbb307: `jj --at-operation 9ac9a6fbb307 status` reported no working-copy
changes while listing the five expected unresolved source conflicts. The
immutable initial merge `0d2dbc498daf32c897011d2631e1f9f91b036c75` is the sole
Task 1 topology and preservation authority. The later reviewed documentation
successor `3a7c2d9d9e2a48340999d927f693bd71476bbe2a` is not a replacement
topology; its four tracked paths are accounted for below. No production source
path was edited here.

## Exact jj verification and counts

All VCS commands below were run from this workspace with jj; Git was not used.
The source-tree identities in the frozen table come from
`jj debug object commit <full-commit>` (`root_tree`), and the topology is
confirmed with the following commands and results:

```text
jj log -r 'heads(ancestors(d0e8e114c0de) & ancestors(30b751b6a083))'
  -> one head: d58a7583ddb4d5793061d7865a6f4daf922ba4b8
jj diff --from d58a7583 --to d0e8e114c0de --summary
  -> A=91 M=116 D=1 (208 paths)
jj diff --from d58a7583 --to 30b751b6a083 --summary
  -> A=99 M=17 D=0 (116 paths)
comm -12 <(jj diff --from d58a7583 --to d0e8e114c0de --name-only | sort) \
  <(jj diff --from d58a7583 --to 30b751b6a083 --name-only | sort)
  -> 8 paths (the table below)
jj diff --from d0e8e114c0de --to 30b751b6a083 --summary
  -> A=99 M=127 D=90 (316 paths)
jj diff --from 30b751b6a083 --to d0e8e114c0de --summary
  -> A=90 M=127 D=99 (316 paths)
```

The immutable initial integration commit
`0d2dbc498daf32c897011d2631e1f9f91b036c75` has exactly the two required
parents and is empty but conflicted. The later documentation successor
`3a7c2d9d9e2a48340999d927f693bd71476bbe2a` retains those same parents but is
not the frozen topology. `jj log -r 0c04c519b046` confirms that the excluded
child is empty and has only `30b751b6a083` as parent; `jj diff --from
30b751b6a083 --to 0c04c519b046 --name-only` returns zero paths.

For every one of the 90 tip-to-tip D paths below, these checks returned zero:

```text
comm -23 <(jj diff --from d0e8e114c0de --to 30b751b6a083 --summary \
  | awk '$1=="D" {sub(/^D /,""); print}' | sort) \
  <(jj file list -r 0d2dbc498daf32c897011d2631e1f9f91b036c75 | sort)
  -> missing from immutable initial merge: 0
comm -12 <(jj diff --from d0e8e114c0de --to 30b751b6a083 --summary \
  | awk '$1=="D" {sub(/^D /,""); print}' | sort) \
  <(jj diff --from d0e8e114c0de --to 0d2dbc498daf32c897011d2631e1f9f91b036c75 --name-only | sort)
  -> differing from current-main content in immutable initial merge: 0
```

Thus each D path is present and unchanged from current main in the immutable
initial two-parent merge. The generated/profile subset is 12 paths: 3 `Profiles/`, 5
`Scripts/upstream-scope-goldens/`, 3 generated `Sources/SwanSpacesWire/` files,
and 1 pinned OAuth fixture; the same missing/differing counts are zero.

## Eight jointly changed paths

The common-ancestor-to-main and common-ancestor-to-account path-set
intersection is exactly these eight M/M paths. The immutable initial merge
state is from `jj file list -r
0d2dbc498daf32c897011d2631e1f9f91b036c75`.

| Path | Common to main | Common to account | Current merge | Disposition |
|---|---|---|---|---|
| Package.swift | M | M | auto-merged file | preserve both changes for serial integration |
| Sources/SwanHTTP/SwanHTTP.swift | M | M | textual conflict, 2-sided | leave unresolved for integration owner |
| Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift | M | M | textual conflict, 2-sided | leave unresolved for integration owner |
| Sources/SwanSQLite/SwanSQLite.swift | M | M | auto-merged file | preserve both changes for serial integration |
| Sources/SwanSpaces/SwanSpaces.swift | M | M | textual conflict, 2-sided | leave unresolved for integration owner |
| Sources/SwanStorage/AppPasswordStore.swift | M | M | textual conflict, 2-sided | leave unresolved; main typed app-password contract remains authority |
| Sources/swan/SwanCommand.swift | M | M | textual conflict, 2-sided | leave unresolved for serial runtime integration |
| Tests/SwanHTTPTests/RemoteOAuthAuthorizationServerHTTPTests.swift | M | M | auto-merged file | preserve both changes for reviewed integration |

The five textual conflicts are exactly SwanHTTP.swift,
SwanOAuthAuthorizationServerHTTP.swift, SwanSpaces.swift,
AppPasswordStore.swift, and SwanCommand.swift. The other three jointly
changed paths are jj files with no conflict.

## Main-only apparent deletions

The tip-to-tip main-to-account diff labels 90 paths as D. Every path below is
present in the immutable initial two-parent merge and is byte-identical to the
same path at current main. There are no exceptions.

| Path | Disposition |
|---|---|
| Profiles/permissioned-data-0016-2026-08-15.generated-wire.sha256 | preserved by two-parent merge |
| Profiles/permissioned-data-0016-2026-08-15.json | preserved by two-parent merge |
| Profiles/permissioned-data-0016-2026-08-15.lexicons.sha256 | preserved by two-parent merge |
| Scripts/upstream-scope-goldens/README.md | preserved by two-parent merge |
| Scripts/upstream-scope-goldens/generate.mjs | preserved by two-parent merge |
| Scripts/upstream-scope-goldens/ts-hook-register.mjs | preserved by two-parent merge |
| Scripts/upstream-scope-goldens/ts-hook.mjs | preserved by two-parent merge |
| Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh | preserved by two-parent merge |
| Sources/SwanAccounts/AppPasswordCredentials.swift | preserved by two-parent merge |
| Sources/SwanAccounts/AppPasswordPresets.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/AtprotoSyntax.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/AccountPermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/BlobPermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/IdentityPermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/IncludeScope.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/IncludeScopeExpansion.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/RepoPermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/RpcPermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/Families/SpacePermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/LexPermissionSyntax.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/LexiconPermissionSet.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopeParameterBag.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopeParameterSchema.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopeParseError.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopePermission.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopePermissions.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopeStringSyntax.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/ScopeToken.swift | preserved by two-parent merge |
| Sources/SwanCore/OAuthScopes/SwanLexiconResolution.swift | preserved by two-parent merge |
| Sources/SwanHTTP/ScopeDescription.swift | preserved by two-parent merge |
| Sources/SwanHTTP/ScopeEnforcement.swift | preserved by two-parent merge |
| Sources/SwanHTTP/SwanCORS.swift | preserved by two-parent merge |
| Sources/SwanHTTP/SwanLegacySessionXRPC.swift | preserved by two-parent merge |
| Sources/SwanInterop/SwanLexiconAuthorityResolver.swift | preserved by two-parent merge |
| Sources/SwanInterop/SwanLexiconResolver.swift | preserved by two-parent merge |
| Sources/SwanOAuth/DurableLegacySessionService.swift | preserved by two-parent merge |
| Sources/SwanOAuth/LegacySessionJWT.swift | preserved by two-parent merge |
| Sources/SwanOAuth/OAuthLexiconScopeResolution.swift | preserved by two-parent merge |
| Sources/SwanOAuth/OAuthScopeAdmission.swift | preserved by two-parent merge |
| Sources/SwanPublicRepository/RepositoryMSTProof.swift | preserved by two-parent merge |
| Sources/SwanPublicRepositoryTestSupport/PublicRepositoryProofFixtures.swift | preserved by two-parent merge |
| Sources/SwanSQLite/AppPasswordControlStore.swift | preserved by two-parent merge |
| Sources/SwanSQLite/LegacySessionControlStore.swift | preserved by two-parent merge |
| Sources/SwanSQLite/OAuthLexiconDocumentStore.swift | preserved by two-parent merge |
| Sources/SwanSpaces/AuthorizationContextTestingSupport.swift | preserved by two-parent merge |
| Sources/SwanSpaces/SpaceScopeTargets.swift | preserved by two-parent merge |
| Sources/SwanSpacesWire/Generated/Lexicons/Com/Atproto/ComAtprotoSimplespaceGetSpace.swift | preserved by two-parent merge |
| Sources/SwanSpacesWire/Generated/Lexicons/Com/Atproto/ComAtprotoSpaceListBlobs.swift | preserved by two-parent merge |
| Sources/SwanSpacesWire/Generated/Lexicons/Com/Atproto/ComAtprotoSpaceUnregisterNotify.swift | preserved by two-parent merge |
| Sources/SwanStorage/LegacySessionStore.swift | preserved by two-parent merge |
| Tests/SwanAccountsTests/AppPasswordPresetTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesAccountBlobIdentityTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesGrammarTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesIncludeAndDispatchTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesIncludeExpansionTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesRepoRpcTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesSpaceTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/OAuthScopesTransitionTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/ScopePermissionsFenceTests.swift | preserved by two-parent merge |
| Tests/SwanCoreTests/SpaceWriteTargetInvariantTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/LegacySessionHTTPTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/PermissionedScopeE2ESupport.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/RefreshScopeRederivationTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/RemoteClientPermissionedScopeE2ETests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/ScopeDescriptionTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/ScopeProvenanceDurabilityTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/ScopeRefreshSurvivalMigrationTests.swift | preserved by two-parent merge |
| Tests/SwanHTTPTests/SwanCORSTests.swift | preserved by two-parent merge |
| Tests/SwanInteropTests/OAuthRegistrationLexicalFloorTests.swift | preserved by two-parent merge |
| Tests/SwanInteropTests/SwanLexiconAuthorityResolverTests.swift | preserved by two-parent merge |
| Tests/SwanInteropTests/SwanLexiconResolverAdversarialTests.swift | preserved by two-parent merge |
| Tests/SwanInteropTests/SwanLexiconResolverTests.swift | preserved by two-parent merge |
| Tests/SwanOAuthTests/DurableLegacySessionServiceTests.swift | preserved by two-parent merge |
| Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json | preserved by two-parent merge |
| Tests/SwanOAuthTests/OAuthLexiconScopeResolutionTests.swift | preserved by two-parent merge |
| Tests/SwanOAuthTests/UpstreamScopeConformanceTests.swift | preserved by two-parent merge |
| Tests/SwanOAuthTests/UpstreamScopeCorpus.swift | preserved by two-parent merge |
| Tests/SwanOAuthTests/UpstreamScopeCorpusIntegrityTests.swift | preserved by two-parent merge |
| Tests/SwanPublicRepositoryTests/RepositoryMSTProofTests.swift | preserved by two-parent merge |
| Tests/SwanSQLiteTests/AppPasswordStoreSQLiteTests.swift | preserved by two-parent merge |
| Tests/SwanSQLiteTests/OAuthScopeProvenancePersistenceTests.swift | preserved by two-parent merge |
| Tests/SwanSQLiteTests/PermissionedSpaceListBlobsTests.swift | preserved by two-parent merge |
| Tests/SwanSpacesTests/SpaceScopeTargetTests.swift | preserved by two-parent merge |
| docs/oauth-scope-limits.md | preserved by two-parent merge |
| docs/permissioned-data-repin-scope.md | preserved by two-parent merge |
| docs/superpowers/plans/2026-08-14-oauth-scopes-phase2-lexicon-resolution.md | preserved by two-parent merge |
| docs/superpowers/plans/2026-08-14-phase2-netcup-redeploy.md | preserved by two-parent merge |
| docs/superpowers/plans/2026-08-15-swan-scoped-app-passwords.md | preserved by two-parent merge |
| docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md | preserved by two-parent merge |
| docs/superpowers/specs/2026-08-14-oauth-permission-scopes-operating-instructions.md | preserved by two-parent merge |

## Generated/profile preservation subset

The three current-main profile files are included in the table above and are
preserved by the merge. The generated subset also includes the five
upstream-scope-goldens files, the three generated SwanSpacesWire files, and
the pinned OAuth fixture; all 12 are preserved by the two-parent merge.

Task 1 does not resolve the five textual conflicts and does not authorize
push, deployment, restart, relay activation, or live swan.place probing.
