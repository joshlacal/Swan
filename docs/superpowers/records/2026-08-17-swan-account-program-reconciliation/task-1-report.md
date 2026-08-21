# Task 1 report: topology and reconciliation evidence

Status: DONE

## Commands and frozen values

All VCS commands were run in
/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-account-integration
using jj only. Git was not used to write history.

- jj workspace-add operation: 9ac9a6fbb307.
- Immutable initial merge working-copy commit (Task 1 authority):
  0d2dbc498daf32c897011d2631e1f9f91b036c75.
- Later documentation successor (not a frozen topology):
  3a7c2d9d9e2a48340999d927f693bd71476bbe2a (same two parents).
- Parent revisions: d0e8e114c0deb4a6c38758466063f1ca1ac8224c and
  30b751b6a083babdcd6d73c3a385e7251aa63b3d.
- Nearest common ancestor: d58a7583ddb4d5793061d7865a6f4daf922ba4b8.
- Excluded empty child: 0c04c519b046b209eda8f9dee9fd1884ac657fa3.

The initial topology check was clean at operation 9ac9a6fbb307:
`jj --at-operation 9ac9a6fbb307 status` reported no working-copy changes and
the five expected unresolved source conflicts. All topology and preservation
proofs below bind to immutable `0d2dbc498daf32c897011d2631e1f9f91b036c75`,
never to a mutable working-copy symbol. The later successor is documented only
to account for its packaged delta; no production-source path was edited here.

## Focused jj verification

1. `jj log -r 'heads(ancestors(d0e8e114c0de) & ancestors(30b751b6a083))'`
   returned one head: d58a7583ddb4d5793061d7865a6f4daf922ba4b8.
2. `jj diff --from d58a7583 --to d0e8e114c0de --summary` counted A=91,
   M=116, D=1, total=208.
3. `jj diff --from d58a7583 --to 30b751b6a083 --summary` counted A=99,
   M=17, D=0, total=116.
4. The sorted `--name-only` intersection of those two diffs counted exactly 8
   jointly changed paths; they are all listed in reconciliation-ledger.md.
5. `jj diff --from d0e8e114c0de --to 30b751b6a083 --summary` counted A=99,
   M=127, D=90, total=316.
6. The reverse diff counted A=90, M=127, D=99, total=316.
7. `jj diff --from 30b751b6a083 --to 0c04c519b046 --name-only` counted zero
   paths; the excluded child is empty and tree-identical to the account tip.
8. Comparing the 90 D paths with `jj file list -r
   0d2dbc498daf32c897011d2631e1f9f91b036c75` found present=90, missing=0.
9. Comparing the 90 D paths with `jj diff --from d0e8e114c0de --to
   0d2dbc498daf32c897011d2631e1f9f91b036c75 --name-only` found
   differing/no-diff=0/90.
10. `jj file list -r
    0d2dbc498daf32c897011d2631e1f9f91b036c75` with the eight jointly changed paths reported exactly
    five `conflict=true sides=2` entries and three regular `file conflict=false`
    entries.
11. The generated/profile preservation subset contains 12 paths (3 profiles,
    5 upstream-scope goldens, 3 generated SwanSpacesWire files, 1 pinned OAuth
    fixture); all 12 are present and unchanged from current main.

## Concerns

The merge remains intentionally conflicted at five textual paths. Task 1 did
not resolve them, commit them, or run tests, per the narrowed task contract.
A Sol topology review remains the next gate before Task 2. Push, deployment,
restart, relay activation, and live swan.place probing are out of scope.

## Sol fix round 1: immutable preservation proof and packaged delta

This fix round removes the mutable working-copy reference from the topology
and preservation evidence. The immutable initial merge
`0d2dbc498daf32c897011d2631e1f9f91b036c75` is the authority. The later
documentation successor under review is
`3a7c2d9d9e2a48340999d927f693bd71476bbe2a`; it retains the same two parents
but is not substituted for the frozen topology.

Focused commands were run with `--ignore-working-copy`:

```text
jj --ignore-working-copy log -r 0d2dbc498daf32c897011d2631e1f9f91b036c75 \
  --no-graph -T 'self.commit_id() ++ " parents=" ++ self.parents().map(|p| p.commit_id()).join(",") ++ " conflict=" ++ self.conflict() ++ " empty=" ++ self.empty() ++ "\\n"'
  -> 0d2dbc498daf32c897011d2631e1f9f91b036c75
     parents=d0e8e114c0deb4a6c38758466063f1ca1ac8224c,30b751b6a083babdcd6d73c3a385e7251aa63b3d
     conflict=true empty=true

jj --ignore-working-copy diff --from d0e8e114c0deb4a6c38758466063f1ca1ac8224c \
  --to 30b751b6a083babdcd6d73c3a385e7251aa63b3d --summary \
  | awk '$1=="D" {n++} END {print n+0}'
  -> 90

comm -23 <(jj --ignore-working-copy diff --from d0e8e114c0deb4a6c38758466063f1ca1ac8224c \
  --to 30b751b6a083babdcd6d73c3a385e7251aa63b3d --summary \
  | awk '$1=="D" {sub(/^D /,""); print}' | sort) \
  <(jj --ignore-working-copy file list -r 0d2dbc498daf32c897011d2631e1f9f91b036c75 | sort) \
  | wc -l
  -> missing from immutable initial merge: 0

comm -12 <(jj --ignore-working-copy diff --from d0e8e114c0deb4a6c38758466063f1ca1ac8224c \
  --to 30b751b6a083babdcd6d73c3a385e7251aa63b3d --summary \
  | awk '$1=="D" {sub(/^D /,""); print}' | sort) \
  <(jj --ignore-working-copy diff --from d0e8e114c0deb4a6c38758466063f1ca1ac8224c \
  --to 0d2dbc498daf32c897011d2631e1f9f91b036c75 --name-only | sort) \
  | wc -l
  -> differing from current-main content in immutable initial merge: 0
```

The 90/0 result means all 90 main-only tip-to-tip deletion paths are present
in `0d2dbc...`, and none appears in the immutable initial merge's diff from
current main. The full 90-path preservation table remains above.

The reviewed packaged delta is exactly four tracked paths, not two:

```text
jj --ignore-working-copy diff --from 0d2dbc498daf32c897011d2631e1f9f91b036c75 \
  --to 3a7c2d9d9e2a48340999d927f693bd71476bbe2a --summary
  -> M .gitignore
     A docs/superpowers/plans/2026-08-17-swan-account-program-reconciliation-and-landing.md
     A docs/superpowers/records/2026-08-17-swan-account-program-reconciliation/reconciliation-ledger.md
     A docs/superpowers/records/2026-08-17-swan-account-program-reconciliation/task-1-report.md

jj --ignore-working-copy diff --from 0d2dbc498daf32c897011d2631e1f9f91b036c75 \
  --to 3a7c2d9d9e2a48340999d927f693bd71476bbe2a --name-only | wc -l
  -> 4
```

Ownership and intent for those four paths:

| Path | Status | Ownership / reason |
|---|---|---|
| `.gitignore` | M | Controller-owned workspace-local SDD isolation; the exact addition is `/.superpowers/`. |
| `docs/superpowers/plans/2026-08-17-swan-account-program-reconciliation-and-landing.md` | A | Controller-owned implementation plan; not one of the two Task 1 record files. |
| `docs/superpowers/records/2026-08-17-swan-account-program-reconciliation/reconciliation-ledger.md` | A | Task 1 reconciliation artifact. |
| `docs/superpowers/records/2026-08-17-swan-account-program-reconciliation/task-1-report.md` | A | Task 1 evidence report. |

No production source conflict was resolved and no commit was created in this
fix round.
