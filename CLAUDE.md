# CLAUDE.md

This file provides guidance to Claude Code when working with the Swan codebase.

## Developer guidelines

Swan's primary developer and agent documentation lives in [AGENTS.md](AGENTS.md). Refer to `AGENTS.md` for:
- Target architecture and module layout across Swift packages and the Svelte frontend.
- The three storage planes (`control.sqlite`, `<did>.sqlite`, `firehose.sqlite`) and per-account data isolation requirements.
- Protocol profiles (`Profiles/*.json`), the active profile (`permissioned-data-0016-2026-10-01`), and wire generation boundaries.
- Mandatory security invariants, authorization contexts, and credential handling rules.
- Complete build, test, and verification commands.

## Essential commands

### Backend (Swift 6.1)
```bash
# Build (takes ~68 seconds)
swift build

# Run test suite
swift test

# Run specific test
swift test --filter SwanSQLiteTests

# Run offline profile verification (default subcommand)
swift run swan verify
```

### Frontend (web/)
```bash
cd web
npm run check
npm test
npm run build
```

## Version control

Jujutsu (`jj`) is the sole history writer for this repository. Git is strictly read-only:
- A detached Git `HEAD` is normal and expected.
- Never run mutating Git commands (`git commit`, `git checkout`, `git stash`, `git reset`, `git merge`, `git pull`, `git push`).
- Leave changes in the working copy for `jj`.
