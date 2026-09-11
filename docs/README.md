# Documentation index

This directory contains technical documentation for Swan, a Swift-native AT Protocol Personal Data Server (PDS) and permissioned-data server running profile `permissioned-data-0016-2026-09-10`.

## Core documentation

- [Swan architecture](architecture.md): Overview of the Hummingbird 2 server runtime, the three SQLite storage planes, the OAuth 2.1 and DPoP subsystem, the public firehose, the spaces engine, and the MFA subsystem.
- [Server surfaces](server-surfaces.md): Technical specification for foreign handle resolution, interactive OAuth browser pages, the SvelteKit Account Management Portal, and XRPC proxy routing.
- [Interoperability lab](interop-lab.md): Test harness and conformance matrix for validating Swan against reference AT Protocol implementations across public and permissioned-data profiles.
- [Forum lab](forum-lab.md): Test environment and verification fixtures for multi-party permissioned-data spaces and threaded forum workloads.
- [API reference](api-reference.md): Endpoint specifications for AT Protocol XRPC methods, OAuth 2.1 authorization endpoints, account portal REST APIs, and loopback management operations.
- [Deployment guide](deployment-guide.md): Production deployment instructions covering Docker, native systemd service configuration, secrets management, CLI flags, and reverse proxy setup.
- [Operational runbook](operational-runbook.md): Procedures for health monitoring, encrypted account backups, disaster recovery, key rotation, and database maintenance.

## Security and protocol specifications

- [Threat boundaries](threat-boundaries.md): Formal definitions of access control boundaries, cryptographic accumulators (LtHash), author commitments, and PLC key resolution caching.
- [OAuth scope limits](oauth-scope-limits.md): Input budgets, grant limits, and protocol admission rules compared to upstream TypeScript reference implementations.

## Research notes

- [Permissioned data repin scope](notes/permissioned-data-repin-scope.md): Engineering analysis examining lexicon differences, scope grammars, and type requirements for re-pinning against upstream permissioned-data branches.

The directories `docs/superpowers/` and `docs/security/` contain internal engineering logs and audit records; they are retained for development provenance rather than user-facing documentation.
