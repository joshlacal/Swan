# Swan Documentation Index

Welcome to the documentation suite for **Swan**, a Swift-native AT Protocol Personal Data Server (PDS) and permissioned-data interoperability engine.

---

## 📚 Core Documentation Library

| Document | Description | Target Audience |
|---|---|---|
| 🏛️ **[Modular Architecture & Component Overview](architecture.md)** | Deep dive into Hummingbird 2 runtime, SQLite dual-plane storage, OAuth 2.1 / DPoP subsystem, public firehose sequencer, MST repository engine, and MFA/Passkey infrastructure. | Engineers, Architects, Security Auditors |
| 🚀 **[Production Deployment & Configuration Guide](deployment-guide.md)** | Production deployment guide covering Docker, native systemd service configuration, secrets management (`0600` owner-only files), CLI flags (`swan serve`), and reverse proxy setups (Caddy / Nginx). | DevOps, SREs, System Administrators |
| 🛠️ **[Operational Runbook & Disaster Recovery](operational-runbook.md)** | Operational guide for health monitoring, online encrypted account backups (`swan backup`), disaster restore (`swan restore`), key rotation, database maintenance, and offline recovery. | SREs, On-Call Operators |
| 📖 **[API & Protocol Reference](api-reference.md)** | Complete reference for all AT Protocol XRPC methods, OAuth 2.1 / DPoP discovery and token endpoints, Account Portal REST APIs (`/account/api/*`), and Loopback Management APIs. | Integrators, Frontend Developers, App Developers |

---

## 🛡️ Security & Protocol Specifications

- **[Threat Boundaries & Security Model](threat-boundaries.md):** Formal definitions of access control boundaries, cryptographic accumulators (LtHash), author commitments, and PLC key resolution caching.
- **[OAuth Scope Limits & Divergences](oauth-scope-limits.md):** Documentation of input budgets, expanded grant limits, and deliberate protocol admission rules compared to `@atproto` TypeScript references.
- **[Permissioned Data Repin Scope](permissioned-data-repin-scope.md):** Pinned protocol profile specifications and upstream compatibility matrices.

---

## ⚡ Quick Start for Operators

1. **Review System Prerequisites:** See [System Requirements in Deployment Guide](deployment-guide.md#1-prerequisites--system-requirements).
2. **Generate Cryptographic Secrets:** Follow the [Zero-Secret Generation Script](deployment-guide.md#2-secrets-management--key-generation).
3. **Deploy via Docker Compose:** Deploy using our [Hardened Production Compose File](deployment-guide.md#4-production-docker-deployment).
4. **Configure Reverse Proxy:** Setup TLS and WebSocket streaming with [Caddy or Nginx Configurations](deployment-guide.md#6-reverse-proxy-configuration).
5. **Verify Service Health:** Validate your installation using [Health Probes](operational-runbook.md#1-health-monitoring--metrics).
