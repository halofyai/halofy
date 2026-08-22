# Changelog

All notable changes to HaloMem are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two kinds of entry get special treatment, because both are promises rather than
code:

- **Scope changes** — any change to `OPEN-SOURCE-SCOPE.md` is recorded here with
  its version, per section 6 of that document. A capability moving from
  commercial to open is a scope change. A capability moving the other way is the
  event described in scope section 3.1 and is never a quiet entry.
- **Migrations** — schema migrations are append-only and numbered. Each release
  names the migration head it ships, because a deployed migration is never
  rewritten.

## [Unreleased]

### Added
- Nothing yet.

## [0.1.0] — unreleased

First public release of the HaloMem kernel.

### Added
- Memory syscalls over MCP and HTTP: `mem_write`, `mem_write_status`,
  `mem_read`, `mem_search`, `mem_assemble`, `mem_fault`, `mem_pin`, `mem_unpin`,
  `mem_stats`, `mem_forget`, `mem_policy`, `mem_policy_ack`, `mem_share`,
  `mem_manifest`.
- Custody write path: extract, verify, resolve entities, dedupe, supersede,
  record provenance, audit. Supersedence closes the prior fact's validity
  interval and links to it; nothing is overwritten (D7).
- Two storage tiers: L2 in Postgres/pgvector, L3 as encrypted, Git-versioned
  markdown concepts, with a context-fault path between them.
- Hierarchical ACL enforced in the query layer, with server-side identity
  resolution from an API key (D9).
- Append-only audit on every syscall outcome, including denied, miss, brownout
  and error (D4).
- Signed erasure: `mem_forget` mints an ed25519 `DeletionCertificate` that
  verifies offline, writes tombstones, and leaves audit history intact.
- Retrieval driver cartridges with a statically enforced import boundary, plus
  the six-check conformance kit (`npx tsx src/cli.ts conformance <driver>`).
- Frameworkless control room: string-rendered, XSS-escaped, no build step.
- Self-host stack: Docker Compose with Postgres/pgvector, a non-root image,
  Kubernetes manifests, numbered migrations, backup and restore scripts.
- Offline operation as a first-class property: `npm run demo` runs the full
  story with no API key, no database server, no network, and no model download.

### Licensing
- AGPL-3.0-or-later for the kernel and console.
- Apache-2.0 for `kernel/src/driver/`, `kernel/src/mcp/`, and
  `kernel/integrations/`.
- `OPEN-SOURCE-SCOPE.md` v1.0 published as a binding statement of what stays
  open.

[Unreleased]: https://github.com/halofyai/halofy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/halofyai/halofy/releases/tag/v0.1.0
