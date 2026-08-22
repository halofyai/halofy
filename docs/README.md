# Halofy documentation

Halofy is the open access and governance layer for AI agents across an
organization. It gives agents, applications, and operators one server-owned
identity and policy model across shared organizational context, with
provenance, audit, and signed erasure. The kernel maintains that context and
delegates ranking to retrieval engines mounted as read-only drivers.

## Start here

| If you want to… | Read |
| --- | --- |
| Run something in the next five minutes | [getting-started.md](getting-started.md) |
| Understand how it works before changing it | [architecture.md](architecture.md) |
| Mount your own retrieval engine | [driver-kit.md](driver-kit.md) |
| Deploy and operate it yourself | [self-hosting.md](self-hosting.md) |

## The four guides

### [getting-started.md](getting-started.md)

Zero to a working kernel. Begins with `npm run demo`, which runs the complete
story — bootstrap, pin, write, hybrid search, cold-tier fault, stats, audit,
and a signed erasure certificate — with no API key, no database, and no
network. Then: installing, issuing the first API key, writing governed context,
searching, assembling a working set, and reading the audit trail, with real
commands and real output.

### [architecture.md](architecture.md)

The mechanism, for people who intend to modify it. The authority model and why
there is exactly one database. A diagram of the real data flow. The syscall
surface and the pipeline every syscall runs. The two storage tiers and how the
fault handler decides between them. The five stages of the write path.
Supersedence chains and bi-temporal validity, including what actually triggers
a supersedence and what does not. The ACL ancestor rule with worked examples
and the SQL `LIKE`/`ESCAPE` hazard that has bitten this codebase twice. The
allocator's budget packing. Where every audit row comes from. Erasure. The
brownout table.

### [driver-kit.md](driver-kit.md)

For anyone building a retrieval engine. The `RetrieverDriver` interface, the
`ScopedView` contract and what it guarantees so you do not have to implement
it, the import boundary and how it is statically enforced, all six conformance
checks explained, and a complete worked cartridge that passes 6/6 — plus how to
mount it, how to route to it by policy, and the failure mode where an unmounted
driver silently falls back to baseline.

### [self-hosting.md](self-hosting.md)

Docker Compose, environment variables, what `env:init` generates, Postgres and
pgvector requirements, indexing at scale, what `NODE_ENV=production` enforces,
backups and restore drills, upgrades, operating notes — and an explicit list of
what the open build does not include, so nothing is a surprise later.

## Elsewhere in the repository

| Path | Contents |
| --- | --- |
| `kernel/README.md` | Kernel package: scripts, layout, development commands. |
| `kernel/src/` | The kernel. `architecture.md` has a per-directory source map. |
| `kernel/test/` | The hermetic test suite: in-memory PGlite, stub LLM, hash embedder, no network. |
| `kernel/console/` | The frameworkless control room UI. |
| `docs/security/threat-model.md` | Assets, boundaries, adversaries, and the controls that stop each — including the ones that are only partial. |
| `docs/commercial/open-vs-managed.md` | Capability-by-capability: what the open build does, and what Halofy sells on top. |
| `docs/adr/` | Architecture decision records. |
| `CONTRIBUTING.md` | How to propose and land a change. |
| `SECURITY.md` | Reporting a vulnerability. |
| `LICENSE`, `LICENSE-APACHE-2.0`, `NOTICE` | AGPL-3.0 for the kernel and console; Apache-2.0 for the permissive subtrees, including the retrieval driver kit. |
| `LICENSING.md` | Which licence applies where, the one-way rule, and the commercial licence. |
| `OPEN-SOURCE-SCOPE.md` | What stays open, permanently, and what happens if that ever changes. |
| `GOVERNANCE.md`, `MAINTAINERS.md`, `SUPPORT.md` | Who decides what, who holds which role, where questions go. |
| `TRADEMARK.md` | Trademarks are granted by neither license. |

## Conventions in these docs

- Transcripts are captured from real runs against this repository, not
  written by hand. Identifiers, timestamps, and timings will differ in your
  run; shapes will not.
- Where output is abridged, it says so.
- Commands whose output is not shown are documented from the scripts and
  source that implement them.
- Claims about behaviour name the file that implements them, so you can check
  rather than trust.
