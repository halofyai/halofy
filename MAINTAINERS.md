# Maintainers

The authoritative roster. [GOVERNANCE.md](GOVERNANCE.md) defines what these
roles mean, how they are granted, and how they end; this file only says who
holds them today.

Changes to this file land as pull requests, so the history of who could merge
what is public and diffable.

> **FILL-BEFORE-PUBLISH** — the GitHub handles below are placeholders. Replace
> every `@handle` with a real account, and delete this block, before the first
> public push. A roster naming nobody is worse than no roster: it makes the
> escalation path in `GOVERNANCE.md` section 3 undefined.

## Project lead

Breaks ties between area owners, owns the locked decisions (D1–D10), and is
accountable for release decisions.

| Name | GitHub | Affiliation |
|---|---|---|
| _to be filled_ | `@handle` | Halofy |

## Area owners and maintainers

One area owner per area is the tiebreaker for that area. Maintainer rights are
per-area: a console maintainer does not merge migrations.

| Area | Owner | Maintainers |
|---|---|---|
| Kernel core — write path, index, storage, tiers, movement, consolidation | `@handle` | `@handle` |
| Retrieval — drivers, conformance kit, allocator, referee | `@handle` | `@handle` |
| Security & tenancy — auth, IAM, tenancy, ACL, policy, audit, encryption, migrations | `@handle` | `@handle` |
| Console — `kernel/console/`, `kernel/src/console/` | `@handle` | `@handle` |
| Platform — HTTP transport, MCP, CLI, deployment, self-hosting | `@handle` | `@handle` |
| Docs — `docs/`, root documents | `@handle` | `@handle` |

`.github/CODEOWNERS` routes review requests using GitHub teams rather than
individual handles. The teams named there must contain the people named here;
GitHub silently ignores a CODEOWNERS row naming a team that does not exist or
lacks write access, so a mismatch fails quietly.

## Security response

Vulnerability reports go through the channels in [SECURITY.md](SECURITY.md) —
GitHub Private Vulnerability Reporting, or <security@halofy.ai>. They are not
routed through this roster and are not discussed in public issues.

## Emeritus

Former maintainers, with thanks. Moving to emeritus removes merge rights and
nothing else; coming back is a message, not a re-application.

_None yet._

## Contact

- Project and contribution questions: GitHub Discussions, or
  [SUPPORT.md](SUPPORT.md).
- Conduct concerns: <conduct@halofy.ai>.
- Licensing and trademark: <licensing@halofy.ai>.
