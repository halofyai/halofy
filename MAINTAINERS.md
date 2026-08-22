# Maintainers

The authoritative roster. [GOVERNANCE.md](GOVERNANCE.md) defines what these
roles mean, how they are granted, and how they end; this file only says who
holds them today.

Changes to this file land as pull requests, so the history of who could merge
what is public and diffable.

## Project lead

Breaks ties between area owners, owns the locked decisions (D1–D10), and is
accountable for release decisions.

| Name | GitHub | Affiliation |
|---|---|---|
| Koushik Bhargav | [`@koushikbhargav`](https://github.com/koushikbhargav) | Halofy |

## Area owners and maintainers

One area owner per area is the tiebreaker for that area. Maintainer rights are
per-area: a console maintainer does not merge migrations.

| Area | Owner | Maintainers |
|---|---|---|
| Kernel core: write path, index, storage, tiers, movement, consolidation | `@koushikbhargav` | `@koushikbhargav` |
| Retrieval: drivers, conformance kit, allocator, referee | `@koushikbhargav` | `@koushikbhargav` |
| Security and tenancy: auth, IAM, tenancy, ACL, policy, audit, encryption, migrations | `@koushikbhargav` | `@koushikbhargav` |
| Console: `kernel/console/`, `kernel/src/console/` | `@koushikbhargav` | `@koushikbhargav` |
| Platform: HTTP transport, MCP, CLI, deployment, self-hosting | `@koushikbhargav` | `@koushikbhargav` |
| Docs: `docs/`, root documents | `@koushikbhargav` | `@koushikbhargav` |

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
