# Architecture decision records

Non-trivial design decisions are recorded here, numbered and immutable, per
[GOVERNANCE.md](../../GOVERNANCE.md) section 6.

An ADR is warranted when a decision is hard to reverse, when it constrains
future work, or when the next person to read the code will otherwise ask "why is
it like this?" and get no answer. Routine implementation choices do not need
one.

## Format

`docs/adr/NNNN-short-slug.md`, using the next free number. Numbers are never
reused and accepted records are never edited in place — a decision that turns
out to be wrong gets a **new** ADR that supersedes it, and the old one is marked
`Superseded by NNNN`. The value of the archive is that it shows what was
believed at the time.

Each record carries:

- **Status** — Proposed, Accepted, Superseded by NNNN, or Rejected.
- **Date.**
- **Context** — the forces in play, including the constraints that made the
  obvious answer unavailable.
- **Decision** — what was decided, stated so it can be checked against the code.
- **Consequences** — what this makes easy, what it makes hard, and what it
  forecloses.

## Locked decisions

The ten locked decisions D1–D10 predate this directory and are stated in
[GOVERNANCE.md](../../GOVERNANCE.md) section 5, with their practical form in
[architecture.md](../architecture.md). Reversing one is a rewrite, not a
refactor. New ADRs may build on them; an ADR proposing to reverse one is a
project-lead decision.

## Index

_No records yet. The first accepted ADR adds its row here._

| # | Title | Status | Date |
|---|---|---|---|
