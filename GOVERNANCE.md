# Governance

Version 1.0 — effective 2026-08-22

This document says who decides what, how those people are chosen, and how a
contributor can change something that looks unchangeable. It is deliberately
short and deliberately honest about where the power actually sits.

---

## 1. What kind of project this is

HaloMem is a **single-vendor open source project**. Halofy employs the
maintainers, owns the copyright in the code it has written, holds the trademarks,
and sells a commercial product built on the same foundation. Final authority
rests with Halofy.

We are not going to describe that as a foundation-style meritocracy, because it
isn't one. What we can offer instead is that the decisions are made in public,
with reasons, in the repository, where you can read them and argue with them
before they land.

Two documents constrain what Halofy may do with that authority:

- **`OPEN-SOURCE-SCOPE.md`** — a versioned, public commitment about which
  capabilities stay open, with a stated consequence (a project rename) if we ever
  break it. Nothing in this governance document overrides it.
- **`LICENSE` / `LICENSE-APACHE-2.0` / `NOTICE`** — the licence grants, which are
  irrevocable for every release already published.

If this project ever grows maintainers who are not employed by Halofy, this
document changes to reflect that. It is versioned so the change is visible.

---

## 2. Roles

**Users.** Anyone running HaloMem. No obligations. Bug reports from users are the
highest-value input the project receives.

**Contributors.** Anyone whose pull request has been merged. Requires a signed
CLA (`CLA.md`, and section 9 of `CONTRIBUTING.md` for why).

**Reviewers.** Contributors with a track record in an area, who are asked to
review pull requests there. Advisory: a reviewer's approval is a strong signal,
not a merge.

**Maintainers.** Have merge rights, scoped to one or more areas. A maintainer is
accountable for the health of their area: its tests, its contracts, its issue
backlog, and the reviews it receives.

**Area owners.** For each area below, one maintainer is the tiebreaker.

| Area | Covers |
|---|---|
| Kernel core | write path, index, storage, tiers, movement, consolidation |
| Retrieval | drivers, conformance kit, allocator, referee |
| Security & tenancy | auth, IAM, tenancy, ACL, policy, audit, encryption, migrations |
| Console | `kernel/console/`, `kernel/src/console/` |
| Platform | HTTP transport, MCP, CLI, deployment, self-hosting |
| Docs | `docs/`, root documents |

**Project lead.** Halofy's kernel lead. Breaks ties between area owners, owns the
locked decisions in section 5, and is accountable for release decisions.

`MAINTAINERS.md` lists the current holders of each role. It is the authoritative
list; this document only defines the roles.

---

## 3. How decisions get made

**Default: lazy consensus.** Propose it in an issue, a discussion, or a pull
request. If nobody with standing in the area objects within a reasonable window —
three business days for ordinary changes, longer for anything cross-cutting — and
CI is green, it merges. Most changes never escalate past this.

**Objections are resolved by argument, not by vote.** A specific technical
objection ("this makes the ACL check a caller responsibility", "this breaks the
no-credentials path") blocks a merge until it is answered. "I would have done it
differently" does not.

**Escalation path.** Contributors and reviewers → the area owner → the project
lead. Escalation happens in the thread, in public, and the decision is written
into the thread with its reasoning. A decision that cannot be explained in the
thread is not ready to be made.

**Exceptions that do not go through consensus:**

- **Security fixes.** Handled privately under `SECURITY.md` until disclosure.
  Speed beats process; the write-up comes after.
- **Licence and trademark decisions.** Halofy only. Not delegable.
- **The open/commercial boundary.** Governed by `OPEN-SOURCE-SCOPE.md`. Changes
  land as pull requests against that file so the diff is permanent, and section 5
  of that document makes the boundary a one-way ratchet: capabilities may move
  from commercial to open, never the other way.
- **Roadmap and release timing.** Halofy's call, informed by issues and
  discussions. We will tell you what we are working on; we will not pretend the
  priority order is community-set when it is funded by a commercial product.

**Declining a contribution.** Some patches are declined on design grounds, and
some areas are maintained in-house (`CONTRIBUTING.md` section 2). When we decline
something, we say why, in the pull request, in enough detail that you could
change our mind with new information. What we will not do is leave it open
indefinitely without an answer.

---

## 4. Becoming a maintainer

There is no application form and no fixed contribution count. The bar is a track
record that makes the decision obvious:

1. **Sustained, merged contributions in one area** over several months — not one
   large pull request.
2. **Reviews of other people's work** in that area, showing you can find defects
   in code you did not write.
3. **Judgement about the non-negotiables.** Someone who has demonstrated they
   will not weaken a test to make it pass, and who understands why the ACL lives
   in the query layer.
4. **Availability.** Being a maintainer is a review obligation, not a badge.

The process: an existing maintainer nominates you in a private maintainers
thread; the area owner and the project lead confirm; you are asked whether you
want it; `MAINTAINERS.md` is updated in a pull request. Nominations are private
so that declining costs nobody anything in public.

**Scope.** Maintainer rights are per-area. A console maintainer does not merge
migrations. Areas can be added to a maintainer over time.

**Stepping back.** Say so, and you move to emeritus in `MAINTAINERS.md`. No
explanation owed, and coming back later is a message, not a re-application.

**Inactivity.** After roughly six months with no reviews or merges, a maintainer
is moved to emeritus and merge rights are removed. This is hygiene — stale merge
rights are a security exposure — not a judgement, and it is reversed by asking.

**Removal for cause.** Repeated violations of the non-negotiables, a Code of
Conduct enforcement action, or actions that endanger users' data or trust.
Decided by the project lead, recorded in `MAINTAINERS.md`, and stated plainly to
the person first.

---

## 5. Locked decisions (D1–D10)

Ten architectural decisions are marked **locked**. Locked does not mean sacred;
it means **reversing one is a rewrite, not a refactor**, so the burden of proof
sits with the proposal rather than with the status quo.

| | Decision |
|---|---|
| **D1** | Retrieval is delegated, permanently. The kernel never builds a competitive retriever; the baseline retriever exists as a referee control lane. |
| **D2** | The context allocator returns ranked blocks. The agent framework places them. The kernel never assembles prompts. |
| **D3** | `mem_forget` is the one governed exception to D7: compliance erasure, cascading and certified. |
| **D4** | Every syscall writes an audit row — including denied, miss, brownout and error outcomes. `audit_log` is append-only. |
| **D5** | One authority. Postgres holds index, vectors, policy and audit. PGlite embeds it for dev and test. Sidecars and warm stores are disposable read-only caches. |
| **D6** | Rule of two: no driver interface until a second implementation exists. |
| **D7** | Stable ULIDs and supersedence chains. A conflicting fact closes the prior fact's validity and links to it. Never overwrite, never delete. |
| **D8** | TypeScript kernel with an MCP syscall surface. |
| **D9** | Identity is resolved server-side from an API key. No caller-asserted namespace, actor, role, team or source scope is ever trusted. |
| **D10** | Connectors and importers feed the write path, never the store directly. Imported data gets the same extraction, verification, provenance, policy and audit as agent conversation. |

Individual subsystems carry further numbered decisions within their own scope,
stated in the module headers of the code that implements them. They follow the
same rules as D1–D10: an ADR, not a pull request.

### What "locked" means for a contributor

- **A pull request that contradicts a locked decision will be closed**, even if
  the code is good and the tests pass. This is not a comment on the work; it is
  that the change costs more than the pull request can carry.
- **The way to change one is an ADR, not a pull request.** Argue the decision
  before writing the code. If the ADR is accepted, the implementation follows and
  is welcome.
- **Some are effectively immutable.** D1, D4, D5, D7 and D9 are the product. A
  proposal to reverse one of them is a proposal to build a different product, and
  it will be read that way. D2, D3, D6, D8 and D10 are load-bearing but arguable
  with a strong enough case.
- **Working within a locked decision is always in scope.** D1 does not forbid
  better retrieval — it says better retrieval arrives as a cartridge. D7 does not
  forbid fixing supersedence — it forbids fixing it by overwriting. Most good
  ideas that look blocked by a locked decision are not.

---

## 6. Architecture decision records

Non-trivial design decisions are recorded as ADRs in `docs/adr/`, numbered and
immutable once accepted.

**An ADR is required for:** changes to a locked decision; new persistent state or
a new table; a new external dependency in the core kernel; a change to a public
surface (syscall, HTTP route, MCP tool, driver interface); anything affecting the
ACL, tenancy, audit, encryption or erasure semantics; anything that changes what
the no-credentials path can do; and any change to the open/commercial boundary.

**An ADR is not required for:** bug fixes, performance work that preserves
behaviour, new tests, docs, console work within existing patterns, or a new
connector or cartridge built on an existing framework.

**Format** — `docs/adr/NNNN-short-slug.md`, next free number, with:

```
# NNNN. Title
Status: Proposed | Accepted | Rejected | Superseded by NNNN
Date: YYYY-MM-DD
Deciders: names

## Context      what is true today, and what forces the decision
## Options      what was considered, including doing nothing
## Decision     what we chose, in one paragraph, in the active voice
## Consequences what gets better, what gets worse, what we now cannot do
```

**Lifecycle.** Open a pull request with the ADR at `Proposed`. Discussion happens
in the pull request. The area owner accepts or rejects; anything touching a
locked decision needs the project lead. Accepted ADRs are then **never edited** —
a decision that changes gets a new ADR that supersedes the old one, and the old
one's status line is updated to point at it. The record of what we used to think,
and why we stopped thinking it, is the valuable part.

A rejected ADR still gets merged, as `Rejected`. The next person to have the same
idea deserves to find the reasoning.

---

## 7. Changing this document

Through a pull request against this file, approved by the project lead, with the
version line updated. History stays in git.

Changes to `OPEN-SOURCE-SCOPE.md` follow that document's own rules, which are
stricter than these — as they should be, since it is the one that constrains us
rather than the contributors.
